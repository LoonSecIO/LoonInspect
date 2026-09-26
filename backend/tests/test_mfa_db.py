"""The second sign-in step (#653) against real Postgres: a challenge instead of a session,
a fresh code signs in, a replayed one never does, and wrong codes share the password lockout."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime

import httpx
import pyotp
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core import mfa

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]
ADMIN = ("mfa-admin@example.com", "mfa-admin-password")


@pytest_asyncio.fixture(loop_scope="session")
async def enrolled(tenant_ready):
    """One admin this suite owns, enrolled on the row the way a confirmed enrolment leaves
    it, with no lockout rows; the factor is removed again afterwards."""
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, AuthIdentity, LoginAttempt, UserSession

    secret = mfa.mint_secret()
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        account = (await db.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first()
        if account is None:
            account, _ = await create_account(db, email=ADMIN[0], display_name="mfa admin", password=ADMIN[1], roles=("admin",))
        # Sessions point at the identity they were minted through, so they go first.
        await db.execute(delete(UserSession).where(UserSession.account_id == account.id))
        await db.execute(delete(AuthIdentity).where(AuthIdentity.account_id == account.id, AuthIdentity.provider == mfa.PROVIDER))
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == ADMIN[0]))
        db.add(
            AuthIdentity(
                account_id=account.id,
                provider=mfa.PROVIDER,
                subject=account.id,
                secret_encrypted=secret,
                confirmed_at=datetime.now(UTC),
            )
        )
        await db.commit()
        account_id = account.id
    yield secret
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        await db.execute(delete(UserSession).where(UserSession.account_id == account_id))
        await db.execute(delete(AuthIdentity).where(AuthIdentity.account_id == account_id, AuthIdentity.provider == mfa.PROVIDER))
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == ADMIN[0]))
        await db.commit()


def _client() -> httpx.AsyncClient:
    from app.main import app

    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mfa.example.com")


async def _password_step(client: httpx.AsyncClient) -> httpx.Response:
    return await client.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})


async def test_the_password_earns_a_challenge_and_only_a_fresh_code_redeems_it(enrolled):
    secret = enrolled
    totp = pyotp.TOTP(secret)
    async with _client() as client:
        step_one = await _password_step(client)
        assert step_one.status_code == 202 and "loon_session" not in client.cookies
        assert step_one.json()["methods"] == ["totp"]
        challenge = step_one.json()["challenge"]
        code = totp.now()
        signed = await client.post("/api/auth/login/mfa", json={"challenge": challenge, "code": code})
        assert signed.status_code == 200 and signed.json()["email"] == ADMIN[0] and "loon_session" in client.cookies
        client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
        assert (await client.get("/api/auth/me")).status_code == 200
        await client.post("/api/auth/logout")

    async with _client() as client:
        challenge = (await _password_step(client)).json()["challenge"]
        # The code that just signed in is spent, and so is any older step.
        replayed = await client.post("/api/auth/login/mfa", json={"challenge": challenge, "code": code})
        assert replayed.status_code == 401 and "work once" in replayed.json()["detail"]
        # The next step's code is not: one step ahead is inside the window.
        ahead = totp.at(int(time.time()) + 30)
        assert (await client.post("/api/auth/login/mfa", json={"challenge": challenge, "code": ahead})).status_code == 200
        await client.post("/api/auth/logout")

    async with _client() as client:
        challenge = (await _password_step(client)).json()["challenge"]
        forged = await client.post("/api/auth/login/mfa", json={"challenge": challenge + "x", "code": totp.now()})
        assert forged.status_code == 401 and "expired or is not valid" in forged.json()["detail"]


async def test_wrong_codes_share_the_password_lockout(enrolled):
    secret = enrolled
    async with _client() as client:
        challenge = (await _password_step(client)).json()["challenge"]
        wrong = str((int(pyotp.TOTP(secret).now()) + 1) % 1_000_000).zfill(6)
        for _ in range(5):
            assert (await client.post("/api/auth/login/mfa", json={"challenge": challenge, "code": wrong})).status_code == 401
        assert (await client.post("/api/auth/login/mfa", json={"challenge": challenge, "code": wrong})).status_code == 429
        # One counter for the address: the password step is locked too.
        assert (await _password_step(client)).status_code == 429
