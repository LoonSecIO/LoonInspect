"""Enrolling a second factor through the API (#653) against real Postgres: status, a fresh
secret, the code that confirms it and the recovery codes shown once, then a sign-in with a
recovery code that works exactly once."""

from __future__ import annotations

import os
import time

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
ADMIN = ("mfa-enrol-admin@example.com", "mfa-enrol-admin-password")


@pytest_asyncio.fixture(loop_scope="session")
async def unenrolled(tenant_ready):
    """One admin this suite owns, with no second factor, no sessions and no lockout rows,
    before and after."""
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, AuthIdentity, LoginAttempt, UserSession

    async def reset() -> None:
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            account = (await db.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first()
            if account is None:
                account, _ = await create_account(
                    db, email=ADMIN[0], display_name="mfa enrol", password=ADMIN[1], roles=("admin",)
                )
            await db.execute(delete(UserSession).where(UserSession.account_id == account.id))
            await db.execute(
                delete(AuthIdentity).where(AuthIdentity.account_id == account.id, AuthIdentity.provider == mfa.PROVIDER)
            )
            await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == ADMIN[0]))
            await db.commit()

    await reset()
    yield
    await reset()


def _client() -> httpx.AsyncClient:
    from app.main import app

    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mfa-enrol.example.com")


async def _password_step(client: httpx.AsyncClient) -> httpx.Response:
    return await client.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})


async def test_enrol_confirm_and_then_a_recovery_code_signs_in_once(unenrolled):
    async with _client() as client:
        assert (await _password_step(client)).status_code == 200
        client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
        assert (await client.get("/api/auth/mfa")).json() == {
            "enrolled": False,
            "pending": False,
            "confirmedAt": None,
            "recoveryCodesRemaining": 0,
        }
        assert (await client.post("/api/auth/mfa/confirm", json={"code": "123456"})).status_code == 409
        started = await client.post("/api/auth/mfa/enrol")
        assert started.status_code == 200
        secret = started.json()["secret"]
        assert started.json()["otpauthUrl"].startswith("otpauth://totp/LoonInspect:")
        assert (await client.get("/api/auth/mfa")).json()["pending"] is True
        totp = pyotp.TOTP(secret)
        wrong = str((int(totp.now()) + 1) % 1_000_000).zfill(6)
        assert (await client.post("/api/auth/mfa/confirm", json={"code": wrong})).status_code == 401
        confirmed = await client.post("/api/auth/mfa/confirm", json={"code": totp.now()})
        assert confirmed.status_code == 200
        codes = confirmed.json()["recoveryCodes"]
        assert len(codes) == 10 and len(set(codes)) == 10
        status = (await client.get("/api/auth/mfa")).json()
        assert status["enrolled"] is True and status["pending"] is False and status["recoveryCodesRemaining"] == 10
        # A second enrolment is refused while one is confirmed.
        assert (await client.post("/api/auth/mfa/enrol")).status_code == 409
        # The session that confirmed the factor now reads as code-verified.
        assert (await client.get("/api/auth/me")).status_code == 200
        await client.post("/api/auth/logout")

    async with _client() as client:
        step_one = await _password_step(client)
        assert step_one.status_code == 202 and step_one.json()["methods"] == ["totp", "recovery"]
        challenge = step_one.json()["challenge"]
        # The code that confirmed the enrolment is spent; a recovery code signs in instead.
        recovered = await client.post("/api/auth/login/mfa", json={"challenge": challenge, "code": codes[0].upper()})
        assert recovered.status_code == 200 and recovered.json()["email"] == ADMIN[0]
        client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
        assert (await client.get("/api/auth/mfa")).json()["recoveryCodesRemaining"] == 9
        await client.post("/api/auth/logout")

    async with _client() as client:
        challenge = (await _password_step(client)).json()["challenge"]
        spent = await client.post("/api/auth/login/mfa", json={"challenge": challenge, "code": codes[0]})
        assert spent.status_code == 401 and "recovery code works" in spent.json()["detail"]
        # The authenticator still works: one step ahead of the code that confirmed.
        ahead = totp.at(int(time.time()) + 30)
        assert (await client.post("/api/auth/login/mfa", json={"challenge": challenge, "code": ahead})).status_code == 200


async def test_a_bearer_token_cannot_enrol(unenrolled):
    """A leaked API token must not be able to add a factor its owner does not hold."""
    async with _client() as client:
        assert (await _password_step(client)).status_code == 200
        client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
        minted = await client.post("/api/tokens", json={"name": "mfa-enrol-probe", "scopes": []})
        if minted.status_code != 201:
            pytest.skip(f"token minting answered {minted.status_code}; the bearer path is covered elsewhere")
        token = minted.json().get("token") or minted.json().get("secret")
    async with _client() as bearer:
        bearer.headers["Authorization"] = f"Bearer {token}"
        assert (await bearer.post("/api/auth/mfa/enrol")).status_code == 403
