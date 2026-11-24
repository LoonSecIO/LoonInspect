"""Environment-created administrators can authenticate at private-domain addresses (#815)."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy import delete, select

from app.api.auth import _LOCKOUT_THRESHOLD, router
from app.core import bootstrap, mfa
from app.core.config import settings
from app.core.database import get_db, session_for_tenant, unscoped_session
from app.models.schema import Account, AccountRole, AuthIdentity, LoginAttempt, Tenant, UserSession
from app.schemas.accounts import AccountCreateRequest

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]
PASSWORD = "bootstrap-private-domain-password"


@pytest_asyncio.fixture(loop_scope="session")
async def install(tenant_ready, monkeypatch, tmp_path):
    tenant_id = uuid.uuid4()
    async with unscoped_session() as db:
        db.add(Tenant(id=tenant_id, slug=f"bootstrap-{tenant_id.hex}", name="Bootstrap login test", kind="operational"))
        await db.commit()
    monkeypatch.setattr(bootstrap, "_claim_token", None)
    monkeypatch.setattr(settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    app = FastAPI()
    app.include_router(router)

    async def scoped_db():
        async with session_for_tenant(tenant_id) as db:
            yield db

    app.dependency_overrides[get_db] = scoped_db
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://bootstrap.example.test") as client:
            yield tenant_id, client
    finally:
        async with session_for_tenant(tenant_id) as db:
            for model in (UserSession, AccountRole, AuthIdentity, LoginAttempt, Account):
                await db.execute(delete(model))
            await db.commit()
        async with unscoped_session() as db:
            await db.execute(delete(Tenant).where(Tenant.id == tenant_id))
            await db.commit()


async def _bootstrap(tenant_id, monkeypatch, email):
    monkeypatch.setattr(settings, "initial_admin_email", email)
    monkeypatch.setattr(settings, "initial_admin_password", PASSWORD)
    async with session_for_tenant(tenant_id) as db:
        await bootstrap.bootstrap_accounts(db)
        account = (await db.scalars(select(Account))).one()
        account_id = account.id
        assert account.email == email.strip().lower()
        assert [role.role for role in account.roles] == ["admin"]
        assert account.identities[0].secret_hash != PASSWORD
    assert bootstrap.get_claim_token() is None
    return account_id


@pytest.mark.parametrize("domain", ["corp.local", "example.test", "corp.localhost", "example.invalid"])
async def test_environment_admin_can_sign_in_without_resetting_the_install(install, monkeypatch, domain):
    tenant_id, client = install
    email = f"  Walk-Admin@{domain.upper()}  "
    account_id = await _bootstrap(tenant_id, monkeypatch, email)
    assert (await client.get("/api/auth/status")).json()["setupRequired"] is False

    # Wrong and unknown credentials still reach the same authentication failure.
    wrong = await client.post("/api/auth/login", json={"email": email, "password": "incorrect-password"})
    missing = await client.post("/api/auth/login", json={"email": f"nobody@{domain}", "password": PASSWORD})
    assert wrong.status_code == missing.status_code == 401
    assert wrong.json() == missing.json() == {"detail": "Invalid email or password"}
    assert "loon_session" not in client.cookies

    response = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    assert response.json()["id"] == account_id and response.json()["email"] == email.strip().lower()
    assert "admin" in response.json()["roles"] and client.cookies.get("loon_session")
    assert response.json()["tenant"]["id"] == str(tenant_id)
    assert (await client.get("/api/auth/status")).json()["authenticated"] is True

    # Restarting bootstrap does not replace the account or reset its password.
    assert await _bootstrap(tenant_id, monkeypatch, email) == account_id


async def test_private_domain_login_retains_lockout_and_inactive_account_checks(install, monkeypatch):
    tenant_id, client = install
    email = "admin@corp.local"
    await _bootstrap(tenant_id, monkeypatch, email)
    async with session_for_tenant(tenant_id) as db:
        account = (await db.scalars(select(Account))).one()
        account.status = "disabled"
        await db.commit()
    for _ in range(_LOCKOUT_THRESHOLD):
        response = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
        assert response.status_code == 401 and response.json() == {"detail": "Invalid email or password"}
    locked = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert locked.status_code == 429
    assert "loon_session" not in client.cookies
    async with session_for_tenant(tenant_id) as db:
        attempt = (await db.scalars(select(LoginAttempt).where(LoginAttempt.identifier == email))).one()
        assert attempt.failure_count == _LOCKOUT_THRESHOLD and attempt.locked_until is not None


async def _create_from_accounts_schema(tenant_id, email, password=PASSWORD):
    payload = AccountCreateRequest(email=email, display_name="Canonical email test", password=password)
    async with session_for_tenant(tenant_id) as db:
        account, _ = await bootstrap.create_account(
            db, email=payload.email, display_name=payload.display_name, password=payload.password
        )
        await db.commit()
        return account.id, account.email


@pytest.mark.parametrize("email", ["admin@xn--bcher-kva.de", "cafe\u0301@example.com"])
async def test_creation_normalization_still_applies_to_sign_in_and_lockout(install, email):
    tenant_id, client = install
    account_id, stored = await _create_from_accounts_schema(tenant_id, email)
    assert stored != email
    signed = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert signed.status_code == 200 and signed.json()["id"] == account_id
    client.cookies.clear()

    # Both spellings address the same account and must exhaust one shared counter.
    for attempt in range(_LOCKOUT_THRESHOLD):
        entered = email if attempt % 2 else stored
        failed = await client.post("/api/auth/login", json={"email": entered, "password": "incorrect-password"})
        assert failed.status_code == 401
    for entered in (email, stored):
        locked = await client.post("/api/auth/login", json={"email": entered, "password": PASSWORD})
        assert locked.status_code == 429
    assert "loon_session" not in client.cookies
    async with session_for_tenant(tenant_id) as db:
        attempt = (await db.scalars(select(LoginAttempt))).one()
        assert attempt.identifier == stored and attempt.failure_count == _LOCKOUT_THRESHOLD


@pytest.mark.parametrize("email", ["admin@xn--bcher-kva.de", "cafe\u0301@example.com"])
async def test_raw_environment_identifier_remains_signable_when_it_has_a_canonical_form(install, monkeypatch, email):
    tenant_id, client = install
    account_id = await _bootstrap(tenant_id, monkeypatch, email)
    signed = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert signed.status_code == 200 and signed.json()["id"] == account_id
    assert signed.json()["email"] == email


@pytest.mark.parametrize("state", ["active", "disabled", "mfa"])
async def test_exact_identifier_wins_without_trying_a_second_accounts_credentials(install, monkeypatch, state):
    tenant_id, client = install
    email = "admin@xn--bcher-kva.de"
    exact_id = await _bootstrap(tenant_id, monkeypatch, email)
    other_password = "different-canonical-account-password"
    other_id, canonical = await _create_from_accounts_schema(tenant_id, email, other_password)
    assert other_id != exact_id and canonical != email
    async with session_for_tenant(tenant_id) as db:
        exact = await db.get(Account, exact_id)
        if state == "disabled":
            exact.status = "disabled"
        elif state == "mfa":
            db.add(AuthIdentity(account_id=exact_id, provider=mfa.PROVIDER, subject=exact_id, confirmed_at=datetime.now(UTC)))
        await db.commit()

    # The canonical account's valid password cannot rescue this exact account.
    failed = await client.post("/api/auth/login", json={"email": email, "password": other_password})
    assert failed.status_code == 401 and "loon_session" not in client.cookies
    signed = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    if state == "active":
        assert signed.status_code == 200 and signed.json()["id"] == exact_id
    elif state == "disabled":
        assert signed.status_code == 401 and "loon_session" not in client.cookies
    else:
        assert signed.status_code == 202 and "loon_session" not in client.cookies
        assert mfa.challenge_account_id(signed.json()["challenge"]) == exact_id


@pytest.mark.parametrize(
    ("made_by", "real", "real_alternate", "ghost", "ghost_alternate"),
    [
        (
            "accounts",
            "real.user@example.com",
            "Anyone <real.user@example.com>",
            "ghost.user@example.com",
            "Anyone <ghost.user@example.com>",
        ),
        (
            "accounts",
            "real.user@example.com",
            '"Anyone" <real.user@example.com>',
            "ghost.user@example.com",
            '"Anyone" <ghost.user@example.com>',
        ),
        ("accounts", "café@example.com", "café@example.com", "ghosté@example.com", "ghosté@example.com"),
        # Keyed on the stored row when an account matched, a raw environment identifier
        # would share no row with its own normalized spelling, and the oracle inverts.
        ("environment", "admin@xn--bcher-kva.de", "admin@bücher.de", "ghost@xn--bcher-kva.de", "ghost@bücher.de"),
    ],
)
async def test_lockout_does_not_reveal_whether_an_account_exists(
    install, monkeypatch, made_by, real, real_alternate, ghost, ghost_alternate
):
    tenant_id, client = install
    if made_by == "accounts":
        await _create_from_accounts_schema(tenant_id, real)
    else:
        await _bootstrap(tenant_id, monkeypatch, real)

    async def probe(entered, alternate):
        for _ in range(_LOCKOUT_THRESHOLD):
            failed = await client.post("/api/auth/login", json={"email": entered, "password": "incorrect-password"})
            assert failed.status_code == 401
        return (await client.post("/api/auth/login", json={"email": alternate, "password": "incorrect-password"})).status_code

    # Five failures, then one more in another spelling of the same address: the answer
    # must not depend on whether an account holds it (429 for one, 401 for the other
    # would be an account enumeration oracle on an unauthenticated route).
    assert await probe(real, real_alternate) == await probe(ghost, ghost_alternate) == 429


async def test_code_and_password_failures_share_one_lockout_for_a_raw_environment_identifier(install, monkeypatch):
    tenant_id, client = install
    email = "admin@xn--bcher-kva.de"
    account_id = await _bootstrap(tenant_id, monkeypatch, email)
    async with session_for_tenant(tenant_id) as db:
        db.add(AuthIdentity(account_id=account_id, provider=mfa.PROVIDER, subject=account_id, confirmed_at=datetime.now(UTC)))
        await db.commit()
    challenge = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert challenge.status_code == 202
    for _ in range(_LOCKOUT_THRESHOLD):
        refused = await client.post("/api/auth/login/mfa", json={"challenge": challenge.json()["challenge"], "code": "000000"})
        assert refused.status_code == 401
    # Wrong codes count against the password step's lockout, whichever spelling it uses.
    for entered in (email, "admin@bücher.de"):
        locked = await client.post("/api/auth/login", json={"email": entered, "password": PASSWORD})
        assert locked.status_code == 429
    assert "loon_session" not in client.cookies
