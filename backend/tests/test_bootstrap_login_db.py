"""Environment-created administrators can authenticate at private-domain addresses (#815)."""

from __future__ import annotations

import os
import uuid

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy import delete, select

from app.api.auth import _LOCKOUT_THRESHOLD, router
from app.core import bootstrap
from app.core.config import settings
from app.core.database import get_db, session_for_tenant, unscoped_session
from app.models.schema import Account, AccountRole, AuthIdentity, LoginAttempt, Tenant, UserSession

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
