"""The tenant switch (#36) against a real Postgres: memberships are listed on `/me`, a
switch mints a new session that acts for the target and revokes the old one, the acting
tenant's rows are the only rows visible, a tenant without a membership is refused, and
the switch lands in both audit trails. Gated on RUN_DB_TESTS like the other suites."""

from __future__ import annotations

import json
import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("switch-admin@example.com", "switch-admin-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        if (await db.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first() is None:
            await create_account(db, email=ADMIN[0], display_name="switch admin", password=ADMIN[1], roles=("admin",))
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == ADMIN[0]))
        await db.commit()


async def _signed_in(credentials: tuple[str, str]) -> httpx.AsyncClient:
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://switch.example.com")
    email, password = credentials
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return client


@pytest_asyncio.fixture(loop_scope="session")
async def admin(accounts):
    client = await _signed_in(ADMIN)
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def second_tenant(db):
    """A second operational tenant with a connection of its own, and the admin's
    membership in it; every row removed afterwards, the tenant last."""
    from app.core.database import session_for_tenant, unscoped_session
    from app.models.schema import Account, AccountTenant, MdmConnection, SessionTenant, Tenant, UserSession

    tenant_id = uuidlib.uuid4()
    async with unscoped_session() as unscoped:
        unscoped.add(Tenant(id=tenant_id, slug=f"second-{tenant_id.hex[:8]}", name="Second tenant", kind="operational"))
        await unscoped.commit()
    account_id = (await db.execute(select(Account.id).where(Account.email == ADMIN[0]))).scalar_one()
    db.add(AccountTenant(account_id=account_id, tenant_id=tenant_id, roles=["admin"]))
    await db.commit()
    async with session_for_tenant(tenant_id) as other:
        other.add(
            MdmConnection(name="second tenant's jamf", provider="jamf", base_url="https://second.example.com", is_active=False)
        )
        await other.commit()
    try:
        yield tenant_id
    finally:
        await db.rollback()
        async with session_for_tenant(tenant_id) as other:
            await other.execute(delete(MdmConnection))
            await other.commit()
        # Sessions switched into the tenant live at home; their index rows name it.
        hashes = select(SessionTenant.token_hash).where(SessionTenant.tenant_id == tenant_id)
        await db.execute(delete(UserSession).where(UserSession.token_hash.in_(hashes)))
        await db.execute(delete(AccountTenant).where(AccountTenant.tenant_id == tenant_id))
        await db.commit()
        async with unscoped_session() as unscoped:
            await unscoped.execute(delete(Tenant).where(Tenant.id == tenant_id))
            await unscoped.commit()


def _last_audit_lines(tenant_id: uuidlib.UUID, action: str) -> list[dict]:
    from app.core.audit import audit_path_for

    path = audit_path_for(str(tenant_id))
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return [row for row in rows if row.get("action") == action]


async def test_a_switch_is_a_new_session_that_acts_for_the_target_and_sees_only_its_rows(admin, db, second_tenant) -> None:
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    home = str(OPERATIONAL_TENANT_ID)
    me = await admin.get("/api/auth/me")
    assert me.status_code == 200, me.text
    body = me.json()
    assert body["tenant"]["id"] == home
    assert {t["id"] for t in body["tenants"]} == {home, str(second_tenant)}
    assert next(t for t in body["tenants"] if t["id"] == home)["current"] is True

    old_cookie = admin.cookies.get("loon_session")
    switched = await admin.post("/api/auth/switch-tenant", json={"tenantId": str(second_tenant)})
    assert switched.status_code == 200, switched.text
    assert switched.json()["tenant"]["id"] == str(second_tenant) and switched.json()["roles"] == ["admin"]
    assert admin.cookies.get("loon_session") != old_cookie, "a switch reissues the credential"
    admin.headers["X-CSRF-Token"] = admin.cookies.get("loon_csrf", "")

    # The new session serves the target tenant: its rows, and only its rows.
    me_after = await admin.get("/api/auth/me")
    assert me_after.json()["tenant"]["id"] == str(second_tenant)
    assert next(t for t in me_after.json()["tenants"] if t["id"] == str(second_tenant))["current"] is True
    listed = await admin.get("/api/mdm/connections")
    assert listed.status_code == 200 and [row["name"] for row in listed.json()] == ["second tenant's jamf"]

    # The session that made the switch is gone, not mutated.
    from app.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://switch.example.com") as stale:
        stale.cookies.set("loon_session", old_cookie)
        assert (await stale.get("/api/auth/me")).status_code == 401

    # Both trails carry the switch: the tenant left and the tenant entered.
    left = _last_audit_lines(OPERATIONAL_TENANT_ID, "auth.tenant.switched")
    entered = _last_audit_lines(second_tenant, "auth.tenant.switched")
    assert left and entered, "the switch is written to the tenant left and the tenant entered"

    # And back home, where the second tenant's connection is not.
    back = await admin.post("/api/auth/switch-tenant", json={"tenantId": home})
    assert back.status_code == 200 and back.json()["tenant"]["id"] == home
    admin.headers["X-CSRF-Token"] = admin.cookies.get("loon_csrf", "")
    names = [row["name"] for row in (await admin.get("/api/mdm/connections")).json()]
    assert "second tenant's jamf" not in names


async def test_a_tenant_without_a_membership_is_refused(admin, second_tenant) -> None:
    refused = await admin.post("/api/auth/switch-tenant", json={"tenantId": str(uuidlib.uuid4())})
    assert refused.status_code == 403
    assert "membership" in refused.json()["detail"]


async def test_a_removed_membership_ends_the_switched_session_on_its_next_request(admin, db, second_tenant) -> None:
    from sqlalchemy import delete as sa_delete

    from app.models.schema import AccountTenant

    switched = await admin.post("/api/auth/switch-tenant", json={"tenantId": str(second_tenant)})
    assert switched.status_code == 200, switched.text
    admin.headers["X-CSRF-Token"] = admin.cookies.get("loon_csrf", "")
    await db.execute(sa_delete(AccountTenant).where(AccountTenant.tenant_id == second_tenant))
    await db.commit()
    try:
        # Fail closed: no fall-back to the home roles, the session is revoked.
        assert (await admin.get("/api/auth/me")).status_code == 401
    finally:
        # Put the membership back for the fixture's own teardown and the next test's
        # sign-in state; the client's session is spent, which is the point.
        from sqlalchemy import select as sa_select

        from app.models.schema import Account

        account_id = (await db.execute(sa_select(Account.id).where(Account.email == ADMIN[0]))).scalar_one()
        db.add(AccountTenant(account_id=account_id, tenant_id=second_tenant, roles=["admin"]))
        await db.commit()
