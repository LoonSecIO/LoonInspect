"""`GET/PUT /api/settings/patching-policy` through the running route (#116): read beside
the evidence by anyone who can read the page, written by `system:write` alone, cleared by
an empty statement, and an unstated policy is an empty statement rather than a missing
row or an error. Gated on RUN_DB_TESTS like the other database-backed suites."""

from __future__ import annotations

import os

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("policy-admin@example.com", "policy-admin-password")
VIEWER = ("policy-viewer@example.com", "policy-viewer-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        for (email, password), role in ((ADMIN, "admin"), (VIEWER, "viewer")):
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=f"policy {role}", password=password, roles=(role,))
            await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
        await db.commit()


async def _signed_in(credentials: tuple[str, str]) -> httpx.AsyncClient:
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://policy.example.com")
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
async def viewer(accounts):
    client = await _signed_in(VIEWER)
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def unstated(db):
    """No policy row before, and none left behind."""
    from app.models.schema import PatchingPolicy

    await db.execute(delete(PatchingPolicy))
    await db.commit()
    try:
        yield
    finally:
        await db.rollback()
        await db.execute(delete(PatchingPolicy))
        await db.commit()


async def test_an_unstated_policy_is_an_empty_statement_for_anyone_who_reads_the_page(viewer, unstated) -> None:
    response = await viewer.get("/api/settings/patching-policy")
    assert response.status_code == 200, response.text
    assert response.json() == {"statement": "", "updatedAt": None, "updatedBy": None}


async def test_only_system_write_states_it_and_the_statement_is_read_back_with_its_author(admin, viewer, unstated) -> None:
    statement = "  We require every update to the latest version within two weeks.  "
    assert (await viewer.put("/api/settings/patching-policy", json={"statement": statement})).status_code == 403

    stated = await admin.put("/api/settings/patching-policy", json={"statement": statement})
    assert stated.status_code == 200, stated.text
    body = stated.json()
    assert body["statement"] == statement.strip() and body["updatedBy"] == ADMIN[0] and body["updatedAt"] is not None

    read = await viewer.get("/api/settings/patching-policy")
    assert read.status_code == 200 and read.json()["statement"] == statement.strip()

    # Cleared with an empty statement, never by deleting the row: the author of the
    # clearing is a fact the audit trail keeps.
    cleared = await admin.put("/api/settings/patching-policy", json={"statement": "   "})
    assert cleared.status_code == 200 and cleared.json()["statement"] == "" and cleared.json()["updatedBy"] == ADMIN[0]

    too_long = await admin.put("/api/settings/patching-policy", json={"statement": "x" * 4001})
    assert too_long.status_code == 422
