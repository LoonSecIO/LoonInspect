"""The Support page's Storage card and its answer, through the route and against a real Postgres (#786).

What is pinned: every table the page reasons about exists in this database (a name typed wrong
in `app.core.storage.CLOCKS` fails here, not on an operator's screen); the clocks are the settings
in force, with the change log reading "for ever" at its default and naming the setting that
bounds it; the sizes are the database's own; and the route is SYSTEM_READ's, so a viewer is
refused.
"""

from __future__ import annotations

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

ADMIN = ("storage-admin@example.com", "storage-admin-password")
VIEWER = ("storage-viewer@example.com", "storage-viewer-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        for email, password, roles in ((*ADMIN, ("admin",)), (*VIEWER, ("viewer",))):
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=email.split("@")[0], password=password, roles=roles)
            await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
        await db.commit()


async def _client(credentials: tuple[str, str]) -> httpx.AsyncClient:
    from app.main import app

    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=f"https://storage-{uuidlib.uuid4().hex[:6]}.example.com"
    )
    response = await client.post("/api/auth/login", json={"email": credentials[0], "password": credentials[1]})
    assert response.status_code == 200, response.text
    return client


async def test_every_table_the_page_reasons_about_exists_and_carries_its_clock(accounts) -> None:
    from app.core.config import settings
    from app.core.storage import CLOCKS

    client = await _client(ADMIN)
    try:
        response = await client.get("/api/system/storage")
    finally:
        await client.aclose()
    assert response.status_code == 200, response.text
    body = response.json()

    by_name = {row["table"]: row for row in body["tables"]}
    assert list(by_name) == [clock.table for clock in CLOCKS]
    missing = [name for name, row in by_name.items() if not row["present"]]
    assert missing == [], f"CLOCKS names tables this database does not have: {missing}"

    assert body["databaseBytes"] > 0 and body["measuredAt"]
    assert all(row["bytes"] >= 0 and row["rowsEstimate"] >= 0 for row in body["tables"])

    # The record is for ever; the change log says which setting would bound it (0 = for ever).
    changes = by_name["device_changes"]
    assert (changes["area"], changes["retentionDays"], changes["setting"]) == ("record", None, "CHANGE_LOG_RETENTION_DAYS")
    assert by_name["observation_entries"]["retentionDays"] is None and by_name["observation_entries"]["setting"] is None
    # The machinery reads the settings in force, and a fixed clock its number.
    assert by_name["runs"]["retentionDays"] == settings.run_retention_days and by_name["runs"]["setting"] == "RUN_RETENTION_DAYS"
    assert by_name["event_outbox"]["retentionDays"] == settings.event_outbox_retention_days
    assert by_name["share_log"]["retentionDays"] == 90 and by_name["share_log"]["setting"] is None


async def test_the_change_log_clock_follows_its_setting(accounts, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "change_log_retention_days", 90)
    client = await _client(ADMIN)
    try:
        response = await client.get("/api/system/storage")
    finally:
        await client.aclose()
    assert response.status_code == 200
    [changes] = [row for row in response.json()["tables"] if row["table"] == "device_changes"]
    assert changes["retentionDays"] == 90


async def test_a_viewer_is_refused(accounts) -> None:
    client = await _client(VIEWER)
    try:
        response = await client.get("/api/system/storage")
    finally:
        await client.aclose()
    assert response.status_code == 403, response.text
