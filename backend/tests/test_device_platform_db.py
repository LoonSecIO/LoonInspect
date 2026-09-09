"""`devices.platform` — one Jamf ID space per platform (#233).

Jamf Pro numbers computers and mobile devices in separate sequences that both start at
1. Keyed on `(connection, external_id)` alone, computer 42 and iPad 42 were one row that
alternated on every sweep, with every app removed and re-added each time and the churn
published as change. The key now includes the platform, and this proves the two coexist
and neither's app rows move when the other syncs.

v0 has no mobile client, so the second platform is manufactured by patching the one
value the computer client stamps: the point is the table, not the fetch.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

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

from tests.jamf_fake import HOST, FakeJamf  # noqa: E402

ADMIN = ("platform-admin@example.com", "platform-admin-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        email, password = ADMIN
        if (await session.execute(select(Account).where(Account.email == email))).scalars().first() is None:
            await create_account(session, email=email, display_name="platform admin", password=password, roles=("admin",))
        await session.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
        await session.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def client(accounts):
    from app.main import app

    signed_in = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://platform.example.com")
    email, password = ADMIN
    response = await signed_in.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    """A Jamf connection, removed with everything under it afterwards."""
    from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"platform {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
        capability_webhooks=True,
    )
    db.add(row)
    await db.commit()
    connection_id = row.id
    try:
        yield row
    finally:
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


async def _rows(db, connection_id: int, external_id: str) -> dict[str, int]:
    """Row ids by platform, read off the table rather than off held instances."""
    from app.models.schema import Device

    rows = (
        await db.execute(
            select(Device.platform, Device.id).where(
                Device.mdm_connection_id == connection_id, Device.external_id == external_id
            )
        )
    ).all()
    return dict(rows)


async def _app_names(db, device_id: int) -> set[str]:
    from app.models.schema import InstalledApp

    rows = (await db.execute(select(InstalledApp).where(InstalledApp.device_id == device_id))).scalars().all()
    return {row.name for row in rows}


async def test_two_platforms_share_an_external_id_without_sharing_a_row(db, jamf: FakeJamf, connection, monkeypatch) -> None:
    from app.mdm.jamf import client as jamf_client
    from app.mdm.service import sync_connection

    # One sweep as the computer client: every row is a Mac, stamped by the client.
    first = await sync_connection(db, connection)
    assert first.ok and first.device_count == 2, first
    synthetic_id = jamf.synthetic["id"]
    macs = await _rows(db, connection.id, synthetic_id)
    assert set(macs) == {"macos"}
    mac_id = macs["macos"]
    mac_apps = await _app_names(db, mac_id)
    assert mac_apps, "the synthetic record carries apps"

    # The same records, read by a client that declares another platform: a second row
    # per device, not a rewrite of the first.
    monkeypatch.setattr(jamf_client, "COMPUTER_PLATFORM", "ios")
    second = await sync_connection(db, connection)
    assert second.ok and second.device_count == 2, second
    both = await _rows(db, connection.id, synthetic_id)
    assert set(both) == {"macos", "ios"}
    assert both["macos"] == mac_id, "the Mac's row is the row it was"
    assert both["ios"] != mac_id
    assert await _app_names(db, both["ios"]) == mac_apps, "same record, so the same apps — on its own rows"

    # Change the record and read it as the other platform again: only that row moves.
    jamf.synthetic["applications"].append({"name": "Only On The iPad", "bundleId": "com.example.ipad", "version": "1.0"})
    third = await sync_connection(db, connection)
    assert third.ok, third
    assert "Only On The iPad" in await _app_names(db, both["ios"])
    assert await _app_names(db, mac_id) == mac_apps, "the Mac's app rows did not move"


async def test_the_list_filters_by_platform_and_the_row_carries_it(db, jamf: FakeJamf, connection, client) -> None:
    from app.mdm.service import sync_connection

    assert (await sync_connection(db, connection)).ok
    macs = await client.get(f"/api/devices?platform=macos&mdmConnectionId={connection.id}")
    assert macs.status_code == 200, macs.text
    assert macs.json()["total"] == 2 and all(item["platform"] == "macos" for item in macs.json()["items"])
    none = await client.get(f"/api/devices?platform=ios&mdmConnectionId={connection.id}")
    assert none.status_code == 200, none.text
    assert none.json()["total"] == 0 and none.json()["items"] == []
