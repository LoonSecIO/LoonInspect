"""`GET /api/devices/{id}/observation` against a real Postgres (#368): after a sweep of the
fake tenant every registry section carries a state, the list sections carry their entries,
groups ride beside them, a never-observed device says so, and a device that is not there
is a 404. RLS is the boundary: the tenancy sweep adds this route to its cross-tenant 404s.
Gated on RUN_DB_TESTS like the other suites."""

from __future__ import annotations

import json
import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("observation-admin@example.com", "observation-admin-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        if (await db.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first() is None:
            await create_account(db, email=ADMIN[0], display_name="observation admin", password=ADMIN[1], roles=("admin",))
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == ADMIN[0]))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def admin(accounts):
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://observation.example.com")
    response = await client.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"observation jamf {uuidlib.uuid4().hex[:8]}",
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


async def test_after_a_sweep_every_section_carries_a_state_and_the_lists_their_entries(
    admin, db, jamf: FakeJamf, connection
) -> None:
    from app.core.wire_vocabulary import SECTION_WRAPPERS
    from app.mdm.service import sync_connection
    from app.models.schema import Device

    result = await sync_connection(db, connection)
    assert result.ok
    device = (
        await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == jamf.real["id"]))
    ).scalar_one()

    response = await admin.get(f"/api/devices/{device.id}/observation")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["deviceId"] == device.id and body["subjectId"] == device.external_id and body["observed"] is True
    assert body["observedAt"] and body["apertureDigest"]

    sections = body["sections"]
    assert [s["name"] for s in sections] == list(SECTION_WRAPPERS), "registry order, every section"
    assert {s["state"] for s in sections} <= {"present", "empty", "not_observed", "outside_aperture"}
    by_name = {s["name"]: s for s in sections}
    # A full sweep reads every section: nothing is outside the aperture or unobserved.
    assert all(s["state"] in ("present", "empty") for s in sections), {s["name"]: s["state"] for s in sections}
    apps = by_name["applications"]
    assert apps["state"] == "present" and apps["entryCount"] == len(apps["entries"]) > 0
    assert all(entry["kind"] == "application" and entry["body"] for entry in apps["entries"])
    general = by_name["general"]
    assert general["state"] == "present" and isinstance(general["body"], dict) and general["body"]
    # A present list section carries no scalar body, and an empty one carries neither.
    assert apps["body"] is None
    for section in sections:
        if section["state"] == "empty":
            assert section["body"] is None and section["entries"] == []

    # Groups ride beside the sections, one per membership entry, named where a group span exists.
    memberships = by_name["group_memberships"]
    assert len(body["groups"]) == memberships["entryCount"]
    for group in body["groups"]:
        assert group["groupId"] and "departedAt" in group


async def test_a_device_the_ledger_never_recorded_says_so_in_every_section(admin, db, connection) -> None:
    from app.models.schema import Device

    device = Device(
        mdm_connection_id=connection.id,
        mdm_provider="jamf",
        external_id=f"never-{uuidlib.uuid4().hex[:6]}",
        serial_number="NEVEROBSERVED",
        hostname="never-observed",
    )
    db.add(device)
    await db.commit()
    response = await admin.get(f"/api/devices/{device.id}/observation")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["observed"] is False and body["observedAt"] is None and body["groups"] == []
    # The default sweep reads every section, so every section is "in the sweep, not yet
    # observed" — never empty, which would claim a read that never happened.
    assert {s["state"] for s in body["sections"]} == {"not_observed"}


async def test_a_device_that_is_not_there_is_a_404(admin) -> None:
    assert (await admin.get("/api/devices/2000000000/observation")).status_code == 404
