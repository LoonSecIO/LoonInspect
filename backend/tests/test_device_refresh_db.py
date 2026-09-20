# ruff: noqa: F811 — imported pytest fixtures are injected by name.
"""Targeted refresh: one Jamf read, normal history writes, isolated authorization."""

import os
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import delete, select

from tests.test_device_history_db import ingest
from tests.test_device_observation_db import connection  # noqa: F401
from tests.test_tenant_switch_db import accounts, admin, second_tenant  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres"),
    pytest.mark.asyncio(loop_scope="session"),
]


async def test_refresh_updates_only_the_requested_device_and_records_history(admin, db, connection, jamf):
    from app.models.schema import Device, EventOutbox, MdmSyncState, Run

    device = await ingest(db, connection, jamf)
    device_id = device.id
    other = await db.scalar(select(Device).where(Device.mdm_connection_id == connection.id, Device.id != device_id))
    other_seen = other.last_seen_at
    state = await db.get(MdmSyncState, connection.id)
    last_sweep = state.last_sync_at
    detail = (await admin.get(f"/api/devices/{device_id}")).json()
    assert detail["jamfUrl"] == f"{connection.base_url}/computers.html?id={device.external_id}&o=r"
    jamf.real["general"]["name"] = "Updated single computer"
    jamf.real["general"]["reportDate"] = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    jamf.requests.clear()
    response = await admin.post(f"/api/devices/{device_id}/refresh")
    assert response.status_code == 200, response.text
    assert response.json()["outcome"] == "changed"
    assert sum("/computers-inventory-detail/" in path for path in jamf.requests) == 1
    assert not any(path.split("?")[0].endswith("/computers-inventory") for path in jamf.requests)
    await db.refresh(device)
    await db.refresh(other)
    await db.refresh(state)
    assert device.hostname == "Updated single computer"
    assert other.last_seen_at == other_seen
    assert state.last_sync_at == last_sweep
    run = await db.get(Run, UUID(response.json()["jobId"]))
    assert run.status == "succeeded" and run.lock_class == "device_refresh" and run.device_count == 1
    event = await db.scalar(
        select(EventOutbox).where(EventOutbox.event_type == "run.completed", EventOutbox.payload["jobID"].astext == str(run.id))
    )
    assert event.payload["lockClass"] == "device_refresh"
    history = (await admin.get(f"/api/devices/{device_id}/history")).json()
    assert len(history["items"]) == 2


async def test_missing_jamf_record_keeps_saved_inventory_and_closes_run(admin, db, connection, jamf):
    from app.models.schema import Run

    device = await ingest(db, connection, jamf)
    before = (await admin.get(f"/api/devices/{device.id}")).json()
    jamf.transient.append((f"computers-inventory-detail/{device.external_id}", 404, {}))
    response = await admin.post(f"/api/devices/{device.id}/refresh")
    assert response.status_code == 502 and "not found in Jamf" in response.json()["detail"]
    assert (await admin.get(f"/api/devices/{device.id}")).json() == before
    run = await db.scalar(select(Run).where(Run.mdm_connection_id == connection.id, Run.lock_class == "device_refresh"))
    assert run.status == "failed" and run.devices_failed == 1


async def test_busy_or_inactive_connection_does_not_start_another_read(admin, db, connection, jamf):
    from app.core.runs import LOCK_DEVICE_REFRESH, acquire, finish

    device = await ingest(db, connection, jamf)
    acquired = await acquire(db, connection, trigger="manual", lock_class=LOCK_DEVICE_REFRESH)
    jamf.requests.clear()
    response = await admin.post(f"/api/devices/{device.id}/refresh")
    assert response.status_code == 409 and "Another device update" in response.json()["detail"]
    assert not jamf.requests
    await finish(db, acquired.run, ok=True)
    connection.is_active = False
    await db.commit()
    assert (await admin.post(f"/api/devices/{device.id}/refresh")).status_code == 409
    assert not jamf.requests


async def test_refresh_rejects_other_tenants_and_read_only_users(admin, db, connection, jamf, second_tenant):
    from app.core.bootstrap import create_account
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt
    from tests.test_tenant_switch_db import _signed_in

    device = await ingest(db, connection, jamf)
    url = f"/api/devices/{device.id}/refresh"
    await admin.post("/api/auth/switch-tenant", json={"tenantId": str(second_tenant)})
    admin.headers["X-CSRF-Token"] = admin.cookies.get("loon_csrf", "")
    jamf.requests.clear()
    try:
        assert (await admin.post(url)).status_code == 404
        assert not jamf.requests
    finally:
        await admin.post("/api/auth/switch-tenant", json={"tenantId": str(OPERATIONAL_TENANT_ID)})
        admin.headers["X-CSRF-Token"] = admin.cookies.get("loon_csrf", "")
    credentials = ("device-refresh-viewer@example.com", "device-refresh-viewer-password")
    if not await db.scalar(select(Account).where(Account.email == credentials[0])):
        await create_account(db, email=credentials[0], display_name="Refresh viewer", password=credentials[1], roles=("viewer",))
    await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == credentials[0]))
    await db.commit()
    viewer = await _signed_in(credentials)
    try:
        assert (await viewer.get(f"/api/devices/{device.id}")).status_code == 200
        assert (await viewer.post(url)).status_code == 403
        assert not jamf.requests
    finally:
        await viewer.aclose()


@pytest.mark.parametrize("failure", ["wrong-device", "timeout"])
async def test_unusable_reply_never_updates_inventory(admin, db, connection, jamf, monkeypatch, failure):
    from app.mdm.jamf.client import JamfClient
    from app.models.schema import Run

    device = await ingest(db, connection, jamf)
    before = (await admin.get(f"/api/devices/{device.id}")).json()

    async def unusable(*args, **kwargs):
        if failure == "timeout":
            raise TimeoutError
        return jamf.synthetic

    monkeypatch.setattr(JamfClient, "fetch_computer_detail", unusable)
    response = await admin.post(f"/api/devices/{device.id}/refresh")
    assert response.status_code == (504 if failure == "timeout" else 502)
    assert (await admin.get(f"/api/devices/{device.id}")).json() == before
    run = await db.scalar(select(Run).where(Run.mdm_connection_id == connection.id, Run.lock_class == "device_refresh"))
    assert run.status == "failed"


async def test_refresh_uses_targeted_scope_and_preserves_older_observation(admin, db, connection, jamf):
    from app.models.schema import Collection

    device = await ingest(db, connection, jamf)
    old_hostname = device.hostname
    collection = await db.scalar(
        select(Collection).where(Collection.mdm_connection_id == connection.id, Collection.kind == "webhook")
    )
    collection.sections = ["general", "security"]
    await db.commit()
    jamf.real["general"]["name"] = "Too old"
    jamf.real["general"]["reportDate"] = "2000-01-01T00:00:00Z"
    response = await admin.post(f"/api/devices/{device.id}/refresh")
    assert response.status_code == 200 and response.json()["outcome"] == "stale"
    assert (await admin.get(f"/api/devices/{device.id}")).json()["hostname"] == old_hostname
    jamf.real["general"]["reportDate"] = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    assert (await admin.post(f"/api/devices/{device.id}/refresh")).status_code == 200
    observation = (await admin.get(f"/api/devices/{device.id}/observation")).json()
    applications = next(section for section in observation["sections"] if section["name"] == "applications")
    assert applications["state"] == "not_observed" and not applications["entries"]
