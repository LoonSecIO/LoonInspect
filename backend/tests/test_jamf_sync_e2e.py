"""The Jamf ingest paths, end to end, against a real Postgres and a mocked Jamf Pro.

`app.mdm.service._sync_jamf` and `ingest_webhook` are where the ledger, the
current-state tables, and the outbox meet. No unit test sees that seam, so this one
drives the whole thing: OAuth, aperture reads, inventory paging, smart groups, the
webhook's fetch-by-id — all answered by an httpx.MockTransport standing in for a tenant,
with the two fixture records as the fleet.

What it pins, in order:

1. A sweep opens one span per device and populates devices/installed_apps.
2. The same sweep again is "repeat" for every device — no spans, no events, no churn.
3. A webhook naming a computer fetches the full record by id and ingests it: one app
   added, zero removed. That last number is the point — before this, the webhook
   payload itself was normalized, it carries no application list, and every webhook
   reported the whole inventory removed.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import func, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

FIXTURES = Path(__file__).parent / "fixtures" / "jamf"
HOST = "https://e2e.jamfcloud.com"


class FakeJamf:
    """Just enough of a tenant: two computers, one smart group, a version, no
    permission to read inventory-collection settings."""

    def __init__(self) -> None:
        self.synthetic = json.loads((FIXTURES / "computer_inventory_detail.json").read_text())
        self.real = json.loads((FIXTURES / "computer_inventory_detail_real.json").read_text())
        # Unique ids per run so re-running locally never collides with a previous pass.
        suffix = uuidlib.uuid4().hex[:6]
        self.synthetic["id"] = f"42{suffix}"
        self.real["id"] = f"3{suffix}"
        self.requests: list[str] = []

    @property
    def computers(self) -> list[dict]:
        return [self.real, self.synthetic]

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append(f"{request.method} {path}")
        if path == "/api/oauth/token":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 1799, "token_type": "Bearer"})
        if request.headers.get("Authorization") != "Bearer tok":
            return httpx.Response(401, json={"httpStatus": 401})
        if path == "/api/v1/jamf-pro-version":
            return httpx.Response(200, json={"version": "11.31.1-t1787060595569"})
        if path == "/api/v1/computer-inventory-collection-settings":
            return httpx.Response(403, json={"httpStatus": 403, "errors": []})
        if path == "/api/v1/computers-inventory":
            page = int(request.url.params.get("page", "0"))
            results = self.computers if page == 0 else []
            return httpx.Response(200, json={"totalCount": len(self.computers), "results": results})
        if path.startswith("/api/v1/computers-inventory-detail/"):
            wanted = path.rsplit("/", 1)[1]
            for computer in self.computers:
                if computer["id"] == wanted:
                    return httpx.Response(200, json=computer)
            return httpx.Response(404, json={"httpStatus": 404})
        if path == "/api/v2/computer-groups/smart-groups":
            return httpx.Response(200, json={"totalCount": 1, "results": [{"id": "1", "name": "All Managed Clients"}]})
        if path == "/api/v2/computer-groups/smart-groups/1":
            return httpx.Response(
                200,
                json={
                    "name": "All Managed Clients",
                    "siteId": "-1",
                    "criteria": [
                        {"name": "Managed", "priority": 0, "andOr": "and", "searchType": "is", "value": "Managed"}
                    ],
                },
            )
        return httpx.Response(404, json={"httpStatus": 404, "path": path})


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenant_ready() -> None:
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, unscoped_session

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)


@pytest_asyncio.fixture(loop_scope="session")
async def db(tenant_ready):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


@pytest.fixture
def jamf(monkeypatch: pytest.MonkeyPatch) -> FakeJamf:
    from app.mdm.jamf.client import JamfClient

    fake = FakeJamf()

    @asynccontextmanager
    async def _mock_http(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as client:
            yield client

    monkeypatch.setattr(JamfClient, "http", _mock_http)
    return fake


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    """A Jamf connection with credentials, removed again afterwards.

    The credentials are encrypted with this run's ENCRYPTION_KEY. Left behind in a
    shared local database they would fail to decrypt under the next run's key and take
    the tenancy sweep's connection listing down with them, so the row — and the devices,
    sync state, and spans that hang off it — is deleted on the way out.
    """
    from sqlalchemy import delete

    from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"e2e jamf {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
        capability_webhooks=True,
    )
    db.add(row)
    await db.commit()
    connection_id = row.id  # read before the teardown's rollback expires the instance
    try:
        yield row
    finally:
        # Plain DELETEs rather than ORM cascades: cascading through `Device.apps` would
        # lazy-load the collection, which under asyncio is MissingGreenlet, not a query.
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        # Spans and apertures cascade in the database.
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


async def _count(db, statement) -> int:
    return (await db.execute(statement)).scalar_one()


async def test_sweep_then_repeat_then_webhook(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.service import ingest_webhook, sync_connection
    from app.models.schema import Device, EventOutbox, InstalledApp, ObservationSpan

    real_id, synthetic_id = jamf.real["id"], jamf.synthetic["id"]
    changed_events = (
        select(func.count()).select_from(EventOutbox).where(EventOutbox.event_type == "device.inventory.changed")
    )

    # 1. First sweep: every device is new, the group definition is observed, state tables filled.
    first = await sync_connection(db, connection)
    assert first.ok and first.device_count == 2, first
    assert first.observations == {"new": 2, "group_new": 1}
    assert first.group_count == 1
    assert "GET /api/v1/jamf-pro-version" in jamf.requests
    assert "GET /api/v1/computer-inventory-collection-settings" in jamf.requests

    devices = (await db.execute(select(Device).where(Device.mdm_connection_id == connection.id))).scalars().all()
    assert {d.external_id for d in devices} == {real_id, synthetic_id}
    real_device = next(d for d in devices if d.external_id == real_id)
    assert real_device.serial_number == "LOONMINI0M4" and real_device.os_version == "27.0"
    real_apps = select(func.count()).select_from(InstalledApp).where(InstalledApp.device_id == real_device.id)
    assert await _count(db, real_apps) == 83

    spans = (
        await db.execute(
            select(ObservationSpan).where(
                ObservationSpan.mdm_connection_id == connection.id, ObservationSpan.is_current.is_(True)
            )
        )
    ).scalars().all()
    assert {(s.subject_kind, s.subject_id) for s in spans} == {
        ("computer", real_id),
        ("computer", synthetic_id),
        ("computer_group", "1"),
    }
    real_span = next(s for s in spans if s.subject_id == real_id)
    assert real_span.last_trigger == "sweep" and real_span.contract_version == "v0"
    assert real_span.udid == "A1B2C3D4-0000-4000-8000-0000000000A3"

    # 2. The same sweep again: Jamf served the same reportDate, so nothing is new and
    #    nothing is written for the devices — no spans, no events. The group has no
    #    device time, so every run is a fresh observation of it: unchanged, count +1.
    events_before = await _count(db, changed_events)
    second = await sync_connection(db, connection)
    assert second.observations == {"repeat": 2, "group_unchanged": 1}
    assert await _count(db, changed_events) == events_before
    all_spans = select(func.count()).select_from(ObservationSpan).where(ObservationSpan.mdm_connection_id == connection.id)
    assert await _count(db, all_spans) == 3

    # 3. A webhook: the device installed one app and submitted inventory. The payload
    #    names the computer; the record is fetched by id; exactly one app is added.
    jamf.real["general"]["reportDate"] = "2026-08-22T09:00:00.000Z"
    jamf.real["applications"].append(
        {
            "name": "Loon Inspector.app", "path": "/Applications/Loon Inspector.app", "version": "0.1",
            "cfBundleShortVersionString": "0.1", "cfBundleVersion": "7", "macAppStore": False,
            "bundleId": "io.loonsec.inspector", "updateAvailable": False, "externalVersionId": "0",
        }
    )
    payload = {
        "webhook": {"id": 1, "name": "inventory", "webhookEvent": "ComputerInventoryCompleted", "eventTimestamp": 1},
        "event": {"jssID": real_id, "udid": "x", "serialNumber": "LOONMINI0M4"},
    }
    result = await ingest_webhook(db, connection, payload)
    assert result is not None and result.outcome == "changed"
    assert result.changed_sections == ("applications",)
    assert f"GET /api/v1/computers-inventory-detail/{real_id}" in jamf.requests
    assert await _count(db, real_apps) == 84

    latest = (
        await db.execute(
            select(EventOutbox)
            .where(EventOutbox.event_type == "device.inventory.changed")
            .order_by(EventOutbox.id.desc())
            .limit(1)
        )
    ).scalar_one()
    assert latest.payload["device_external_id"] == real_id
    assert [app["bundle_id"] for app in latest.payload["added_apps"]] == ["io.loonsec.inspector"]
    assert latest.payload["removed_apps"] == []

    current = (
        await db.execute(
            select(ObservationSpan).where(
                ObservationSpan.mdm_connection_id == connection.id,
                ObservationSpan.subject_id == real_id,
                ObservationSpan.is_current.is_(True),
            )
        )
    ).scalar_one()
    assert current.last_trigger == "webhook" and current.previous_id == real_span.id


async def test_webhook_without_a_computer_is_ignored(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.service import ingest_webhook

    assert await ingest_webhook(db, connection, {"webhook": {"webhookEvent": "ComputerAdded"}, "event": {}}) is None
    assert not any(path.startswith("GET /api/v1/computers-inventory-detail") for path in jamf.requests)
