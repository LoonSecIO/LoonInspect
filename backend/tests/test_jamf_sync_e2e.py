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
4. A webhook collection scoped without applications wipes nothing and emits nothing,
   and the full sweep after it derives no phantom per-app changes — while a full-scope
   read of a device with genuinely zero apps still diffs to removals (#93).
5. The same discipline for the rest of the row (#98): a read scoped below GENERAL and
   the EA section leaves the device's scalars and extension-attribute rows exactly as
   the last full read left them, any full-aperture read heals, and a full-scope read
   of genuinely empty values still writes.
6. The department and the building, all the way through: the ids Jamf actually sends
   onto the device row, the two catalogs that give them names, and `/api/devices`
   filtered by a name a person typed — the chain that returned nothing at all while the
   normalizer was reading keys the inventory API does not have.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from contextlib import asynccontextmanager

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

from tests.jamf_fake import HOST, FakeJamf  # noqa: E402


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


ADMIN = ("e2e-devices-admin@build.example.com", "e2e-devices-admin-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def admin(tenant_ready) -> None:
    """One admin, get-or-create — the device list is behind `device:read`, and the
    filter is only proved by asking for it the way the UI does."""
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        existing = (await session.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first()
        if existing is None:
            await create_account(session, email=ADMIN[0], display_name="e2e devices admin", password=ADMIN[1], roles=("admin",))
        # A crashed previous run's failed logins would trip the lockout and turn this
        # suite red about rate limiting instead of about departments.
        await session.execute(delete(LoginAttempt).where(LoginAttempt.identifier == ADMIN[0]))
        await session.commit()


def _client() -> httpx.AsyncClient:
    from app.main import app

    # https, not http: the session cookies are Secure and a plain-http origin discards
    # them, so every request after the login would 401.
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://build.example.com")


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    """A Jamf connection with credentials, removed again afterwards.

    The credentials are encrypted with this run's ENCRYPTION_KEY. Left behind in a
    shared local database they would fail to decrypt under the next run's key and take
    the tenancy sweep's connection listing down with them, so the row — and the devices,
    sync state, and spans that hang off it — is deleted on the way out.
    """
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
    assert "GET /api/v2/computer-inventory-collection-settings" in jamf.requests

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
    assert f"GET /api/v4/computers-inventory-detail/{real_id}" in jamf.requests
    assert await _count(db, real_apps) == 84

    latest = (
        await db.execute(
            select(EventOutbox)
            .where(EventOutbox.event_type == "device.inventory.changed")
            .order_by(EventOutbox.id.desc())
            .limit(1)
        )
    ).scalar_one()
    assert latest.payload["deviceExternalID"] == real_id
    assert [app["bundleId"] for app in latest.payload["addedApps"]] == ["io.loonsec.inspector"]
    assert latest.payload["removedApps"] == []

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


async def test_narrow_webhook_scope_never_wipes_apps(db, jamf: FakeJamf, connection) -> None:
    """Kyle's ruling (#93): device state is wiped only when a webhook properly pulls
    the device — an absent section must never read as "everything was removed".

    The detail endpoint returns every section regardless, so this also pins that the
    guard keys off the *requested* sections, not the response shape."""
    from app.mdm.collections import list_collections
    from app.mdm.service import ingest_webhook, sync_connection
    from app.models.schema import Device, DeviceChange, EventOutbox, InstalledApp

    real_id = jamf.real["id"]
    changed_events = (
        select(func.count()).select_from(EventOutbox).where(EventOutbox.event_type == "device.inventory.changed")
    )

    first = await sync_connection(db, connection)
    assert first.ok and first.device_count == 2
    real_device = (
        await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == real_id))
    ).scalar_one()
    real_apps = select(func.count()).select_from(InstalledApp).where(InstalledApp.device_id == real_device.id)
    apps_before = await _count(db, real_apps)
    assert apps_before > 0
    events_before = await _count(db, changed_events)

    webhook = next(row for row in await list_collections(db, connection.id) if row.kind == "webhook")
    webhook.sections = ["general", "hardware", "operating_system"]
    await db.commit()

    # The device submits inventory; the webhook reads it under the narrowed scope.
    jamf.real["general"]["reportDate"] = "2026-08-29T09:00:00.000Z"
    payload = {
        "webhook": {"webhookEvent": "ComputerInventoryCompleted"},
        "event": {"jssID": real_id, "serialNumber": "LOONMINI0M4"},
    }
    result = await ingest_webhook(db, connection, payload)
    # The aperture changed, so a new span opens — but no section's content moved, no
    # app row is touched, and nothing reaches the event stream.
    assert result is not None and result.outcome == "changed"
    assert result.changed_sections == ()
    assert await _count(db, real_apps) == apps_before
    assert await _count(db, changed_events) == events_before

    # The following full sweep re-widens the aperture. The apps it reads are the ones
    # the rows already hold, so nothing is added, removed, or minted as a change.
    second = await sync_connection(db, connection)
    assert second.ok and second.observations.get("changed") == 1
    assert await _count(db, real_apps) == apps_before
    assert await _count(db, changed_events) == events_before
    phantom_changes = (
        select(func.count())
        .select_from(DeviceChange)
        .where(DeviceChange.mdm_connection_id == connection.id, DeviceChange.subject_id == real_id)
    )
    assert await _count(db, phantom_changes) == 0


async def test_a_full_scope_read_of_zero_apps_still_wipes(db, jamf: FakeJamf, connection) -> None:
    """The other half of the ruling: [] is a real read of a device with no apps, and
    still diffs to removals — the guard must not swallow genuine loss."""
    from app.mdm.service import ingest_webhook, sync_connection
    from app.models.schema import Device, EventOutbox, InstalledApp

    real_id = jamf.real["id"]
    first = await sync_connection(db, connection)
    assert first.ok
    real_device = (
        await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == real_id))
    ).scalar_one()
    real_apps = select(func.count()).select_from(InstalledApp).where(InstalledApp.device_id == real_device.id)
    apps_before = await _count(db, real_apps)
    assert apps_before > 0

    jamf.real["general"]["reportDate"] = "2026-08-29T09:00:00.000Z"
    jamf.real["applications"] = []
    payload = {
        "webhook": {"webhookEvent": "ComputerInventoryCompleted"},
        "event": {"jssID": real_id, "serialNumber": "LOONMINI0M4"},
    }
    result = await ingest_webhook(db, connection, payload)
    assert result is not None and result.outcome == "changed"
    assert "applications" in result.changed_sections
    assert await _count(db, real_apps) == 0

    latest = (
        await db.execute(
            select(EventOutbox)
            .where(EventOutbox.event_type == "device.inventory.changed")
            .order_by(EventOutbox.id.desc())
            .limit(1)
        )
    ).scalar_one()
    assert latest.payload["deviceExternalID"] == real_id
    assert latest.payload["addedApps"] == []
    assert len(latest.payload["removedApps"]) == apps_before


async def test_narrow_scope_leaves_scalars_and_eas_untouched(db, jamf: FakeJamf, connection) -> None:
    """#98, the unfinished half of #93's discipline: a read scoped below GENERAL (and
    the EA section) must not blank the device row's scalars or wipe its extension-
    attribute rows. The detail endpoint still returns every section, so this pins —
    like its #93 sibling — that the guard keys off the request, not the response."""
    from app.mdm.collections import list_collections
    from app.mdm.service import ingest_webhook, sync_connection
    from app.models.schema import Device, DeviceExtensionAttribute

    real_id = jamf.real["id"]
    first = await sync_connection(db, connection)
    assert first.ok
    real_device = (
        await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == real_id))
    ).scalar_one()
    hostname_before = real_device.hostname
    assert hostname_before and real_device.os_version == "27.0" and real_device.supervised is True
    ea_rows = select(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id == real_device.id)
    eas_before = {(ea.definition_id, tuple(ea.values)) for ea in (await db.execute(ea_rows)).scalars()}
    # Two in the top-level array and one displayed under General — all three reach the
    # rows since the hoist (#197); the nested one was invisible before it.
    assert len(eas_before) == 3

    webhook = next(row for row in await list_collections(db, connection.id) if row.kind == "webhook")
    webhook.sections = ["applications"]
    await db.commit()

    # The tenant renames the device, updates the OS, and fills an EA — all outside the
    # webhook collection's scope, all present in the detail response regardless.
    jamf.real["general"]["reportDate"] = "2026-08-30T09:00:00.000Z"
    jamf.real["general"]["name"] = "renamed while unwatched"
    jamf.real["operatingSystem"]["version"] = "27.1"
    jamf.real["extensionAttributes"][0]["values"] = ["set while unwatched"]
    payload = {
        "webhook": {"webhookEvent": "ComputerInventoryCompleted"},
        "event": {"jssID": real_id, "serialNumber": "LOONMINI0M4"},
    }
    result = await ingest_webhook(db, connection, payload)
    assert result is not None and result.outcome == "changed"

    await db.refresh(real_device)
    assert real_device.hostname == hostname_before
    assert real_device.os_version == "27.0" and real_device.supervised is True
    assert {(ea.definition_id, tuple(ea.values)) for ea in (await db.execute(ea_rows)).scalars()} == eas_before

    # Any full-aperture read heals: the next sweep reads everything and writes it.
    second = await sync_connection(db, connection)
    assert second.ok
    await db.refresh(real_device)
    assert real_device.hostname == "renamed while unwatched"
    assert real_device.os_version == "27.1"
    healed = {(ea.definition_id, tuple(ea.values)) for ea in (await db.execute(ea_rows)).scalars()}
    assert ("3", ("set while unwatched",)) in healed


async def test_a_full_scope_read_of_genuinely_empty_values_still_writes(db, jamf: FakeJamf, connection) -> None:
    """The guard's other edge, mirroring the applications pair: a full-aperture read
    that carries empty values is a real observation, and writes."""
    from app.mdm.service import ingest_webhook, sync_connection
    from app.models.schema import Device, DeviceExtensionAttribute

    real_id = jamf.real["id"]
    first = await sync_connection(db, connection)
    assert first.ok
    real_device = (
        await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == real_id))
    ).scalar_one()
    assert real_device.supervised is True
    ea_count = (
        select(func.count())
        .select_from(DeviceExtensionAttribute)
        .where(DeviceExtensionAttribute.device_id == real_device.id)
    )
    assert await _count(db, ea_count) == 3

    # The tenant unsupervises the device and deletes every EA definition — the one
    # displayed under General included; the full detail read genuinely carries the
    # emptiness, and it lands.
    jamf.real["general"]["reportDate"] = "2026-08-30T09:00:00.000Z"
    jamf.real["general"]["supervised"] = False
    jamf.real["extensionAttributes"] = []
    jamf.real["general"]["extensionAttributes"] = []
    payload = {
        "webhook": {"webhookEvent": "ComputerInventoryCompleted"},
        "event": {"jssID": real_id, "serialNumber": "LOONMINI0M4"},
    }
    result = await ingest_webhook(db, connection, payload)
    assert result is not None and result.outcome == "changed"

    await db.refresh(real_device)
    assert real_device.supervised is False
    assert await _count(db, ea_count) == 0


async def test_webhook_without_a_computer_is_ignored(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.service import ingest_webhook

    assert await ingest_webhook(db, connection, {"webhook": {"webhookEvent": "ComputerAdded"}, "event": {}}) is None
    assert not any(path.startswith("GET /api/v4/computers-inventory-detail") for path in jamf.requests)


async def test_page_size_flows_and_throttling_lands_on_the_run(db, jamf: FakeJamf, connection) -> None:
    from app.mdm.service import sync_connection
    from app.models.schema import Run

    # Null on the connection means the default on the wire.
    first = await sync_connection(db, connection)
    assert first.ok
    assert jamf.page_sizes and all(size == 400 for size in jamf.page_sizes)

    # The connection's setting carries to Jamf, and a scripted 429 is retried,
    # counted, and lands in the observations of the run the sweep happened inside.
    connection.sweep_page_size = 137
    await db.commit()
    jamf.transient.append(("/api/v4/computers-inventory", 429, {"Retry-After": "0"}))
    second = await sync_connection(db, connection)
    assert second.ok
    assert 137 in jamf.page_sizes
    assert second.observations.get("throttled_429") == 1

    run = (
        await db.execute(
            select(Run)
            .where(Run.mdm_connection_id == connection.id)
            .order_by(Run.started_at.desc())
            .limit(1)
        )
    ).scalars().first()
    assert run is not None and run.observations.get("throttled_429") == 1

    # The collection's own override wins over the connection's setting (#73).
    from app.models.schema import Collection

    sweep_row = (
        await db.execute(
            select(Collection).where(
                Collection.mdm_connection_id == connection.id, Collection.kind == "device_sweep"
            )
        )
    ).scalars().first()
    assert sweep_row is not None
    sweep_row.page_size = 250
    await db.commit()
    third = await sync_connection(db, connection)
    assert third.ok
    assert 250 in jamf.page_sizes


async def test_checkin_is_dropped_before_any_fetch(db, jamf: FakeJamf, connection) -> None:
    """Kyle's ruling (#76): a check-in is a heartbeat times the whole fleet and does
    not warrant the reaction — no run row, not one API call."""
    from app.mdm.service import ingest_webhook
    from app.models.schema import Run

    payload = {
        "webhook": {"webhookEvent": "ComputerCheckIn"},
        "event": {"trigger": "CLIENT_CHECKIN", "computer": {"jssID": jamf.real["id"], "udid": "x"}},
    }
    requests_before = len(jamf.requests)
    runs = select(func.count()).select_from(Run).where(Run.mdm_connection_id == connection.id)
    runs_before = await _count(db, runs)

    assert await ingest_webhook(db, connection, payload) is None

    assert len(jamf.requests) == requests_before
    assert await _count(db, runs) == runs_before


async def test_department_and_building_ids_resolve_to_names_and_filter(db, jamf: FakeJamf, connection, admin) -> None:
    """The whole chain for the two fields that never worked.

    `userAndLocation` names its department and building by id — `departmentId: "7"` —
    and the normalizer was reading `department` / `building`, keys the inventory API
    does not have. Both columns were NULL on every device ever synced, so the two
    filters over them could only ever return zero rows. The fix has three parts, and
    all three are asserted here: the id reaches the row, the id gets a name from Jamf's
    own catalog, and the filter takes the name a person would type.
    """
    from app.mdm.org_units import BUILDING, DEPARTMENT, ids_for_name
    from app.mdm.service import run_jamf_catalog, sync_connection
    from app.models.schema import Device, JamfOrgUnit

    result = await sync_connection(db, connection)
    assert result.ok and result.device_count == 2, result
    assert "GET /api/v1/departments" in jamf.requests and "GET /api/v1/buildings" in jamf.requests

    devices = (await db.execute(select(Device).where(Device.mdm_connection_id == connection.id))).scalars().all()
    assigned = next(d for d in devices if d.external_id == jamf.synthetic["id"])
    unassigned = next(d for d in devices if d.external_id == jamf.real["id"])
    assert (assigned.department_id, assigned.building_id) == ("7", "2")
    # The real 11.31 record's ids are null — an unassigned Mac, not a failed read.
    assert (unassigned.department_id, unassigned.building_id) == (None, None)

    units = (
        await db.execute(select(JamfOrgUnit).where(JamfOrgUnit.mdm_connection_id == connection.id))
    ).scalars().all()
    assert {(u.kind, u.external_id, u.name) for u in units} == {
        (DEPARTMENT, "7", "Engineering"),
        (DEPARTMENT, "9", "Sales"),
        (BUILDING, "2", "Bletchley Park"),
    }

    async with _client() as c:
        response = await c.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        assert response.status_code == 200, response.text

        # The name, as typed — case and all. This is the assertion the bug owned: this
        # request returned an empty list for every fleet that ever ran this container.
        listed = await c.get("/api/devices", params={"department": "engineering"})
        assert listed.status_code == 200, listed.text
        items = listed.json()["items"]
        assert [item["externalId"] for item in items] == [assigned.external_id]
        assert items[0]["department"] == "Engineering" and items[0]["departmentId"] == "7"
        assert items[0]["building"] == "Bletchley Park" and items[0]["buildingId"] == "2"

        # Both narrowing directions still narrow: a real department nobody is in, and a
        # name no catalog knows, are zero rows — never the whole fleet.
        assert (await c.get("/api/devices", params={"department": "Sales"})).json()["total"] == 0
        assert (await c.get("/api/devices", params={"building": "Nowhere"})).json()["total"] == 0

        # The id is a filter too, for the tenant whose API client cannot read the
        # catalogs and has nothing but ids.
        by_id = await c.get("/api/devices", params={"department": "7"})
        assert [item["externalId"] for item in by_id.json()["items"]] == [assigned.external_id]

        detail = await c.get(f"/api/devices/{assigned.id}")
        assert detail.json()["department"] == "Engineering"

    # A rename is not a device change: the catalog class alone carries the new name to
    # every device that was in it, with no inventory read at all.
    jamf.departments = [{"id": "7", "name": "Platform"}, {"id": "9", "name": "Sales"}]
    catalog = await run_jamf_catalog(db, connection, trigger="manual")
    assert catalog.ok, catalog
    assert await ids_for_name(db, kind=DEPARTMENT, name="Platform") == [(connection.id, "7")]
    assert await ids_for_name(db, kind=DEPARTMENT, name="Engineering") == []
    # Scoped to this connection. Unscoped, this counts every org unit the tenant holds
    # — including the ones a real Jamf sync left behind — so it passed only on a
    # database nothing else had ever written to. The assertion is that a rename updates
    # the row in place rather than inserting a second one, and that is per connection.
    renamed_count = await db.execute(
        select(func.count())
        .select_from(JamfOrgUnit)
        .where(JamfOrgUnit.mdm_connection_id == connection.id)
    )
    assert renamed_count.scalar_one() == len(units)
