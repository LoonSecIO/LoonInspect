"""The Splunk HEC fan-out through the real path (#242): the real fixture, `sync_connection`,
both worker passes, and a mocked HEC. Gated on RUN_DB_TESTS.

`tests/test_hec_fanout.py` pins the expansion over the builder's own payload; this file
pins that the outbox worker actually sends it — one delivery row, one POST, N objects —
on rows the producer stored, carrying the `eventID` only a real run produces, beside a
generic webhook receiving the same rows whole, the run family arriving under `loon:run`,
the delta unstamped, and the test button unchanged.

Its own tenant, like `test_outbox_passes_db.py`: both passes act on every row and every
enabled destination they can see, so exact request counts need a tenant nothing else
writes to.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from contextlib import asynccontextmanager

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core.outbox import TEST_EVENT_TYPE, deliver_pending, fan_out_pending, hec_events, send_test_event
from app.core.wire import ENVELOPE
from app.core.wire_vocabulary import ASSERTION_SOURCETYPE, SUB_EVENT_KEYS, registry_rows
from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-000000000242")
SPLUNK_URL = "https://splunk.example.com:8088/services/collector/event"
WEBHOOK_URL = "https://siem.example/hook"
# 83 apps + 3 EAs + 1 group + 5 profiles + 2 local user accounts + 5 certificates + 1
# software update + the seven anchors (tests/test_hec_fanout.py).
REAL_FIXTURE_SUB_EVENTS = 107


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenant_ready() -> None:
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, unscoped_session
    from app.models.schema import Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, TENANT_ID) is None:
            db.add(Tenant(id=TENANT_ID, slug="hec-fan-out", name="HEC fan-out", kind="operational"))
            await db.commit()


async def _clear(db) -> None:
    from app.models.schema import Destination, EventOutbox, OutboxDelivery

    await db.rollback()
    await db.execute(delete(OutboxDelivery))
    await db.execute(delete(EventOutbox))
    await db.execute(delete(Destination))
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def db(tenant_ready):
    from app.core.database import session_for_tenant

    async with session_for_tenant(TENANT_ID) as session:
        await _clear(session)
        try:
            yield session
        finally:
            await _clear(session)


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
    from app.models.schema import (
        AppCatalogEntry,
        ChangePolicy,
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
    )

    row = MdmConnection(
        name=f"hec fan-out jamf {uuidlib.uuid4().hex[:8]}",
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
        await db.execute(delete(ChangePolicy))
        await db.execute(delete(AppCatalogEntry))
        await db.commit()


def _mock_posts(monkeypatch: pytest.MonkeyPatch) -> list[httpx.Request]:
    """Every outbound delivery behind a MockTransport that answers HEC's own success
    body; `deliver_pending` opens its own client, so the class is the seam."""
    from app.core import outbox

    seen: list[httpx.Request] = []

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"text": "Success", "code": 0})

    class _MockedClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(_record)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(outbox.httpx, "AsyncClient", _MockedClient)
    return seen


def _splunk_destination():
    from app.models.schema import Destination

    return Destination(
        name="splunk",
        type="splunk_hec",
        url=SPLUNK_URL,
        auth_type="splunk_hec",
        auth_secret_encrypted="00000000-1111-2222-3333-444444444444",
        enabled=True,
        subscribed_events=None,
    )


def _webhook_destination():
    from app.models.schema import Destination

    return Destination(name="siem", type="generic_webhook", url=WEBHOOK_URL, auth_type="none", enabled=True)


async def test_one_snapshot_delivery_is_one_request_of_n_sub_events_on_the_real_path(
    db, connection, jamf: FakeJamf, monkeypatch
) -> None:
    """One sweep of the two-device fake tenant, two catch-all destinations, both worker
    passes. The Splunk destination receives five requests — one per event row: the two
    snapshots fanned out (107 objects for the real fixture, each under a registry string,
    every one carrying the run's `eventID`), the two deltas as one unstamped object each,
    and `run.completed` under `loon:run`. The webhook receives the same five rows whole.
    Every delivery row is `delivered` after one attempt."""
    from app.mdm.service import sync_connection
    from app.models.schema import EventOutbox, OutboxDelivery

    splunk, webhook = _splunk_destination(), _webhook_destination()
    db.add_all([splunk, webhook])
    await db.commit()

    result = await sync_connection(db, connection)
    assert result.ok and result.device_count == 2, result
    # Installed AFTER the sync: the mock replaces `httpx.AsyncClient` for the whole
    # process, and the fake Jamf tenant is an `httpx.AsyncClient` too.
    seen = _mock_posts(monkeypatch)
    await fan_out_pending(db)
    await deliver_pending(db)

    rows = (await db.execute(select(EventOutbox).order_by(EventOutbox.id))).scalars().all()
    by_type = {}
    for row in rows:
        by_type.setdefault(row.event_type, []).append(row)
    assert {kind: len(items) for kind, items in by_type.items()} == {
        "device.inventory": 2, "device.inventory.changed": 2, "run.completed": 1,
    }
    deliveries = (await db.execute(select(OutboxDelivery))).scalars().all()
    assert len(deliveries) == 10 and {row.status for row in deliveries} == {"delivered"}
    assert {row.attempt_count for row in deliveries} == {1}

    # One request per delivery, on both destinations: never one POST per sub-event.
    splunk_requests = [request for request in seen if str(request.url) == SPLUNK_URL]
    webhook_requests = [request for request in seen if str(request.url) == WEBHOOK_URL]
    assert len(splunk_requests) == 5 and len(webhook_requests) == 5 and len(seen) == 10

    # What each Splunk request carried, keyed by the family of its first object.
    requests_by_family: dict[str, list[list[dict]]] = {}
    for request in splunk_requests:
        assert request.headers["Content-Type"] == "application/json"
        assert request.headers["Authorization"] == "Splunk 00000000-1111-2222-3333-444444444444"
        objects = [json.loads(line) for line in request.content.split(b"\n")]
        requests_by_family.setdefault(objects[0]["event"]["event"], []).append(objects)
    assert {family: len(items) for family, items in requests_by_family.items()} == {
        "device.inventory": 2, "device.inventory.changed": 2, "run.completed": 1,
    }

    registry = {stype for _section, _key, _wrapper, stype in registry_rows()}
    snapshots = {row.payload["deviceMeta"]["jamfProID"]: row for row in by_type["device.inventory"]}
    for objects in requests_by_family["device.inventory"]:
        jamf_id = objects[0]["event"]["deviceMeta"]["jamfProID"]
        row = snapshots[jamf_id]
        assert objects == hec_events(row.payload), "the wire carries exactly what the builder expands"
        assert {obj["sourcetype"] for obj in objects} <= registry
        assert all(set(SUB_EVENT_KEYS) <= set(obj["event"]) for obj in objects)
        # The correlation key only a real run produces, identical on every sub-event and
        # equal to the delta's for the same pull (#81 ruling 4).
        event_id = row.payload["deviceMeta"]["eventID"]
        assert {obj["event"]["deviceMeta"]["eventID"] for obj in objects} == {event_id}
        assert {obj["event"]["jobID"] for obj in objects} == {row.payload["jobID"]}
        assert {obj["time"] for obj in objects} == {row.payload[ENVELOPE]["time"]}
        if jamf_id == jamf.real["id"]:
            assert len(objects) == REAL_FIXTURE_SUB_EVENTS
            assert sum(1 for obj in objects if obj["sourcetype"] == "loon:jamf:mac:app") == 83
            assert sum(1 for obj in objects if obj["sourcetype"] == "loon:jamf:mac:general") == 1
    for objects in requests_by_family["device.inventory.changed"]:
        (obj,) = objects
        assert "sourcetype" not in obj and set(obj) == {"event", "time", "host", "source"}
    ((completed,),) = requests_by_family["run.completed"]
    assert completed["sourcetype"] == ASSERTION_SOURCETYPE == "loon:run"
    assert "host" not in completed

    # The generic webhook: the canonical row, whole, envelope removed, no sourcetype.
    canonical = {row.id: {key: value for key, value in row.payload.items() if key != ENVELOPE} for row in rows}
    received = [json.loads(request.content) for request in webhook_requests]
    assert sorted(received, key=lambda body: (body["event"], json.dumps(body, sort_keys=True))) == sorted(
        canonical.values(), key=lambda body: (body["event"], json.dumps(body, sort_keys=True))
    )
    assert all("sourcetype" not in body and ENVELOPE not in body for body in received)

    # And the test button: one identifiable object, unstamped, straight down the same path.
    seen.clear()
    assert await send_test_event(splunk) == (True, None)
    (request,) = seen
    body = json.loads(request.content)
    assert set(body) == {"event"} and body["event"]["event"] == TEST_EVENT_TYPE
