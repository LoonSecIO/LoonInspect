"""The re-emit (#356) against a real Postgres: after a sweep of the fake tenant, a re-emit
enqueues one `device.inventory` per device that says what the sweep's snapshot said, under
its own run and — when scoped — for one destination alone; it acquires beside a running
sweep; its `run.completed` carries `comparison: "re-emit"`; and the route is gated on
`destination:write`. Gated on RUN_DB_TESTS like the other database-backed suites."""

from __future__ import annotations

import json
import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select, update

from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("re-emit-admin@example.com", "re-emit-admin-password")
VIEWER = ("re-emit-viewer@example.com", "re-emit-viewer-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        for (email, password), role in ((ADMIN, "admin"), (VIEWER, "viewer")):
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=f"re-emit {role}", password=password, roles=(role,))
            await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
        await db.commit()


async def _signed_in(credentials: tuple[str, str]) -> httpx.AsyncClient:
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://re-emit.example.com")
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
async def connection(db):
    """A Jamf connection answered by the fake, removed with its fleet afterwards."""
    from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"re-emit jamf {uuidlib.uuid4().hex[:8]}",
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


@pytest_asyncio.fixture(loop_scope="session")
async def destinations(db):
    """Two enabled destinations, removed afterwards with whatever deliveries reached them."""
    from app.models.schema import Destination, OutboxDelivery

    rows = [
        Destination(
            name=f"re-emit {uuidlib.uuid4().hex[:6]} {index}",
            type="generic_webhook",
            url=f"https://siem.example/re-emit-{index}",
            auth_type="none",
            enabled=True,
        )
        for index in range(2)
    ]
    db.add_all(rows)
    await db.commit()
    ids = [row.id for row in rows]
    try:
        yield ids
    finally:
        await db.rollback()
        await db.execute(delete(OutboxDelivery).where(OutboxDelivery.destination_id.in_(ids)))
        await db.execute(delete(Destination).where(Destination.id.in_(ids)))
        await db.commit()


async def _max_event_id(db) -> int:
    from app.models.schema import EventOutbox

    return (await db.execute(select(func.coalesce(func.max(EventOutbox.id), 0)))).scalar_one()


async def _snapshots_after(db, connection_id: int, after_id: int) -> dict[str, object]:
    """The latest `device.inventory` row per Jamf id for this connection's devices, among
    events newer than `after_id`. Matched on `jamfProID` against the connection's own
    device rows rather than on the run's `connectionID`, so it reads the same whether the
    sweep ran under a run context or not."""
    from app.models.schema import Device, EventOutbox
    from app.schemas.payload import INVENTORY_EVENT_TYPE

    mine = set((await db.execute(select(Device.external_id).where(Device.mdm_connection_id == connection_id))).scalars().all())
    rows = (
        (
            await db.execute(
                select(EventOutbox)
                .where(EventOutbox.event_type == INVENTORY_EVENT_TYPE, EventOutbox.id > after_id)
                .order_by(EventOutbox.id)
            )
        )
        .scalars()
        .all()
    )
    latest: dict[str, object] = {}
    for row in rows:
        meta = row.payload.get("deviceMeta", {})
        if meta.get("jamfProID") in mine:
            latest[meta["jamfProID"]] = row
    return latest


def _ea_key(items: list[dict]) -> list[tuple[str, tuple[str, ...]]]:
    return sorted((item["ea"]["definitionId"], tuple(item["ea"]["values"])) for item in items)


async def test_a_re_emit_says_what_the_sweep_said_under_its_own_run(db, jamf: FakeJamf, connection, destinations) -> None:
    from app.core.outbox import fan_out_pending
    from app.core.runs import COMPARISON_RE_EMIT, LOCK_RE_EMIT, RUN_COMPLETED_EVENT, TRIGGER_MANUAL, acquire, entered, finish
    from app.core.wire import ENVELOPE
    from app.mdm.reemit import re_emit_connection
    from app.mdm.service import sync_connection
    from app.models.schema import EventOutbox, OutboxDelivery

    before_sweep = await _max_event_id(db)
    result = await sync_connection(db, connection)
    assert result.ok
    swept = await _snapshots_after(db, connection.id, before_sweep)
    assert len(swept) >= 2, "the fake tenant is two devices"

    # Everything held so far is somebody else's: mark it considered, so the fan-out
    # below answers for this test's events alone (the trap the redrive test names).
    await db.execute(update(EventOutbox).where(EventOutbox.fanned_out.is_(False)).values(fanned_out=True))
    await db.commit()

    scoped_to = destinations[0]
    acquisition = await acquire(db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_RE_EMIT, actor_label="re-emit test")
    assert acquisition.started and acquisition.run.comparison == COMPARISON_RE_EMIT
    run = acquisition.run
    before = await _max_event_id(db)
    async with entered(run):
        outcome = await re_emit_connection(db, connection, run=run, destination_id=scoped_to)
    assert (outcome.devices_processed, outcome.devices_skipped, outcome.devices_failed) == (len(swept), 0, 0)

    again = await _snapshots_after(db, connection.id, before)
    assert set(again) == set(swept)
    volatile = {"jobID", "occurredAt", "deviceMeta", ENVELOPE, "ea"}
    for jamf_id, original in swept.items():
        emitted = again[jamf_id]
        assert emitted.only_destination_id == scoped_to
        assert emitted.payload["jobID"] == str(run.id)
        assert emitted.payload["deviceMeta"]["trigger"] == "manual"
        # A newer observation, not a duplicate: a fresh pull id under a new run.
        assert emitted.payload["deviceMeta"]["eventID"] != original.payload["deviceMeta"]["eventID"]
        # The baseline's emission with the ledger's current state: every section the sweep
        # sent, byte for byte, apart from the run's own keys.
        assert {k: v for k, v in emitted.payload.items() if k not in volatile} == {
            k: v for k, v in original.payload.items() if k not in volatile
        }
        if "ea" in original.payload:
            assert _ea_key(emitted.payload["ea"]) == _ea_key(original.payload["ea"])

    assert await finish(db, run, ok=True, device_count=outcome.device_count, devices_processed=outcome.devices_processed)
    completed = (
        (
            await db.execute(
                select(EventOutbox).where(EventOutbox.event_type == RUN_COMPLETED_EVENT).order_by(EventOutbox.id.desc())
            )
        )
        .scalars()
        .first()
    )
    assert completed is not None and completed.payload["jobID"] == str(run.id)
    assert completed.payload["comparison"] == "re-emit"

    # Scoped: a delivery for the one destination, and none for the other.
    await fan_out_pending(db)
    ids = [row.id for row in again.values()]
    delivered_to = (
        (await db.execute(select(OutboxDelivery.destination_id).where(OutboxDelivery.outbox_event_id.in_(ids)))).scalars().all()
    )
    assert len(delivered_to) == len(ids) and set(delivered_to) == {scoped_to}


async def test_a_re_emit_acquires_beside_a_running_sweep_and_joins_its_own_kind(db, connection) -> None:
    from app.core.runs import LOCK_DEVICE_SWEEP, LOCK_RE_EMIT, TRIGGER_MANUAL, TRIGGER_SWEEP, acquire, finish

    sweep = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert sweep.started
    try:
        first = await acquire(db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_RE_EMIT, actor_label="one")
        assert first.started and first.run.id != sweep.run.id, "its own lock class: a sweep does not hold it off"
        second = await acquire(db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_RE_EMIT, actor_label="two")
        assert not second.started and second.run.id == first.run.id, "two re-emits of one connection serialize"
        assert await finish(db, first.run, ok=True)
    finally:
        await finish(db, sweep.run, ok=True)


async def test_the_route_is_gated_and_answers_with_a_run(admin, viewer, db, connection, destinations) -> None:
    from app.core.runs import COMPARISON_RE_EMIT, LOCK_RE_EMIT, STATUS_RUNNING
    from app.models.schema import Run

    path = f"/api/mdm/connections/{connection.id}/re-emit"
    assert (await viewer.post(path, json={})).status_code == 403
    assert (await admin.post(path, json={"destinationId": 2_000_000_000})).status_code == 404

    accepted = await admin.post(path, json={"destinationId": destinations[1]})
    assert accepted.status_code == 202, accepted.text
    body = accepted.json()
    assert body["connectionId"] == connection.id and body["started"] is True

    # The background task ran inside the ASGI transport before the response came back;
    # an empty fleet re-emits nothing and closes clean.
    run = await db.get(Run, uuidlib.UUID(body["jobId"]))
    assert run is not None and run.lock_class == LOCK_RE_EMIT and run.comparison == COMPARISON_RE_EMIT
    await db.refresh(run)
    assert run.status != STATUS_RUNNING and run.error is None
