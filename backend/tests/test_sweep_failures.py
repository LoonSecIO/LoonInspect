"""Per-device error isolation in the sweep (#92), against a real Postgres.

One bad device — or one Jamf load-balancer hiccup landing on one device's ingest —
must not kill a 40,000-device run. What this suite pins, in order:

1. A device that dies mid-sweep is rolled back, recorded in the run log with its
   identity, and the sweep carries on: the run finishes `succeeded` with the failure
   on the row, and the run.completed event carries the same accounting. The failure
   here is a real aborted Postgres transaction, so the test also proves the session is
   returned to a clean state before the next device — without the rollback, every
   later statement dies of InFailedSQLTransaction and the whole run fails.
2. Past the tolerance (`max(sweep_failure_max_absolute, sweep_failure_max_percent%
   of devices attempted)`), the run is failed and the loop stops where it stands —
   a fleet-wide outage is not ground through 40,000 individually-logged failures.
3. RunReclaimed is not a device failure. The #94 fence must unwind the whole run,
   uncounted, with the reclaim's verdict left exactly as the reclaim wrote it.
4. A webhook ingest — one device, its own run — emits run.completed too (#224): the
   same accounting the sweep gets, just for a run of one.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text, update

from app.core.outbox import _build_body
from app.core.wire import ENVELOPE
from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]


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
    from app.models.schema import (
        AppCatalogEntry,
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
    )

    row = MdmConnection(
        name=f"sweep failures jamf {uuidlib.uuid4().hex[:8]}",
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
        # Keyed by tenant, not connection — see test_runs.py's fixture for why leaving
        # these behind fails test_catalog_db on the next local run.
        await db.execute(delete(AppCatalogEntry))
        await db.commit()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _sweep_collection(db, connection):
    from app.mdm.collections import ensure_default_collections, list_collections

    await ensure_default_collections(db, connection)
    await db.commit()
    return next(row for row in await list_collections(db, connection.id) if row.kind == "device_sweep")


async def _latest_run(db, connection_id):
    from app.models.schema import Run

    run = (
        await db.execute(
            select(Run).where(Run.mdm_connection_id == connection_id).order_by(Run.started_at.desc()).limit(1)
        )
    ).scalars().one()
    await db.refresh(run)
    return run


async def _run_completed_events(db, run_id) -> list:
    """Every run.completed event this run emitted, matched by payload rather than by
    recency — the shared local database accumulates events across tests."""
    from app.models.schema import EventOutbox

    rows = (
        await db.execute(
            select(EventOutbox).where(EventOutbox.event_type == "run.completed").order_by(EventOutbox.id)
        )
    ).scalars().all()
    return [row for row in rows if row.payload.get("jobID") == str(run_id)]


async def _run_failed_events(db, run_id) -> list:
    """Same matching for run.failed (#103) — the alarm beside run.completed's heartbeat."""
    from app.models.schema import EventOutbox

    rows = (
        await db.execute(
            select(EventOutbox).where(EventOutbox.event_type == "run.failed").order_by(EventOutbox.id)
        )
    ).scalars().all()
    return [row for row in rows if row.payload.get("jobID") == str(run_id)]


async def test_one_dead_device_does_not_kill_the_sweep(db, jamf: FakeJamf, connection, monkeypatch) -> None:
    """The headline case: device two of five dies of a real aborted transaction, the
    other four are processed, and the run finishes `succeeded` with the failure on the
    row, in the log with the device's identity, and on the wire."""
    from app.core.runs import TRIGGER_MANUAL
    from app.mdm import service
    from app.mdm.collections import run_collection
    from app.models.schema import Device, RunLogLine

    jamf.seed(3)  # five devices in all
    real_ingest = service.ingest_computer
    seen = {"calls": 0, "victim": None}

    async def failing_second_device(db_, connection_, raw, **kwargs):
        seen["calls"] += 1
        if seen["calls"] == 2:
            seen["victim"] = raw.get("id")
            # A genuine Postgres error, mid-transaction: until the sweep rolls back,
            # every subsequent statement on this session is InFailedSQLTransaction.
            await db_.execute(text("SELECT 1/0"))
        return await real_ingest(db_, connection_, raw, **kwargs)

    monkeypatch.setattr(service, "ingest_computer", failing_second_device)
    sweep = await _sweep_collection(db, connection)
    result = await run_collection(db, sweep, trigger=TRIGGER_MANUAL)

    assert result.ok is True
    assert result.device_count == 5
    assert result.devices_processed == 4
    assert result.devices_failed == 1
    assert seen["calls"] == 5  # every device was attempted

    devices = (
        await db.execute(select(Device.external_id).where(Device.mdm_connection_id == connection.id))
    ).scalars().all()
    assert len(devices) == 4 and seen["victim"] not in devices

    run = await _latest_run(db, connection.id)
    assert run.status == "succeeded"
    assert run.device_count == 5
    assert run.devices_processed == 4
    assert run.devices_failed == 1

    # The failure is in the run log with the device's identity and the error class.
    lines = (
        await db.execute(select(RunLogLine).where(RunLogLine.run_id == run.id).order_by(RunLogLine.id))
    ).scalars().all()
    failure_lines = [line for line in lines if line.message == "device failed; sweep continues"]
    assert len(failure_lines) == 1
    assert failure_lines[0].level == "warning"
    assert failure_lines[0].fields["jamfId"] == seen["victim"]
    assert "division by zero" in failure_lines[0].fields["error"]

    # And on the wire: one run.completed, same accounting, exactly the ruled fields.
    events = await _run_completed_events(db, run.id)
    assert len(events) == 1
    # The envelope is lifted off first so this stays an assertion about the ruled WIRE
    # vocabulary. `_envelope` is outbox transport that `_build_body` pops before any
    # destination sees it, so it is not a new field on the event — and popping it here
    # rather than adding it to the set keeps this test failing if a real key is ever
    # added or renamed without a ruling.
    payload = dict(events[0].payload)
    payload.pop(ENVELOPE)
    assert set(payload) == {
        "event", "jobID", "connectionID", "trigger", "comparison",
        "occurredAt", "devicesTotal", "devicesProcessed", "devicesFailed", "status",
    }
    assert payload["status"] == "succeeded"
    assert payload["devicesTotal"] == 5
    assert payload["devicesProcessed"] == 4
    assert payload["devicesFailed"] == 1
    assert payload["connectionID"] == connection.id
    assert payload["trigger"] == TRIGGER_MANUAL

    # Failures inside the tolerance are a healthy night, not an alarm: no run.failed
    # for a run that closed `succeeded`, however many devices it isolated (#103).
    assert await _run_failed_events(db, run.id) == []

    # The envelope. Before this, run.completed carried none at all, so Splunk stamped
    # `_time` with its own receive time — the run that closed at 01:40 sorted wherever
    # the outbox drain happened to land it.
    hints = events[0].payload[ENVELOPE]
    assert hints["time"] == datetime.fromisoformat(payload["occurredAt"]).timestamp()
    assert hints["time"] == run.window_end.timestamp()  # and the row agrees
    assert hints["source"] == "e2e.jamfcloud.com"
    # The ruling: a run is not about a Mac, so `host` is genuinely absent rather than
    # filled with the Jamf server or the worker's container. If this ever starts
    # asserting a host, `dc(host)` across a customer's index counts something that is
    # not a device.
    assert "host" not in hints
    body = _build_body(SimpleNamespace(type="splunk_hec"), events[0].payload)
    assert body["time"] == hints["time"] and body["source"] == "e2e.jamfcloud.com"
    assert "host" not in body
    # And the reserved key is transport only: it must never reach a customer's index.
    assert ENVELOPE not in body["event"]


async def test_failures_past_the_threshold_fail_the_run_and_stop_it(
    db, jamf: FakeJamf, connection, monkeypatch
) -> None:
    """A fleet-wide outage: every device fails. The run must stop just past the
    tolerance — not iterate the remaining fleet — and be failed with the count in its
    error, with the same accounting on the wire."""
    from app.core.config import settings
    from app.core.runs import TRIGGER_MANUAL
    from app.mdm import service
    from app.mdm.collections import run_collection

    # The floor lowered so the test doesn't need 26 devices; the percent term is 0 at
    # this fleet size, so the tolerance is exactly 1.
    monkeypatch.setattr(settings, "sweep_failure_max_absolute", 1)
    jamf.seed(6)  # eight devices in all
    attempts = {"n": 0}

    async def every_device_fails(db_, connection_, raw, **kwargs):
        attempts["n"] += 1
        await db_.execute(text("SELECT 1/0"))

    monkeypatch.setattr(service, "ingest_computer", every_device_fails)
    sweep = await _sweep_collection(db, connection)
    result = await run_collection(db, sweep, trigger=TRIGGER_MANUAL)

    # Failure one is within tolerance, failure two crosses it — and nothing after it
    # was attempted.
    assert attempts["n"] == 2
    assert result.ok is False
    assert result.device_count == 2
    assert result.devices_processed == 0
    assert result.devices_failed == 2
    assert result.error and "2 of 2 devices failed" in result.error

    run = await _latest_run(db, connection.id)
    assert run.status == "failed"
    assert run.devices_failed == 2 and run.devices_processed == 0
    assert run.error and "over the tolerance" in run.error

    await db.refresh(sweep)
    assert sweep.last_run_status == "failed"

    events = await _run_completed_events(db, run.id)
    assert len(events) == 1
    payload = events[0].payload
    assert payload["status"] == "failed"
    assert payload["devicesTotal"] == 2
    assert payload["devicesProcessed"] == 0
    assert payload["devicesFailed"] == 2

    # And beside the heartbeat, exactly one alarm (#103): a run.failed carrying the
    # same run id and the tolerance verdict as its error summary.
    alarms = await _run_failed_events(db, run.id)
    assert len(alarms) == 1
    assert alarms[0].payload["connectionID"] == connection.id
    assert alarms[0].payload["error"] and "over the tolerance" in alarms[0].payload["error"]

    # run.failed's envelope. Its occurrence is `window_end` — the instant the run
    # reached `failed`, already on the payload and on the row — rather than a new
    # field minted to carry the same value.
    hints = alarms[0].payload[ENVELOPE]
    assert hints["time"] == datetime.fromisoformat(alarms[0].payload["windowEnd"]).timestamp()
    assert hints["time"] == run.window_end.timestamp()
    assert hints["source"] == "e2e.jamfcloud.com"
    assert "host" not in hints  # same ruling: a run is not about a Mac
    body = _build_body(SimpleNamespace(type="splunk_hec"), alarms[0].payload)
    assert ENVELOPE not in body["event"]
    # The alarm is the failure that most needs a true `_time`: a destination outage is
    # exactly the condition that both fails runs and delays their delivery, so receive
    # time would file the whole outage at the moment it ended.
    assert body["time"] == hints["time"]


async def test_a_reclaim_still_aborts_the_run_and_is_not_a_device_failure(
    db, jamf: FakeJamf, connection, monkeypatch
) -> None:
    """The #94 fence through the #92 catch: mid-sweep, the run is reclaimed out from
    under the process (the exact transition _reclaim_stale performs) and its in-memory
    heartbeat aged past the throttle, so the loop's next beat raises RunReclaimed. The
    isolation must let it unwind — no failure counted, no more devices attempted, the
    reclaim's verdict untouched, and nothing on the wire."""
    from app.core.runs import TRIGGER_MANUAL, get_run
    from app.mdm import service
    from app.mdm.collections import run_collection
    from app.models.schema import Run

    jamf.seed(3)  # five devices in all
    reclaim_error = "reclaimed: no heartbeat within 300s — the process running it stopped"
    real_ingest = service.ingest_computer
    seen = {"calls": 0, "run_id": None}

    async def reclaimed_under_device_two(db_, connection_, raw, **kwargs):
        seen["calls"] += 1
        if seen["calls"] == 2:
            context = get_run()
            seen["run_id"] = context.id
            await db_.execute(
                update(Run)
                .where(Run.id == context.id)
                .values(status="failed", finished_at=_now(), window_end=_now(), error=reclaim_error)
            )
            await db_.commit()
            # The same identity-mapped instance the sweep loop holds: aging its
            # heartbeat gets beat() past the 15s throttle to the conditional UPDATE,
            # which is where the fence lives.
            run_obj = await db_.get(Run, context.id)
            run_obj.heartbeat_at = _now() - timedelta(seconds=60)
        return await real_ingest(db_, connection_, raw, **kwargs)

    monkeypatch.setattr(service, "ingest_computer", reclaimed_under_device_two)
    sweep = await _sweep_collection(db, connection)
    result = await run_collection(db, sweep, trigger=TRIGGER_MANUAL)

    assert result.ok is False
    assert result.error and "reclaimed" in result.error
    assert seen["calls"] == 2  # the loop stopped where it stood

    run = await db.get(Run, seen["run_id"])
    await db.refresh(run)
    assert run.status == "failed"
    assert run.error == reclaim_error  # the reclaim's verdict, word for word
    # Not counted as a device failure, and no late accounting written over the reclaim.
    assert run.devices_failed == 0 and run.devices_processed == 0 and run.device_count == 0

    assert await _run_completed_events(db, run.id) == []
    # No run.failed from the refused finish either. When the transition is the real
    # _reclaim_stale's rather than this test's hand-written copy of it, the reclaim
    # itself emits the one alarm — test_runs pins that end (#103).
    assert await _run_failed_events(db, run.id) == []


async def test_a_webhook_ingest_emits_run_completed(db, jamf: FakeJamf, connection) -> None:
    """#224: a webhook is a run with one device in it, and it now gets the same
    run.completed heartbeat a sweep gets — the identical ruled fields, for a run of
    one device rather than a fleet. Every jobID an inventory event carries, sweep or
    webhook, now resolves to a run.completed that actually arrives."""
    from app.mdm.service import ingest_webhook
    from app.models.schema import Run

    payload = {
        "webhook": {"webhookEvent": "ComputerInventoryCompleted"},
        "event": {"jssID": jamf.real["id"], "serialNumber": "LOONMINI0M4"},
    }
    result = await ingest_webhook(db, connection, payload)
    assert result is not None

    run = (
        await db.execute(
            select(Run).where(Run.mdm_connection_id == connection.id, Run.lock_class == "webhook")
        )
    ).scalars().one()
    # finish() writes the row with a bulk UPDATE; the identity-mapped instance from
    # acquire is stale without a refresh.
    await db.refresh(run)
    assert run.status == "succeeded"
    assert run.devices_processed == 1 and run.devices_failed == 0

    events = await _run_completed_events(db, run.id)
    assert len(events) == 1
    # Same envelope-stripping discipline as test_one_dead_device_does_not_kill_the_sweep
    # above: popping ENVELOPE rather than widening the set keeps this failing if a real
    # key is ever added or renamed without a ruling.
    emitted = dict(events[0].payload)
    emitted.pop(ENVELOPE)
    assert set(emitted) == {
        "event", "jobID", "connectionID", "trigger", "comparison",
        "occurredAt", "devicesTotal", "devicesProcessed", "devicesFailed", "status",
    }
    assert emitted["status"] == "succeeded"
    assert emitted["trigger"] == "webhook"
    assert emitted["devicesTotal"] == 1
    assert emitted["devicesProcessed"] == 1
    assert emitted["devicesFailed"] == 0
    assert emitted["connectionID"] == connection.id
    assert emitted["jobID"] == str(run.id)

    # The envelope: a webhook's run is still not a Mac, so no `host` here either.
    hints = events[0].payload[ENVELOPE]
    assert hints["source"] == "e2e.jamfcloud.com"
    assert "host" not in hints
    body = _build_body(SimpleNamespace(type="splunk_hec"), events[0].payload)
    assert body["source"] == "e2e.jamfcloud.com"
    assert "host" not in body
