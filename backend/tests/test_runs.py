"""The run as a first-class object (#31) against a real Postgres.

The four clauses this issue folds together, each asserted on the mechanism rather than
on a status string: the row is the mutex, its id is the jobID stamped on every event,
its window is the `_time` anchor for scheduled runs, and it is what the log is scoped by.

The mutex tests matter most and are the reason this suite needs a real database. The
partial unique index *is* the lock; it cannot be exercised against anything that does not
enforce it, and the race it closes (two readers both seeing 'idle') is precisely the kind
a single-threaded test with a stubbed store reports as passing.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

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
        name=f"runs jamf {uuidlib.uuid4().hex[:8]}",
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
        # `runs` and `run_log` cascade from the connection, so nothing here deletes them
        # explicitly — which is also the assertion that the cascade is wired.
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        # The app catalog is keyed by tenant, not by connection, so it survives the
        # cascade above — and a sweep here would otherwise leave rows that make
        # test_catalog_db's "a key the fleet has not shown" assertion fail on the *next*
        # run against the same local database. Title matches go by cascade.
        await db.execute(delete(AppCatalogEntry))
        await db.commit()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- the mutex ------------------------------------------------------------------------


async def test_a_second_acquisition_joins_rather_than_starting_a_duplicate(db, connection) -> None:
    """The race the check-then-set could not close.

    Two run-now clicks arriving together both used to read 'idle' from mdm_sync_state,
    both pass the guard, and both start a full pull against the same Jamf server. Now
    both INSERT, the partial unique index rejects one, and the loser is handed the
    winner's jobID — 202 with someone else's run, not a duplicate sweep.
    """
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_MANUAL, acquire, finish

    first = await acquire(db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_DEVICE_SWEEP)
    second = await acquire(db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_DEVICE_SWEEP)

    assert first.started is True
    assert second.started is False
    assert second.run.id == first.run.id  # the loser polls the winner's log

    await finish(db, first.run, ok=True)
    third = await acquire(db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_DEVICE_SWEEP)
    assert third.started is True and third.run.id != first.run.id
    await finish(db, third.run, ok=True)


async def test_a_catalog_refresh_does_not_wait_behind_a_device_sweep(db, connection) -> None:
    """The grain correction: the lock is per (connection, class), not per tenant.

    #31 originally keyed the index on tenant alone, which would have let a tenant with
    two Jamf instances sweep only one at a time, and would have starved the catalog
    exactly when a long sweep is generating references into it.
    """
    from app.core.runs import LOCK_CATALOG, LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, acquire, finish

    sweep = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    catalog = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_CATALOG)

    assert sweep.started and catalog.started
    assert sweep.run.id != catalog.run.id

    await finish(db, sweep.run, ok=True)
    await finish(db, catalog.run, ok=True)


async def test_webhooks_are_lock_exempt(db, connection) -> None:
    """A webhook gets a run — for the jobID and the log — but never the lock.

    They must ACK fast and a busy tenant fires many; serializing them behind a
    forty-minute sweep makes the real-time path useless. Exemption lives in the index
    predicate rather than in a branch, so there is nowhere for code to forget it.
    """
    from app.core.runs import LOCK_DEVICE_SWEEP, LOCK_WEBHOOK, TRIGGER_SWEEP, TRIGGER_WEBHOOK, acquire, finish

    sweep = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    one = await acquire(db, connection, trigger=TRIGGER_WEBHOOK, lock_class=LOCK_WEBHOOK)
    two = await acquire(db, connection, trigger=TRIGGER_WEBHOOK, lock_class=LOCK_WEBHOOK)

    # Concurrent with the sweep and with each other.
    assert one.started and two.started and one.run.id != two.run.id

    for run in (sweep.run, one.run, two.run):
        await finish(db, run, ok=True)


async def test_a_run_with_no_heartbeat_is_reclaimed(db, connection) -> None:
    """A mutex without a heartbeat is a deadlock, which is worse than the race.

    A process that dies holding the lock leaves the row `running` forever and nothing on
    that connection can sync again. Duplicate load is noisy and self-limiting; permanent
    silence pages nobody. Reclaim happens on the next acquisition, not at startup — the
    blanket startup reset this replaces failed runs that other, healthy processes were
    still performing.
    """
    from sqlalchemy import update

    from app.core.config import settings
    from app.core.runs import LOCK_DEVICE_SWEEP, STATUS_FAILED, TRIGGER_SWEEP, acquire, finish
    from app.models.schema import Run

    dead = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert dead.started

    # The process stops beating. Nothing else about the row changes: to the database it
    # is still a perfectly good running run.
    stale = _now() - timedelta(seconds=settings.run_stale_after_seconds + 60)
    await db.execute(update(Run).where(Run.id == dead.run.id).values(heartbeat_at=stale))
    await db.commit()

    revived = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert revived.started is True and revived.run.id != dead.run.id

    reclaimed = await db.get(Run, dead.run.id)
    await db.refresh(reclaimed)
    assert reclaimed.status == STATUS_FAILED
    assert reclaimed.error and "heartbeat" in reclaimed.error
    await finish(db, revived.run, ok=True)


async def test_a_beating_run_is_not_reclaimed(db, connection) -> None:
    """The other half of the same guarantee: a live run keeps its lock. A reclaim that
    fires early is a stolen lock and two concurrent sweeps, which is the failure the
    mutex exists to prevent."""
    from app.core.runs import LOCK_DEVICE_SWEEP, STATUS_RUNNING, TRIGGER_SWEEP, acquire, beat, finish
    from app.models.schema import Run

    live = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    await beat(db, live.run)

    blocked = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert blocked.started is False and blocked.run.id == live.run.id
    assert (await db.get(Run, live.run.id)).status == STATUS_RUNNING
    await finish(db, live.run, ok=True)


# --- the window, and the `_time` rule ---------------------------------------------------


async def test_a_scheduled_run_back_dates_events_to_its_window(db, connection) -> None:
    """A sweep's events carry the occurrence it serves, not the moment each device was
    processed. Otherwise a forty-minute pull smears one nightly sweep across forty
    minutes of the index, and a sweep that started late reports the wrong hour."""
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, acquire, entered, event_time, finish

    due_at = _now().replace(hour=1, minute=0, second=0, microsecond=0) - timedelta(days=1)
    run = await acquire(
        db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP, due_at=due_at
    )
    async with entered(run.run):
        # Every device in the sweep resolves to the same `_time`, whenever it was reached.
        assert event_time() == due_at
        assert event_time(_now()) == due_at
    await finish(db, run.run, ok=True)


async def test_a_webhook_carries_device_time_and_lands_after_the_run_stamp(db, connection) -> None:
    """The contract's checkable statement: webhooks always land after the run stamp.

    Only expressible once the window exists to compare against. The sweep's events sit at
    the window; the webhook's sit at the device's own reportDate, which is later because
    that is why the webhook fired.
    """
    from app.core.runs import (
        LOCK_WEBHOOK,
        TRIGGER_WEBHOOK,
        acquire,
        entered,
        event_time,
        finish,
    )

    window = _now() - timedelta(hours=2)
    device_time = _now() - timedelta(minutes=5)

    run = await acquire(db, connection, trigger=TRIGGER_WEBHOOK, lock_class=LOCK_WEBHOOK)
    async with entered(run.run):
        assert event_time(device_time) == device_time
        assert event_time(device_time) > window
    await finish(db, run.run, ok=True)


async def test_outside_a_run_the_time_is_now(db) -> None:
    """Paths not yet brought inside a run behave exactly as they did before it existed."""
    from app.core.runs import event_time, run_meta

    before = _now()
    assert before <= event_time() <= _now()
    assert run_meta() == {}


# --- the jobID on the wire --------------------------------------------------------------


async def test_a_sweep_stamps_its_job_id_on_the_events_it_produces(db, connection, jamf: FakeJamf) -> None:
    """The meta block, end to end: a real sweep of the fake tenant, and the inventory
    event it enqueues carries the run's identity so a search can collect everything one
    pull produced."""
    from app.core.runs import TRIGGER_MANUAL
    from app.mdm.collections import ensure_default_collections, list_collections, run_collection
    from app.models.schema import EventOutbox, Run

    await ensure_default_collections(db, connection)
    await db.commit()
    sweep = next(row for row in await list_collections(db, connection.id) if row.kind == "device_sweep")

    result = await run_collection(db, sweep, trigger=TRIGGER_MANUAL)
    assert result.ok and result.device_count > 0

    run = (
        await db.execute(
            select(Run).where(Run.mdm_connection_id == connection.id).order_by(Run.started_at.desc()).limit(1)
        )
    ).scalars().one()
    assert run.status == "succeeded"
    assert run.comparison == "baseline"  # nothing succeeded on this connection before
    assert run.trigger == TRIGGER_MANUAL
    assert run.device_count == result.device_count

    event = (
        await db.execute(
            select(EventOutbox)
            .where(EventOutbox.event_type == "device.inventory.changed")
            .order_by(EventOutbox.id.desc())
            .limit(1)
        )
    ).scalars().one()
    meta = event.payload["meta"]
    assert meta["jobId"] == str(run.id)
    assert meta["trigger"] == TRIGGER_MANUAL
    assert meta["comparison"] == "baseline"
    assert meta["serialNumber"]
    assert meta["shortDate"] == run.window_start.strftime("%Y-%m-%d")

    # And the second run of the same connection and class is a delta, not another
    # baseline — the distinction the contract's `run_type` was carrying.
    second = await run_collection(db, sweep, trigger=TRIGGER_MANUAL)
    assert second.ok
    latest = (
        await db.execute(
            select(Run).where(Run.mdm_connection_id == connection.id).order_by(Run.started_at.desc()).limit(1)
        )
    ).scalars().one()
    assert latest.comparison == "delta"


# --- the log ----------------------------------------------------------------------------


async def test_the_run_log_is_scoped_by_job_id_and_paged_by_cursor(db, connection, jamf: FakeJamf) -> None:
    from app.core.runs import TRIGGER_MANUAL
    from app.mdm.collections import ensure_default_collections, list_collections, run_collection
    from app.models.schema import Run, RunLogLine

    await ensure_default_collections(db, connection)
    await db.commit()
    sweep = next(row for row in await list_collections(db, connection.id) if row.kind == "device_sweep")
    await run_collection(db, sweep, trigger=TRIGGER_MANUAL)

    run = (
        await db.execute(
            select(Run).where(Run.mdm_connection_id == connection.id).order_by(Run.started_at.desc()).limit(1)
        )
    ).scalars().one()

    lines = (
        await db.execute(select(RunLogLine).where(RunLogLine.run_id == run.id).order_by(RunLogLine.id))
    ).scalars().all()
    messages = [row.message for row in lines]
    assert "run started" in messages
    assert "aperture captured" in messages
    assert "run finished" in messages
    assert all(row.run_id == run.id for row in lines)

    # The cursor the panel polls with: `after` the last id it holds returns nothing new
    # once the run is over, rather than re-sending the whole log every two seconds.
    after = lines[-1].id
    remaining = (
        await db.execute(
            select(RunLogLine).where(RunLogLine.run_id == run.id, RunLogLine.id > after)
        )
    ).scalars().all()
    assert remaining == []


async def test_the_api_serializes_the_keys_the_panel_reads(db, connection) -> None:
    """The wire shape, asserted against the names the browser actually uses.

    The run-now panel is the one consumer of these endpoints and it reads camelCase.
    Nothing else in the stack would notice a field that serialized as `job_id`, or one
    quietly renamed — the panel would simply show `undefined` and poll a URL ending in
    "undefined" forever.
    """
    from app.api.runs import get_run_log, list_runs
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_MANUAL, acquire, finish

    acquired = await acquire(
        db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_DEVICE_SWEEP, actor_label="verify@example.com"
    )
    await finish(db, acquired.run, ok=True, device_count=3, group_count=2)

    listed = await list_runs(connection_id=connection.id, status=None, limit=5, db=db)
    assert str(listed[0].id) == str(acquired.run.id)

    page = await get_run_log(job_id=acquired.run.id, after=0, db=db)
    body = page.model_dump(by_alias=True)

    assert body["run"]["id"] == acquired.run.id
    assert body["complete"] is True
    for key in ("mdmConnectionId", "lockClass", "windowStart", "deviceCount", "groupCount", "actorLabel"):
        assert key in body["run"], f"{key} missing from the serialized run"
    assert body["run"]["deviceCount"] == 3
    assert body["lines"][0]["message"] == "run started"

    # `after` the last line returns an empty page but still a live `complete` flag —
    # the poller's stop condition is the status, never an empty page.
    tail = await get_run_log(job_id=acquired.run.id, after=body["lines"][-1]["id"], db=db)
    assert tail.lines == [] and tail.complete is True


async def test_purge_drops_finished_runs_and_never_a_live_one(db, connection) -> None:
    from sqlalchemy import update

    from app.core.runs import LOCK_CATALOG, LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, acquire, finish, purge_runs
    from app.models.schema import Run, RunLogLine

    old = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    await finish(db, old.run, ok=True)
    await db.execute(
        update(Run).where(Run.id == old.run.id).values(finished_at=_now() - timedelta(days=400))
    )
    await db.commit()

    live = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_CATALOG)

    purged = await purge_runs(db, 30)
    assert purged >= 1

    # Queried rather than db.get()'d: the session is configured expire_on_commit=False,
    # so a get() after a bulk delete answers from the identity map and would pass here
    # whether or not the row is actually gone.
    async def _exists(run_id) -> bool:
        found = await db.execute(select(Run.id).where(Run.id == run_id))
        return found.scalar_one_or_none() is not None

    assert not await _exists(old.run.id)
    # The log goes with it by cascade rather than by a second delete that could drift.
    orphans = (
        await db.execute(select(RunLogLine.id).where(RunLogLine.run_id == old.run.id))
    ).scalars().all()
    assert orphans == []

    # A run still holding its lock is never purged, whatever its age says.
    assert await _exists(live.run.id)
    await finish(db, live.run, ok=True)
