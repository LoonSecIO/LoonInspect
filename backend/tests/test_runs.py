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
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text

from app.core.outbox import _build_body
from app.core.wire import ENVELOPE, instance_label
from app.schemas.payload import WIRE_SCHEMA_VERSION
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


async def _run_failed_events(db, run_id) -> list:
    """Every run.failed event this run emitted, matched by payload rather than by
    recency — the shared local database accumulates events across tests."""
    from app.models.schema import EventOutbox

    rows = (
        await db.execute(
            select(EventOutbox).where(EventOutbox.event_type == "run.failed").order_by(EventOutbox.id)
        )
    ).scalars().all()
    return [row for row in rows if row.payload.get("jobID") == str(run_id)]


async def _run_completed_events(db, run_id) -> list:
    """The same matching for run.completed — the heartbeat beside run.failed's alarm."""
    from app.models.schema import EventOutbox

    rows = (
        await db.execute(
            select(EventOutbox).where(EventOutbox.event_type == "run.completed").order_by(EventOutbox.id)
        )
    ).scalars().all()
    # `jobID`, matching its sibling above: #212 renamed the run id on every family and
    # updated the run.failed helper, but nothing on main exercised this one, so its
    # stale `run_id` lookup silently matched zero rows until these tests arrived.
    return [row for row in rows if row.payload.get("jobID") == str(run_id)]


@pytest_asyncio.fixture(loop_scope="session")
async def sibling_connection(db):
    """A SECOND connection in the same tenant, for the blast-radius assertions.

    The failure those tests pin was never confined to the connection that broke: the
    reclaim runs on every acquisition, so one unwritable INSERT stopped syncing on
    connections with nothing wrong with them. A suite with one connection in it cannot
    see that, and would have reported the outage as a single stuck run.
    """
    from app.models.schema import MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"runs jamf sibling {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
    )
    db.add(row)
    await db.commit()
    connection_id = row.id
    try:
        yield row
    finally:
        # `runs` and `run_log` go with the connection by cascade, as in the fixture above.
        await db.rollback()
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


@pytest.fixture
def unwritable_outbox(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """An `enqueue_event` that fails the way the full disk failed: with a statement error
    that ABORTS the surrounding transaction.

    A bare `raise RuntimeError` would be the weaker fake, and a dangerous one: the
    transaction would stay perfectly usable, the commit after it would write the release
    anyway, and the test would pass against the very code it exists to condemn. What was
    observed was an INSERT into `event_outbox` that could not be written — after which
    every statement on that connection errors until someone rolls back. This reproduces
    that, which is as close as a test gets to exhausting a disk on purpose.

    Returns the event types it was asked for, so a test can tell "the emit was attempted
    and failed" from "the emit was quietly skipped".
    """
    from app.core import runs

    attempted: list[str] = []

    async def _unwritable(db, event_type, payload, *, request_id=None):
        attempted.append(event_type)
        await db.execute(text("INSERT INTO no_such_table_anywhere (id) VALUES (1)"))

    monkeypatch.setattr(runs, "enqueue_event", _unwritable)
    return attempted


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

    # The reclaim is loud (#103): the run's own log states the failure — before this,
    # a reclaimed run's log just stopped mid-sweep after the last progress line — and
    # the wire carries one run.failed with the reclaim's own error as the summary.
    from app.models.schema import RunLogLine

    lines = (
        await db.execute(select(RunLogLine).where(RunLogLine.run_id == dead.run.id).order_by(RunLogLine.id))
    ).scalars().all()
    assert lines[-1].level == "error" and lines[-1].message == "run failed"
    assert "heartbeat" in lines[-1].fields["error"]

    events = await _run_failed_events(db, dead.run.id)
    assert len(events) == 1
    assert events[0].payload["trigger"] == TRIGGER_SWEEP
    assert "heartbeat" in events[0].payload["error"]

    # The reclaim is run.failed's *other* producer, and its envelope must match the
    # verdict it just wrote: `time` is the instant the reclaim stamped window_end, not
    # the moment the outbox drains. This is the event that most needs a true `_time` —
    # the process that would have reported the failure is the one that died, so the
    # only clock left is the reclaimer's.
    hints = events[0].payload[ENVELOPE]
    assert hints["time"] == reclaimed.window_end.timestamp()
    assert hints["time"] == datetime.fromisoformat(events[0].payload["windowEnd"]).timestamp()
    assert hints["source"] == instance_label(HOST) == "e2e.jamfcloud.com"
    # A run is not about a Mac, so no `host` — deliberately, not by omission.
    assert "host" not in hints
    body = _build_body(SimpleNamespace(type="splunk_hec"), events[0].payload)
    assert body["time"] == hints["time"] and "host" not in body
    assert ENVELOPE not in body["event"]

    await finish(db, revived.run, ok=True)
    # A run that closed cleanly emits no run.failed — the alarm never cries wolf.
    assert await _run_failed_events(db, revived.run.id) == []


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


async def test_a_reclaimed_run_cannot_be_resurrected_by_its_zombie(db, connection) -> None:
    """The fence (#94): the reclaim frees the lock by failing a quiet row, but the
    process it declared dead may only be stalled — a worst-case Jamf retry budget sits
    uncomfortably close to the staleness threshold. That zombie's heartbeat must not
    make the row look alive again, and its finish must not overwrite the reclaim's
    verdict in either direction: a late `succeeded` is the double-run record the module
    preamble promises cannot exist, and a late `failed` swaps the reclaim's accounting
    for the zombie's.
    """
    from sqlalchemy import update

    from app.core.runs import (
        LOCK_DEVICE_SWEEP,
        STATUS_FAILED,
        TRIGGER_SWEEP,
        RunReclaimed,
        acquire,
        beat,
        finish,
    )
    from app.models.schema import Run, RunLogLine

    zombie = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert zombie.started
    reclaim_error = "reclaimed: no heartbeat within 300s — the process running it stopped"

    # Exactly the transition _reclaim_stale performs, minus the acquisition that finds
    # the row: the fence must hold against the state, not against who wrote it.
    await db.execute(
        update(Run)
        .where(Run.id == zombie.run.id)
        .values(status=STATUS_FAILED, finished_at=_now(), window_end=_now(), error=reclaim_error)
    )
    await db.commit()

    # (a) The heartbeat reports the loss instead of quietly keeping a dead run warm.
    # The in-memory throttle is aged past the interval the way a real stall ages it.
    zombie.run.heartbeat_at = _now() - timedelta(seconds=60)
    with pytest.raises(RunReclaimed):
        await beat(db, zombie.run)
    # beat's refusal rolled the session back, which expires the ORM row; reload it
    # explicitly rather than letting an attribute read try to refresh mid-await.
    await db.refresh(zombie.run)

    # (b) finish cannot resurrect the row as succeeded — the zombie's happy path...
    assert await finish(db, zombie.run, ok=True, device_count=40_000) is False
    # ...and cannot restamp it as failed either — the zombie's own exception handler.
    assert await finish(db, zombie.run, ok=False, error="the zombie's last words") is False

    # (c) The history still shows the reclaim's verdict, accounting untouched.
    await db.refresh(zombie.run)
    assert zombie.run.status == STATUS_FAILED
    assert zombie.run.error == reclaim_error
    assert zombie.run.device_count == 0

    # And the run log shows the late finisher was turned away — the evidence trail
    # records that the zombie came back, not just that the run went quiet.
    messages = (
        await db.execute(select(RunLogLine.message).where(RunLogLine.run_id == zombie.run.id))
    ).scalars().all()
    assert any("finish refused" in message for message in messages)

    # (d) A refused finish emits no run.failed either — the reclaim owns this run's
    # one alarm, and the zombie's late `failed` on the wire would double-count it.
    assert await _run_failed_events(db, zombie.run.id) == []


async def test_a_failed_run_emits_exactly_one_run_failed_with_the_ruled_fields(db, connection) -> None:
    """The wire half of #103: the moment finish writes `failed`, one run.failed leaves
    through the outbox in the same transaction — trigger, the connection by id and
    name, the run id, the window, and the stored error truncated to a summary. Nothing
    else: no credentials, no log lines; the run id is the pointer to the full story.
    """
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_MANUAL, acquire, finish

    long_error = "Jamf returned 502 at page 41 of the inventory pull; " * 20  # far past the cap
    failed = await acquire(db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_DEVICE_SWEEP)
    await finish(db, failed.run, ok=False, error=long_error)

    events = await _run_failed_events(db, failed.run.id)
    assert len(events) == 1
    # The envelope is lifted off first so this stays an assertion about the ruled WIRE
    # fields. `_envelope` is outbox transport that `_build_body` pops before any
    # destination sees it — popping it here rather than widening the set keeps this
    # test failing if a real field is ever added or renamed without a ruling.
    payload = dict(events[0].payload)
    hints = payload.pop(ENVELOPE)
    assert set(payload) == {
        "event", "jobID", "connectionID", "connectionName", "trigger",
        "windowStart", "windowEnd", "error",
    }
    assert payload["event"] == "run.failed"
    assert payload["connectionID"] == connection.id
    assert payload["connectionName"] == connection.name
    assert payload["trigger"] == TRIGGER_MANUAL
    assert payload["windowStart"] == failed.run.window_start.isoformat()
    assert payload["windowEnd"]  # stamped from the same instant as the row's window_end
    # Truncated sanely: the summary is the error's head, never the whole text.
    assert payload["error"] == long_error[:500]
    # And the envelope carries the occurrence, from the field the payload already had:
    # window_end is the instant the run reached `failed`, at both of run.failed's
    # producers, so nothing new had to be minted to give Splunk a true `_time`.
    assert hints["time"] == datetime.fromisoformat(payload["windowEnd"]).timestamp()
    assert hints["source"] == instance_label(HOST) == "e2e.jamfcloud.com"
    assert "host" not in hints  # a run is not about a Mac
    # The error summary is the one free-text field on this event, and the envelope must
    # not become a second place it can leak: the hints are three keys, nothing more.
    assert set(hints) == {"time", "source"}


async def test_a_failed_webhook_run_emits_run_failed_unlike_run_completed(db, connection) -> None:
    """run.completed excludes webhook runs because success-per-webhook is volume
    without signal — but a failed webhook run is exactly as silent as a failed sweep,
    which is why #103 scopes the alarm to every trigger and every lock class."""
    from app.core.runs import LOCK_WEBHOOK, TRIGGER_WEBHOOK, acquire, finish
    from app.models.schema import EventOutbox

    hook = await acquire(db, connection, trigger=TRIGGER_WEBHOOK, lock_class=LOCK_WEBHOOK)
    await finish(db, hook.run, ok=False, error="device record vanished mid-ingest")

    events = await _run_failed_events(db, hook.run.id)
    assert len(events) == 1
    assert events[0].payload["trigger"] == TRIGGER_WEBHOOK
    # And still no run.completed for a webhook run — the #92 exclusion is untouched.
    completed = (
        await db.execute(select(EventOutbox).where(EventOutbox.event_type == "run.completed"))
    ).scalars().all()
    assert all(row.payload.get("jobID") != str(hook.run.id) for row in completed)


# --- the emit is outside the release ----------------------------------------------------


async def test_the_run_releases_even_when_the_event_emit_fails(db, connection, unwritable_outbox) -> None:
    """The whole point of the change: releasing the mutex must not depend on being able
    to enqueue an event.

    `finish` used to enqueue run.completed and run.failed in the same transaction as the
    status UPDATE that frees the lock. A failed INSERT aborted that transaction and took
    the release with it — the row stayed ('running', False, None), which is a connection
    that can never sync again. Found by a destructive disk-exhaustion test, and
    non-deterministic there: a second attempt whose row happened to fit in existing page
    space released fine, so an operator could not even predict which failure they had.
    """
    from app.core.runs import (
        EVENT_LOST_MESSAGE,
        LOCK_DEVICE_SWEEP,
        RUN_COMPLETED_EVENT,
        RUN_FAILED_EVENT,
        STATUS_FAILED,
        TRIGGER_SWEEP,
        acquire,
        finish,
    )
    from app.models.schema import Run, RunLogLine

    acquired = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert acquired.started

    assert await finish(db, acquired.run, ok=False, error="Jamf stopped answering") is True

    # Selected rather than db.get()'d: the session is expire_on_commit=False and the
    # status was written by a Core UPDATE, so the identity map still says `running`.
    closed = (
        await db.execute(select(Run.status, Run.finished_at, Run.error).where(Run.id == acquired.run.id))
    ).one()
    assert closed.status == STATUS_FAILED
    assert closed.finished_at is not None
    assert closed.error == "Jamf stopped answering"

    # Both events were attempted, and both were lost. Asserted separately from the
    # release so a change that stops attempting one of them cannot pass by looking
    # like this one: losing an event is the ruled trade, not skipping it.
    assert unwritable_outbox == [RUN_COMPLETED_EVENT, RUN_FAILED_EVENT]
    assert await _run_completed_events(db, acquired.run.id) == []
    assert await _run_failed_events(db, acquired.run.id) == []

    # And the loss is recorded where an operator who noticed the missing event will
    # look. Without this the run they open would show a clean close and the only trace
    # would be a container log line they had to already suspect something to find.
    lines = (
        await db.execute(select(RunLogLine).where(RunLogLine.run_id == acquired.run.id).order_by(RunLogLine.id))
    ).scalars().all()
    lost = [line for line in lines if line.message == EVENT_LOST_MESSAGE]
    assert [line.fields["eventType"] for line in lost] == [RUN_COMPLETED_EVENT, RUN_FAILED_EVENT]
    assert all(line.level == "error" for line in lost)
    # The run's own closing line is still written after them: a lost event does not cost
    # the run its history as well.
    assert "run failed" in [line.message for line in lines]


async def test_a_failed_emit_leaves_every_connection_still_able_to_acquire(
    db, connection, sibling_connection, unwritable_outbox, monkeypatch
) -> None:
    """The blast radius, and the reason this was never merely a lost event.

    A run stuck at `running` blocks its own connection — but `acquire()` calls
    `_reclaim_stale()` first, and on the old code that reclaim re-raised the identical
    INSERT failure for every caller. One unwritable row stopped syncing everywhere,
    including on connections that had nothing wrong with them.
    """
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, acquire, finish

    doomed = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert await finish(db, doomed.run, ok=True, device_count=7) is True
    assert unwritable_outbox  # the emit really was attempted, and really did fail

    # The connection whose emit failed can start a new run...
    again = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert again.started is True and again.run.id != doomed.run.id
    # ...and so can a connection that was never anywhere near the failure.
    sibling = await acquire(db, sibling_connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert sibling.started is True

    # Nothing latches: with the outbox writable again the next close emits normally,
    # exactly one run.completed carrying the ordinary accounting.
    monkeypatch.undo()
    assert await finish(db, again.run, ok=True, device_count=7) is True
    events = await _run_completed_events(db, again.run.id)
    assert len(events) == 1
    assert events[0].payload["status"] == "succeeded"
    assert events[0].payload["devicesTotal"] == 7
    await finish(db, sibling.run, ok=True)


async def test_the_reclaim_frees_the_lock_even_when_its_event_emit_fails(
    db, connection, sibling_connection, unwritable_outbox
) -> None:
    """The reclaim needed the same treatment as `finish`, and its failure mode is worse.

    `finish`'s bad transaction wedges the one connection it was closing. The reclaim runs
    on EVERY acquisition, so its failed INSERT raised out of `acquire` for callers with no
    stale run to reclaim and nothing to emit — which is how one unwritable row became a
    tenant-wide stop. The acquisition that trips the reclaim here therefore belongs to a
    different connection on purpose: that caller is the bystander the old code broke.
    """
    from sqlalchemy import update as sa_update

    from app.core.config import settings
    from app.core.runs import (
        EVENT_LOST_MESSAGE,
        LOCK_DEVICE_SWEEP,
        STATUS_FAILED,
        TRIGGER_SWEEP,
        acquire,
        finish,
    )
    from app.models.schema import Run, RunLogLine

    dead = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert dead.started
    stale = _now() - timedelta(seconds=settings.run_stale_after_seconds + 60)
    await db.execute(sa_update(Run).where(Run.id == dead.run.id).values(heartbeat_at=stale))
    await db.commit()

    bystander = await acquire(db, sibling_connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert bystander.started is True

    # The reclaim's verdict committed even though its recording could not.
    reclaimed = (await db.execute(select(Run.status, Run.error).where(Run.id == dead.run.id))).one()
    assert reclaimed.status == STATUS_FAILED
    assert reclaimed.error and "heartbeat" in reclaimed.error
    assert await _run_failed_events(db, dead.run.id) == []

    # And the lock it freed is genuinely free, for the connection it was freed on.
    revived = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert revived.started is True and revived.run.id != dead.run.id

    # The reclaimed run's log carries the loss in place of the "run failed" line the
    # healthy path writes there — the two ride one transaction because they are one
    # statement about one run, so a reclaim never announces on the wire what its own log
    # does not say. Either way the log does not simply stop mid-sweep, which is the
    # property #103 added it for.
    lines = (
        await db.execute(select(RunLogLine).where(RunLogLine.run_id == dead.run.id).order_by(RunLogLine.id))
    ).scalars().all()
    assert lines[-1].message == EVENT_LOST_MESSAGE
    assert lines[-1].level == "error"
    assert lines[-1].fields["eventType"] == "run.failed"

    await finish(db, revived.run, ok=True)
    await finish(db, bystander.run, ok=True)


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
    meta = event.payload["deviceMeta"]
    assert meta["jobID"] == str(run.id)
    assert meta["trigger"] == TRIGGER_MANUAL
    assert meta["serialNumber"]
    assert meta["shortDate"] == run.window_start.strftime("%Y-%m-%d")

    # The ruled block (#189): identity, correlation, provenance, freshness, integrity.
    # Asserted by name because every one of these is permanent the moment a customer
    # writes SPL against it, and a silent rename returns zero rows rather than an error.
    assert meta["jamfProID"]
    assert meta["hostName"]
    assert meta["schemaVersion"] == WIRE_SCHEMA_VERSION
    assert meta["eventID"] == str(uuidlib.uuid5(run.id, meta["jamfProID"]))
    # Capped at thirteen, and `custom` is a reserved name that ships no bytes in v0.
    assert len(meta) <= 13
    assert "custom" not in meta

    # The two keys the ruling CUT and PR #191 shipped anyway. Both values are real on this
    # run — `comparison` is the `baseline` asserted above, and the run served a collection
    # — so their absence below is a refusal, not a null that happened to be dropped.
    # `comparison` describes run history rather than the row and rides `run.completed`;
    # `collectionID` is null on the whole webhook path, where a BY clause over it produces
    # a null bucket that silently means "intraday". tests/test_device_meta.py holds the
    # ruling's whole refused table; these two are pinned here as well because this is the
    # only place the assertion runs against a real sweep.
    assert run.collection_id == sweep.id
    assert "comparison" not in meta
    assert "collectionID" not in meta

    # Nulls are dropped rather than shipped: the block is over half the raw feed, so a
    # key with no value costs bytes and carries nothing.
    assert all(value is not None for value in meta.values())

    # The envelope is transport, not vocabulary — it must never reach a customer index.
    hints = event.payload[ENVELOPE]
    assert hints["host"] == meta["hostName"]
    assert hints["source"] == instance_label(HOST) == "e2e.jamfcloud.com"
    body = _build_body(SimpleNamespace(type="splunk_hec"), event.payload)
    assert body["source"] == "e2e.jamfcloud.com"
    # Exact, not approx. `pytest.approx`'s default rel=1e-6 against an epoch near 1.79e9
    # is a half-hour tolerance, which would pass for delivery time, enqueue time or
    # `now()` — every regression the envelope exists to prevent. Compared against the
    # event's OWN occurredAt rather than the run window, because those are two different
    # clock reads and only one of them is what `time` is built from.
    assert body["time"] == datetime.fromisoformat(event.payload["occurredAt"]).timestamp()
    assert ENVELOPE not in body["event"]
    # Not yet ruled for this event type, and a minted sourcetype is a permanent
    # props.conf stanza — so it stays absent until the fan-out lands (#188).
    assert "sourcetype" not in body

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
