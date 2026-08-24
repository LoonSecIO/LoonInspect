"""The run — mutex, jobID, window, and log (#31, docs/ingest-scheduling.md §4).

A run is the object every pull happens inside. This module owns its whole life:
acquiring it (which *is* taking the lock), keeping it alive, resolving the `_time` rule
from its window, writing its log, finishing it, and reclaiming one whose process died.

Three things are worth reading before changing anything here.

**Acquisition is the INSERT.** `runs` carries a partial unique index on
(tenant_id, mdm_connection_id, lock_class) where status = 'running'. Two callers racing
for the same connection both insert, one commits, the other takes an integrity error and
learns who holds it. The check-then-set this replaced — read `mdm_sync_state.status`,
and if it is not 'syncing' write 'syncing' — was a race across an await: both readers
saw 'idle', both passed, and both started a sweep against the same Jamf server.

**The heartbeat is not polish.** A mutex without one is a deadlock: a process that dies
holding a run leaves the row `running` and nothing on that connection can ever sync
again. That is worse than the race it replaces, because duplicate load is noisy and
self-limiting while permanent silence pages nobody. Reclaim runs on every acquisition,
so the recovery path is exercised constantly rather than only at startup.

**The run is in a context variable, not a parameter.** `process_sync` is six frames
below the acquisition and needs the jobID and the window; the actor, tenant, and request
id already travel this way (app.core.context), and threading a seventh argument through
every ingest signature to reach one dict is how the three ingest paths drift apart.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from collections.abc import AsyncIterator
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete as sa_delete
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.schema import MdmConnection, Run, RunLogLine

logger = logging.getLogger(__name__)

# What started a run. The same three words the observation ledger stamps on every span
# as `last_trigger` — one vocabulary across the ledger, the run, and the wire.
TRIGGER_SWEEP = "sweep"
TRIGGER_MANUAL = "manual"
TRIGGER_WEBHOOK = "webhook"

# What kind of comparison a run is. Baseline: nothing has been recorded for this
# connection and lock class yet, so there is nothing to diff against and every subject
# is new by construction. Delta: everything after that.
COMPARISON_BASELINE = "baseline"
COMPARISON_DELTA = "delta"

# The mutex dimension. A catalog refresh reads hundreds of small rows and a device sweep
# paginates thousands of devices; making the cheap one wait behind the expensive one
# starves the catalog exactly when the sweep is generating references into it (§6.2).
LOCK_DEVICE_SWEEP = "device_sweep"
LOCK_CATALOG = "catalog"
# Lock-exempt by the index predicate, not by a branch here: a webhook gets a run for the
# jobID and the log but never waits for one (§4.4).
LOCK_WEBHOOK = "webhook"

STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"

# How often the heartbeat is actually written. The device loop calls beat() constantly;
# this throttles it to one small UPDATE per interval rather than one per device.
_HEARTBEAT_INTERVAL_SECONDS = 15


@dataclass(frozen=True, slots=True)
class RunContext:
    """The active run, as the ingest path sees it."""

    id: uuid.UUID
    connection_id: int
    collection_id: int | None
    trigger: str
    comparison: str
    lock_class: str
    window_start: datetime


_run: ContextVar[RunContext | None] = ContextVar("run", default=None)


def get_run() -> RunContext | None:
    return _run.get()


def set_run(run: RunContext) -> Token[RunContext | None]:
    return _run.set(run)


def reset_run(token: Token[RunContext | None]) -> None:
    _run.reset(token)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def event_time(device_time: datetime | None = None) -> datetime:
    """The `_time` an emitted event carries — the contract's back-dating rule.

    Three cases, and the distinction between them is the whole point:

    - **A scheduled run back-dates to its window.** Every event a sweep produces is
      stamped with the occurrence the sweep serves, not the moment the container got
      around to processing that device. A sweep that starts four minutes late and takes
      forty must not smear its events across forty-four minutes of the index.
    - **A webhook carries device time.** Jamf's `reportDate` for the record that
      triggered it, when the caller has one. This is what makes the contract's
      "verify webhooks always land after the run stamp" a checkable statement rather
      than a hope: the sweep's events sit at the window, the webhook's sit at the
      device's own clock, and the ordering falls out.
    - **A manual run stamps now.** Someone is watching it happen; there is no window to
      belong to, and back-dating an interactive action is a lie about when it occurred.

    Outside any run — a path that has not been brought inside one yet — this is `now`,
    which is exactly what every call site did before the run existed.
    """
    run = _run.get()
    if run is None:
        return _utcnow()
    if run.trigger == TRIGGER_WEBHOOK:
        return device_time or _utcnow()
    if run.trigger == TRIGGER_SWEEP:
        return run.window_start
    return _utcnow()


def run_meta() -> dict[str, object]:
    """The run's contribution to an event's meta block.

    `trigger` and `comparison` are the contract's `runtype` and `run_type`, renamed.
    The originals differ by one underscore and mean unrelated things — what started this
    versus what kind of comparison it is — which sits badly against the contract's own
    "field names readable English, no abbreviations" rule. An analyst reading
    `runtype=manual run_type=delta` in a search has no way to tell them apart, and will
    eventually type the wrong one and get zero results with no error. Renamed while it
    is still free: customer SPL written against these names makes them permanent.

    `short_date` rides along because every consumer of this block wants the cheap
    daily-grain dedup key (`| dedup serial short_date`) and deriving it here costs
    nothing (docs/splunk-event-shaping.md).
    """
    run = _run.get()
    if run is None:
        return {}
    return {
        "jobId": str(run.id),
        "trigger": run.trigger,
        "comparison": run.comparison,
        "connectionId": run.connection_id,
        "collectionId": run.collection_id,
        "shortDate": run.window_start.strftime("%Y-%m-%d"),
    }


async def _reclaim_stale(db: AsyncSession) -> int:
    """Fail every run in this tenant whose process stopped heartbeating.

    Runs on each acquisition rather than at startup. Startup was the wrong moment twice
    over: it never fires in a process that stays up for a month, and the blanket version
    it replaces failed runs that a *different, healthy* instance was still performing
    during a rolling restart — while that instance carried on writing under a status
    saying it had died.
    """
    cutoff = _utcnow() - timedelta(seconds=settings.run_stale_after_seconds)
    result = await db.execute(
        update(Run)
        .where(Run.status == STATUS_RUNNING, Run.heartbeat_at < cutoff)
        .values(
            status=STATUS_FAILED,
            finished_at=_utcnow(),
            window_end=_utcnow(),
            error="reclaimed: no heartbeat within "
            f"{settings.run_stale_after_seconds}s — the process running it stopped",
        )
        .returning(Run.id)
    )
    reclaimed = list(result.scalars().all())
    if reclaimed:
        await db.commit()
        logger.warning(
            "reclaimed runs with no heartbeat",
            extra={"count": len(reclaimed), "run_ids": [str(run_id) for run_id in reclaimed]},
        )
    return len(reclaimed)


async def _comparison_for(db: AsyncSession, connection_id: int, lock_class: str) -> str:
    """Baseline until this connection and lock class have completed one run."""
    seen = await db.execute(
        select(Run.id)
        .where(
            Run.mdm_connection_id == connection_id,
            Run.lock_class == lock_class,
            Run.status == STATUS_SUCCEEDED,
        )
        .limit(1)
    )
    return COMPARISON_DELTA if seen.scalar_one_or_none() is not None else COMPARISON_BASELINE


async def active_run(db: AsyncSession, connection_id: int, lock_class: str) -> Run | None:
    result = await db.execute(
        select(Run).where(
            Run.mdm_connection_id == connection_id,
            Run.lock_class == lock_class,
            Run.status == STATUS_RUNNING,
        )
    )
    return result.scalars().first()


async def active_connection_ids(db: AsyncSession, lock_class: str) -> set[int]:
    """Connections currently holding a run of this class, for the tick's due check.

    The tick uses this to leave a collection unclaimed rather than claim it and lose the
    acquisition a moment later — claiming advances `next_due_at`, so a lost race would
    push the next sweep a full day out instead of retrying next minute.
    """
    result = await db.execute(
        select(Run.mdm_connection_id).where(Run.lock_class == lock_class, Run.status == STATUS_RUNNING)
    )
    return set(result.scalars().all())


@dataclass(frozen=True, slots=True)
class Acquisition:
    """Either a run this caller started, or the one already holding the lock.

    Both cases are useful to a caller, which is why this is not `Run | None`. Run-now
    returns 202 with a jobID either way: someone clicking it during a cron sweep wants
    to know the fleet is syncing, and pointing them at the running sweep's log answers
    that better than a 409 does (§4.2).
    """

    run: Run
    started: bool


async def acquire(
    db: AsyncSession,
    connection: MdmConnection,
    *,
    trigger: str,
    lock_class: str = LOCK_DEVICE_SWEEP,
    collection_id: int | None = None,
    due_at: datetime | None = None,
    actor_label: str | None = None,
) -> Acquisition:
    """Take the run lock for this connection and class, or report who holds it.

    `due_at` is the scheduled occurrence this run serves, and becomes the window the
    run's events are back-dated to. The tick passes the `next_due_at` it claimed — the
    time the run was *due* — so a sweep delayed by a busy tick still stamps its events
    at the hour the customer configured.
    """
    await _reclaim_stale(db)

    now = _utcnow()
    run = Run(
        id=uuid.uuid4(),
        mdm_connection_id=connection.id,
        collection_id=collection_id,
        trigger=trigger,
        comparison=await _comparison_for(db, connection.id, lock_class),
        lock_class=lock_class,
        status=STATUS_RUNNING,
        window_start=due_at or now,
        heartbeat_at=now,
        started_at=now,
        actor_label=actor_label,
    )

    try:
        # Nested so the integrity error rolls back the failed INSERT alone. Without the
        # savepoint the whole transaction is poisoned and the caller cannot go on to
        # read the row that beat it.
        async with db.begin_nested():
            db.add(run)
            await db.flush()
    except IntegrityError:
        holder = await active_run(db, connection.id, lock_class)
        if holder is None:
            # The holder finished between the conflict and this read. Nothing is running
            # now, so the caller is free to try again; one retry, not a loop.
            return await acquire(
                db,
                connection,
                trigger=trigger,
                lock_class=lock_class,
                collection_id=collection_id,
                due_at=due_at,
                actor_label=actor_label,
            )
        logger.info(
            "run already in flight for this connection",
            extra={
                "connection_id": connection.id,
                "lock_class": lock_class,
                "holder_job_id": str(holder.id),
                "holder_trigger": holder.trigger,
                "trigger": trigger,
            },
        )
        return Acquisition(run=holder, started=False)

    await db.commit()
    await log(db, run, "info", "run started", trigger=trigger, comparison=run.comparison, lockClass=lock_class)
    return Acquisition(run=run, started=True)


@contextlib.asynccontextmanager
async def entered(run: Run) -> AsyncIterator[RunContext]:
    """Make `run` the active run for everything called inside.

    Entered by whoever acquired it *and* by a caller reusing one acquired elsewhere —
    the background task behind run-now takes the run from the request that acquired it,
    and a fresh task has a fresh context to establish.
    """
    context = RunContext(
        id=run.id,
        connection_id=run.mdm_connection_id,
        collection_id=run.collection_id,
        trigger=run.trigger,
        comparison=run.comparison,
        lock_class=run.lock_class,
        window_start=run.window_start,
    )
    token = set_run(context)
    try:
        yield context
    finally:
        reset_run(token)


async def log(
    db: AsyncSession, run: Run, level: str, message: str, **fields: object
) -> None:
    """Append one engine line, and commit it.

    Committed on its own rather than riding the caller's transaction: the point of the
    log is that someone watching run-now sees progress *while* the run is in flight, and
    a line that only lands when the sweep commits forty minutes later is a line nobody
    reads. Cheap enough to be unconditional — this is called at milestones and every few
    hundred devices, never per device.
    """
    db.add(
        RunLogLine(
            run_id=run.id,
            ts=_utcnow(),
            level=level,
            message=message[:512],
            fields=fields or None,
        )
    )
    await db.commit()


async def beat(db: AsyncSession, run: Run) -> None:
    """Keep the run alive. Throttled — safe to call per device."""
    now = _utcnow()
    if run.heartbeat_at and (now - run.heartbeat_at).total_seconds() < _HEARTBEAT_INTERVAL_SECONDS:
        return
    await db.execute(update(Run).where(Run.id == run.id).values(heartbeat_at=now))
    run.heartbeat_at = now
    await db.commit()


async def finish(
    db: AsyncSession,
    run: Run,
    *,
    ok: bool,
    device_count: int = 0,
    group_count: int = 0,
    observations: dict | None = None,
    error: str | None = None,
) -> None:
    """Close the run, releasing the lock.

    A separate UPDATE rather than an ORM write on `run`, because the failure path
    reaches here with a rolled-back session whose identity map cannot be trusted — the
    one moment it matters most that the lock is actually released.
    """
    now = _utcnow()
    await db.execute(
        update(Run)
        .where(Run.id == run.id)
        .values(
            status=STATUS_SUCCEEDED if ok else STATUS_FAILED,
            finished_at=now,
            window_end=now,
            heartbeat_at=now,
            device_count=device_count,
            group_count=group_count,
            observations=observations or None,
            error=error,
        )
    )
    await db.commit()
    await log(
        db,
        run,
        "info" if ok else "error",
        "run finished" if ok else "run failed",
        deviceCount=device_count,
        groupCount=group_count,
        seconds=round((now - run.started_at).total_seconds(), 1),
        error=error,
    )


async def purge_runs(db: AsyncSession, retention_days: int) -> int:
    """Drop finished runs past retention. Log lines go with them by cascade.

    Follows `audit_retention_days` (30) rather than `event_outbox_retention_days` (7):
    the run log is what someone opens to answer "did this run last month", so a week is
    too short to serve its own purpose. It is also far smaller than the outbox, which
    carries a row per event per destination.
    """
    cutoff = _utcnow() - timedelta(days=retention_days)
    result = await db.execute(
        sa_delete(Run).where(Run.status != STATUS_RUNNING, Run.finished_at < cutoff)
    )
    await db.commit()
    return result.rowcount or 0
