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
so the recovery path is exercised constantly rather than only at startup. And it is
fenced: every write a run makes to its own row is conditional on still being `running`,
so a process the reclaim declared dead but that was merely stalled cannot beat the row
back to life or overwrite the reclaim's verdict with `succeeded` (#94).

**The run is in a context variable, not a parameter.** `process_sync` is six frames
below the acquisition and needs the jobID and the window; the actor, tenant, and request
id already travel this way (app.core.context), and threading a seventh argument through
every ingest signature to reach one dict is how the three ingest paths drift apart.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete as sa_delete
from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.context import get_request_id
from app.core.outbox import enqueue_event
from app.core.uuid7 import uuid7
from app.core.wire import ENVELOPE, envelope, instance_label
from app.core.wire_vocabulary import RUN_COMPLETED_EVENT_TYPE, RUN_FAILED_EVENT_TYPE
from app.models.schema import Collection, MdmConnection, Run, RunLogLine

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

# Emitted through the outbox when a device-sweep or webhook run closes — success or
# failure — so absence is itself a signal downstream: the silent gap this product must
# never have. Device sweeps only until #224: a webhook run's inventory event stamped a
# `jobID` the same as a sweep's, but no run.completed ever closed over it, so the one
# join a SIEM most wants to make ("show me everything this run produced") silently
# dropped every webhook-sourced event, and #188's ruling that the aperture digest and
# shortDate basis ride run.completed, joined by jobID, was void for those runs. Widened
# to LOCK_WEBHOOK by #224 (see RUN_COMPLETED_LOCK_CLASSES); LOCK_CATALOG stays excluded
# because an hourly catalog refresh would satisfy the absence search the nightly sweep
# was supposed to answer, and a catalog pull has no device count worth reporting. One
# consequence of the widening: "is the fleet fully inventoried" is now
# `trigger=sweep OR trigger=manual`, not a bare `event=run.completed` — a busy tenant's
# webhooks emit this event too, and would silence a naive absence search on a night the
# actual sweep never closed. Payload is snake_case, matching the envelope convention and
# staying out of the way of the pending casing ruling (#90).
#
# The literal lives in `app.core.wire_vocabulary`, beside the `loon:run` sourcetype this
# family is delivered under (#242): the module that mints the string and the module that
# emits the event cannot drift apart, the way `app.changes.derive.EVENT_TYPE` is the
# vocabulary's `CHANGE_EVENT_TYPE`.
RUN_COMPLETED_EVENT = RUN_COMPLETED_EVENT_TYPE

# Lock classes whose closed run also gets a run.completed. LOCK_CATALOG is the one
# exclusion left standing after #224 — see RUN_COMPLETED_EVENT above.
RUN_COMPLETED_LOCK_CLASSES = frozenset({LOCK_DEVICE_SWEEP, LOCK_WEBHOOK})

# Emitted the moment any run reaches `failed` — every trigger and every lock class,
# wider than run.completed's scope (#103): run.completed excludes LOCK_CATALOG even
# after #224. run.completed is the heartbeat whose absence is the signal; this is the
# alarm, and a failed catalog run is exactly as silent as a failed sweep without it.
# Both fire for a failed device sweep or webhook, deliberately: one answers "did the
# run close", the other pages on why.
# Default-on for every destination — null/empty subscriptions already mean "all", and
# the a9d4c7e1f3b8 migration appends the type to every explicit list; the subs model
# stays in charge, so an org unsubscribes a destination the ordinary way. Payload is
# snake_case like run.completed's, one casing throughout (#90). The literal is the
# vocabulary's, as above.
RUN_FAILED_EVENT = RUN_FAILED_EVENT_TYPE

# The error summary a run.failed event carries: the stored run error, truncated at the
# same cap the delivery worker puts on an HTTP error — enough to say what happened,
# never a log dump. The full text stays on the run row.
_ERROR_SUMMARY_MAX = 500

# What a run's own log says when its closing event could not be enqueued. Named rather
# than written inline at the one place it is used, because it is what an operator who
# noticed a missing event greps for and what the run tests assert on — a message that can
# be reworded silently is not evidence anyone can rely on finding.
EVENT_LOST_MESSAGE = "closing event was not enqueued; the run is closed and its lock is free"


class RunReclaimed(Exception):
    """This process's run was reclaimed while it was still working.

    Raised when a conditional write to the run row matches nothing because the row is
    no longer `running`: the reclaim decided this process was dead, failed the run, and
    freed the lock — and a fresh acquisition may already be sweeping the same
    connection. The only correct response is to stop where the loop stands. Every
    further write made under this run is a second, unaccounted copy of work someone
    else now owns, and a final status written over the reclaim's would make the history
    lie about whether the connection double-ran.
    """

# How often the heartbeat is actually written. The device loop calls beat() constantly;
# this throttles it to one small UPDATE per interval rather than one per device.
_HEARTBEAT_INTERVAL_SECONDS = 15


@dataclass(frozen=True, slots=True)
class RunContext:
    """The active run, as the ingest path sees it.

    `collection_id` and `comparison` are carried here and deliberately do NOT reach the
    wire: #189 refused both from `deviceMeta` (see `run_meta` below). They stay on the
    context because they describe the run the ingest path is inside, not because anything
    is meant to stamp them onto a device event.
    """

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
    """The run's contribution to an event's meta block — four keys, and two refusals.

    `trigger` is the contract's `runtype`, renamed. The original sat one underscore away
    from `run_type` and meant something unrelated — what started this, versus what kind
    of comparison it is — which sits badly against the contract's own "field names
    readable English, no abbreviations" rule. An analyst reading
    `runtype=manual run_type=delta` in a search has no way to tell them apart, and will
    eventually type the wrong one and get zero results with no error. Renamed while it
    was still free: customer SPL written against these names makes them permanent.

    **`comparison` and `collectionID` are refused here** (#189, ruled 2026-08-31). Both
    shipped in this block before the ruling and both were cut by it, so they are removed
    rather than carried — a `deviceMeta` key is written once per app, per extension
    attribute, per certificate and per profile, and the fan-out (#242) multiplies that
    again. Each was cut on its own argument, not on volume alone:

    - `comparison` describes run *history*, not the row. `_comparison_for` below returns
      `delta` the moment any prior run on this connection has succeeded, so the value is
      identical on every device of every run after the first. It rides `run.completed`
      instead, joined by `jobID`.
    - `collectionID` is null on the entire webhook path — a webhook run is acquired with
      no collection — so a `BY` clause over it produces a null bucket that silently means
      "intraday". It belongs on the run's own event, joined by `jobID`; nothing emits it
      there yet, and it is a run-family key when something does, never a device one.

    Both remain on `RunContext` and on the `runs` row. What was refused is a place on the
    wire, per device, per sub-event.

    `shortDate` rides along because every consumer of this block wants a cheap daily
    grain and deriving it here costs nothing. Derived at ENQUEUE, not at delivery: the
    outbox's `_build_body` can reach neither this run nor the device.

    A note on the idiom this docstring used to teach. `| dedup serialNumber shortDate`
    is correct on a one-event-per-device sourcetype and WRONG on a fan-out one, where it
    collapses ~107 sub-events to a single arbitrary row. On a fan-out sourcetype the
    selector is `deviceMeta.eventID`, which names one device's one pull exactly (#189).
    Two sweeps in a day share a shortDate, so the daily grain cannot separate them.

    The keys are camelCase with `ID` uppercased on LoonInspect-minted names (#188).
    Renamed while renaming was still free: SPL field names are case-sensitive, so a
    customer search against the wrong spelling returns zero rows with no error — the
    same argument the `trigger` rename above is making.
    """
    run = _run.get()
    if run is None:
        return {}
    return {
        "jobID": str(run.id),
        "trigger": run.trigger,
        "connectionID": run.connection_id,
        "shortDate": run.window_start.strftime("%Y-%m-%d"),
    }


async def _connection_wire(db: AsyncSession, connection_id: int) -> tuple[str | None, str | None]:
    """A run event's connection name and its Splunk `source` — one small SELECT per
    closed run.

    `source` is knowable for a run and worth the read: a run belongs to exactly one Jamf
    Pro, and `source` is the key that lets one SPL search collect every family a single
    instance produced. Read here rather than carried on RunContext, because the reclaim
    path never had a RunContext in the first place — it revives rows another process
    left behind — and one lookup per closed run is not the per-device cost that would
    have argued the other way.

    There is deliberately no `host`. A run is not about a device: the closest candidates
    are the Jamf server (already `source`, and counting it as a Mac would break every
    `dc(host)`) and the container the worker happens to run in (infrastructure naming a
    customer's SPL cannot join to anything). `host` means "the Mac this is about"
    everywhere else on the wire, and the fix for it meaning two things is to leave it
    genuinely absent where there is no Mac, not to fill it. `envelope()` drops a None,
    so HEC applies the input's own default host — an obvious, overridable placeholder
    rather than a fact the product asserted.
    """
    row = (
        await db.execute(
            select(MdmConnection.name, MdmConnection.base_url).where(MdmConnection.id == connection_id)
        )
    ).first()
    if row is None:
        return None, None
    return row.name, (instance_label(row.base_url) if row.base_url else None)


async def _enqueue_run_failed(
    db: AsyncSession,
    *,
    run_id: uuid.UUID,
    connection_id: int,
    trigger: str,
    window_start: datetime,
    window_end: datetime,
    error: str | None,
) -> None:
    """The run.failed event (#103), added to the caller's open transaction.

    One builder for both producers — finish's failure path and the reclaim — so the
    wire shape cannot drift between them. Exactly the ruled fields: trigger, the
    connection by id and name, the run id, the window, and an error summary. Nothing
    else rides along — no credentials, no log lines; anyone who needs the full story
    has the run id and the run-log endpoint.

    Keys are camelCase with `ID` uppercased (#188), and the run id is `jobID` — the
    spelling `deviceMeta` already carries. Deliberately NOT `runID`: a second name for
    one value is what made the join docs/runs.md promises unwritable in SPL.
    """
    connection_name, source = await _connection_wire(db, connection_id)
    await enqueue_event(
        db,
        RUN_FAILED_EVENT,
        {
            # `event`, not `eventType`. The discriminator has to be one key across all
            # four families or no single SPL predicate selects LoonInspect events, and
            # the device families were already spelling it `event` on far more indexed
            # volume than the run families will ever carry.
            "event": RUN_FAILED_EVENT,
            "jobID": str(run_id),
            "connectionID": connection_id,
            "connectionName": connection_name,
            "trigger": trigger,
            "windowStart": window_start.isoformat(),
            "windowEnd": window_end.isoformat(),
            "error": (error or "")[:_ERROR_SUMMARY_MAX] or None,
            # `window_end` is the moment the run reached `failed` at both producers —
            # finish's failure path and the reclaim — so it is the occurrence, and no
            # new field had to be minted to carry it. NOT `event_time()`: that
            # back-dates a sweep to its window, which would file the closing event
            # before every device event it closes over.
            ENVELOPE: envelope(occurred_at=window_end, host=None, source=source),
        },
        request_id=get_request_id(),
    )


async def _enqueue_run_completed(
    db: AsyncSession,
    *,
    run_id: uuid.UUID,
    connection_id: int,
    trigger: str,
    comparison: str,
    closed_at: datetime,
    status: str,
    device_count: int,
    devices_processed: int,
    devices_failed: int,
) -> None:
    """The run.completed event (#92), added to the caller's open transaction.

    Lifted out of `finish` so both closing events are built by a named builder and handed
    to the same best-effort emitter below, rather than one being a builder and the other
    twenty-eight inline lines. Not a shape change: every key, every value and every
    comment below is the payload `finish` built before the lift (#212's casing included), and the tests assert
    the set of keys exactly.
    """
    # Both halves, not just `source` (#287). `run.failed` has carried `connectionName`
    # since it was written; this path read it from the same helper on every closed run and
    # dropped it on the floor, so the two run families disagreed about whether a run says
    # which connection it belongs to in words. No new query — one binding.
    connection_name, source = await _connection_wire(db, connection_id)
    await enqueue_event(
        db,
        RUN_COMPLETED_EVENT,
        {
            # camelCase with `ID` uppercased (#188), `event` as the one discriminator
            # across all four families, and the run id under the `jobID` that
            # `deviceMeta` already carries — see _enqueue_run_failed.
            "event": RUN_COMPLETED_EVENT,
            "jobID": str(run_id),
            "connectionID": connection_id,
            # Beside `connectionID`, the position it occupies on `run.failed`, so the two
            # families read alike (#287). Additive-only clause 1; clause 2 is satisfied by
            # construction — same name, same type, same meaning `run.failed` already gave
            # it, which is why this needed no new ruling on a name.
            "connectionName": connection_name,
            "trigger": trigger,
            "comparison": comparison,
            # The run's window end — the same instant the row's window_end was
            # just stamped with, so the event and the row tell one time.
            "occurredAt": closed_at.isoformat(),
            "devicesTotal": device_count,
            "devicesProcessed": devices_processed,
            "devicesFailed": devices_failed,
            "status": status,
            # The same instant the payload's occurred_at and the row's window_end were
            # stamped with, so the row, the body and Splunk's `_time` all tell one
            # time. NOT `event_time()`, which back-dates a sweep to its window: the run
            # closing is not part of the occurrence the run serves, and stamping it at
            # window_start would sort the sweep's closing event before every event it
            # closes over.
            ENVELOPE: envelope(occurred_at=closed_at, host=None, source=source),
        },
        request_id=get_request_id(),
    )


async def _emit_after_release(
    db: AsyncSession, run_id: uuid.UUID, event_type: str, emit: Callable[[], Awaitable[None]]
) -> None:
    """Enqueue one closing event in its own transaction, AFTER the release has committed.

    Both producers used to enqueue in the SAME transaction as the run-status UPDATE that
    frees the mutex, on the argument that "the run closed" and "the wire says it closed"
    should never drift apart. The argument was right about the pairing and wrong about
    the cost: a single failed INSERT into `event_outbox` aborts that transaction and
    takes the release with it, so the row stays `running` and the connection can never
    sync again. Worse, `acquire()` calls `_reclaim_stale()` first, so the identical
    INSERT then fails for every OTHER connection's acquisition too. One full disk stopped
    all syncing everywhere; the asyncpg bind-parameter ceiling was a second trigger, and
    any INSERT failure has the same blast radius. It is also non-deterministic — a
    retried close whose row happens to fit in existing page space succeeds — so an
    operator cannot predict which of the two failures they get.

    Release-then-emit, not emit-then-release-in-two-transactions. The other order can
    double-emit: whether a close may emit at all is decided by whether the fenced UPDATE
    matched a still-`running` row (#94), which is knowable only after the UPDATE runs, so
    emitting first means emitting for a run the reclaim already closed — the double-count
    `finish`'s docstring rules out — and a retry after a release that failed post-emit
    files a second copy of one close. This order can only LOSE an event, and losing one
    is strictly cheaper than wedging every connection: `run.completed`'s ABSENCE is
    already the monitored signal ("no run.completed today means the sweep did not run to
    completion"), so the operator's absence search fires exactly as it would for a
    genuinely incomplete sweep, and the run row, the ERROR line this writes into the
    run's own log, and the logged exception together say which of the two it was. A
    duplicate would instead corrupt every `stats count` written against the heartbeat,
    silently and permanently.

    Modelled on the posture snapshot at the end of `finish`: commit the thing that must
    not be lost, then attempt the thing that may be.
    """

    async def lost() -> None:
        logger.exception(EVENT_LOST_MESSAGE, extra={"run_id": str(run_id), "event_type": event_type})
        # Into the run's own log as well. Without it the only trace is a container log
        # line an operator has to already suspect something to go looking for — and the
        # run they open, having noticed the missing event, would show a clean close.
        with contextlib.suppress(Exception):
            db.add(
                RunLogLine(
                    run_id=run_id,
                    ts=_utcnow(),
                    level="error",
                    message=EVENT_LOST_MESSAGE,
                    fields={"eventType": event_type},
                )
            )
            await db.commit()

    try:
        # Inside a savepoint, for the same reason `acquire`'s INSERT is: the failed
        # statement unwinds alone and the session is usable afterwards. A blanket
        # `rollback()` here would satisfy the database and wreck the caller — a full
        # rollback expires EVERY orm object in the session, and `acquire` reads
        # `connection.id` on the line after `_reclaim_stale()` returns. A best-effort
        # emit that breaks the acquisition running it has not fixed anything.
        async with db.begin_nested():
            await emit()
    except Exception:
        await lost()
        return
    try:
        await db.commit()
    except Exception:
        # The commit itself rather than the INSERT: there is no savepoint left to unwind
        # it, so this is the one place the blunt instrument is the right one.
        with contextlib.suppress(Exception):
            await db.rollback()
        await lost()


async def _reclaim_stale(db: AsyncSession) -> int:
    """Fail every run in this tenant whose process stopped heartbeating.

    Runs on each acquisition rather than at startup. Startup was the wrong moment twice
    over: it never fires in a process that stays up for a month, and the blanket version
    it replaces failed runs that a *different, healthy* instance was still performing
    during a rolling restart — while that instance carried on writing under a status
    saying it had died.

    The reclaim is a run reaching `failed`, so it is loud the same two ways finish's
    failure path is (#103): a final line into the run's own log — which otherwise just
    stops mid-sweep after the last progress line — and a run.failed event. This is the
    failure that most needs the wire: the process that would have reported it is the one
    that died.

    Both of those are recorded AFTER the verdicts commit, not with them (`_emit_after_
    release`). The reclaim's failure mode is the worse of the two the module had: it runs
    on EVERY acquisition, so an insert it cannot complete does not merely wedge the
    connection whose run went stale — it raises out of every acquire in the tenant,
    including connections with nothing stuck and nothing to reclaim. The lock-freeing
    UPDATE is the one statement here that must not be hostage to anything else.

    **The collection the run served is stamped too, and it rides WITH the verdict** —
    `_mark_collections_reclaimed`, below — but in a savepoint, so that riding with the
    verdict never means outranking it. It went in without one, and the paragraph above
    stopped being true the moment it did: a mark that raised propagated out of this
    function and out of `acquire` with the verdicts uncommitted, so the reclaim wedged
    the very mutex it exists to free, on every connection in the tenant. The savepoint
    keeps the pairing on the ordinary path — one commit, no window for the two rows to
    disagree — and drops only a mark that genuinely cannot be written.
    `collections.last_run_status` was written in four places, all of them inside the live
    frame that performs a run; when that frame's process dies there is nobody left to
    write it, so the run row read `failed` while the collection it served went on reading
    `ok` forever. Everything the product says about whether a collection is healthy —
    #106's Needs Attention panel first among them — reads the collection row, so the
    morning after a killed 3,000-Mac sweep the front page printed a dated all-clear over
    it. That is the same failure this docstring already names one paragraph up, one table
    across.
    """
    now = _utcnow()
    cutoff = now - timedelta(seconds=settings.run_stale_after_seconds)
    error = (
        "reclaimed: no heartbeat within "
        f"{settings.run_stale_after_seconds}s — the process running it stopped"
    )
    result = await db.execute(
        update(Run)
        .where(Run.status == STATUS_RUNNING, Run.heartbeat_at < cutoff)
        .values(
            status=STATUS_FAILED,
            finished_at=now,
            window_end=now,
            error=error,
        )
        .returning(
            Run.id,
            Run.mdm_connection_id,
            Run.collection_id,
            Run.trigger,
            Run.started_at,
            Run.window_start,
        )
    )
    reclaimed = result.all()
    if reclaimed:
        try:
            # In the same transaction as the verdicts, deliberately — see the function's
            # own docstring for why this one is not held to `_emit_after_release`'s rule
            # — but inside a savepoint, for the reason `acquire`'s INSERT is: a mark that
            # cannot be written unwinds alone, and the commit below still happens.
            async with db.begin_nested():
                await _mark_collections_reclaimed(db, reclaimed, error=error)
        except Exception:
            # The collection keeps whatever it last read, so this is #106's blind panel
            # again — for these collections only, and only when the UPDATE itself failed.
            # That is the disclosed cost of never letting this stop the line below.
            logger.exception(
                "reclaimed runs but could not stamp the collections they served",
                extra={
                    "run_ids": [str(row.id) for row in reclaimed],
                    "collection_ids": [row.collection_id for row in reclaimed if row.collection_id],
                },
            )
        # The verdicts, and the marks that could be written with them. Every lock this
        # reclaim freed is free from here on, whatever happens to the recording below —
        # and whatever happened to the marking above.
        await db.commit()
        # Only now: the marks deliberately do not reach into this session while a
        # savepoint can still roll that reach into an expiry, so the session is brought
        # into line here instead, where nothing can undo it. Best-effort, like everything
        # else below the commit.
        await _resync_marked_collections(db, [row.collection_id for row in reclaimed if row.collection_id])
        logger.warning(
            "reclaimed runs with no heartbeat",
            extra={"count": len(reclaimed), "run_ids": [str(row.id) for row in reclaimed]},
        )
        for row in reclaimed:
            await _record_reclaim(db, row, at=now, error=error)
    return len(reclaimed)


async def _mark_collections_reclaimed(db: AsyncSession, reclaimed, *, error: str) -> None:
    """Carry each reclaimed run's verdict onto the collection row it served.

    `collections.last_run_status` is a cache of the newest thing that happened to a
    collection, and every writer of it lives inside `run_collection` — inside the frame
    doing the work. A deploy, an OOM kill or a node eviction at 03:12 takes that frame
    with it, so the four in-process writers cover every outcome a run can *report* and
    none of the ways a run can stop reporting. This is the fifth writer, and the only one
    that survives the process.

    **Why it commits with the verdict rather than after it.** The rest of the recording
    here is best-effort by design (`_emit_after_release`): the lock must be freed even if
    the run log and the wire event cannot be written. This is not in that class. The
    collection's cached outcome and the run's verdict are one statement about one event —
    `run_collection` commits them together for exactly that reason, and its `closed is
    False` branch says it out loud: "this row's cached outcome must not disagree with the
    history it summarizes." Split across two transactions they can disagree, and if the
    second one fails they disagree *permanently*: the run is no longer `running`, so no
    later reclaim ever revisits it. The blast-radius argument does not carry over either.
    What `_emit_after_release` guards against is an INSERT that cannot be completed — a
    full disk, asyncpg's bind-parameter ceiling — poisoning the transaction of every
    acquisition in the tenant. These are UPDATEs of rows that already exist, keyed by
    primary key, one per stale run and so bounded by connections times lock classes.

    **And why the caller wraps it in a savepoint anyway.** All of that argues the pairing
    is worth having; none of it argues the pairing may outrank the lock, and bare in the
    verdicts' transaction it did. "Unlikely" is not "impossible": any raise in here — a
    statement timeout, a deadlock with the in-frame writer this exists to stand in for, a
    bug in the values above — aborted the transaction the lock-freeing UPDATE was sitting
    in, so every run the reclaim had just failed stayed `running` and every acquisition
    on the connection failed from then on. A blind panel is one morning read wrong; a
    wedged mutex is a fleet that never syncs again until someone edits the database by
    hand. The savepoint concedes nothing on the ordinary path — mark and verdict still
    commit together in one transaction, and there is no gap between two commits for a
    crash to land in, which is what moving this after the commit would have cost. It
    concedes only the failing case: the mark is dropped, the run reads `failed` beside a
    collection still reading `ok`, and #106's panel is blind about that collection. That
    is precisely the defect this function was written to fix, narrowed from *every killed
    sweep* to *an UPDATE that cannot be performed*, and logged by the caller when it
    happens instead of passing silently. Pinned by
    `test_a_mark_that_cannot_be_written_still_frees_the_lock`.

    **`synchronize_session=False`, because the savepoint's rollback is not free.** The
    paragraph above is only true of the *database*. `update(Collection)` is an ORM-enabled
    UPDATE, and left to synchronise it does a second thing: it matches the in-session
    `Collection` instances against the criteria, writes the new values onto them, and
    registers them as altered on the innermost transaction — the savepoint. Rolling that
    savepoint back runs `SessionTransaction._restore_snapshot(dirty_only=True)`, which
    EXPIRES every instance so registered, and under asyncio touching an expired attribute
    raises `MissingGreenlet` rather than lazily reloading. So a batch that marked one
    collection and then failed on the next handed the failure back to the caller anyway,
    by a different door: `acquire` returns normally and the lock genuinely is free, but
    `run_collection` — the scheduled tick, the unattended path — reads `collection.id` off
    the instance the tick handed it (`app.mdm.collections`, one line after the
    acquisition) and raises there, *after* `acquire` has committed a fresh `running` run.
    An orphaned `device_sweep` lock, held until the next `run_stale_after_seconds` reclaim
    comes round: the wedged mutex the savepoint was added to prevent, reached by way of
    the ORM session instead of the transaction. Two collection-bearing stale runs in one
    batch is all it takes, which is the ordinary shape of a pod dying while it holds
    `device_sweep` and `catalog`. Pinned by
    `test_a_failed_mark_does_not_orphan_the_lock_it_just_freed`, which holds the caller's
    `Collection` across the failure and reads it unrefreshed; the test above cannot see
    this, because it refreshes first.

    So the statement no longer touches the session — and the session is put back in step
    afterwards instead, by `_resync_marked_collections`, once the marks are committed and
    a rollback can no longer turn that into an expiry. Both halves are load-bearing, and
    the first without the second is a worse bug than the one it fixes: with the
    synchronisation simply off, the caller's instance keeps its pre-mark values, so when
    `run_collection` finishes a *successful* sweep and assigns `last_run_status = "ok"`
    over a stale in-memory `"ok"`, the ORM sees no change and leaves the column at the
    mark's `"failed"`. Same day, same connection: the panel would print a permanent alarm
    over a collection that had just succeeded — #106's blind panel again, pointing the
    other way, and self-healing no sooner than the next tick that loads the row fresh.
    That is `test_a_reclaimed_collection_that_then_succeeds_reads_ok`.

    **What the caller's `except Exception` still does not catch.** `BaseException` is not
    `Exception`: an `asyncio.CancelledError` delivered inside this function (shutdown,
    a cancelled task), or a backend that dies mid-mark, unwinds past `_reclaim_stale`'s
    handler and out of `acquire` with the verdicts uncommitted — the bare-in-the-
    transaction failure, on the one class of exception the savepoint's handler declines to
    swallow. Stated rather than caught: swallowing a cancellation to finish committing is
    its own defect, and neither case wedges anything permanently — the next healthy
    acquisition reclaims the same runs, since a run whose verdict never committed is still
    `running` and still without a heartbeat.

    **The freshness guard is what keeps it from lying in the other direction.**
    `collections.last_run_at` is the attempt's start, always later than the start of the
    run the attempt happens inside, so a row whose `last_run_at` is at or after the
    reclaimed run's `started_at` has already recorded its own outcome *for this run* and
    is better informed than the reclaim is. Two cases need that: run-now hands one run to
    every enabled sweep on a connection, and dying inside the fourth must not restamp the
    three that finished; and a process that died in the sliver between committing a
    collection's `ok` and calling `finish` did complete that collection's work.

    **`last_success_at` is not touched.** It is written only where a run actually
    succeeded, an earlier real success stays true, and the reclaim has no way to know
    what the value was before — the in-frame downgrade can *restore* it because it read
    it on the way in; this cannot, and clearing it would make a collection with years of
    history read as never-succeeded, which #106 turns into a louder, wronger row.

    **A run with no `collection_id` marks nothing.** Webhook runs have none by
    construction, which is what keeps this off the webhook collection. So does run-now,
    which acquires at the connection and then runs every sweep the connection has: there
    is no single collection to attribute its death to, and marking all of them would
    overwrite the ones that finished. That gap is real and left open on purpose — the
    scheduled tick, which is the unattended path and the one the panel exists for, always
    passes `collection_id` (`app.mdm.collections.run_collection`).
    """
    for row in reclaimed:
        if row.collection_id is None:
            continue
        await db.execute(
            update(Collection)
            # See the docstring: synchronising this UPDATE into the session is what let a
            # dropped mark expire the caller's `Collection` and orphan the lock.
            .execution_options(synchronize_session=False)
            .where(
                Collection.id == row.collection_id,
                or_(
                    Collection.last_run_at.is_(None),
                    Collection.last_run_at < row.started_at,
                ),
            )
            .values(
                last_run_at=row.started_at,
                # The same word `run_collection` writes on every other failure, so the
                # panel and the collections list need no second vocabulary.
                last_run_status="failed",
                last_run_summary={
                    "jobId": str(row.id),
                    "trigger": row.trigger,
                    "error": error,
                },
            )
        )


async def _resync_marked_collections(db: AsyncSession, collection_ids: list[int]) -> None:
    """Bring this session's own copies of the marked rows back into line with the table.

    The other half of `_mark_collections_reclaimed`'s `synchronize_session=False`. That
    flag stops the UPDATE reaching into the session *while a savepoint can still roll it
    back into an expiry*; this reads the rows back once the marks are committed and that
    window is shut. One SELECT keyed by primary key, bounded by connections times lock
    classes, and only on a reclaim that actually found something — which is to say only
    after a process died, not on the ordinary acquisition.

    `populate_existing` is the point of it. Without that the ORM returns the instance the
    session already has and leaves its loaded attributes alone, which is precisely the
    stale copy that must not survive: `run_collection` holds one across `acquire`, and an
    instance still reading `last_run_status == "ok"` makes its own later assignment of
    `"ok"` a no-op, leaving the row on the mark's `"failed"` for as long as that session
    lives. Overwriting rather than merging is safe here because nothing in this path has
    pending edits to a `Collection` — the reclaim runs at the top of `acquire`, before its
    caller has written anything, and the marks were just committed.

    Suppressed rather than raised, and after the commit rather than inside it, for the
    same reason everything else downstream of `db.commit()` in `_reclaim_stale` is: the
    verdicts are durable and the locks are free by the time this runs, and a read that
    cannot be performed must not become the reason an acquisition fails. What is lost when
    it is suppressed is one session's freshness, which the next tick reloads anyway.
    """
    if not collection_ids:
        return
    with contextlib.suppress(Exception):
        await db.execute(
            select(Collection)
            .where(Collection.id.in_(collection_ids))
            .execution_options(populate_existing=True)
        )


async def _record_reclaim(db: AsyncSession, row, *, at: datetime, error: str) -> None:
    """One reclaimed run's log line and run.failed event, once its verdict has committed.

    Per row rather than one attempt for the batch: a reclaim that finds three stale runs
    should not lose all three events because the first one's insert failed. The log line
    rides with the event because they are the same statement about the same run, and
    splitting them would let a run announce its failure on the wire while its own log
    still just stops mid-sweep.
    """

    async def emit() -> None:
        db.add(
            RunLogLine(
                run_id=row.id,
                ts=at,
                level="error",
                message="run failed",
                fields={"error": error},
            )
        )
        await _enqueue_run_failed(
            db,
            run_id=row.id,
            connection_id=row.mdm_connection_id,
            trigger=row.trigger,
            window_start=row.window_start,
            window_end=at,
            error=error,
        )

    await _emit_after_release(db, row.id, RUN_FAILED_EVENT, emit)


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

    The id is minted here, not left to the column's own default (`app.models.schema.
    Run.id`) — this is the one place a `Run` is ever constructed, and minting explicitly
    keeps that fact visible rather than implicit in a default two files away. `uuid7()`,
    not `uuid.uuid4()`, since #225: `jobID` — this same value — is a correlation key on
    the wire now, and a fan-out sourcetype's `eventstats max(jobID) by serialNumber`
    needs an id that sorts by creation time to mean anything.
    """
    await _reclaim_stale(db)

    now = _utcnow()
    run = Run(
        id=uuid7(),
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
    """Keep the run alive. Throttled — safe to call per device.

    Conditional on the row still being `running` (#94). The reclaim frees the lock by
    failing a quiet row; a heartbeat written unconditionally would let the process the
    reclaim declared dead keep its row looking warm while a second sweep runs beside
    it. Zero rows updated means the run is no longer this process's to keep alive, and
    the raise is what stops the ingest loop before it commits more work under a jobID
    whose verdict is already written.
    """
    now = _utcnow()
    if run.heartbeat_at and (now - run.heartbeat_at).total_seconds() < _HEARTBEAT_INTERVAL_SECONDS:
        return
    held = await db.execute(
        update(Run)
        .where(Run.id == run.id, Run.status == STATUS_RUNNING)
        .values(heartbeat_at=now)
        .returning(Run.id)
    )
    if held.scalar_one_or_none() is None:
        # Read before the rollback: rollback expires ORM state, and touching an
        # expired attribute under asyncio raises instead of lazily refreshing.
        run_id, lock_class = run.id, run.lock_class
        await db.rollback()
        logger.warning(
            "heartbeat refused: run was reclaimed; aborting this process's work",
            extra={"run_id": str(run_id), "lock_class": lock_class},
        )
        raise RunReclaimed(f"run {run_id} was reclaimed while this process was still working it")
    run.heartbeat_at = now
    await db.commit()


async def finish(
    db: AsyncSession,
    run: Run,
    *,
    ok: bool,
    device_count: int = 0,
    group_count: int = 0,
    devices_processed: int = 0,
    devices_failed: int = 0,
    observations: dict | None = None,
    error: str | None = None,
) -> bool:
    """Close the run, releasing the lock. True when this call is what closed it.

    A separate UPDATE rather than an ORM write on `run`, because the failure path
    reaches here with a rolled-back session whose identity map cannot be trusted — the
    one moment it matters most that the lock is actually released. The RETURNING clause
    carries the identity fields the events below need, for the same reason: read from
    the row the UPDATE just matched, never from ORM state a rollback may have expired.

    Conditional on `running`, for the same reason the heartbeat is (#94). A run the
    reclaim already failed is closed, and its row — status, error, the reclaim's
    timestamps — is the verdict an auditor reads. A late `succeeded` written over it is
    the double-run record this row exists to rule out; a late `failed` is no better,
    because it swaps the reclaim's accounting for the zombie's. Refusal is a return
    value rather than a raise: every caller is either already done or inside an
    exception handler, where raising would mask the error being handled. The refusal is
    logged here; the call site decides what, if anything, is left to unwind.

    A device-sweep or webhook run also emits `run.completed` (#92, widened to webhooks
    by #224) — RUN_COMPLETED_LOCK_CLASSES, not `ok`, decides that: a run that closes
    `failed` gets one too, with `status: "failed"` on it, same as a sweep. And any run
    that closes `failed` also emits `run.failed` (#103) — every trigger and every lock
    class, including LOCK_CATALOG, which run.completed still excludes; a failed catalog
    run is exactly as silent as a failed sweep. Neither fires for a refused finish — the
    reclaim's verdict stands, and the reclaim already emitted its own run.failed when it
    wrote that verdict, so a second event here would double-count one failure.

    Both are enqueued AFTER the release commits, not with it (`_emit_after_release`).
    They used to ride the same transaction as the status flip, which paired them
    perfectly and made the release hostage to an INSERT: one that failed rolled the
    release back with it, the row stayed `running`, and the reclaim on every subsequent
    acquire — for every connection — failed on the same INSERT. The pairing was worth
    less than the mutex.
    """
    now = _utcnow()
    status = STATUS_SUCCEEDED if ok else STATUS_FAILED
    closed = await db.execute(
        update(Run)
        .where(Run.id == run.id, Run.status == STATUS_RUNNING)
        .values(
            status=status,
            finished_at=now,
            window_end=now,
            heartbeat_at=now,
            device_count=device_count,
            group_count=group_count,
            devices_processed=devices_processed,
            devices_failed=devices_failed,
            observations=observations or None,
            error=error,
        )
        .returning(Run.id, Run.mdm_connection_id, Run.trigger, Run.comparison, Run.lock_class, Run.window_start)
    )
    row = closed.first()
    # The release, committed alone and first. Everything else this close records — the
    # two wire events, the log line, the posture snapshot — happens after this line and
    # cannot take the lock back down with it.
    await db.commit()
    if row is None:
        logger.warning(
            "finish refused: run is not running (reclaimed); its recorded verdict stands",
            extra={
                "run_id": str(run.id),
                "attempted_status": STATUS_SUCCEEDED if ok else STATUS_FAILED,
            },
        )
        # Into the run's own log as well: the evidence trail should show the late
        # finisher came back and was turned away, not just that the run went quiet.
        await log(
            db,
            run,
            "warning",
            "finish refused: this run was reclaimed; a late result was discarded",
            attemptedStatus=STATUS_SUCCEEDED if ok else STATUS_FAILED,
            deviceCount=device_count,
        )
        return False
    if row.lock_class in RUN_COMPLETED_LOCK_CLASSES:

        async def emit_completed() -> None:
            await _enqueue_run_completed(
                db,
                run_id=row.id,
                connection_id=row.mdm_connection_id,
                trigger=row.trigger,
                comparison=row.comparison,
                closed_at=now,
                status=status,
                device_count=device_count,
                devices_processed=devices_processed,
                devices_failed=devices_failed,
            )

        await _emit_after_release(db, row.id, RUN_COMPLETED_EVENT, emit_completed)
    if not ok:

        async def emit_failed() -> None:
            await _enqueue_run_failed(
                db,
                run_id=row.id,
                connection_id=row.mdm_connection_id,
                trigger=row.trigger,
                window_start=row.window_start,
                window_end=now,
                error=error,
            )

        # Its own attempt, not one transaction shared with run.completed above. A failed
        # device sweep or webhook run emits both, and the alarm is the one an operator
        # is paged by: losing it because the heartbeat beside it could not be written
        # would be the worst possible pairing to keep.
        await _emit_after_release(db, row.id, RUN_FAILED_EVENT, emit_failed)
    await log(
        db,
        run,
        "info" if ok else "error",
        "run finished" if ok else "run failed",
        deviceCount=device_count,
        groupCount=group_count,
        seconds=round((now - run.started_at).total_seconds(), 1),
        error=error,
        # Only when something failed: the common all-clear line stays as short as it
        # has always been, and a non-zero count is the anomaly worth a field.
        **({"devicesFailed": devices_failed} if devices_failed else {}),
    )
    if row.lock_class == LOCK_DEVICE_SWEEP:
        # Deliberately narrower than RUN_COMPLETED_LOCK_CLASSES above: a posture snapshot
        # is a fleet-wide capture, and a webhook run touched exactly one device, so #224
        # widening run.completed did not widen this.
        #
        # The posture snapshot (#102, docs/posture-snapshot.md): the last act of every
        # closed full sweep, success AND failure — a failed night's database state is
        # real, and the failed run id on the rows is what makes staleness visible. Only
        # after the terminal status is committed, so a capture reads the run it stamps;
        # never for a refused finish, whose reclaim already recorded (or will record)
        # its own close. A capture failure is logged and swallowed — a night can lose
        # its snapshot, it must never lose its sweep.
        from app.core.posture import record_full_sweep_snapshot  # local: posture reads this module's vocabulary

        try:
            written = await record_full_sweep_snapshot(db, run_id=row.id)
            await log(db, run, "info", "posture snapshot captured", keys=written)
        except Exception:
            with contextlib.suppress(Exception):
                await db.rollback()
            logger.exception(
                "posture snapshot failed; the run's verdict stands", extra={"run_id": str(row.id)}
            )
    return True


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
