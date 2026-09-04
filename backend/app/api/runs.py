"""The run log, queryable — #31's fourth clause.

Read-only. A run is started by triggering a sync or by the tick; nothing here creates or
cancels one. Scoped by tenant through RLS like every other table, and by jobID in the
path, which is the pair the contract asks for.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.runs import (
    LOCK_DEVICE_SWEEP,
    LOCK_WEBHOOK,
    STATUS_RUNNING,
    STATUS_SUCCEEDED,
    TRIGGER_WEBHOOK,
)
from app.models.schema import MdmConnection, Run, RunLogLine
from app.schemas.runs import RunLogLineOut, RunLogResponse, RunOut, RunSummaryOut

router = APIRouter(prefix="/api/runs", tags=["runs"])

# One page of engine lines. A run that somehow produced more is read across several
# polls by advancing `after` — the panel already does that for the live case.
_MAX_LINES = 500


def _to_out(run: Run) -> RunOut:
    return RunOut(
        id=run.id,
        mdm_connection_id=run.mdm_connection_id,
        collection_id=run.collection_id,
        trigger=run.trigger,
        comparison=run.comparison,
        lock_class=run.lock_class,
        status=run.status,
        window_start=run.window_start,
        window_end=run.window_end,
        started_at=run.started_at,
        finished_at=run.finished_at,
        heartbeat_at=run.heartbeat_at,
        device_count=run.device_count,
        group_count=run.group_count,
        devices_processed=run.devices_processed,
        devices_failed=run.devices_failed,
        observations=run.observations,
        error=run.error,
        actor_label=run.actor_label,
    )


async def _get_or_404(job_id: uuid.UUID, db: AsyncSession) -> Run:
    run = await db.get(Run, job_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@router.get("", response_model=list[RunOut], dependencies=[Depends(require(Permission.CONNECTION_READ))])
async def list_runs(
    connection_id: int | None = Query(default=None, alias="connectionId"),
    status: str | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> list[RunOut]:
    query = select(Run).order_by(Run.started_at.desc()).limit(limit)
    if connection_id is not None:
        query = query.where(Run.mdm_connection_id == connection_id)
    if status is not None:
        query = query.where(Run.status == status)
    result = await db.execute(query)
    return [_to_out(row) for row in result.scalars().all()]


# DECLARED ABOVE `/{job_id}` ON PURPOSE, AND THE ORDER IS LOAD-BEARING. FastAPI matches
# in declaration order, and `job_id` is typed `uuid.UUID` — so a `/summary` declared
# *after* it does not fall through to this route, it 422s on UUID parsing and reads like
# a client bug rather than the routing mistake it is. `tests/test_runs.py` pins the
# order rather than trusting the next person to notice.
@router.get(
    "/summary",
    response_model=list[RunSummaryOut],
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def run_summary(
    connection_id: int | None = Query(default=None, alias="connectionId"),
    db: AsyncSession = Depends(get_db),
) -> list[RunSummaryOut]:
    """What the status strip's run segment says, per connection (#105).

    Three bounded questions the strip cannot answer from a page of `/api/runs` — see
    `RunSummaryOut` for why the page runs out — asked once per connection:

    **Which run does the stamp name?** The last *completed full sweep*: lock class
    `device_sweep`, trigger not `webhook`, status `succeeded`. That predicate is the
    server-side twin of `heroRun.ts:takesTheHero` and must stay identical to it — the
    hero and the stamp are two renderings of the same idea of "the fleet arrived", and
    a pod where the front page's hero and its status line disagree about which run that
    was has no evidence story at all. A `limit=1` over all runs would routinely name a
    two-device webhook sweep, which is the whole reason the compound form exists.

    **How much has landed since?** Succeeded `webhook`-class runs that *started* after
    the pinned run *finished*. Only succeeded ones count, deliberately: this clause
    exists to warn that the device numbers beside the stamp may be newer than the run
    the stamp names, and only a webhook that succeeded wrote anything. A failed webhook
    run changed no data, so it is not a correction to the stamp — it is a Needs
    Attention row (#106). Zero when nothing is pinned; never a raw count of every
    webhook run, which would print "+4,812 webhook sweeps since" beside no stamp at all.

    **What ran most recently?** Newest run of any lock class. Returned so #106's
    failed-run check reads a value the Overview already has rather than adding a second
    run request to the same fifteen-second refresh.

    Connections come from `mdm_connections`, not from the distinct connection ids
    present in `runs`: a connection added an hour ago and never swept is exactly the
    case the strip has a sentence for, and deriving the list from run rows would drop
    it silently.
    """
    connection_query = select(MdmConnection.id).order_by(MdmConnection.id)
    if connection_id is not None:
        connection_query = connection_query.where(MdmConnection.id == connection_id)
    connection_ids = list((await db.execute(connection_query)).scalars().all())

    summaries: list[RunSummaryOut] = []
    for cid in connection_ids:
        pinned = (
            await db.execute(
                select(Run)
                .where(
                    Run.mdm_connection_id == cid,
                    Run.lock_class == LOCK_DEVICE_SWEEP,
                    Run.trigger != TRIGGER_WEBHOOK,
                    Run.status == STATUS_SUCCEEDED,
                )
                .order_by(Run.started_at.desc())
                .limit(1)
            )
        ).scalars().first()

        since = 0
        if pinned is not None:
            # `finished_at` is always set on a succeeded run; falling back to
            # `started_at` rather than skipping the count keeps a hand-edited or
            # half-migrated row from turning the clause off entirely, which would be a
            # silent under-report where an over-report is merely noisy.
            anchor = pinned.finished_at or pinned.started_at
            since = (
                await db.execute(
                    select(func.count())
                    .select_from(Run)
                    .where(
                        Run.mdm_connection_id == cid,
                        Run.lock_class == LOCK_WEBHOOK,
                        Run.status == STATUS_SUCCEEDED,
                        Run.started_at > anchor,
                    )
                )
            ).scalar_one()

        latest = (
            await db.execute(
                select(Run).where(Run.mdm_connection_id == cid).order_by(Run.started_at.desc()).limit(1)
            )
        ).scalars().first()

        summaries.append(
            RunSummaryOut(
                mdm_connection_id=cid,
                last_full_sweep=_to_out(pinned) if pinned is not None else None,
                webhook_sweeps_since=since,
                latest_run=_to_out(latest) if latest is not None else None,
            )
        )
    return summaries


@router.get("/{job_id}", response_model=RunOut, dependencies=[Depends(require(Permission.CONNECTION_READ))])
async def get_run(job_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> RunOut:
    return _to_out(await _get_or_404(job_id, db))


@router.get(
    "/{job_id}/log",
    response_model=RunLogResponse,
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def get_run_log(
    job_id: uuid.UUID,
    after: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> RunLogResponse:
    """The engine lines for one run, newest-last, incrementally.

    `after` is the last line id the caller already has, so a panel polling every couple
    of seconds transfers only what appeared since — the alternative re-sends the whole
    log on every tick for the length of a forty-minute sweep.

    The run is returned alongside the lines deliberately: the poller needs the terminal
    state to know when to stop, and asking two endpoints for that would let the two
    answers disagree at exactly the moment the run ends.
    """
    run = await _get_or_404(job_id, db)
    result = await db.execute(
        select(RunLogLine)
        .where(RunLogLine.run_id == job_id, RunLogLine.id > after)
        .order_by(RunLogLine.id)
        .limit(_MAX_LINES)
    )
    lines = [
        RunLogLineOut(id=row.id, ts=row.ts, level=row.level, message=row.message, fields=row.fields)
        for row in result.scalars().all()
    ]
    return RunLogResponse(run=_to_out(run), lines=lines, complete=run.status != STATUS_RUNNING)
