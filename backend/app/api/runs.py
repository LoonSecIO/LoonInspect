"""The run log, queryable — #31's fourth clause.

Read-only. A run is started by triggering a sync or by the tick; nothing here creates or
cancels one. Scoped by tenant through RLS like every other table, and by jobID in the
path, which is the pair the contract asks for.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.runs import STATUS_RUNNING
from app.models.schema import Run, RunLogLine
from app.schemas.runs import RunLogLineOut, RunLogResponse, RunOut

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
