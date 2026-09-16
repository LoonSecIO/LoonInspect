"""The evidence artefact, served (#472). Its contract is docs/compliance-evidence.md.

A router of its own rather than more surface on `system.py`: this artefact grows a page, a download and a history.
`AUDIT_READ`, for the reason `/api/system/share-log` already gives — the auditor role exists precisely for *prove to
me what this thing does*, which is the whole of this question.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.baseline.intervals import ledger_heartbeat
from app.baseline.report import evidence_report
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.models.schema import MdmConnection

router = APIRouter(prefix="/api/evidence", tags=["evidence"])

_WINDOW_DAYS = 90
NO_LEDGER = (
    "This connection has no observations, so there is nothing to report on. The report reads the observation ledger, "
    "which a device sweep writes: run one from Connections, then ask again."
)
EMPTY_WINDOW = "The report window is empty: `start` must be earlier than `asOf`."


def _utc(value: datetime) -> datetime:
    """A bare instant is read as UTC — the clock the ledger keeps and the artefact prints. Comparing a naive
    timestamp with an aware one raises instead of answering."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


@router.get("/report", dependencies=[Depends(require(Permission.AUDIT_READ))])
async def evidence_report_route(
    connection_id: int = Query(alias="connectionID"),
    start: datetime | None = Query(default=None),
    as_of: datetime | None = Query(default=None, alias="asOf"),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """`asOf` defaults to the ledger's own heartbeat and `start` to a quarter before it. Neither is clamped to the
    data: a window reaching past what was observed is answered with not-observed days, by name and by device,
    because losing them is how a headline gets pretty (#219 R5 5.2)."""
    connection = (await db.execute(select(MdmConnection).where(MdmConnection.id == connection_id))).scalars().first()
    if connection is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    heartbeat = await ledger_heartbeat(db, connection_id=connection_id)
    if heartbeat is None:
        raise HTTPException(status_code=409, detail=NO_LEDGER)
    at = _utc(as_of) if as_of else heartbeat
    window_from = _utc(start) if start else at - timedelta(days=_WINDOW_DAYS)
    if window_from >= at:
        raise HTTPException(status_code=422, detail=EMPTY_WINDOW)
    return await evidence_report(db, connection=connection, window_from=window_from, as_of=at)
