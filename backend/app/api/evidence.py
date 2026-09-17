"""The evidence artefact, served (#472) — as the object, and as the printable document (#473).

Its contract is docs/compliance-evidence.md. A router of its own rather than more surface on `system.py`: this
artefact grows a page, a download and a history. `AUDIT_READ`, for the reason `/api/system/share-log` already gives —
the auditor role exists precisely for *prove to me what this thing does*, which is the whole of this question. The
download follows that endpoint's shape verbatim rather than inventing a second one: an explicit `media_type` and a
`Content-Disposition: attachment` naming the file.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.baseline.catalogue import CatalogueError
from app.baseline.intervals import ledger_heartbeat
from app.baseline.page import CATALOGUE_UNREADABLE, page_filename, render_evidence_page, with_read_this_first
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
EMPTY_WINDOW = (
    "The report window is empty: `start` must be earlier than `asOf`. Given neither, the report covers the ninety "
    "days before the ledger's last collection."
)


def _utc(value: datetime) -> datetime:
    """A bare instant is read as UTC — the clock the ledger keeps and the artefact prints. Comparing a naive
    timestamp with an aware one raises instead of answering."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def _assembled(db: AsyncSession, connection_id: int, start: datetime | None, as_of: datetime | None) -> dict[str, Any]:
    """The object both renderings of the same answer are built from, its `readThisFirst` sentences already inside it
    (#536) — computed once, from the ledger heartbeat this function holds and the object does not carry.

    `asOf` defaults to that heartbeat and `start` to a quarter before it. Neither is clamped to the data: a window
    reaching past what was observed is answered with not-observed days, by name and by device, because losing them is
    how a headline gets pretty (#219 R5 5.2). A catalogue that will not load refuses the whole report rather than
    answering from a partial one — a rule that failed to load looks exactly like a passing fleet (#473)."""
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
    try:
        report = await evidence_report(db, connection=connection, window_from=window_from, as_of=at)
    except CatalogueError as exc:
        raise HTTPException(status_code=503, detail=CATALOGUE_UNREADABLE.format(detail=str(exc))) from exc
    return with_read_this_first(report, heartbeat=heartbeat)


@router.get("/report", dependencies=[Depends(require(Permission.AUDIT_READ))])
async def evidence_report_route(
    connection_id: int = Query(alias="connectionID"),
    start: datetime | None = Query(default=None),
    as_of: datetime | None = Query(default=None, alias="asOf"),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """The artefact as the JSON object docs/compliance-evidence.md contracts — read by the in-app page at
    /posture/compliance (#536), which renders it and computes nothing it does not carry."""
    return await _assembled(db, connection_id, start, as_of)


@router.get(
    "/report.html",
    response_class=HTMLResponse,
    dependencies=[Depends(require(Permission.AUDIT_READ))],
)
async def download_evidence_page(
    connection_id: int = Query(alias="connectionID"),
    start: datetime | None = Query(default=None),
    as_of: datetime | None = Query(default=None, alias="asOf"),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """The same answer as one self-contained document, downloaded rather than displayed: the object above is inside
    it, so what gets filed and what gets parsed cannot drift apart. The filename carries the window and `asOf` so two
    reports do not collide in a downloads folder."""
    report = await _assembled(db, connection_id, start, as_of)
    return HTMLResponse(
        render_evidence_page(report),
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{page_filename(report)}"'},
    )
