from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.alerts.service import KINDS
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.models.schema import Alert, Device, MdmConnection
from app.schemas.alerts import AlertListResponse, AlertOut

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get(
    "",
    response_model=AlertListResponse,
    dependencies=[Depends(require(Permission.DEVICE_READ, Permission.APP_READ))],
)
async def list_alerts(
    open_only: bool = Query(default=True, alias="open"),
    kind: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
    db: AsyncSession = Depends(get_db),
) -> AlertListResponse:
    """The latches, oldest first. `open=true` (the default) is the work queue; `open=false`
    is the history of closed ones, which exists so an operator can see that a latch closed
    rather than having to infer it from an absence.

    **Behind `device:read` AND `app:read`** (Kyle, 2026-09-04), because the guard should
    name what the response actually hands over and this response hands over two identities
    at once: `device_id` / `device_label` are the fleet — a named Mac — and `app_hash` /
    `app_name` / `bundle_id` are the application. `require()` asserts every permission it
    is given, so this is the whole implementation.

    The spot check that flagged this suggested *moving* the route to `app:read`, and that
    was backwards: `catalog`, `applications` and `jamf_patch` carry `app:read` because
    their payloads are about an application and name no device. This one names a device, so
    moving it would have let a role holding app read but not device read pull
    `device_label` for every alerted Mac — a strictly weaker guard dressed as a correction.

    Nothing changes today and that is the argument for doing it now. Every role holds both
    — `_INVENTORY_READ` is `{device:read, app:read, vuln:read}` and `Role.viewer` is
    exactly that set, with analyst, auditor and admin as supersets — so no role loses
    access. It bites only the day someone splits them ("the application team sees the
    catalog but not the fleet"), and on that day it is the difference between a correct 403
    and a silent leak of fleet identities to an app-scoped caller. The change is free while
    every role holds both, and stops being free the moment one does not.

    The persona is unaffected: the read-only account is exactly the one told to watch for
    software nobody deployed, and Viewer still holds everything this route asks for.

    **Oldest first, deliberately against the house newest-first convention.** This is not
    a feed; it is a list of things that are still true. The row that has been true longest
    is the one that has gone unanswered longest, and it is the ordering Needs Attention
    ranks by within a level (`frontend/src/features/overview/needsAttention.ts`) — so the
    bounded page the panel fetches is the page whose rows it would actually show.

    Rows are scoped to devices on **active** connections, the same population rule
    `devices.*` and the posture keys count over: a connection an operator switched off is
    not a fleet they are being asked to look at.
    """
    if kind is not None and kind not in KINDS:
        # Named rather than silently empty. An unknown kind returning zero rows reads as
        # "nothing is wrong", which is the one thing this product refuses to let a shape
        # say by accident (#150).
        raise HTTPException(status_code=422, detail=f"kind must be one of {', '.join(KINDS)}")

    conditions = [MdmConnection.is_active.is_(True)]
    if open_only:
        conditions.append(Alert.closed_at.is_(None))
    else:
        conditions.append(Alert.closed_at.is_not(None))
    if kind:
        conditions.append(Alert.kind == kind)

    scoped = (
        select(Alert.id)
        .join(Device, Device.id == Alert.device_id)
        .join(MdmConnection, MdmConnection.id == Device.mdm_connection_id)
        .where(*conditions)
    )
    total = (await db.execute(select(func.count()).select_from(scoped.subquery()))).scalar_one()
    rows = (
        await db.execute(
            select(Alert, Device.hostname)
            .join(Device, Device.id == Alert.device_id)
            .join(MdmConnection, MdmConnection.id == Device.mdm_connection_id)
            .where(*conditions)
            .order_by(Alert.opened_at.asc(), Alert.id.asc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()

    return AlertListResponse(
        items=[
            AlertOut(
                id=row.id,
                kind=row.kind,
                level=row.level,
                device_id=row.device_id,
                device_label=hostname,
                app_hash=row.app_hash,
                app_name=row.app_name,
                bundle_id=row.bundle_id,
                opened_at=row.opened_at,
                closed_at=row.closed_at,
            )
            for row, hostname in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
    )
