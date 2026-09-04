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
    dependencies=[Depends(require(Permission.DEVICE_READ))],
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

    Behind `device:read` rather than a permission of its own: every role including Viewer
    holds it, and the persona this latch is for — the one who wants to know a Mac grew an
    app nobody deployed — is exactly the persona given read-only access.

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
