from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.models.schema import InstalledApp
from app.schemas.applications import ApplicationListResponse, ApplicationOut

router = APIRouter(
    prefix="/api/applications",
    tags=["applications"],
    dependencies=[Depends(require(Permission.APP_READ))],
)


RETIRED_PARAMETERS = {"limit": "page and pageSize", "offset": "page and pageSize", "search": "q"}


def _refuse_retired_parameters(request: Request) -> None:
    """This endpoint paged by `limit`/`offset` and searched by `search` while every other
    list paged by `page`/`pageSize` and searched by `q` (#137). The old names are refused
    rather than ignored: FastAPI drops unknown query parameters silently, so a client
    still sending `limit=50` would get page one of a hundred and never learn why."""
    retired = [name for name in RETIRED_PARAMETERS if name in request.query_params]
    if retired:
        raise HTTPException(
            status_code=422,
            detail=", ".join(f"`{name}` was retired; use {RETIRED_PARAMETERS[name]}" for name in retired),
        )


@router.get("", response_model=ApplicationListResponse, dependencies=[Depends(_refuse_retired_parameters)])
async def list_applications(
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(default=None, max_length=255),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500, alias="pageSize"),
) -> ApplicationListResponse:
    """Applications grouped by app_hash, ordered by how many devices have them.

    Paged by `page` and `pageSize` (at most 500) and searched by `q`, like every other
    list; the response echoes the page it served.

    One query. The per-version breakdown this used to fetch for the page (~4 s of the
    request's database time at the 40k target) existed only to fill an expansion the
    Applications table no longer has; the version spread lives on the application record
    page, read from the catalog by `appHash` (#299).
    """
    device_count = func.count(distinct(InstalledApp.device_id)).label("device_count")

    # name and bundle_id are inputs to app_hash, so every row in a group carries the
    # same pair — min() just picks it without needing them in the GROUP BY.
    grouped = (
        select(
            InstalledApp.app_hash,
            func.min(InstalledApp.name).label("name"),
            func.min(InstalledApp.bundle_id).label("bundle_id"),
            device_count,
            func.count(distinct(InstalledApp.version_hash)).label("version_count"),
        )
        .group_by(InstalledApp.app_hash)
        .order_by(device_count.desc(), func.min(InstalledApp.name))
    )

    if q:
        pattern = f"%{q}%"
        grouped = grouped.having(func.min(InstalledApp.name).ilike(pattern) | func.min(InstalledApp.bundle_id).ilike(pattern))

    total = await db.scalar(select(func.count()).select_from(grouped.subquery()))

    page_rows = (await db.execute(grouped.limit(page_size).offset((page - 1) * page_size))).all()

    return ApplicationListResponse(
        items=[
            ApplicationOut(
                app_hash=row.app_hash,
                name=row.name,
                bundle_id=row.bundle_id,
                device_count=row.device_count,
                version_count=row.version_count,
            )
            for row in page_rows
        ],
        total=total or 0,
        page=page,
        page_size=page_size,
    )
