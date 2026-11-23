from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.application_risk import application_rows, risk_output
from app.core.auth import Principal, current_principal, require
from app.core.database import get_snapshot_db
from app.core.device_scope import parse_scope
from app.core.permissions import Permission
from app.core.vuln_library import earned_corpus, loaded_epoch_signature
from app.core.vuln_read import NO_ANSWER, corpus_as_of
from app.schemas.applications import ApplicationListResponse, ApplicationOut, ApplicationScope, Severity

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
    db: AsyncSession = Depends(get_snapshot_db),
    principal: Principal = Depends(current_principal),
    device_scope: Annotated[str | None, Query(alias="deviceScope", max_length=12000)] = None,
    q: str | None = Query(default=None, max_length=255),
    severity: Annotated[list[Severity] | None, Query(max_length=4)] = None,
    has_kev: Annotated[bool, Query(alias="hasKev")] = False,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500, alias="pageSize"),
) -> ApplicationListResponse:
    """Applications and known vulnerability findings within the selected device population.

    Severity selections match any selected band; KEV and name narrow that result further.
    Totals count findings once per device/build, not unique CVEs across different builds.
    Unknown builds contribute no zeroes to the average over assessed devices. Filters and
    pagination share one repeatable-read aggregate, including when a page has no rows.
    """
    if device_scope is not None and Permission.DEVICE_READ not in principal.permissions:
        raise HTTPException(403, "Device read permission is required to filter applications by device.")
    scope = parse_scope(device_scope) if device_scope is not None else None
    app_scope = ApplicationScope(q=q or "", severities=severity or [], hasKev=has_kev)
    corpus = await earned_corpus(db)
    stamp = corpus_as_of(corpus)
    epoch = loaded_epoch_signature() if stamp is not None else None
    if (severity or has_kev) and epoch is None:
        raise HTTPException(409, NO_ANSWER)
    grouped = application_rows(scope, app_scope, epoch).cte("scoped_applications").prefix_with("MATERIALIZED")
    page_query = select(grouped).order_by(grouped.c.device_count.desc(), grouped.c.name, grouped.c.app_hash)
    page_rows = page_query.limit(page_size).offset((page - 1) * page_size).subquery()
    totals = select(func.count().label("application_total")).select_from(grouped).subquery()
    rows = (
        await db.execute(select(totals.c.application_total, page_rows).select_from(totals.outerjoin(page_rows, true())))
    ).all()
    return ApplicationListResponse(
        items=[
            ApplicationOut(
                app_hash=row.app_hash,
                name=row.name,
                bundle_id=row.bundle_id,
                device_count=row.device_count,
                version_count=row.version_count,
                matched_device_count=row.matched_device_count,
                patch_available_device_count=row.patch_available_device_count,
                vulnerabilities=risk_output(row, available=epoch is not None),
            )
            for row in rows
            if row.app_hash is not None
        ],
        total=rows[0].application_total,
        corpus_as_of=stamp.isoformat() if stamp else None,
        corpus_release=epoch,
        page=page,
        page_size=page_size,
    )
