from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.models.schema import InstalledApp
from app.schemas.applications import (
    ApplicationListResponse,
    ApplicationOut,
    ApplicationVersionOut,
)

router = APIRouter(
    prefix="/api/applications",
    tags=["applications"],
    dependencies=[Depends(require(Permission.APP_READ))],
)


@router.get("", response_model=ApplicationListResponse)
async def list_applications(
    db: AsyncSession = Depends(get_db),
    search: str | None = Query(default=None, max_length=255),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ApplicationListResponse:
    """Applications grouped by app_hash, ordered by how many devices have them.

    Two queries rather than one per row: the first ranks applications, the second
    fetches version breakdowns for only the page being returned.
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

    if search:
        pattern = f"%{search}%"
        grouped = grouped.having(
            func.min(InstalledApp.name).ilike(pattern)
            | func.min(InstalledApp.bundle_id).ilike(pattern)
        )

    total = await db.scalar(select(func.count()).select_from(grouped.subquery()))

    page = (await db.execute(grouped.limit(limit).offset(offset))).all()
    app_hashes = [row.app_hash for row in page]

    versions_by_app: dict[str, list[ApplicationVersionOut]] = {}
    if app_hashes:
        version_device_count = func.count(distinct(InstalledApp.device_id)).label("device_count")
        version_rows = (
            await db.execute(
                select(
                    InstalledApp.app_hash,
                    InstalledApp.version_hash,
                    func.min(InstalledApp.version).label("version"),
                    func.min(InstalledApp.short_version).label("short_version"),
                    version_device_count,
                    # Any device reporting a patch for this build makes the build
                    # patchable; max() over a boolean column is the aggregate form of
                    # "any". Null stays null when nothing has been checked yet.
                    func.max(InstalledApp.patch_available).label("patch_available"),
                    func.min(InstalledApp.is_compliant).label("is_compliant"),
                )
                .where(InstalledApp.app_hash.in_(app_hashes))
                .group_by(InstalledApp.app_hash, InstalledApp.version_hash)
                .order_by(version_device_count.desc())
            )
        ).all()

        for row in version_rows:
            versions_by_app.setdefault(row.app_hash, []).append(
                ApplicationVersionOut(
                    version_hash=row.version_hash,
                    version=row.version,
                    short_version=row.short_version,
                    device_count=row.device_count,
                    patch_available=None if row.patch_available is None else bool(row.patch_available),
                    is_compliant=None if row.is_compliant is None else bool(row.is_compliant),
                )
            )

    return ApplicationListResponse(
        items=[
            ApplicationOut(
                app_hash=row.app_hash,
                name=row.name,
                bundle_id=row.bundle_id,
                device_count=row.device_count,
                version_count=row.version_count,
                versions=versions_by_app.get(row.app_hash, []),
            )
            for row in page
        ],
        total=total or 0,
    )
