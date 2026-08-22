from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.mdm.patch.jamf_catalog import sync_catalog
from app.models.schema import InstalledApp, InstalledAppPatchMatch, JamfPatchTitle
from app.schemas.jamf_patch import (
    JamfPatchSyncResult,
    JamfPatchTitleDetailOut,
    JamfPatchTitleListResponse,
    JamfPatchTitleOut,
)

router = APIRouter(prefix="/api/jamf-patch", tags=["jamf-patch"])


async def title_device_counts(db: AsyncSession, title_ids: list[str]) -> dict[str, tuple[int, int]]:
    """title id -> (distinct devices with a matched app, distinct devices on the title's latest).
    The matches table is under RLS, so a tenant-bound session only ever counts its own fleet."""
    if not title_ids:
        return {}
    on_latest_device = case((InstalledAppPatchMatch.on_latest.is_(True), InstalledApp.device_id))
    rows = (
        await db.execute(
            select(
                InstalledAppPatchMatch.title_id,
                func.count(distinct(InstalledApp.device_id)),
                func.count(distinct(on_latest_device)),
            )
            .join(InstalledApp, InstalledApp.id == InstalledAppPatchMatch.installed_app_id)
            .where(InstalledAppPatchMatch.title_id.in_(title_ids))
            .group_by(InstalledAppPatchMatch.title_id)
        )
    ).all()
    return {title_id: (int(devices), int(on_latest)) for title_id, devices, on_latest in rows}


async def title_version_counts(db: AsyncSession, title_id: str) -> dict[str, int]:
    """installed version -> distinct devices, for the apps matched to one title."""
    rows = (
        await db.execute(
            select(InstalledAppPatchMatch.installed_version, func.count(distinct(InstalledApp.device_id)))
            .join(InstalledApp, InstalledApp.id == InstalledAppPatchMatch.installed_app_id)
            .where(InstalledAppPatchMatch.title_id == title_id)
            .group_by(InstalledAppPatchMatch.installed_version)
        )
    ).all()
    return {version or "": int(count) for version, count in rows}


@router.post(
    "/sync",
    response_model=JamfPatchSyncResult,
    dependencies=[Depends(require(Permission.PATCH_CATALOG_SYNC))],
)
async def sync_titles(db: AsyncSession = Depends(get_db)) -> JamfPatchSyncResult:
    synced = await sync_catalog(db)
    return JamfPatchSyncResult(synced=synced)


@router.get(
    "/titles",
    response_model=JamfPatchTitleListResponse,
    dependencies=[Depends(require(Permission.APP_READ))],
)
async def list_titles(
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=5000, alias="pageSize"),
) -> JamfPatchTitleListResponse:
    stmt = select(JamfPatchTitle)
    if q:
        like = f"%{q}%"
        stmt = stmt.where((JamfPatchTitle.name.ilike(like)) | (JamfPatchTitle.bundle_id.ilike(like)))

    count_result = await db.execute(select(func.count()).select_from(stmt.subquery()))
    total = count_result.scalar_one()

    stmt = stmt.order_by(JamfPatchTitle.name).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    titles = result.scalars().all()
    counts = await title_device_counts(db, [title.id for title in titles])

    items = []
    for title in titles:
        out = JamfPatchTitleOut.model_validate(title)
        out.device_count, out.devices_on_latest = counts.get(title.id, (0, 0))
        items.append(out)
    return JamfPatchTitleListResponse(items=items, total=total)


@router.get(
    "/titles/{title_id}",
    response_model=JamfPatchTitleDetailOut,
    dependencies=[Depends(require(Permission.APP_READ))],
)
async def get_title(title_id: str, db: AsyncSession = Depends(get_db)) -> JamfPatchTitleDetailOut:
    title = await db.get(JamfPatchTitle, title_id)
    if title is None:
        raise HTTPException(status_code=404, detail="Patch title not found")
    out = JamfPatchTitleDetailOut.model_validate(title)
    out.device_count, out.devices_on_latest = (await title_device_counts(db, [title.id])).get(title.id, (0, 0))
    out.version_device_counts = await title_version_counts(db, title.id)
    return out
