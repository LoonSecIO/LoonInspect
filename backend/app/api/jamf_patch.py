from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.index import rebuild_index
from app.catalog.service import refresh_tenant
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.mdm.patch.jamf_catalog import sync_catalog
from app.mdm.patch.matching import STATE_BEHIND
from app.models.schema import AppCatalogEntry, AppCatalogTitleMatch, InstalledApp, JamfPatchTitle
from app.schemas.jamf_patch import (
    JamfPatchSyncResult,
    JamfPatchTitleDetailOut,
    JamfPatchTitleListResponse,
    JamfPatchTitleOut,
)

router = APIRouter(prefix="/api/jamf-patch", tags=["jamf-patch"])


def _matched_devices():
    """Title matches → the catalog row → every installed app with that version hash. All three
    tables are tenant-scoped (RLS), so a tenant-bound session only ever counts its own fleet."""
    return (
        select(
            AppCatalogTitleMatch.title_id,
            AppCatalogTitleMatch.on_latest,
            AppCatalogTitleMatch.state,
            AppCatalogTitleMatch.installed_version,
            InstalledApp.device_id,
        )
        .join(AppCatalogEntry, AppCatalogEntry.id == AppCatalogTitleMatch.app_catalog_id)
        .join(InstalledApp, InstalledApp.version_hash == AppCatalogEntry.version_hash)
    )


async def title_device_counts(db: AsyncSession, title_ids: list[str]) -> dict[str, tuple[int, int, int]]:
    """title id -> (distinct devices with a matched app, on the title's latest, genuinely behind).

    The third number is not derivable from the first two, which is the whole reason it is here
    (#314): `device_count - devices_on_latest` counts a device running a build NEWER than the
    title lists as behind, and that is the steady state for anything that auto-updates. One more
    conditional aggregate over a subquery already being scanned — no extra join, no extra pass.
    """
    if not title_ids:
        return {}
    matched = _matched_devices().where(AppCatalogTitleMatch.title_id.in_(title_ids)).subquery()
    on_latest_device = case((matched.c.on_latest.is_(True), matched.c.device_id))
    behind_device = case((matched.c.state == STATE_BEHIND, matched.c.device_id))
    stmt = select(
        matched.c.title_id,
        func.count(distinct(matched.c.device_id)),
        func.count(distinct(on_latest_device)),
        func.count(distinct(behind_device)),
    )
    rows = (await db.execute(stmt.group_by(matched.c.title_id))).all()
    return {title_id: (int(devices), int(on_latest), int(behind)) for title_id, devices, on_latest, behind in rows}


async def title_version_counts(db: AsyncSession, title_id: str) -> dict[str, int]:
    """installed version -> distinct devices, for the apps matched to one title."""
    matched = _matched_devices().where(AppCatalogTitleMatch.title_id == title_id).subquery()
    rows = (
        await db.execute(
            select(matched.c.installed_version, func.count(distinct(matched.c.device_id))).group_by(matched.c.installed_version)
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
    # The catalog moved: rebuild the lookup index and re-judge this tenant's rows against it.
    await rebuild_index(db)
    await refresh_tenant(db)
    await db.commit()
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
        out.device_count, out.devices_on_latest, out.devices_behind = counts.get(title.id, (0, 0, 0))
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
    out.device_count, out.devices_on_latest, out.devices_behind = (
        await title_device_counts(db, [title.id])
    ).get(title.id, (0, 0, 0))
    out.version_device_counts = await title_version_counts(db, title.id)
    return out
