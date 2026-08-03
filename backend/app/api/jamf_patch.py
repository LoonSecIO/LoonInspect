from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.mdm.patch.jamf_catalog import sync_catalog
from app.models.schema import JamfPatchTitle
from app.schemas.jamf_patch import (
    JamfPatchSyncResult,
    JamfPatchTitleDetailOut,
    JamfPatchTitleListResponse,
    JamfPatchTitleOut,
)

router = APIRouter(prefix="/api/jamf-patch", tags=["jamf-patch"])


@router.post("/sync", response_model=JamfPatchSyncResult)
async def sync_titles(db: AsyncSession = Depends(get_db)) -> JamfPatchSyncResult:
    synced = await sync_catalog(db)
    return JamfPatchSyncResult(synced=synced)


@router.get("/titles", response_model=JamfPatchTitleListResponse)
async def list_titles(
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
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

    return JamfPatchTitleListResponse(items=[JamfPatchTitleOut.model_validate(title) for title in titles], total=total)


@router.get("/titles/{title_id}", response_model=JamfPatchTitleDetailOut)
async def get_title(title_id: str, db: AsyncSession = Depends(get_db)) -> JamfPatchTitleDetailOut:
    title = await db.get(JamfPatchTitle, title_id)
    if title is None:
        raise HTTPException(status_code=404, detail="Patch title not found")
    return JamfPatchTitleDetailOut.model_validate(title)
