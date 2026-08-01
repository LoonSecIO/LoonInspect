from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.schema import MdmSyncState
from app.schemas.payload import MdmSyncStatusOut

router = APIRouter(prefix="/api", tags=["mdm"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/mdm/status", response_model=list[MdmSyncStatusOut])
async def mdm_status(db: AsyncSession = Depends(get_db)) -> list[MdmSyncState]:
    result = await db.execute(select(MdmSyncState))
    return list(result.scalars().all())
