from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.feature_flags import FEATURE_FLAG_REGISTRY
from app.models.schema import FeatureFlag
from app.schemas.feature_flags import FeatureFlagOut, FeatureFlagUpdate

router = APIRouter(prefix="/api/feature-flags", tags=["feature-flags"])


@router.get("", response_model=list[FeatureFlagOut])
async def list_feature_flags(db: AsyncSession = Depends(get_db)) -> list[FeatureFlagOut]:
    result = await db.execute(select(FeatureFlag))
    enabled_by_key = {row.key: row.enabled for row in result.scalars().all()}

    return [
        FeatureFlagOut(key=key, label=meta["label"], description=meta["description"], enabled=enabled_by_key.get(key, False))
        for key, meta in FEATURE_FLAG_REGISTRY.items()
    ]


@router.patch("/{key}", response_model=FeatureFlagOut)
async def update_feature_flag(
    key: str, payload: FeatureFlagUpdate, db: AsyncSession = Depends(get_db)
) -> FeatureFlagOut:
    meta = FEATURE_FLAG_REGISTRY.get(key)
    if meta is None:
        raise HTTPException(status_code=404, detail="Unknown feature flag")

    flag = await db.get(FeatureFlag, key)
    if flag is None:
        flag = FeatureFlag(key=key, enabled=payload.enabled)
        db.add(flag)
    else:
        flag.enabled = payload.enabled

    await db.commit()
    return FeatureFlagOut(key=key, label=meta["label"], description=meta["description"], enabled=flag.enabled)
