from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.database import get_db
from app.core.feature_flags import FEATURE_FLAG_REGISTRY
from app.core.permissions import Permission
from app.models.schema import FeatureFlag
from app.schemas.feature_flags import FeatureFlagOut, FeatureFlagUpdate

router = APIRouter(prefix="/api/feature-flags", tags=["feature-flags"])


# Readable by any authenticated caller, with no permission of its own: the SPA reads
# flags to decide which tabs to render (see ApplicationsPage), so gating this would
# break navigation for every non-admin rather than protecting anything — flag names
# and states aren't sensitive. Writing them is another matter.
@router.get("", response_model=list[FeatureFlagOut])
async def list_feature_flags(db: AsyncSession = Depends(get_db)) -> list[FeatureFlagOut]:
    result = await db.execute(select(FeatureFlag))
    enabled_by_key = {row.key: row.enabled for row in result.scalars().all()}

    return [
        FeatureFlagOut(key=key, label=meta["label"], description=meta["description"], enabled=enabled_by_key.get(key, False))
        for key, meta in FEATURE_FLAG_REGISTRY.items()
    ]


@router.patch(
    "/{key}",
    response_model=FeatureFlagOut,
    dependencies=[Depends(require(Permission.FEATURE_FLAG_WRITE))],
)
async def update_feature_flag(
    key: str, payload: FeatureFlagUpdate, db: AsyncSession = Depends(get_db)
) -> FeatureFlagOut:
    meta = FEATURE_FLAG_REGISTRY.get(key)
    if meta is None:
        raise HTTPException(status_code=404, detail="Unknown feature flag")

    # Selected rather than db.get(): the primary key is (tenant_id, key) now, and
    # the tenant half is the session's, not something this route should be naming.
    # RLS narrows this to one row.
    flag = (await db.execute(select(FeatureFlag).where(FeatureFlag.key == key))).scalar_one_or_none()
    if flag is None:
        flag = FeatureFlag(key=key, enabled=payload.enabled)
        db.add(flag)
    else:
        flag.enabled = payload.enabled

    await db.commit()

    audit(
        AuditAction.FEATURE_FLAG_UPDATED,
        target_type="feature_flag",
        target_id=key,
        enabled=flag.enabled,
    )
    return FeatureFlagOut(key=key, label=meta["label"], description=meta["description"], enabled=flag.enabled)
