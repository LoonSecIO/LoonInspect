from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.sharing import build_exchange_request, get_or_create_settings
from app.core.update_check import get_update_status
from app.schemas.system import DataSharingOut, DataSharingUpdate, UpdateStatusOut

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get(
    "/update-status",
    response_model=UpdateStatusOut,
    dependencies=[Depends(require(Permission.SYSTEM_READ))],
)
async def update_status() -> UpdateStatusOut:
    """Whether a newer build of main exists than the one running. Authenticated on
    purpose: the sign-in page must not advertise that an instance is behind."""
    status = await get_update_status()
    return UpdateStatusOut(
        enabled=status.enabled,
        current_version=status.current_version,
        update_available=status.update_available,
        latest_sha=status.latest_sha,
        checked_at=status.checked_at,
    )


def _sharing_out(row) -> DataSharingOut:
    return DataSharingOut(
        tier=row.tier,
        submission_uuid=str(row.submission_uuid),
        exclude_globs=list(row.exclude_globs or []),
        env_disabled=not settings.community_sharing,
    )


@router.get(
    "/data-sharing",
    response_model=DataSharingOut,
    dependencies=[Depends(require(Permission.SYSTEM_READ))],
)
async def get_data_sharing(db: AsyncSession = Depends(get_db)) -> DataSharingOut:
    return _sharing_out(await get_or_create_settings(db))


@router.put(
    "/data-sharing",
    response_model=DataSharingOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def update_data_sharing(
    payload: DataSharingUpdate, db: AsyncSession = Depends(get_db)
) -> DataSharingOut:
    """Persisted even while COMMUNITY_SHARING=false: the env override wins at
    exchange time, but an operator's recorded choice should survive the override
    being lifted rather than silently resetting."""
    row = await get_or_create_settings(db)
    if payload.tier is not None:
        row.tier = payload.tier.value
    if payload.exclude_globs is not None:
        row.exclude_globs = [g.strip() for g in payload.exclude_globs if g.strip()]
    row.updated_at = datetime.now(timezone.utc)
    await db.commit()

    audit(
        AuditAction.SHARING_SETTINGS_UPDATED,
        target_type="data_sharing",
        tier=row.tier,
        exclude_glob_count=len(row.exclude_globs or []),
    )
    return _sharing_out(row)


@router.post(
    "/data-sharing/reset-uuid",
    response_model=DataSharingOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def reset_submission_uuid(db: AsyncSession = Depends(get_db)) -> DataSharingOut:
    """The disclosure page promises the pseudonymous identity is resettable; this is
    that promise. The old UUID's snapshots age out server-side on their own."""
    row = await get_or_create_settings(db)
    row.submission_uuid = uuid.uuid4()
    row.updated_at = datetime.now(timezone.utc)
    await db.commit()

    audit(AuditAction.SHARING_UUID_RESET, target_type="data_sharing")
    return _sharing_out(row)


@router.get(
    "/data-sharing/preview",
    dependencies=[Depends(require(Permission.SYSTEM_READ))],
)
async def preview_exchange(db: AsyncSession = Depends(get_db)) -> dict:
    """The literal next exchange request, from live data, through the same builder
    the exchange job uses — the preview cannot drift from the wire."""
    row = await get_or_create_settings(db)
    return await build_exchange_request(db, row)
