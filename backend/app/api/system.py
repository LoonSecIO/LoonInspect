from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.auth import require
from app.core.permissions import Permission
from app.core.update_check import get_update_status
from app.schemas.system import UpdateStatusOut

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
