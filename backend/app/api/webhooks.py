from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.mdm.jamf.client import JamfClient
from app.mdm.service import process_sync

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/jamf")
async def jamf_webhook(payload: dict, db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    device = JamfClient().parse_webhook(payload)
    await process_sync(db, device)
    return {"status": "accepted"}
