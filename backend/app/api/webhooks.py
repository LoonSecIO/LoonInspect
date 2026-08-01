from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.mdm.factory import get_mdm_client
from app.mdm.service import process_sync
from app.models.schema import MdmConnection

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/jamf/{connection_id}")
async def jamf_webhook(
    connection_id: int, payload: dict, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    connection = await db.get(MdmConnection, connection_id)
    if connection is None or not connection.is_active:
        raise HTTPException(status_code=404, detail="Connection not found")

    client = get_mdm_client(connection)
    device = client.parse_webhook(payload)
    await process_sync(db, device, connection)
    return {"status": "accepted"}
