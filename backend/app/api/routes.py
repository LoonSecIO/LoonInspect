from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.mdm.credentials import CREDENTIAL_SCHEMAS, field_specs
from app.models.schema import MdmSyncState
from app.schemas.connections import ProviderCredentialField, ProviderInfo
from app.schemas.payload import MdmSyncStatusOut

router = APIRouter(prefix="/api", tags=["mdm"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get(
    "/mdm/status",
    response_model=list[MdmSyncStatusOut],
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def mdm_status(db: AsyncSession = Depends(get_db)) -> list[MdmSyncState]:
    result = await db.execute(select(MdmSyncState))
    return list(result.scalars().all())


@router.get(
    "/mdm/providers",
    response_model=list[ProviderInfo],
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def list_providers() -> list[ProviderInfo]:
    return [
        ProviderInfo(
            provider=provider,
            credential_fields=[ProviderCredentialField(**spec) for spec in field_specs(schema)],
        )
        for provider, schema in CREDENTIAL_SCHEMAS.items()
    ]
