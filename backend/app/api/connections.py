from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.schema import MdmConnection
from app.schemas.connections import (
    MdmConnectionCreate,
    MdmConnectionOut,
    MdmConnectionUpdate,
    PatchManagementProvider,
    validate_loonsecio_requirement,
)

router = APIRouter(prefix="/api/mdm/connections", tags=["connections"])


def _to_out(conn: MdmConnection) -> MdmConnectionOut:
    return MdmConnectionOut(
        id=conn.id,
        name=conn.name,
        provider=conn.provider,
        base_url=conn.base_url,
        is_active=conn.is_active,
        patch_management_provider=conn.patch_management_provider,
        loonsecio_data_sharing_enabled=conn.loonsecio_data_sharing_enabled,
        has_client_secret=bool(conn.client_secret_encrypted),
        has_api_key=bool(conn.api_key_encrypted),
        has_webhook_secret=bool(conn.webhook_secret_encrypted),
        has_loonsecio_license_key=bool(conn.loonsecio_license_key_encrypted),
        created_at=conn.created_at,
        updated_at=conn.updated_at,
    )


async def _get_or_404(connection_id: int, db: AsyncSession) -> MdmConnection:
    connection = await db.get(MdmConnection, connection_id)
    if connection is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return connection


@router.post("", response_model=MdmConnectionOut, status_code=status.HTTP_201_CREATED)
async def create_connection(
    payload: MdmConnectionCreate, db: AsyncSession = Depends(get_db)
) -> MdmConnectionOut:
    connection = MdmConnection(
        name=payload.name,
        provider=payload.provider.value,
        base_url=payload.base_url,
        is_active=payload.is_active,
        client_id=payload.client_id,
        client_secret_encrypted=payload.client_secret,
        api_key_encrypted=payload.api_key,
        webhook_secret_encrypted=payload.webhook_secret,
        patch_management_provider=payload.patch_management_provider.value,
        loonsecio_license_key_encrypted=payload.loonsecio_license_key,
        loonsecio_data_sharing_enabled=payload.loonsecio_data_sharing_enabled,
    )
    db.add(connection)
    await db.commit()
    await db.refresh(connection)
    return _to_out(connection)


@router.get("", response_model=list[MdmConnectionOut])
async def list_connections(db: AsyncSession = Depends(get_db)) -> list[MdmConnectionOut]:
    result = await db.execute(select(MdmConnection))
    return [_to_out(conn) for conn in result.scalars().all()]


@router.get("/{connection_id}", response_model=MdmConnectionOut)
async def get_connection(connection_id: int, db: AsyncSession = Depends(get_db)) -> MdmConnectionOut:
    connection = await _get_or_404(connection_id, db)
    return _to_out(connection)


@router.patch("/{connection_id}", response_model=MdmConnectionOut)
async def update_connection(
    connection_id: int, payload: MdmConnectionUpdate, db: AsyncSession = Depends(get_db)
) -> MdmConnectionOut:
    connection = await _get_or_404(connection_id, db)
    data = payload.model_dump(exclude_unset=True, mode="json")

    if "name" in data:
        connection.name = data["name"]
    if "provider" in data:
        connection.provider = data["provider"]
    if "base_url" in data:
        connection.base_url = data["base_url"]
    if "is_active" in data:
        connection.is_active = data["is_active"]
    if "client_id" in data:
        connection.client_id = data["client_id"]
    if "client_secret" in data:
        connection.client_secret_encrypted = data["client_secret"]
    if "api_key" in data:
        connection.api_key_encrypted = data["api_key"]
    if "webhook_secret" in data:
        connection.webhook_secret_encrypted = data["webhook_secret"]
    if "patch_management_provider" in data:
        connection.patch_management_provider = data["patch_management_provider"]
    if "loonsecio_license_key" in data:
        connection.loonsecio_license_key_encrypted = data["loonsecio_license_key"]
    if "loonsecio_data_sharing_enabled" in data:
        connection.loonsecio_data_sharing_enabled = data["loonsecio_data_sharing_enabled"]

    try:
        validate_loonsecio_requirement(
            PatchManagementProvider(connection.patch_management_provider),
            connection.loonsecio_license_key_encrypted,
            connection.loonsecio_data_sharing_enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    await db.commit()
    await db.refresh(connection)
    return _to_out(connection)


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connection(connection_id: int, db: AsyncSession = Depends(get_db)) -> None:
    connection = await _get_or_404(connection_id, db)
    await db.delete(connection)
    await db.commit()
