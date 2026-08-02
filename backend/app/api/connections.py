from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pydantic.alias_generators import to_camel

from app.core.database import get_db
from app.mdm.credentials import CREDENTIAL_SCHEMAS, fingerprint_field
from app.mdm.jamf.client import JamfClient
from app.models.schema import MdmConnection
from app.schemas.connections import (
    MdmConnectionCreate,
    MdmConnectionOut,
    MdmConnectionTestRequest,
    MdmConnectionTestResult,
    MdmConnectionUpdate,
    PatchManagementProvider,
    validate_jamf_specific_fields,
    validate_loonsecio_requirement,
)
from app.schemas.payload import MdmProvider

router = APIRouter(prefix="/api/mdm/connections", tags=["connections"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _credentials_dict(conn: MdmConnection) -> dict[str, str]:
    if not conn.credentials_encrypted:
        return {}
    try:
        return json.loads(conn.credentials_encrypted)
    except (json.JSONDecodeError, TypeError):
        return {}


def _validate_credentials(provider: MdmProvider, credentials: dict[str, str]) -> dict[str, str]:
    schema_cls = CREDENTIAL_SCHEMAS.get(provider)
    if schema_cls is None:
        return credentials
    try:
        validated = schema_cls.model_validate(credentials)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return validated.model_dump()


def _normalize_credential_keys(provider: MdmProvider, raw: dict[str, str]) -> dict[str, str]:
    """Map camelCase wire keys (or already-canonical field names) to the schema's
    canonical (snake_case) field names, so merging with stored credentials overwrites
    the same key instead of adding a duplicate under the other casing."""
    schema_cls = CREDENTIAL_SCHEMAS.get(provider)
    if schema_cls is None:
        return raw
    alias_to_name = {(field.alias or name): name for name, field in schema_cls.model_fields.items()}
    return {alias_to_name.get(key, key): value for key, value in raw.items()}


def _to_out(conn: MdmConnection) -> MdmConnectionOut:
    credentials = _credentials_dict(conn)
    return MdmConnectionOut(
        id=conn.id,
        name=conn.name,
        provider=conn.provider,
        base_url=conn.base_url,
        is_active=conn.is_active,
        patch_management_provider=conn.patch_management_provider,
        loonsecio_data_sharing_enabled=conn.loonsecio_data_sharing_enabled,
        credential_fields_set=[to_camel(key) for key, value in credentials.items() if value],
        has_webhook_secret=bool(conn.webhook_secret_encrypted),
        has_loonsecio_license_key=bool(conn.loonsecio_license_key_encrypted),
        user_agent_override=conn.user_agent_override,
        capability_devices=conn.capability_devices,
        capability_users=conn.capability_users,
        capability_webhooks=conn.capability_webhooks,
        capability_jamf_pro=conn.capability_jamf_pro,
        last_successful_auth_at=conn.last_successful_auth_at,
        credentials_rotated_at=conn.credentials_rotated_at,
        credentials_fingerprint=conn.credentials_fingerprint,
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
    validated_credentials = _validate_credentials(payload.provider, payload.credentials)

    connection = MdmConnection(
        name=payload.name,
        provider=payload.provider.value,
        base_url=payload.base_url,
        is_active=payload.is_active,
        credentials_encrypted=json.dumps(validated_credentials) if validated_credentials else None,
        webhook_secret_encrypted=payload.webhook_secret,
        patch_management_provider=payload.patch_management_provider.value,
        loonsecio_license_key_encrypted=payload.loonsecio_license_key,
        loonsecio_data_sharing_enabled=payload.loonsecio_data_sharing_enabled,
        user_agent_override=payload.user_agent_override,
        capability_devices=payload.capability_devices,
        capability_users=payload.capability_users,
        capability_webhooks=payload.capability_webhooks,
        capability_jamf_pro=payload.capability_jamf_pro,
    )

    fp_field = fingerprint_field(payload.provider)
    if fp_field and validated_credentials.get(fp_field):
        connection.credentials_rotated_at = _utcnow()
        connection.credentials_fingerprint = validated_credentials[fp_field][:3]

    db.add(connection)
    await db.commit()
    await db.refresh(connection)
    return _to_out(connection)


@router.post("/test", response_model=MdmConnectionTestResult)
async def test_connection(
    payload: MdmConnectionTestRequest, db: AsyncSession = Depends(get_db)
) -> MdmConnectionTestResult:
    if payload.provider != MdmProvider.jamf:
        return MdmConnectionTestResult(
            success=False, message="Testing is currently only supported for Jamf connections."
        )

    existing: MdmConnection | None = None
    if payload.connection_id is not None:
        existing = await db.get(MdmConnection, payload.connection_id)

    client_secret = payload.client_secret
    if not client_secret and existing is not None:
        client_secret = _credentials_dict(existing).get("client_secret")

    if not client_secret:
        return MdmConnectionTestResult(success=False, message="Enter a client secret to test.")

    user_agent_override = payload.user_agent_override or (existing.user_agent_override if existing else None)
    jamf_client = JamfClient(
        base_url=payload.base_url,
        client_id=payload.client_id,
        client_secret=client_secret,
        user_agent_override=user_agent_override,
    )

    try:
        token_info = await jamf_client.test_connection()
    except httpx.HTTPStatusError as exc:
        return MdmConnectionTestResult(
            success=False,
            message=f"Jamf rejected the request ({exc.response.status_code}).",
            detail=f"HTTP {exc.response.status_code}\n{exc.response.text}",
        )
    except httpx.RequestError as exc:
        return MdmConnectionTestResult(
            success=False, message=f"Could not reach {payload.base_url}.", detail=str(exc)
        )

    if existing is not None:
        existing.last_successful_auth_at = _utcnow()
        await db.commit()

    return MdmConnectionTestResult(
        success=True,
        message="Connected — received a short-lived access token.",
        detail=json.dumps(token_info, indent=2),
    )


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
    if "webhook_secret" in data:
        connection.webhook_secret_encrypted = data["webhook_secret"]
    if "patch_management_provider" in data:
        connection.patch_management_provider = data["patch_management_provider"]
    if "loonsecio_license_key" in data:
        connection.loonsecio_license_key_encrypted = data["loonsecio_license_key"]
    if "loonsecio_data_sharing_enabled" in data:
        connection.loonsecio_data_sharing_enabled = data["loonsecio_data_sharing_enabled"]
    if "user_agent_override" in data:
        connection.user_agent_override = data["user_agent_override"]
    if "capability_devices" in data:
        connection.capability_devices = data["capability_devices"]
    if "capability_users" in data:
        connection.capability_users = data["capability_users"]
    if "capability_webhooks" in data:
        connection.capability_webhooks = data["capability_webhooks"]
    if "capability_jamf_pro" in data:
        connection.capability_jamf_pro = data["capability_jamf_pro"]

    if data.get("credentials"):
        provider = MdmProvider(connection.provider)
        existing_credentials = _credentials_dict(connection)
        incoming = _normalize_credential_keys(provider, {k: v for k, v in data["credentials"].items() if v})
        merged = {**existing_credentials, **incoming}
        validated = _validate_credentials(provider, merged)

        fp_field = fingerprint_field(provider)
        if fp_field and validated.get(fp_field) != existing_credentials.get(fp_field):
            connection.credentials_rotated_at = _utcnow()
            connection.credentials_fingerprint = validated[fp_field][:3]

        connection.credentials_encrypted = json.dumps(validated)

    try:
        validate_loonsecio_requirement(
            PatchManagementProvider(connection.patch_management_provider),
            connection.loonsecio_license_key_encrypted,
            connection.loonsecio_data_sharing_enabled,
        )
        validate_jamf_specific_fields(
            MdmProvider(connection.provider),
            PatchManagementProvider(connection.patch_management_provider),
            connection.capability_jamf_pro,
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
