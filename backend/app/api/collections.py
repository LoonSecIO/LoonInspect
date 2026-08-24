from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.context import Actor, reset_actor, set_actor
from app.core.database import get_db, session_for_tenant
from app.core.permissions import Permission
from app.core.scheduling import KIND_CATALOG, KIND_DEVICE_SWEEP, KIND_WEBHOOK, ScheduleError
from app.core.tenancy import reset_tenant_id, set_tenant_id
from app.mdm.collections import apply_schedule, list_collections, run_collection
from app.mdm.jamf.contract import SECTIONS
from app.mdm.service import TRIGGER_MANUAL
from app.models.schema import Collection, MdmConnection, MdmSyncState
from app.schemas.collections import (
    CollectionCreate,
    CollectionOut,
    CollectionRunResult,
    CollectionUpdate,
    SectionInfo,
)
from app.schemas.payload import MdmProvider, SyncStatus

router = APIRouter(prefix="/api/mdm", tags=["collections"])


def _to_out(row: Collection) -> CollectionOut:
    return CollectionOut(
        id=row.id,
        mdm_connection_id=row.mdm_connection_id,
        name=row.name,
        kind=row.kind,
        enabled=row.enabled,
        sections=list(row.sections or []),
        selector=row.selector,
        page_size=row.page_size,
        quarantined_extension_attributes=list(row.quarantined_extension_attributes or []),
        frequency=row.frequency,
        interval_n=row.interval_n,
        at_hour=row.at_hour,
        at_minute=row.at_minute,
        weekday=row.weekday,
        timezone=row.timezone,
        next_due_at=row.next_due_at,
        last_run_at=row.last_run_at,
        last_run_status=row.last_run_status,
        last_run_summary=row.last_run_summary,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _connection_or_404(connection_id: int, db: AsyncSession) -> MdmConnection:
    connection = await db.get(MdmConnection, connection_id)
    if connection is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return connection


async def _collection_or_404(collection_id: int, db: AsyncSession) -> Collection:
    collection = await db.get(Collection, collection_id)
    if collection is None:
        raise HTTPException(status_code=404, detail="Collection not found")
    return collection


def _validate_scope(collection: Collection) -> None:
    """The what, checked against the contract: sections must be contract sections, a
    device sweep or webhook needs at least one, a catalog has none, and only a device
    sweep carries a selector."""
    sections = list(collection.sections or [])
    unknown = [name for name in sections if name not in SECTIONS]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown sections: {', '.join(unknown)}")
    if collection.kind in (KIND_DEVICE_SWEEP, KIND_WEBHOOK) and not sections:
        raise HTTPException(status_code=422, detail="Choose at least one section")
    if collection.kind == KIND_CATALOG:
        collection.sections = []
        collection.selector = None
    if collection.kind == KIND_WEBHOOK:
        collection.selector = None
    if collection.kind != KIND_DEVICE_SWEEP:
        collection.page_size = None  # webhooks fetch by id and catalogs read no computers
    if collection.selector is not None:
        collection.selector = collection.selector.strip() or None
    collection.quarantined_extension_attributes = [
        str(item).strip() for item in (collection.quarantined_extension_attributes or []) if str(item).strip()
    ]


def _finalize(collection: Collection) -> None:
    _validate_scope(collection)
    try:
        apply_schedule(collection, datetime.now(timezone.utc))
    except ScheduleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/providers/jamf/sections",
    response_model=list[SectionInfo],
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def list_jamf_sections() -> list[SectionInfo]:
    """The contract's section registry, for the collection editor."""
    return [
        SectionInfo(
            name=spec.name,
            jamf_section=spec.jamf_section,
            kind="list" if spec.is_list else "scalar",
            entry_kind=spec.entry_kind,
        )
        for spec in SECTIONS.values()
    ]


@router.get(
    "/connections/{connection_id}/collections",
    response_model=list[CollectionOut],
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def list_connection_collections(connection_id: int, db: AsyncSession = Depends(get_db)) -> list[CollectionOut]:
    await _connection_or_404(connection_id, db)
    return [_to_out(row) for row in await list_collections(db, connection_id)]


@router.post(
    "/connections/{connection_id}/collections",
    response_model=CollectionOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.CONNECTION_WRITE))],
)
async def create_collection(
    connection_id: int, payload: CollectionCreate, db: AsyncSession = Depends(get_db)
) -> CollectionOut:
    connection = await _connection_or_404(connection_id, db)
    if connection.provider != MdmProvider.jamf.value:
        raise HTTPException(status_code=422, detail="Collections are available for Jamf Pro connections")

    row = Collection(
        mdm_connection_id=connection.id,
        name=payload.name,
        kind=payload.kind.value,
        enabled=payload.enabled,
        sections=list(payload.sections),
        selector=payload.selector,
        page_size=payload.page_size,
        quarantined_extension_attributes=list(payload.quarantined_extension_attributes),
        frequency=payload.frequency.value if payload.frequency else None,
        interval_n=payload.interval_n,
        at_hour=payload.at_hour,
        at_minute=payload.at_minute,
        weekday=payload.weekday,
        timezone=payload.timezone,
    )
    _finalize(row)
    db.add(row)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="A collection with that name already exists on this connection") from exc
    await db.refresh(row)

    audit(
        AuditAction.COLLECTION_CREATED,
        target_type="collection",
        target_id=row.id,
        name=row.name,
        kind=row.kind,
        connection_id=connection.id,
        sections=list(row.sections or []),
        frequency=row.frequency,
    )
    return _to_out(row)


@router.get(
    "/collections/{collection_id}",
    response_model=CollectionOut,
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def get_collection(collection_id: int, db: AsyncSession = Depends(get_db)) -> CollectionOut:
    return _to_out(await _collection_or_404(collection_id, db))


@router.patch(
    "/collections/{collection_id}",
    response_model=CollectionOut,
    dependencies=[Depends(require(Permission.CONNECTION_WRITE))],
)
async def update_collection(
    collection_id: int, payload: CollectionUpdate, db: AsyncSession = Depends(get_db)
) -> CollectionOut:
    row = await _collection_or_404(collection_id, db)
    data = payload.model_dump(exclude_unset=True, mode="json")

    for key in ("name", "enabled", "sections", "selector", "page_size", "quarantined_extension_attributes",
                "frequency", "interval_n", "at_hour", "at_minute", "weekday", "timezone"):
        if key in data:
            setattr(row, key, data[key])

    _finalize(row)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="A collection with that name already exists on this connection") from exc
    await db.refresh(row)

    audit(
        AuditAction.COLLECTION_UPDATED,
        target_type="collection",
        target_id=row.id,
        name=row.name,
        kind=row.kind,
        changed=sorted(data.keys()),
    )
    return _to_out(row)


@router.delete(
    "/collections/{collection_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.CONNECTION_WRITE))],
)
async def delete_collection(collection_id: int, db: AsyncSession = Depends(get_db)) -> None:
    row = await _collection_or_404(collection_id, db)
    name, kind, connection_id = row.name, row.kind, row.mdm_connection_id
    await db.delete(row)
    await db.commit()
    audit(
        AuditAction.COLLECTION_DELETED,
        target_type="collection",
        target_id=collection_id,
        name=name,
        kind=kind,
        connection_id=connection_id,
    )


async def _run_collection_task(collection_id: int, actor: Actor, tenant_id: uuid.UUID) -> None:
    """Background worker for a manual run — same shape as the connection-level one:
    re-establishes the actor and the tenant, because the request's context is gone."""
    token = set_actor(actor)
    tenant_token = set_tenant_id(tenant_id)
    try:
        async with session_for_tenant(tenant_id) as db:
            collection = await db.get(Collection, collection_id)
            if collection is None:
                return
            await run_collection(db, collection, trigger=TRIGGER_MANUAL)
    finally:
        reset_tenant_id(tenant_token)
        reset_actor(token)


@router.post(
    "/collections/{collection_id}/run",
    response_model=CollectionRunResult,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require(Permission.DEVICE_SYNC))],
)
async def run_collection_now(
    collection_id: int,
    background_tasks: BackgroundTasks,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> CollectionRunResult:
    """Run one collection now. 202 and a background task, like the connection-level
    sync: a sweep can outlive any sensible request timeout."""
    row = await _collection_or_404(collection_id, db)
    if row.kind == KIND_WEBHOOK:
        raise HTTPException(status_code=409, detail="A webhook collection is event-driven and cannot be run")
    connection = await _connection_or_404(row.mdm_connection_id, db)
    if not connection.is_active:
        raise HTTPException(status_code=409, detail="Connection is not active")

    if row.kind == KIND_DEVICE_SWEEP:
        state = await db.get(MdmSyncState, connection.id)
        if state is not None and state.status == SyncStatus.syncing.value:
            raise HTTPException(status_code=409, detail="A sync is already running for this connection")

    audit(
        AuditAction.COLLECTION_RUN_TRIGGERED,
        target_type="collection",
        target_id=row.id,
        name=row.name,
        kind=row.kind,
        connection_id=connection.id,
    )
    background_tasks.add_task(
        _run_collection_task,
        row.id,
        Actor(type="account", id=principal.account.id, label=principal.account.email, tenant_id=principal.tenant_id),
        principal.tenant_id,
    )
    return CollectionRunResult(collection_id=row.id, status="queued")
