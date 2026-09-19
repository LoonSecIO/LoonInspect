from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.context import Actor, reset_actor, set_actor
from app.core.database import get_db, session_for_tenant
from app.core.permissions import Permission
from app.core.runs import RunReclaimed, acquire, entered, finish
from app.core.scheduling import KIND_CATALOG, KIND_DEVICE_SWEEP, KIND_WEBHOOK, ScheduleError, stale_after
from app.core.tenancy import reset_tenant_id, set_tenant_id
from app.mdm.collections import (
    LOCK_CLASS_FOR_KIND,
    apply_schedule,
    list_all_collections,
    list_collections,
    run_one_collection,
    schedule_of,
)
from app.mdm.jamf.contract import EXTENSION_ATTRIBUTE_CARRIERS, SECTIONS, with_extension_attribute_carriers
from app.mdm.service import TRIGGER_MANUAL, sync_result_kwargs
from app.models.schema import Collection, MdmConnection, Run
from app.schemas.collections import (
    CollectionCreate,
    CollectionOut,
    CollectionRunResult,
    CollectionSummaryOut,
    CollectionUpdate,
    SectionInfo,
)
from app.schemas.payload import MdmProvider

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/mdm", tags=["collections"])


def _stale_after_seconds(row: Collection) -> int | None:
    """The row's staleness threshold, in seconds, for whoever is judging freshness.

    Served rather than left to the client to compute, because the multiple and the
    cadence table are a ruling (#106) and a ruling encoded twice in two languages is a
    ruling that will eventually disagree with itself. `app.core.scheduling` is the only
    interpreter of a collection's "when", and this keeps it so.
    """
    window = stale_after(schedule_of(row))
    return None if window is None else int(window.total_seconds())


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
        last_success_at=row.last_success_at,
        stale_after_seconds=_stale_after_seconds(row),
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
    device sweep or webhook needs at least one and reads the EA carriers whenever it
    reads EAs, a catalog has none, and only a device sweep carries a selector."""
    sections = list(collection.sections or [])
    unknown = [name for name in sections if name not in SECTIONS]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown sections: {', '.join(unknown)}")
    if collection.kind in (KIND_DEVICE_SWEEP, KIND_WEBHOOK) and not sections:
        raise HTTPException(status_code=422, detail="Choose at least one section")
    if collection.kind in (KIND_DEVICE_SWEEP, KIND_WEBHOOK):
        # Asking for extension attributes reads the five sections they are displayed
        # under (#197). Applied at save so the row, the editor and the aperture all show
        # the set that is actually fetched, rather than a picker that silently narrows
        # EAs; sweep_jamf_connection and webhook_scope apply the same closure for rows that predate it.
        collection.sections = list(with_extension_attribute_carriers(sections))
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
        apply_schedule(collection, datetime.now(UTC))
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
            carries_extension_attributes=spec.name in EXTENSION_ATTRIBUTE_CARRIERS,
        )
        for spec in SECTIONS.values()
    ]


def _to_summary(row: Collection) -> CollectionSummaryOut:
    return CollectionSummaryOut(
        id=row.id,
        mdm_connection_id=row.mdm_connection_id,
        name=row.name,
        kind=row.kind,
        enabled=row.enabled,
        next_due_at=row.next_due_at,
        last_run_at=row.last_run_at,
        last_run_status=row.last_run_status,
        last_success_at=row.last_success_at,
        stale_after_seconds=_stale_after_seconds(row),
        created_at=row.created_at,
    )


@router.get(
    "/collections",
    response_model=list[CollectionSummaryOut],
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def list_tenant_collections(db: AsyncSession = Depends(get_db)) -> list[CollectionSummaryOut]:
    """Every collection in the tenant, across connections (#106).

    The per-connection route below is the one the collection editor uses, because it is
    editing one connection. A caller asking a question *about the pod* — is anything
    overdue, is any inventory stale — has no connection in hand and would otherwise
    issue one request per connection on every poll. Mirrors `/destinations` and
    `/runs`, which are already tenant-wide for the same reason.

    Answered with `CollectionSummaryOut`, deliberately not the row the editor gets. This
    is the front page's sixty-second poll, and the fat model would put the operator's
    `selector` RSQL — often a named username — on the wire on every tick, to be read by
    nothing. Same permission, same tenant line, far less reach.
    """
    return [_to_summary(row) for row in await list_all_collections(db)]


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
async def create_collection(connection_id: int, payload: CollectionCreate, db: AsyncSession = Depends(get_db)) -> CollectionOut:
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
async def update_collection(collection_id: int, payload: CollectionUpdate, db: AsyncSession = Depends(get_db)) -> CollectionOut:
    row = await _collection_or_404(collection_id, db)
    data = payload.model_dump(exclude_unset=True, mode="json")

    for key in (
        "name",
        "enabled",
        "sections",
        "selector",
        "page_size",
        "quarantined_extension_attributes",
        "frequency",
        "interval_n",
        "at_hour",
        "at_minute",
        "weekday",
        "timezone",
    ):
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


async def _run_collection_task(collection_id: int, actor: Actor, tenant_id: uuid.UUID, job_id: uuid.UUID) -> None:
    """Background worker for a manual run — same shape as `_run_connection_sync` in
    `app.api.connections`: re-establishes the actor and the tenant, because the request's
    context is gone, and takes the run the request already acquired rather than acquiring
    one of its own.

    **Closing that run is this frame's job** (#582). `run_one_collection` finishes only a
    run it acquired itself (`owned`); a handed-in one it leaves open, because the caller
    that acquired it may have more collections to run under the same jobID — which is
    what `run_enabled_collections` does. Here there is exactly one, so every path out
    ends at `finish`, or the run row sits `running` and holds the connection's lock until
    the reclaim frees it five minutes later.

    **The failure path reloads the run before it closes it**, and the reload is load-
    bearing — see the comment on it. Success does not need one only because the session
    factory is `expire_on_commit=False` (`app.core.database`); `rollback()` expires
    regardless of that setting, which is what makes the two paths differ.
    """
    token = set_actor(actor)
    tenant_token = set_tenant_id(tenant_id)
    try:
        async with session_for_tenant(tenant_id) as db:
            collection = await db.get(Collection, collection_id)
            run = await db.get(Run, job_id)
            if collection is None or run is None:
                return
            async with entered(run):
                try:
                    result = await run_one_collection(db, collection, trigger=TRIGGER_MANUAL, run=run)
                except RunReclaimed:
                    # Already handled where it was detected: the reclaim closed the run
                    # and freed the lock, and `run_one_collection` recorded the abort on
                    # the collection row. Nothing to finish — the row's verdict is the
                    # reclaim's — and nothing to re-raise.
                    await db.rollback()
                    logger.warning(
                        "manual collection run aborted: its run was reclaimed mid-flight",
                        extra={"collection_id": collection_id, "job_id": str(job_id)},
                    )
                    return
                except Exception as exc:
                    # The lock is this run row, and an unhandled failure that left it
                    # `running` would block the connection until the heartbeat went stale
                    # — five minutes of silence for something already known to be over,
                    # with the cause of death nowhere on the row.
                    #
                    # The rollback is what makes the reload necessary. It is needed — the
                    # exception may have left a half-written transaction, and `finish`
                    # must not commit that — but `Session.rollback()` expires every
                    # instance in the session, including `run`, and reading an expired
                    # attribute under asyncio raises `MissingGreenlet` instead of lazily
                    # refreshing. Handing the expired `run` straight to `finish` therefore
                    # crashed on its own `Run.id == run.id`, and the UPDATE that releases
                    # the lock never ran. `db.get` is awaited, so the refresh is legal;
                    # `job_id` is this frame's own argument and no attribute of anything.
                    await db.rollback()
                    reloaded = await db.get(Run, job_id)
                    if reloaded is not None:
                        await finish(db, reloaded, ok=False, error=str(exc))
                    raise
                await finish(db, run, **sync_result_kwargs(result))
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
    sync: a sweep can outlive any sensible request timeout.

    **The lock is taken here, in the request** (#582), the way `POST /connections/{id}/
    sync` and `/re-emit` take it. The run row is the mutex (#31, #94). Reading
    `mdm_sync_state.status` instead put the decision on two surfaces: that row is a
    mirror the sweep writes and clears on finish, so after a crash it reads `syncing`
    until the reclaim and refuses a sync that is not running, and it says nothing at all
    about a catalog run — while the acquisition that actually decides happened later, in
    the background task, long after the operator had been told *queued*.

    **Contention answers 202, not 409**, for the reason the connection-level sync does
    (docs/ingest-scheduling.md §4.2): a click during a sweep means "is this collecting?",
    and the running job's id answers that better than an error. `started` says which
    happened, and nothing is queued behind the holder — a run this request did not start
    is a run it must not promise.
    """
    row = await _collection_or_404(collection_id, db)
    if row.kind == KIND_WEBHOOK:
        raise HTTPException(status_code=409, detail="A webhook collection is event-driven and cannot be run")
    connection = await _connection_or_404(row.mdm_connection_id, db)
    if not connection.is_active:
        raise HTTPException(status_code=409, detail="Connection is not active")

    acquisition = await acquire(
        db,
        connection,
        trigger=TRIGGER_MANUAL,
        lock_class=LOCK_CLASS_FOR_KIND[row.kind],
        collection_id=row.id,
        actor_label=principal.account.email,
    )
    if not acquisition.started:
        return CollectionRunResult(collection_id=row.id, job_id=acquisition.run.id, status="running", started=False)

    audit(
        AuditAction.COLLECTION_RUN_TRIGGERED,
        target_type="collection",
        target_id=row.id,
        name=row.name,
        kind=row.kind,
        connection_id=connection.id,
        job_id=str(acquisition.run.id),
    )
    background_tasks.add_task(
        _run_collection_task,
        row.id,
        Actor(type="account", id=principal.account.id, label=principal.account.email, tenant_id=principal.tenant_id),
        principal.tenant_id,
        acquisition.run.id,
    )
    return CollectionRunResult(collection_id=row.id, job_id=acquisition.run.id, status="queued", started=True)
