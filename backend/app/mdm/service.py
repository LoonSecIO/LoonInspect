from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.changes.derive import derive_and_record
from app.core.content_keys import app_full_key, app_title_key
from app.core.context import get_request_id
from app.core.hashing import compute_app_hash, compute_version_hash
from app.core.outbox import enqueue_event
from app.mdm.factory import get_mdm_client
from app.mdm.jamf.client import JamfClient, normalize_computer, parse_webhook_event
from app.mdm.jamf.contract import (
    V0_SECTIONS,
    Aperture,
    build_aperture,
    canonicalize_computer,
    canonicalize_smart_group,
)
from app.mdm.patch.factory import get_patch_provider
from app.models.schema import Collection, Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState
from app.observations.ledger import (
    RecordResult,
    current_span,
    ensure_aperture,
    is_stale,
    record_observation,
)
from app.schemas.payload import (
    InventoryChangedEvent,
    NormalizedApp,
    NormalizedDevice,
    SyncStatus,
)

logger = logging.getLogger(__name__)

# What triggered an ingest. Stamped on every span as `last_trigger`; #31's run object
# will carry the same vocabulary.
TRIGGER_SWEEP = "sweep"
TRIGGER_MANUAL = "manual"
TRIGGER_WEBHOOK = "webhook"


def apply_hashes(app: NormalizedApp) -> NormalizedApp:
    """Stamp both hashes onto a normalized app.

    Called from process_sync so recon sweeps, manual syncs, and inbound HEC webhooks
    all hash identically — the MDM clients deliberately don't do this themselves, or
    the three paths would drift.
    """
    app.app_hash = compute_app_hash(app.name, app.bundle_id)
    app.version_hash = compute_version_hash(
        app.name, app.bundle_id, app.version, app.short_version
    )
    app.key_title = app_title_key(app.name, app.bundle_id)
    app.key_full = app_full_key(app.name, app.bundle_id, app.version, app.short_version)
    return app


@dataclass(frozen=True, slots=True)
class ConnectionSyncResult:
    connection_id: int
    device_count: int = 0
    ok: bool = True
    skipped: bool = False
    error: str | None = None
    # Ledger outcomes for this run, keyed by app.observations.ledger.Outcome, plus the
    # number of group definitions observed. Empty for providers without a ledger.
    observations: Mapping[str, int] = field(default_factory=dict)
    group_count: int = 0
    # Which collection this run served, when it served one (None for the generic path
    # and for connection-level runs that aggregate several).
    collection_id: int | None = None


async def set_sync_status(
    db: AsyncSession, connection: MdmConnection, status: SyncStatus
) -> None:
    """Upsert just the status field, leaving counts alone.

    Used to publish 'syncing' before a long pull starts and 'failed' after one dies, so
    the UI can show something other than a stale 'idle'.
    """
    result = await db.execute(
        select(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection.id)
    )
    state = result.scalar_one_or_none()

    if state is None:
        state = MdmSyncState(mdm_connection_id=connection.id, provider=connection.provider)
        db.add(state)

    state.status = status.value
    await db.commit()


async def sync_connection(
    db: AsyncSession, connection: MdmConnection, *, trigger: str = TRIGGER_SWEEP
) -> ConnectionSyncResult:
    """Pull inventory for a single connection.

    Deliberately does not raise on a connection-level failure. Both callers — the
    nightly sweep across every connection, and the manual trigger for one — need the
    failure reported rather than propagated: an expired credential on one Jamf tenant
    previously aborted the whole sweep, silently skipping every connection ordered
    after it.
    """
    try:
        client = get_mdm_client(connection)
    except NotImplementedError:
        logger.debug(
            "sync skipped, provider not implemented",
            extra={"connection_id": connection.id, "provider": connection.provider},
        )
        return ConnectionSyncResult(connection_id=connection.id, skipped=True)

    if isinstance(client, JamfClient):
        # What to pull and how is a property of the connection's collections, not of
        # the connection; the connection-level entry point runs every enabled device
        # sweep it has (creating the defaults if none exist yet).
        from app.mdm.collections import run_connection  # local: collections imports this module

        return await run_connection(db, connection, trigger=trigger)

    try:
        result = await _sync_generic(db, connection, client)
    except Exception as exc:
        # Rollback first: a failure mid-loop leaves the session dirty, and the status
        # write below would otherwise fail too.
        await db.rollback()
        await set_sync_status(db, connection, SyncStatus.failed)
        logger.exception(
            "connection sync failed",
            extra={"connection_id": connection.id, "provider": connection.provider},
        )
        return ConnectionSyncResult(connection_id=connection.id, ok=False, error=str(exc))

    logger.info(
        "connection synced",
        extra={"connection_id": connection.id, "provider": connection.provider, "device_count": result.device_count},
    )
    return result


async def _sync_generic(db: AsyncSession, connection: MdmConnection, client) -> ConnectionSyncResult:
    """Providers without an observation ledger: the original pull-everything path."""
    devices = await client.fetch_devices()
    connection.last_successful_auth_at = datetime.now(timezone.utc)
    await db.commit()

    for device in devices:
        await process_sync(db, device, connection)

    await sync_state(db, connection)
    await db.commit()
    return ConnectionSyncResult(connection_id=connection.id, device_count=len(devices))


async def capture_aperture(
    client: JamfClient,
    http: httpx.AsyncClient,
    *,
    sections: Sequence[str] = V0_SECTIONS,
    quarantined_extension_attributes: Iterable[str] = (),
) -> Aperture:
    """Read how Jamf is configured to inventory, and stamp it with how we asked.

    Two reads per run (version, inventory-collection settings) — never per device.
    Either may be unavailable to an API client without the privilege; the aperture
    records the absence rather than failing the sweep. The sections and quarantine are
    the collection's, so a narrowed collection is an explicit aperture rather than
    every omitted section "disappearing".
    """
    version = await client.fetch_version(http)
    settings = await client.fetch_inventory_collection_settings(http)
    return build_aperture(
        host=client.host,
        jamf_version=version,
        sections=sections,
        inventory_collection=settings,
        quarantined_extension_attributes=quarantined_extension_attributes,
    )


async def run_jamf(
    db: AsyncSession,
    connection: MdmConnection,
    *,
    trigger: str,
    sections: Sequence[str] = V0_SECTIONS,
    selector: str | None = None,
    quarantined_extension_attributes: Iterable[str] = (),
    include_catalog: bool = True,
    collection_id: int | None = None,
) -> ConnectionSyncResult:
    """One device sweep of a Jamf connection, as a collection describes it.

    Like sync_connection, this reports a failure rather than raising: the tick runs
    many collections in turn and one expired credential must not abort the rest.
    """
    quarantine = tuple(quarantined_extension_attributes)
    try:
        client = get_mdm_client(connection)
        assert isinstance(client, JamfClient)
        result = await _sync_jamf(
            db,
            connection,
            client,
            trigger=trigger,
            sections=tuple(sections),
            selector=selector,
            quarantine=quarantine,
            include_catalog=include_catalog,
        )
    except Exception as exc:
        await db.rollback()
        await set_sync_status(db, connection, SyncStatus.failed)
        logger.exception(
            "jamf sweep failed",
            extra={"connection_id": connection.id, "collection_id": collection_id, "trigger": trigger},
        )
        return ConnectionSyncResult(connection_id=connection.id, ok=False, error=str(exc), collection_id=collection_id)

    logger.info(
        "jamf sweep finished",
        extra={
            "connection_id": connection.id,
            "collection_id": collection_id,
            "device_count": result.device_count,
            "observations": dict(result.observations),
            "group_count": result.group_count,
            "trigger": trigger,
        },
    )
    return ConnectionSyncResult(
        connection_id=result.connection_id,
        device_count=result.device_count,
        observations=result.observations,
        group_count=result.group_count,
        collection_id=collection_id,
    )


async def run_jamf_catalog(
    db: AsyncSession,
    connection: MdmConnection,
    *,
    trigger: str,
    collection_id: int | None = None,
) -> ConnectionSyncResult:
    """The catalog class on its own: smart-group definitions with criteria, no devices.
    Tens to hundreds of small reads, so it can run far more often than a sweep and
    timestamp a criteria edit finer than the sweep would."""
    try:
        client = get_mdm_client(connection)
        assert isinstance(client, JamfClient)
        outcomes: Counter[str] = Counter()
        async with client.http() as http:
            aperture = await capture_aperture(client, http)
            aperture_digest = await ensure_aperture(db, connection_id=connection.id, aperture=aperture)
            connection.last_successful_auth_at = datetime.now(timezone.utc)
            await db.commit()
            group_count = await _observe_groups(db, connection, client, http, aperture_digest, trigger, outcomes)
            await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.exception(
            "jamf catalog refresh failed",
            extra={"connection_id": connection.id, "collection_id": collection_id, "trigger": trigger},
        )
        return ConnectionSyncResult(connection_id=connection.id, ok=False, error=str(exc), collection_id=collection_id)

    logger.info(
        "jamf catalog refreshed",
        extra={"connection_id": connection.id, "collection_id": collection_id, "group_count": group_count, "trigger": trigger},
    )
    return ConnectionSyncResult(
        connection_id=connection.id, observations=dict(outcomes), group_count=group_count, collection_id=collection_id
    )


async def _observe_groups(
    db: AsyncSession,
    connection: MdmConnection,
    client: JamfClient,
    http: httpx.AsyncClient,
    aperture_digest: str,
    trigger: str,
    outcomes: Counter[str],
) -> int:
    group_count = 0
    for raw_group in await client.fetch_smart_groups(http):
        observation = canonicalize_smart_group(raw_group)
        result = await record_observation(
            db,
            connection_id=connection.id,
            observation=observation,
            aperture_digest=aperture_digest,
            trigger=trigger,
        )
        if result.outcome == "changed":
            await derive_and_record(db, connection=connection, observation=observation, result=result, trigger=trigger)
        outcomes[f"group_{result.outcome}"] += 1
        group_count += 1
    return group_count


async def _sync_jamf(
    db: AsyncSession,
    connection: MdmConnection,
    client: JamfClient,
    *,
    trigger: str,
    sections: Sequence[str] = V0_SECTIONS,
    selector: str | None = None,
    quarantine: Sequence[str] = (),
    include_catalog: bool = True,
) -> ConnectionSyncResult:
    outcomes: Counter[str] = Counter()
    device_count = 0
    group_count = 0

    async with client.http() as http:
        aperture = await capture_aperture(
            client, http, sections=sections, quarantined_extension_attributes=quarantine
        )
        aperture_digest = await ensure_aperture(db, connection_id=connection.id, aperture=aperture)
        connection.last_successful_auth_at = datetime.now(timezone.utc)
        await db.commit()

        # Streamed, not collected: a 40,000-device tenant is paged through one record
        # at a time, and each device commits on its own (process_sync), so a failure on
        # device 30,000 leaves 29,999 correctly recorded. The selector is pushed into
        # Jamf's query rather than applied after the fetch — filtering client-side would
        # still spend the API budget the selector exists to save.
        async for raw in client.iter_computers(http, sections, rsql_filter=selector):
            result = await ingest_computer(
                db,
                connection,
                raw,
                aperture_digest=aperture_digest,
                trigger=trigger,
                sections=sections,
                quarantined_extension_attributes=quarantine,
            )
            outcomes[result.outcome] += 1
            device_count += 1

        # Group definitions ride along with the device sweep so the catalog is never
        # older than the memberships that reference it (docs/ingest-scheduling.md §6.2).
        if include_catalog:
            group_count = await _observe_groups(db, connection, client, http, aperture_digest, trigger, outcomes)
        await db.commit()

    await sync_state(db, connection)
    await db.commit()
    return ConnectionSyncResult(
        connection_id=connection.id,
        device_count=device_count,
        observations=dict(outcomes),
        group_count=group_count,
    )


async def ingest_computer(
    db: AsyncSession,
    connection: MdmConnection,
    raw: dict,
    *,
    aperture_digest: str,
    trigger: str,
    sections: Sequence[str] = V0_SECTIONS,
    quarantined_extension_attributes: Iterable[str] = (),
) -> RecordResult:
    """One raw Jamf computer record, through both layers: the observation ledger and
    the current-state tables. The single function every Jamf ingest path — sweep,
    manual run, webhook — goes through, so the two layers can never disagree about
    what was seen.

    The ledger is consulted first because it owns the monotonic guard: if this record
    is older than what the ledger already holds for the device, neither layer is
    written. Otherwise the ledger write and process_sync's updates commit together.
    """
    observation = canonicalize_computer(
        raw, sections, quarantined_extension_attributes=quarantined_extension_attributes
    )
    current = await current_span(
        db,
        connection_id=connection.id,
        subject_kind=observation.subject_kind,
        subject_id=observation.subject_id,
    )
    collected_at = datetime.now(timezone.utc)
    if is_stale(current, observation.observed_at or collected_at):
        logger.info(
            "stale observation ignored",
            extra={
                "connection_id": connection.id,
                "subject_id": observation.subject_id,
                "observed_at": observation.observed_at,
                "current_observed_at": current.last_observed_at if current else None,
                "trigger": trigger,
            },
        )
        return RecordResult(
            outcome="stale",
            head_digest="",
            span_id=current.id if current else None,
        )

    result = await record_observation(
        db,
        connection_id=connection.id,
        observation=observation,
        aperture_digest=aperture_digest,
        trigger=trigger,
        collected_at=collected_at,
        current=current,
        current_loaded=True,
    )
    if result.outcome == "changed":
        # The change log is derived from the two spans and written in the same
        # transaction as the device's state tables below.
        await derive_and_record(
            db, connection=connection, observation=observation, result=result, trigger=trigger, collected_at=collected_at
        )
    await process_sync(db, normalize_computer(raw), connection)
    return result


async def ingest_webhook(db: AsyncSession, connection: MdmConnection, payload: dict) -> RecordResult | None:
    """A Jamf webhook names a computer; the inventory comes from a fetch.

    Returns None when the payload names nothing (no jssID) — a test webhook, or an event
    type that does not carry a computer. The aperture is captured per event (two small
    reads) under the connection's webhook collection, which may be scoped differently
    from the sweep's; an aperture is content-addressed, so an unchanged one is an upsert
    of `last_seen_at` and nothing more.
    """
    client = get_mdm_client(connection)
    if not isinstance(client, JamfClient):
        device = client.parse_webhook(payload)
        await process_sync(db, device, connection)
        return None

    event = parse_webhook_event(payload)
    if event.jamf_id is None:
        logger.info(
            "jamf webhook carried no computer id; nothing to ingest",
            extra={"connection_id": connection.id, "event": event.event_name},
        )
        return None

    sections, quarantine = await webhook_scope(db, connection)
    async with client.http() as http:
        aperture = await capture_aperture(
            client, http, sections=sections, quarantined_extension_attributes=quarantine
        )
        aperture_digest = await ensure_aperture(db, connection_id=connection.id, aperture=aperture)
        raw = await client.fetch_computer_detail(http, event.jamf_id)

    return await ingest_computer(
        db,
        connection,
        raw,
        aperture_digest=aperture_digest,
        trigger=TRIGGER_WEBHOOK,
        sections=sections,
        quarantined_extension_attributes=quarantine,
    )


async def webhook_scope(db: AsyncSession, connection: MdmConnection) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The sections and EA quarantine the webhook path fetches under: the connection's
    enabled webhook collection, or the whole contract when none exists."""
    result = await db.execute(
        select(Collection).where(
            Collection.mdm_connection_id == connection.id,
            Collection.kind == "webhook",
            Collection.enabled.is_(True),
        )
    )
    collection = result.scalars().first()
    if collection is None or not collection.sections:
        return tuple(V0_SECTIONS), ()
    return tuple(collection.sections), tuple(collection.quarantined_extension_attributes or ())


async def sync_state(db: AsyncSession, connection: MdmConnection) -> None:
    """Stamp the run's end on the connection's sync state. Once per run, not per device:
    the previous per-device call recounted every device row each time, which made a
    sweep quadratic in fleet size."""
    result = await db.execute(
        select(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection.id)
    )
    state = result.scalar_one_or_none()

    device_count = (
        await db.execute(
            select(func.count()).select_from(Device).where(Device.mdm_connection_id == connection.id)
        )
    ).scalar_one()

    if state is None:
        state = MdmSyncState(mdm_connection_id=connection.id, provider=connection.provider)
        db.add(state)

    state.last_sync_at = datetime.now(timezone.utc)
    state.status = SyncStatus.idle.value
    state.device_count = device_count


async def _apply_patch_status(existing: Device, connection: MdmConnection) -> None:
    patch_provider = get_patch_provider(connection)
    if patch_provider is None:
        return

    apps = [
        NormalizedApp(
            name=row.name,
            bundle_id=row.bundle_id,
            version=row.version,
            short_version=row.short_version,
            app_hash=row.app_hash,
            version_hash=row.version_hash,
        )
        for row in existing.apps
    ]

    try:
        results = await patch_provider.check_apps(apps)
    except NotImplementedError:
        return

    results_by_hash = {result.version_hash: result for result in results}
    now = datetime.now(timezone.utc)

    for row in existing.apps:
        result = results_by_hash.get(row.version_hash)
        if result is None:
            continue

        was_available = row.patch_available
        row.is_compliant = result.is_compliant
        row.patch_available = result.patch_available
        row.last_patch_check_at = now
        if result.patch_available and not was_available:
            row.patch_available_since = now


async def process_sync(
    db: AsyncSession, device: NormalizedDevice, connection: MdmConnection
) -> InventoryChangedEvent | None:
    """Bring the current-state tables for one device up to date and emit the delta.

    Commits. Anything the caller wrote to the session before this — the observation
    ledger's rows for the same device — lands in the same transaction.
    """
    for app in device.apps:
        apply_hashes(app)

    result = await db.execute(
        # Both collections are eagerly loaded because the code below reads `apps` to
        # compute the delta and replaces `extension_attributes` wholesale. Under
        # asyncio a lazy load raises MissingGreenlet rather than quietly issuing a
        # query — and it only triggers on the *second* sync of a device, since the
        # first takes the `existing is None` path and never touches either.
        select(Device)
        .options(selectinload(Device.apps), selectinload(Device.extension_attributes))
        .where(
            Device.mdm_connection_id == connection.id,
            Device.external_id == device.external_id,
        )
    )
    existing = result.scalar_one_or_none()

    previous_hashes: dict[str, InstalledApp] = {}
    if existing is None:
        existing = Device(
            mdm_connection_id=connection.id,
            mdm_provider=device.mdm_provider.value,
            external_id=device.external_id,
            serial_number=device.serial_number,
            hostname=device.hostname,
        )
        db.add(existing)
    else:
        # Keyed on the version hash: a version bump is an install change, so the old
        # build shows as removed and the new one as added.
        previous_hashes = {app.version_hash: app for app in existing.apps}

    existing.hostname = device.hostname
    existing.serial_number = device.serial_number
    existing.last_seen_at = datetime.now(timezone.utc)
    existing.managed = device.managed
    existing.supervised = device.supervised
    existing.os_version = device.os_version
    existing.site = device.site
    existing.building = device.building
    existing.department = device.department
    existing.last_check_in = device.last_check_in
    existing.last_inventory_at = device.last_inventory_at
    # Replaced rather than merged, but the delete has to be flushed first. Assigning a
    # fresh list in one go lets the unit of work order the INSERTs before the DELETEs,
    # which trips uq_device_extension_attribute_key on any device that already has
    # attributes — i.e. every device after its first sync.
    if existing.extension_attributes:
        existing.extension_attributes.clear()
        await db.flush()

    existing.extension_attributes = [
        DeviceExtensionAttribute(key=ea.key, value=ea.value) for ea in device.extension_attributes
    ]

    incoming_hashes = {app.version_hash: app for app in device.apps if app.version_hash}

    added = [app for version_hash, app in incoming_hashes.items() if version_hash not in previous_hashes]
    removed_rows = [
        row for version_hash, row in previous_hashes.items() if version_hash not in incoming_hashes
    ]

    for row in removed_rows:
        await db.delete(row)

    for app in added:
        db.add(
            InstalledApp(
                device=existing,
                name=app.name,
                bundle_id=app.bundle_id,
                version=app.version,
                short_version=app.short_version,
                app_hash=app.app_hash,
                version_hash=app.version_hash,
                key_title=app.key_title,
                key_full=app.key_full,
            )
        )

    await db.flush()
    await _apply_patch_status(existing, connection)

    if not added and not removed_rows:
        await db.commit()
        return None

    event = InventoryChangedEvent(
        provider=device.mdm_provider,
        device_external_id=device.external_id,
        added_apps=added,
        removed_apps=[
            NormalizedApp(
                name=row.name,
                bundle_id=row.bundle_id,
                version=row.version,
                short_version=row.short_version,
                app_hash=row.app_hash,
                version_hash=row.version_hash,
            )
            for row in removed_rows
        ],
        occurred_at=datetime.now(timezone.utc),
    )

    # Enqueued in the same transaction as the device/app state change below, so "we
    # updated the database" and "we recorded the event" can never drift apart from a
    # partial failure. Delivery itself happens later, on the outbox worker's own
    # schedule — a slow or down destination must never be able to block a sync.
    await enqueue_event(
        db, event.event, event.model_dump(mode="json"), request_id=get_request_id()
    )
    await db.commit()
    return event
