from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.hashing import compute_app_hash, compute_version_hash
from app.mdm.factory import get_mdm_client
from app.mdm.patch.factory import get_patch_provider
from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState
from app.schemas.payload import (
    InventoryChangedEvent,
    NormalizedApp,
    NormalizedDevice,
    SyncStatus,
)

logger = logging.getLogger(__name__)


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
    return app


async def stream_event(event: InventoryChangedEvent) -> None:
    payload = event.model_dump(mode="json")

    if not settings.siem_webhook_url:
        logger.info("siem event not delivered, no webhook configured", extra={"siem_event": payload})
        return

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(settings.siem_webhook_url, json=payload)
            response.raise_for_status()
    except httpx.HTTPError:
        # The device data behind this event is already committed, so a SIEM outage
        # must not fail the sync that produced it. Log the whole event so it can be
        # replayed by hand rather than being lost with the exception.
        logger.exception("siem delivery failed", extra={"siem_event": payload})
    else:
        logger.info(
            "siem event delivered",
            extra={
                "device_external_id": event.device_external_id,
                "added": len(event.added_apps),
                "removed": len(event.removed_apps),
            },
        )


@dataclass(frozen=True, slots=True)
class ConnectionSyncResult:
    connection_id: int
    device_count: int = 0
    ok: bool = True
    skipped: bool = False
    error: str | None = None


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


async def sync_connection(db: AsyncSession, connection: MdmConnection) -> ConnectionSyncResult:
    """Pull inventory for a single connection.

    Deliberately does not raise on a connection-level failure. Both callers — the
    nightly sweep across every connection, and the manual trigger for one — need the
    failure reported rather than propagated: an expired credential on one Jamf tenant
    previously aborted the whole sweep, silently skipping every connection ordered
    after it.
    """
    try:
        client = get_mdm_client(connection)
        devices = await client.fetch_devices()
    except NotImplementedError:
        logger.debug(
            "sync skipped, provider not implemented",
            extra={"connection_id": connection.id, "provider": connection.provider},
        )
        return ConnectionSyncResult(connection_id=connection.id, skipped=True)
    except Exception as exc:
        await db.rollback()
        await set_sync_status(db, connection, SyncStatus.failed)
        logger.exception(
            "connection sync failed while fetching devices",
            extra={"connection_id": connection.id, "provider": connection.provider},
        )
        return ConnectionSyncResult(connection_id=connection.id, ok=False, error=str(exc))

    try:
        connection.last_successful_auth_at = datetime.now(timezone.utc)
        await db.commit()

        for device in devices:
            await process_sync(db, device, connection)
    except Exception as exc:
        # Rollback first: a failure mid-loop leaves the session dirty, and the status
        # write below would otherwise fail too.
        await db.rollback()
        await set_sync_status(db, connection, SyncStatus.failed)
        logger.exception(
            "connection sync failed while processing devices",
            extra={"connection_id": connection.id, "provider": connection.provider},
        )
        return ConnectionSyncResult(connection_id=connection.id, ok=False, error=str(exc))

    logger.info(
        "connection synced",
        extra={
            "connection_id": connection.id,
            "provider": connection.provider,
            "device_count": len(devices),
        },
    )
    return ConnectionSyncResult(connection_id=connection.id, device_count=len(devices))


async def sync_state(db: AsyncSession, connection: MdmConnection) -> None:
    result = await db.execute(
        select(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection.id)
    )
    state = result.scalar_one_or_none()

    device_count_result = await db.execute(
        select(Device).where(Device.mdm_connection_id == connection.id)
    )
    device_count = len(device_count_result.scalars().all())

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
            )
        )

    await db.flush()
    await _apply_patch_status(existing, connection)
    await sync_state(db, connection)

    if not added and not removed_rows:
        await db.commit()
        return None

    event = InventoryChangedEvent(
        provider=device.mdm_provider,
        device_external_id=device.external_id,
        added_apps=added,
        removed_apps=[
            NormalizedApp(name=row.name, bundle_id=row.bundle_id, version=row.version, full_hash=row.full_hash)
            for row in removed_rows
        ],
        occurred_at=datetime.now(timezone.utc),
    )
    await db.commit()
    await stream_event(event)
    return event
