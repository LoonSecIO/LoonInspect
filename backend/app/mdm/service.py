from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.schema import Device, InstalledApp, MdmSyncState
from app.schemas.payload import (
    InventoryChangedEvent,
    NormalizedApp,
    NormalizedDevice,
    SyncStatus,
)


def compute_full_hash(app: NormalizedApp) -> str:
    payload = f"{app.bundle_id}:{app.version}".encode()
    return hashlib.md5(payload).hexdigest()


async def stream_event(event: InventoryChangedEvent) -> None:
    payload = event.model_dump(mode="json")

    if not settings.siem_webhook_url:
        print(f"[siem] {payload}")
        return

    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(settings.siem_webhook_url, json=payload)


async def sync_state(db: AsyncSession, provider: str) -> None:
    result = await db.execute(select(MdmSyncState).where(MdmSyncState.provider == provider))
    state = result.scalar_one_or_none()

    device_count_result = await db.execute(select(Device).where(Device.mdm_provider == provider))
    device_count = len(device_count_result.scalars().all())

    if state is None:
        state = MdmSyncState(provider=provider)
        db.add(state)

    state.last_sync_at = datetime.now(timezone.utc)
    state.status = SyncStatus.idle.value
    state.device_count = device_count


async def process_sync(db: AsyncSession, device: NormalizedDevice) -> InventoryChangedEvent | None:
    for app in device.apps:
        app.full_hash = compute_full_hash(app)

    result = await db.execute(select(Device).where(Device.external_id == device.external_id))
    existing = result.scalar_one_or_none()

    previous_hashes: dict[str, InstalledApp] = {}
    if existing is None:
        existing = Device(
            mdm_provider=device.mdm_provider.value,
            external_id=device.external_id,
            serial_number=device.serial_number,
            hostname=device.hostname,
        )
        db.add(existing)
    else:
        previous_hashes = {app.full_hash: app for app in existing.apps}

    existing.hostname = device.hostname
    existing.serial_number = device.serial_number
    existing.last_seen_at = datetime.now(timezone.utc)

    incoming_hashes = {app.full_hash: app for app in device.apps if app.full_hash}

    added = [app for full_hash, app in incoming_hashes.items() if full_hash not in previous_hashes]
    removed_rows = [row for full_hash, row in previous_hashes.items() if full_hash not in incoming_hashes]

    for row in removed_rows:
        await db.delete(row)

    for app in added:
        db.add(
            InstalledApp(
                device=existing,
                name=app.name,
                bundle_id=app.bundle_id,
                version=app.version,
                full_hash=app.full_hash,
            )
        )

    await db.flush()
    await sync_state(db, device.mdm_provider.value)

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
