from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class MdmProvider(str, Enum):
    jamf = "jamf"
    simplemdm = "simplemdm"
    addigy = "addigy"
    nano = "nano"


class SyncStatus(str, Enum):
    idle = "idle"
    syncing = "syncing"
    failed = "failed"


class NormalizedApp(BaseModel):
    name: str
    bundle_id: str
    version: str
    # CFBundleVersion vs CFBundleShortVersionString. Jamf's inventory API exposes only
    # one version field, so this is null for recon and manual syncs and populated only
    # where the source carries both.
    short_version: str | None = None

    # Populated by process_sync, not by the MDM clients — every ingest path funnels
    # through there, so hashing happens in exactly one place.
    app_hash: str | None = None
    version_hash: str | None = None


class NormalizedExtensionAttribute(BaseModel):
    key: str
    value: str | None = None


class NormalizedDevice(BaseModel):
    mdm_provider: MdmProvider
    external_id: str
    serial_number: str
    hostname: str
    managed: bool | None = None
    supervised: bool | None = None
    os_version: str | None = None
    site: str | None = None
    building: str | None = None
    department: str | None = None
    last_check_in: datetime | None = None
    last_inventory_at: datetime | None = None
    apps: list[NormalizedApp] = []
    extension_attributes: list[NormalizedExtensionAttribute] = []


class MdmSyncStatusOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    # Without this the UI can't tell which connection a status row belongs to, which
    # makes per-connection sync state unrenderable.
    mdm_connection_id: int
    provider: MdmProvider
    last_sync_at: datetime | None
    status: SyncStatus
    device_count: int


class InventoryChangedEvent(BaseModel):
    event: str = "device.inventory.changed"
    provider: MdmProvider
    device_external_id: str
    added_apps: list[NormalizedApp]
    removed_apps: list[NormalizedApp]
    occurred_at: datetime
