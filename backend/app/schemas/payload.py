from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class MdmProvider(str, Enum):
    jamf = "jamf"
    simplemdm = "simplemdm"
    addigy = "addigy"
    fleet = "fleet"
    nano = "nano"


class SyncStatus(str, Enum):
    idle = "idle"
    syncing = "syncing"
    failed = "failed"


class NormalizedApp(BaseModel):
    name: str
    bundle_id: str
    version: str
    full_hash: str | None = None


class NormalizedDevice(BaseModel):
    mdm_provider: MdmProvider
    external_id: str
    serial_number: str
    hostname: str
    apps: list[NormalizedApp] = []


class MdmSyncStatusOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

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
