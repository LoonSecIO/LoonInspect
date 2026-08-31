from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, computed_field
from pydantic.alias_generators import to_camel

from app.schemas.payload import MdmProvider


class VersionOperator(str, Enum):
    eq = "eq"
    lt = "lt"
    lte = "lte"
    gt = "gt"
    gte = "gte"
    regex = "regex"


class ExtensionAttributeFilter(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key: str
    value: str | None = None


class InstalledAppOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    id: int
    name: str
    bundle_id: str
    version: str
    short_version: str | None
    app_hash: str
    version_hash: str
    is_compliant: bool | None
    patch_available: bool | None
    patch_available_since: datetime | None
    last_patch_check_at: datetime | None
    # Jamf Patch matching (app.mdm.patch.matching): the titles this build belongs to, the
    # rolling title's state and latest version, and whether Jamf has listed this version.
    jamf_title_ids: list[str] | None = None
    patch_state: str | None = None
    this_version_seen: bool | None = None
    latest_version: str | None = None
    latest_released_at: datetime | None = None

    @computed_field
    @property
    def days_since_patch_available(self) -> int | None:
        if self.patch_available_since is None:
            return None
        return (datetime.now(timezone.utc) - self.patch_available_since).days


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    id: int
    mdm_provider: MdmProvider
    mdm_connection_id: int | None
    external_id: str
    serial_number: str
    hostname: str
    last_seen_at: datetime | None
    last_check_in: datetime | None
    last_inventory_at: datetime | None
    managed: bool | None
    supervised: bool | None
    os_version: str | None
    site: str | None
    # Both halves of the same fact. The id is what Jamf put on the device and what the
    # row stores; the name is resolved per request from the connection's catalog
    # (app.mdm.org_units) and is null while that catalog has not been read since the id
    # first appeared — never the id in disguise, so a caller can always tell "no name
    # yet" from a department genuinely called "7".
    building_id: str | None
    department_id: str | None
    building: str | None = None
    department: str | None = None


class DeviceDetailOut(DeviceOut):
    apps: list[InstalledAppOut] = []
    extension_attributes: list[ExtensionAttributeFilter] = []


class DeviceListResponse(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    items: list[DeviceOut]
    total: int
    page: int
    page_size: int
