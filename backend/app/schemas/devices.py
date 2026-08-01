from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, computed_field
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


class DeviceFilterCriteria(BaseModel):
    """Reusable filter/criteria shape — also intended as the future basis for smart-group criteria."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    q: str | None = None
    ai: str | None = None
    os_version: str | None = None
    os_version_operator: VersionOperator = VersionOperator.eq
    site: str | None = None
    building: str | None = None
    department: str | None = None
    managed: bool | None = None
    supervised: bool | None = None
    last_check_in_after: datetime | None = None
    last_check_in_before: datetime | None = None
    last_inventory_after: datetime | None = None
    last_inventory_before: datetime | None = None
    mdm_connection_id: int | None = None
    extension_attributes: list[ExtensionAttributeFilter] = []
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class InstalledAppOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    id: int
    name: str
    bundle_id: str
    version: str
    full_hash: str
    is_compliant: bool | None
    patch_available: bool | None
    patch_available_since: datetime | None
    last_patch_check_at: datetime | None

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
    building: str | None
    department: str | None


class DeviceDetailOut(DeviceOut):
    apps: list[InstalledAppOut] = []
    extension_attributes: list[ExtensionAttributeFilter] = []


class DeviceListResponse(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    items: list[DeviceOut]
    total: int
    page: int
    page_size: int
