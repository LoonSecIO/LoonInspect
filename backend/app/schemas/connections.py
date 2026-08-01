from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic.alias_generators import to_camel

from app.schemas.payload import MdmProvider


class PatchManagementProvider(str, Enum):
    none = "none"
    jamf = "jamf"
    loonsecio = "loonsecio"


def validate_loonsecio_requirement(
    provider: PatchManagementProvider, license_key: str | None, data_sharing_enabled: bool
) -> None:
    if provider == PatchManagementProvider.loonsecio and not license_key and not data_sharing_enabled:
        raise ValueError("LoonSecIO requires a license key and/or data_sharing_enabled=true")


class MdmConnectionCreate(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    name: str
    provider: MdmProvider
    base_url: str
    is_active: bool = True
    client_id: str | None = None
    client_secret: str | None = None
    api_key: str | None = None
    webhook_secret: str | None = None
    patch_management_provider: PatchManagementProvider = PatchManagementProvider.none
    loonsecio_license_key: str | None = None
    loonsecio_data_sharing_enabled: bool = False

    @model_validator(mode="after")
    def _check_loonsecio(self) -> "MdmConnectionCreate":
        validate_loonsecio_requirement(
            self.patch_management_provider, self.loonsecio_license_key, self.loonsecio_data_sharing_enabled
        )
        return self


class MdmConnectionUpdate(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    name: str | None = None
    provider: MdmProvider | None = None
    base_url: str | None = None
    is_active: bool | None = None
    client_id: str | None = None
    client_secret: str | None = None
    api_key: str | None = None
    webhook_secret: str | None = None
    patch_management_provider: PatchManagementProvider | None = None
    loonsecio_license_key: str | None = None
    loonsecio_data_sharing_enabled: bool | None = None


class MdmConnectionOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: int
    name: str
    provider: MdmProvider
    base_url: str
    is_active: bool
    patch_management_provider: PatchManagementProvider
    loonsecio_data_sharing_enabled: bool
    has_client_secret: bool
    has_api_key: bool
    has_webhook_secret: bool
    has_loonsecio_license_key: bool
    created_at: datetime
    updated_at: datetime
