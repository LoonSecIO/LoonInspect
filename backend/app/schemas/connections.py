from __future__ import annotations

import uuid
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


def validate_jamf_specific_fields(
    mdm_provider: MdmProvider,
    patch_management_provider: PatchManagementProvider,
    capability_jamf_pro: bool,
) -> None:
    if mdm_provider == MdmProvider.jamf:
        return
    if patch_management_provider == PatchManagementProvider.jamf:
        raise ValueError("Jamf patch management requires the connection's provider to be Jamf")
    if capability_jamf_pro:
        raise ValueError("The Jamf Pro capability requires the connection's provider to be Jamf")


class MdmConnectionCreate(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    name: str
    provider: MdmProvider
    base_url: str
    is_active: bool = True
    credentials: dict[str, str] = {}
    webhook_secret: str | None = None
    patch_management_provider: PatchManagementProvider = PatchManagementProvider.none
    loonsecio_license_key: str | None = None
    loonsecio_data_sharing_enabled: bool = False
    user_agent_override: str | None = None
    capability_devices: bool = True
    capability_users: bool = False
    capability_webhooks: bool = False
    capability_jamf_pro: bool = False

    @model_validator(mode="after")
    def _check_loonsecio(self) -> MdmConnectionCreate:
        validate_loonsecio_requirement(
            self.patch_management_provider, self.loonsecio_license_key, self.loonsecio_data_sharing_enabled
        )
        validate_jamf_specific_fields(self.provider, self.patch_management_provider, self.capability_jamf_pro)
        return self


class MdmConnectionUpdate(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    name: str | None = None
    provider: MdmProvider | None = None
    base_url: str | None = None
    is_active: bool | None = None
    credentials: dict[str, str] | None = None
    webhook_secret: str | None = None
    patch_management_provider: PatchManagementProvider | None = None
    loonsecio_license_key: str | None = None
    loonsecio_data_sharing_enabled: bool | None = None
    user_agent_override: str | None = None
    capability_devices: bool | None = None
    capability_users: bool | None = None
    capability_webhooks: bool | None = None
    capability_jamf_pro: bool | None = None


class MdmConnectionTestRequest(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    connection_id: int | None = None
    provider: MdmProvider
    base_url: str
    client_id: str
    client_secret: str | None = None
    user_agent_override: str | None = None


class MdmSyncTriggerResult(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    connection_id: int
    # The run to poll: GET /api/runs/{jobId} and /api/runs/{jobId}/log.
    job_id: uuid.UUID
    status: str
    # False when this request joined a run that was already in flight rather than
    # starting one. The UI needs the distinction to say "already syncing" instead of
    # implying the click caused the sweep it is now watching.
    started: bool = True


class MdmConnectionTestResult(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    success: bool
    message: str
    detail: str | None = None


class MdmConnectionOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: int
    name: str
    provider: MdmProvider
    base_url: str
    is_active: bool
    patch_management_provider: PatchManagementProvider
    loonsecio_data_sharing_enabled: bool
    credential_fields_set: list[str]
    has_webhook_secret: bool
    has_loonsecio_license_key: bool
    user_agent_override: str | None
    capability_devices: bool
    capability_users: bool
    capability_webhooks: bool
    capability_jamf_pro: bool
    last_successful_auth_at: datetime | None
    credentials_rotated_at: datetime | None
    credentials_fingerprint: str | None
    created_at: datetime
    updated_at: datetime


class ProviderCredentialField(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    key: str
    label: str
    secret: bool


class ProviderInfo(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    provider: MdmProvider
    credential_fields: list[ProviderCredentialField]
