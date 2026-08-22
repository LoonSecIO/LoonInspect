from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class DeviceChangeOut(_Base):
    id: int
    mdm_connection_id: int
    subject_kind: str
    subject_id: str
    subject_label: str | None
    serial_number: str | None
    udid: str | None
    span_id: str | None
    previous_span_id: str | None
    observed_at: datetime
    collected_at: datetime
    trigger: str
    section: str
    field: str | None
    entry_kind: str | None
    entry_identity: dict | None
    entry_label: str | None
    change: str
    old_value: dict | None
    new_value: dict | None
    level: str
    details: dict | None
    policy_version: str


class DeviceChangeListResponse(_Base):
    items: list[DeviceChangeOut]
    total: int
    page: int
    page_size: int


class ChangePolicyUpdate(_Base):
    """The whole override document, replaced on PUT. Sparse by construction: only what
    the admin chose is present."""

    minimum_level: str = "normal"
    fields: dict[str, bool] = Field(default_factory=dict)
    entries: dict[str, bool] = Field(default_factory=dict)
    system_apps_individually: bool = False
    muted_groups: list[str] = Field(default_factory=list)
    muted_extension_attributes: list[str] = Field(default_factory=list)


class KnownGroup(_Base):
    id: str
    name: str | None


class KnownExtensionAttribute(_Base):
    definition_id: str
    name: str | None
