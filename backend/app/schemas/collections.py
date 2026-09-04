from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class CollectionKind(str, Enum):
    device_sweep = "device_sweep"
    catalog = "catalog"
    webhook = "webhook"


class Frequency(str, Enum):
    hourly = "hourly"
    daily = "daily"
    weekly = "weekly"
    every_n_days = "every_n_days"


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class CollectionCreate(_Base):
    name: str = Field(min_length=1, max_length=255)
    kind: CollectionKind
    enabled: bool = True
    sections: list[str] = []
    selector: str | None = None
    page_size: int | None = Field(default=None, ge=100, le=1000)
    quarantined_extension_attributes: list[str] = []
    frequency: Frequency | None = None
    interval_n: int | None = None
    at_hour: int | None = None
    at_minute: int | None = None
    weekday: int | None = None
    timezone: str | None = None


class CollectionUpdate(_Base):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    enabled: bool | None = None
    sections: list[str] | None = None
    selector: str | None = None
    page_size: int | None = Field(default=None, ge=100, le=1000)
    quarantined_extension_attributes: list[str] | None = None
    frequency: Frequency | None = None
    interval_n: int | None = None
    at_hour: int | None = None
    at_minute: int | None = None
    weekday: int | None = None
    timezone: str | None = None


class CollectionOut(_Base):
    id: int
    mdm_connection_id: int
    name: str
    kind: CollectionKind
    enabled: bool
    sections: list[str]
    selector: str | None
    page_size: int | None
    quarantined_extension_attributes: list[str]
    frequency: Frequency | None
    interval_n: int | None
    at_hour: int | None
    at_minute: int | None
    weekday: int | None
    timezone: str | None
    next_due_at: datetime | None
    last_run_at: datetime | None
    last_run_status: str | None
    last_run_summary: dict | None
    # When this collection last *succeeded* — distinct from last_run_at, which is the
    # last attempt whatever its outcome.
    last_success_at: datetime | None
    # How long without a success before this collection's data is stale: twice its own
    # cadence (#106). Computed from the row's schedule, never stored, so editing the
    # schedule moves the threshold with it. Null means the collection makes no
    # staleness claim — an event-driven webhook has no cadence to double.
    stale_after_seconds: int | None
    created_at: datetime
    updated_at: datetime


class CollectionRunResult(_Base):
    collection_id: int
    status: str  # queued | skipped


class SectionInfo(_Base):
    name: str
    jamf_section: str
    kind: str  # scalar | list
    entry_kind: str | None
    # One of the five inventory-display sections extension attributes nest under. It is
    # read whenever `extension_attributes` is, and the editor says so (#197).
    carries_extension_attributes: bool = False
