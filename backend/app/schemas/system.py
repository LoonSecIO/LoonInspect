from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class VersionOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    version: str


class UpdateStatusOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    enabled: bool
    current_version: str
    # None is "unknown" — checking disabled, a dev build, or the provider was
    # unreachable. False means "checked and current". The UI treats None as
    # nothing-to-say, never as an error.
    update_available: bool | None
    latest_sha: str | None
    checked_at: datetime | None


class SharingTier(StrEnum):
    off = "off"
    keys = "keys"
    reveal = "reveal"


class DataSharingOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    tier: SharingTier
    submission_uuid: str
    exclude_globs: list[str]
    # COMMUNITY_SHARING=false wins over the stored tier; the UI shows this as the
    # reason the control is locked rather than silently reporting tier "off".
    env_disabled: bool
    # AI-inference consent (INSPECT-0112): whether any byte may leave the pod for
    # inference. Distinct from the ai_features flag, which only turns the area on.
    ai_inference: bool
    last_exchange_at: datetime | None = None
    last_exchange_outcome: str | None = None
    # Whether that last exchange had to shed its reveals to a 413 (INSPECT-0083). The
    # page says so beside the outcome: "sent" alone would report a degraded day as a
    # whole one, and the share log is the only other place the difference shows.
    last_exchange_reveals_shed: bool = False
    # Why that last exchange failed, in the sentence the share-log row carries (#408).
    # Before, the page said "(failed)" and the reason lived only in the NDJSON download.
    last_exchange_error: str | None = None


class ShareLogEntryOut(BaseModel):
    """One share-log row, in the NDJSON download's field names — Send now answers with the
    row its exchange wrote, and the download and the answer are the same record."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, from_attributes=True)

    occurred_at: datetime
    tier: str
    trigger: str | None
    endpoint: str
    outcome: str
    payload: dict | None
    reveals_shed: bool
    reveal_requests: list | None
    error: str | None


class SendExchangeOut(BaseModel):
    """Send now's answer: the row it wrote, and the settings as they now read, so the
    page's *Last exchange* line and the row cannot disagree."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    exchange: ShareLogEntryOut
    settings: DataSharingOut


class DataSharingUpdate(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    tier: SharingTier | None = None
    exclude_globs: list[str] | None = None
    ai_inference: bool | None = None
