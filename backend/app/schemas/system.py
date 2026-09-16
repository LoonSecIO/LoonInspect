from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class VersionOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    version: str


class UpdateStatusOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    enabled: bool
    current_version: str
    # None is "unknown", and `reason` says which. False means "checked, and this build
    # contains the latest published release". The banner treats None as nothing-to-say,
    # never as an error; Settings > Support's Updates block names the reason (#407).
    update_available: bool | None
    # The commit the latest release's tag points at (#407: a release, no longer main's HEAD).
    latest_sha: str | None
    checked_at: datetime | None
    # The latest published release: its tag and its page — "what changed" (#407).
    latest_tag: str | None = None
    release_url: str | None = None
    # Why `update_available` is None: `disabled` (UPDATE_CHECK=false), `dev_build` (no
    # comparable commit in the stamp), `unreachable`, `refused` (403/429, usually the shared
    # rate limit), `no_release` (none published yet), `unknown_commit` (GitHub does not know
    # this build's commit). Null whenever the check answered.
    reason: Literal["disabled", "dev_build", "unreachable", "refused", "no_release", "unknown_commit"] | None = None


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


class ExclusionCandidateAppOut(BaseModel):
    """One title no public source on this container knows (#483): its name, the bundle ID
    a glob would have to match, the devices carrying it, and why it is listed. `reason` is
    `no_public_source` today — the only reason there is — and a client that does not know a
    value shows the row without the tag rather than hiding it."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    name: str
    bundle_id: str
    device_count: int
    reason: str


class ExclusionCandidateGroupOut(BaseModel):
    """Unknown titles under one reverse-DNS prefix. `suggestion` is null where the prefix
    does not earn one — a single unknown title, or a prefix some title a public source DOES
    know already uses — and `excluded` means a glob in the box already removes them all."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    prefix: str
    suggestion: str | None
    excluded: bool
    app_count: int
    device_count: int
    apps: list[ExclusionCandidateAppOut]


class ExclusionGlobCountOut(BaseModel):
    """What one glob matches, counted with the exchange's own `_excluded`. `source` is
    `typed` (it is in the box) or `suggested` (this page proposed it and nothing is saved).
    `case_misses` are bundle IDs it would match if either side were lower-cased: the Linux
    container's `fnmatch` is case-sensitive, so these are the quiet misses."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    glob: str
    source: str
    app_count: int
    device_count: int
    case_misses: list[str]


class ExclusionCandidatesOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    groups: list[ExclusionCandidateGroupOut]
    more_groups: int
    globs: list[ExclusionGlobCountOut]
    # What "unknown" was decided against, so an empty list is a legible state and not a
    # blank panel: with no catalog synced and no epoch loaded nothing here is known, and
    # the page names the missing source instead of calling the whole fleet public.
    catalog_titles: int
    library_titles: int


class DataSharingUpdate(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    tier: SharingTier | None = None
    exclude_globs: list[str] | None = None
    ai_inference: bool | None = None
