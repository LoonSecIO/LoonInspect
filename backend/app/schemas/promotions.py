from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class _Model(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class PromotionCreate(_Model):
    # The `app.title` key of a title this organization has installed. The name and bundle ID
    # that leave are read from inventory by it, never taken from the request.
    key_title: str = Field(pattern=r"^v1:[0-9a-f]{64}$")


class PromotionOut(_Model):
    """One promoted application, and whether the next exchange carries it."""

    id: uuid.UUID
    key_title: str
    app_name: str
    bundle_id: str
    promoted_at: datetime
    promoted_by: str | None
    # Devices that have the title now, and how many versions of it they run: what the
    # `promotions` row would list.
    device_count: int
    version_count: int
    # Why this title is held back although promoted: an exclusion pattern matches it
    # (`excluded_by` names the pattern), or nothing has it installed any more.
    held: Literal["excluded", "not_installed"] | None
    excluded_by: str | None


class PromotionCandidateOut(_Model):
    """An installed title that could be promoted. `known` is whether a public source on this
    container already knows it (a Jamf Patch title matches a build of it, or the loaded
    vulnerability library names it): the ones nothing knows are listed first."""

    key_title: str
    app_name: str
    bundle_id: str
    device_count: int
    known: bool
    excluded_by: str | None


class PromotionsOut(_Model):
    # The `app_promotion` flag. Off: nothing can be promoted and nothing promoted leaves.
    enabled: bool
    # Why no promotion is leaving at all (`flag_off`, `env_disabled`, `sharing_off`), or null
    # when the next exchange carries the ones not held back.
    paused: Literal["flag_off", "env_disabled", "sharing_off"] | None
    limit: int
    items: list[PromotionOut]
    candidates: list[PromotionCandidateOut]
    more_candidates: int
