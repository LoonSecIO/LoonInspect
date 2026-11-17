from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

FleetCatalogOutcome = Literal["ok", "unchanged", "refused", "unreachable", "unexpected"]


class FleetCatalogStateOut(BaseModel):
    """What the last check of Fleet's catalogue found (#794). Absent from the page's answer
    before the first check, which is its own state and not an empty one."""

    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    # When GitHub was last asked, whatever it answered.
    checked_at: datetime | None
    # When the titles held here last changed. Older than `checkedAt` on a day Fleet changed
    # nothing, and on a day the check failed.
    changed_at: datetime | None
    # `ok` and `unchanged` are answers. The other three are a check that got none, and
    # `detail` is then the sentence: what failed, why, and what to check.
    outcome: FleetCatalogOutcome | None
    # On `ok` it can carry a sentence too: manifests that could not be read and were left.
    detail: str | None
    app_count: int


class FleetCatalogTitleOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    slug: str
    name: str
    bundle_id: str
    latest_version: str
    # The version before the last move this instance saw, and when it saw it. Both null
    # until the version moves while this instance is watching: the first reading of a
    # title is not a move.
    previous_version: str | None
    version_changed_at: datetime | None
    first_seen_at: datetime
    # This organization's Macs with the title installed, matched on the bundle identifier.
    device_count: int = 0
    # Of those, the Macs with any copy older than Fleet's latest version, and the rest.
    # Shipped as a pair so neither is derived by subtraction on the page.
    devices_behind: int = 0
    devices_current: int = 0


class FleetCatalogOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    # The `fleet_maintained_apps` flag for this organization. False answers no state and no
    # titles, whatever the instance holds for another organization.
    enabled: bool
    # The repository the catalogue is read from, for the page's status line.
    source: str
    state: FleetCatalogStateOut | None = None
    items: list[FleetCatalogTitleOut] = []
    total: int = 0
    page: int = 1
    page_size: int = 50
    # Titles with at least one of this organization's Macs, before `q` narrows the list:
    # what tells "nothing Fleet lists is installed here" from "nothing matches the search".
    installed_titles: int = 0
