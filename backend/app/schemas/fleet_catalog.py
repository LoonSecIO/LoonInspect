from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

FleetCatalogOutcome = Literal["ok", "unchanged", "refused", "unreachable", "unexpected"]
# The version history read's words (#838): `waiting` is leaving GitHub's last requests of the
# hour to the daily check and other tools, and carries on by itself.
FleetHistoryOutcome = Literal["ok", "waiting", "refused", "unreachable", "unexpected"]


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
    # The last version history read, background or a person's (#838): when, its word, and
    # its sentence. All null before the first.
    history_checked_at: datetime | None = None
    history_outcome: FleetHistoryOutcome | None = None
    history_detail: str | None = None


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
    # From the version history read from Fleet's commits (#838), when it holds the latest
    # version: the date Fleet's catalog first carried it, and the version it carried before.
    # Null until the history is read, and for a latest version the history could not date.
    in_catalog_since: datetime | None = None
    version_before: str | None = None
    # When this instance last read the title's history; null: never.
    history_read_at: datetime | None = None


class FleetVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    version: str
    # The date GitHub records for the first commit whose manifest carried this version: when
    # Fleet's catalog took it, not when the vendor released it.
    seen_at: datetime
    commit_sha: str
    # The version the manifest carried at the change before; null at the title's first change.
    previous_version: str | None = None


class FleetTitleHistoryOut(BaseModel):
    """One title's version history as this instance holds it (#838)."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    slug: str
    name: str
    latest_version: str
    # When it was last read (null: never), the oldest and newest change the reads reached,
    # and whether the oldest was the title's first change in Fleet's history.
    history_read_at: datetime | None
    history_since: datetime | None
    history_through: datetime | None
    history_complete: bool
    # What the last read left undated or could not read, in the operator's words.
    history_detail: str | None
    # Newest first.
    versions: list[FleetVersionOut] = []


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
    # Of those, the titles whose version history this instance has read (#838).
    installed_titles_with_history: int = 0
