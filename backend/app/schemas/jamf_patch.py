from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class JamfPatchTitleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    id: str
    name: str
    publisher: str | None
    app_name: str | None
    # Where `app_name` came from (#478, over the column #385 writes): `jamf`, `kill_apps`,
    # `unnamed`, or NULL on a row stored before that rule existed. Served because the page
    # cannot otherwise tell a name Jamf published from one LoonInspect read out of the
    # patches' `killApps`, and only the second is a possible miss (docs/app-catalog.md §2a).
    # Camel-cased to `appNameSource` by the alias generator above; the wire vocabulary
    # freeze (#188) is about the Splunk wire and not this response, but the spelling obeys
    # the same rule. Defaulted so a construction that predates the field still builds.
    app_name_source: str | None = None
    bundle_id: str | None
    current_version: str
    last_modified: str
    synced_at: datetime
    # Tenant-scoped: distinct devices with an app matched to this title, and how many of them
    # are on the title's current version.
    device_count: int = 0
    devices_on_latest: int = 0
    # Distinct devices whose match on this title is `behind` (#314). Shipped BESIDE the pair
    # above rather than left to be derived, because `deviceCount - devicesOnLatest` is the
    # obvious derivation and it is wrong: a Mac running a build NEWER than Jamf publishes is
    # not on latest and is not behind either. Chrome on the reference tenant reads
    # `deviceCount 1, devicesOnLatest 0` — one implied laggard, zero actual ones — and Chrome
    # and Safari sit in that state on essentially every Mac fleet, because they auto-update
    # ahead of the catalog. The posture tape had the same bug under the name
    # `patch.titles_with_laggards` and #314 corrected it; this is the surface that fed it, and
    # https://github.com/LoonSecIO/LoonInspect/issues/110's tile is specified to rank by the
    # subtraction, so the honest number has to exist before that tile does.
    devices_behind: int = 0


class JamfPatchTitleListResponse(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    items: list[JamfPatchTitleOut]
    total: int
    # The page and page size echoed, as every paged list does (#137).
    page: int
    page_size: int


class JamfPatchTitleDetailOut(JamfPatchTitleOut):
    patches: list[dict]
    requirements: list[dict]
    extension_attributes: list[dict] | None = None
    # Installed version -> distinct devices, for the devices matched to this title.
    version_device_counts: dict[str, int] = {}


class JamfPatchCoverageOut(BaseModel):
    """The two inputs the Overview's coverage tile derives its ratio from (#109), at the
    pair grain the posture recorder writes `patch.pairs_total` / `patch.pairs_on_latest`
    at, from the same function — one definition, live and recorded."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    pairs_total: int
    pairs_on_latest: int


class JamfPatchSyncResult(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    synced: int
