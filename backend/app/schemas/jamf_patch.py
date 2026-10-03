from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from app.schemas.payload import VulnEnrichment


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
    # Distinct devices whose match on this title is out of the organization's confirmed
    # patching rule (`app.mdm.patch.policy`). **Null is not zero**: null means nothing judges
    # this title — no rule is confirmed, or the title is exempt — and a zero there would read
    # as a clean bill nobody issued. `policySource` says which rule judged, or `exempt`.
    devices_out_of_policy: int | None = None
    policy_source: Literal["default", "override", "exempt"] | None = None


class JamfPatchTitleListResponse(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    items: list[JamfPatchTitleOut]
    total: int
    # The page and page size echoed, as every paged list does (#137).
    page: int
    page_size: int
    # Whether a corpus is answering for this organization, where a confirmed rule has a
    # limit for builds with critical or high findings; null where none does. False means
    # that limit is judging nothing and every build is judged by the ordinary one.
    severity_answering: bool | None = None


class PolicyVersionOut(BaseModel):
    """One version of the title against the rule that judges it (`policy.Verdict`)."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    state: Literal["within", "out", "not_judged"]
    # Which limit put it out; `days` when both did.
    reason: Literal["days", "releases"] | None = None
    # When it went out of policy by the days limit. Null under the releases limit.
    since: datetime | None = None
    # Whole days a newer release has been listed, and listed releases newer than this one.
    days_behind: int | None = None
    releases_behind: int | None = None
    # The days limit this version was judged by: the severe one or the ordinary one.
    limit_days: int | None = None
    # Whether the build carries a critical or high finding. Null where the corpus has not
    # assessed it (it is then judged by the ordinary limit), and wherever the rule has no
    # severe limit, since nothing was read.
    severe: bool | None = None


class TitlePolicyOut(BaseModel):
    """The rule judging this title, and every version's verdict under it. Absent from the
    response entirely when nothing judges the title."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    source: Literal["default", "override"]
    exempt: bool = False
    max_days_behind: int | None = None
    max_releases_behind: int | None = None
    max_days_behind_severe: int | None = None
    # Whether a corpus is answering for this organization, where the rule has a severe
    # limit; null where it has none. False means the severe limit is judging nothing.
    severity_answering: bool | None = None
    # Listed versions and the unlisted ones a device is on. Empty for an exempt title.
    versions: dict[str, PolicyVersionOut] = Field(default_factory=dict)


class JamfPatchTitleDetailOut(JamfPatchTitleOut):
    patches: list[dict]
    requirements: list[dict]
    extension_attributes: list[dict] | None = None
    # Installed version -> distinct devices, for the devices matched to this title.
    version_device_counts: dict[str, int] = {}
    # Listed version -> the corpus's answer for that build (`app.core.vuln_versions`): the
    # wire's own `vuln{}` block, as every other REST row carries it. Empty, with
    # `corpusAsOf` null, when nothing answers for this organization — `off` for the whole
    # title, said once rather than once a row. Otherwise every listed version has a key.
    version_vulns: dict[str, VulnEnrichment] = Field(default_factory=dict)
    corpus_as_of: date | None = None
    policy: TitlePolicyOut | None = None


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
