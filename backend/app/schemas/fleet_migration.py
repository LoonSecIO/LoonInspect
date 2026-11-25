"""The migration report (#895): installed Jamf Mac apps and the Fleet titles that carry their bundle identifiers."""

from datetime import date, datetime
from typing import Literal

from pydantic import Field

from app.schemas.fleet_assessment import FleetAssessmentOut
from app.schemas.patch_plans import ReportModel


class MigrationScope(ReportModel):
    eligible_macs: int = 0
    selected_macs: int = 0
    unknown_contact_macs: int = 0
    unknown_inventory_macs: int = 0


class FleetCandidate(ReportModel):
    slug: str
    name: str
    bundle_id: str
    latest_version: str


class LocalApp(ReportModel):
    app_hash: str
    name: str
    bundle_id: str
    macs: int
    version_count: int
    match: Literal["exact", "ambiguous", "none", "unknown"]
    has_jamf_match: bool
    jamf_evaluated: bool
    fleet_candidates: list[FleetCandidate]


class InstalledEvidence(ReportModel):
    """One app's builds on the selected Macs, each read through the answer it already stores (#896).

    A build is one version, however many Macs carry it. Installed Apps counts device/build pairs, so a build
    on 500 Macs reads 500 there and 1 here. The three finding counts count builds, never findings summed
    across builds, and are null, never 0, under `off` and `unknown_app`, where nobody looked."""

    assessment: Literal["off", "unknown_app", "partial", "covered"]
    as_of: date | None
    assessed_builds: int = 0
    unknown_builds: int = 0
    affected_builds: int | None = None
    high_or_critical_builds: int | None = None
    kev_builds: int | None = None


class ReportContext(ReportModel):
    enabled: bool = True
    as_of: datetime
    scope: MigrationScope
    fleet_catalog_ready: bool = False
    fleet_catalog_readiness: Literal["unread", "partial", "complete"] = "unread"
    jamf_catalog_ready: bool = False
    # One entry per reported app, keyed by `appHash`, from the same snapshot as the apps.
    installed_evidence: dict[str, InstalledEvidence] = Field(default_factory=dict)
    # One #897 assessment per `exact` app, keyed by `appHash`, against Fleet's current version (#898). The list asks
    # for neither per-build rows nor finding IDs, so each carries counts and codes only, and `builds` is empty.
    app_assessments: dict[str, FleetAssessmentOut] = Field(default_factory=dict)


class MigrationReport(ReportContext):
    fleet_device_counts: dict[str, int] = Field(default_factory=dict)
    items: list[LocalApp] = Field(default_factory=list)


class JamfTitle(ReportModel):
    id: str
    name: str


class InstalledBuild(ReportModel):
    app_hash: str
    version_hash: str
    version: str
    short_version: str | None
    macs: int


class VersionImpact(ReportModel):
    target_version: str
    installed_macs: int
    older_macs: int
    at_or_above_macs: int
    unknown_macs: int


class ObservedChanges(ReportModel):
    """Version moves of the detail's identities on the selected Macs over the last `windowDays` (#900). Both adoption
    fields are null when timing was not measured (no one `exact` Fleet title); measured, nothing paired reads 0 and null."""

    window_days: int
    version_changes: int
    macs: int
    last_at: datetime | None
    adoption_samples: int | None
    median_days_after_fleet_publication: float | None


class MigrationDetail(ReportContext):
    observed_changes: ObservedChanges
    item: LocalApp | None = None
    title: FleetCandidate | None = None
    items: list[LocalApp]
    builds: list[InstalledBuild]
    jamf_titles: list[JamfTitle]
    installed_macs: int
    impact: VersionImpact | None = None
    # Set only when `impact` is null, to say why no Mac is counted against the target.
    impact_unavailable: Literal["catalog_incomplete", "no_fleet_title", "identity_review", "unordered_target"] | None = None
    # The title route's one assessment, keyed by slug: only with a complete catalog and every identity `exact`.
    assessments: dict[str, FleetAssessmentOut] = Field(default_factory=dict)
