"""Jamf-inventoried Mac apps and the Fleet catalog candidates observed for them."""

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from app.schemas.fleet_assessment import FleetAssessmentOut

Clock = Literal["contact", "inventory"]


class ReportModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, from_attributes=True)


class MigrationScope(ReportModel):
    connection_id: int | None = None
    clock: Clock = "contact"
    days: int | None = None
    eligible_macs: int = 0
    active_macs: int = 0
    stale_macs: int = 0
    unknown_macs: int = 0


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
    as_of: date | None
    assessed_builds: int = 0
    unknown_builds: int = 0
    affected_builds: int = 0
    high_or_critical_builds: int = 0
    kev_builds: int = 0


class ReportContext(ReportModel):
    installed_evidence: dict[str, InstalledEvidence] = Field(default_factory=dict)
    enabled: bool = True
    as_of: datetime
    scope: MigrationScope
    fleet_catalog_ready: bool = False
    fleet_catalog_readiness: Literal["unread", "partial", "complete"] = "unread"
    jamf_catalog_ready: bool = False
    app_assessments: dict[str, FleetAssessmentOut] = Field(default_factory=dict)
    assessments: dict[str, FleetAssessmentOut] = Field(default_factory=dict)


class SourceConnection(ReportModel):
    id: int
    name: str


class MigrationReport(ReportContext):
    fleet_device_counts: dict[str, int] = Field(default_factory=dict)
    connections: list[SourceConnection] = Field(default_factory=list)
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
    window_days: int = 90
    version_changes: int = 0
    macs: int = 0
    first_at: datetime | None = None
    last_at: datetime | None = None
    adoption_samples: int = 0
    median_days_after_fleet_publication: float | None = None


class MigrationDetail(ReportContext):
    observed_changes: ObservedChanges
    item: LocalApp | None = None
    title: FleetCandidate | None = None
    items: list[LocalApp]
    builds: list[InstalledBuild]
    jamf_titles: list[JamfTitle]
    installed_macs: int
    impact: VersionImpact | None = None
