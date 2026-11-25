"""The migration report (#895): installed Jamf Mac apps and the Fleet titles that carry their bundle identifiers."""

from datetime import datetime
from typing import Literal

from pydantic import Field

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


class ReportContext(ReportModel):
    enabled: bool = True
    as_of: datetime
    scope: MigrationScope
    fleet_catalog_ready: bool = False
    fleet_catalog_readiness: Literal["unread", "partial", "complete"] = "unread"
    jamf_catalog_ready: bool = False


class MigrationReport(ReportContext):
    fleet_device_counts: dict[str, int] = Field(default_factory=dict)
    items: list[LocalApp] = Field(default_factory=list)
