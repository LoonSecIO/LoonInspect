"""Projected update effects for one Fleet target and the older installed builds in scope."""

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class _Out(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class FleetBuildAssessmentOut(_Out):
    name: str
    version: str
    device_count: int
    comparison: Literal["exact", "net_only", "off", "unknown_source", "unknown_target", "ambiguous"]
    addresses: int | None = None
    introduces: int | None = None
    remains: int | None = None
    addressed_ids: list[str] | None = None
    introduced_ids: list[str] | None = None
    remaining_ids: list[str] | None = None
    net: int | None = None
    installed_kev: int | None = None
    policy_state: Literal["within", "out", "exempt", "unassessed"] = "unassessed"
    policy_source: Literal["default", "override"] | None = None
    policy_reason: str
    policy_due_at: datetime | None = None


class FleetAssessmentOut(_Out):
    target_version: str
    priority: Literal["review_now", "plan_update", "review_identity", "monitor"] = "monitor"
    reason: str
    management: Literal["recurring", "one_time", "observe"] = "observe"
    management_reason: str
    recent_versions: int | None = None
    history_read_at: datetime | None = None
    history_since: datetime | None = None
    history_through: datetime | None = None
    history_complete: bool = False
    history_detail: str | None = None
    corpus_as_of: date | None = None
    behind_builds: int = 0
    unordered_builds: int = 0
    # Age of the earliest newer Jamf release on a confirmed, still-behind line.
    # This is an outstanding gap, never the duration of a completed deployment.
    oldest_gap_days: int | None = None
    exact_builds: int = 0
    net_only_builds: int = 0
    unknown_builds: int = 0
    out_of_policy_builds: int = 0
    within_policy_builds: int = 0
    policy_exempt_builds: int = 0
    policy_unassessed_builds: int = 0
    # Null when none of the older installed builds has a corpus answer. Includes
    # only assessed builds. A KEV-listed finding also belongs in its severity band.
    kev_builds: int | None = None
    # Each is a union of finding IDs across EXACT pairs only. An ID can disappear
    # from one installed build and remain on another. These are title-level
    # possibilities under the target, never proof of a host's remediation.
    addresses: int | None = None
    introduces: int | None = None
    remains: int | None = None
    builds: list[FleetBuildAssessmentOut] = Field(default_factory=list)
