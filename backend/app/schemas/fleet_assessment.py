"""What moving one Mac app's installed builds to a Fleet target version would change, and each
build's patch-rule verdict. No field holds a sentence: the page words every code."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from app.schemas.jamf_patch import PolicyVersionOut
from app.schemas.settings import PatchRule


class FleetBuildAssessmentOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

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
    # Why the build reads `unassessed`; null in every other state.
    policy_unassessed: Literal["identity", "no_jamf_title", "no_rule", "not_judged"] | None = None
    # Set whenever the build matches exactly one Jamf Patch title.
    policy_title_id: str | None = None
    # Set for `within` and `out` only: the title page's own rule and verdict, `policySentence`'s inputs.
    policy_rule: PatchRule | None = None
    policy_verdict: PolicyVersionOut | None = None
    # The first newer Jamf release's date plus the days limit judged by; null without that date.
    policy_due_at: datetime | None = None


class FleetAssessmentOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    target_version: str
    priority: Literal["review_now", "plan_update", "review_identity", "monitor"] = "monitor"
    priority_reason: Literal["none_behind", "unordered", "identity", "out_of_policy", "kev", "comparable"] = "none_behind"
    management: Literal["recurring", "one_time", "observe"] = "observe"
    # Versions Fleet dated in the past 90 days; null until the title's history has been read.
    recent_versions: int | None = None
    corpus_as_of: date | None = None
    behind_builds: int = 0
    unordered_builds: int = 0
    # Age of the earliest newer Jamf release on a confirmed, still-behind line: an open gap, not a rollout's.
    oldest_gap_days: int | None = None
    exact_builds: int = 0
    net_only_builds: int = 0
    unknown_builds: int = 0
    out_of_policy_builds: int = 0
    within_policy_builds: int = 0
    policy_exempt_builds: int = 0
    policy_unassessed_builds: int = 0
    # Assessed older builds only; null when none has an answer. A KEV finding also counts in its band.
    kev_builds: int | None = None
    # Unions of finding IDs across exact pairs only: an ID can leave one build and stay on another.
    # Title-level possibilities under the target, never proof of a host's remediation.
    addresses: int | None = None
    introduces: int | None = None
    remains: int | None = None
    builds: list[FleetBuildAssessmentOut] = Field(default_factory=list)
