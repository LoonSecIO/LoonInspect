"""Compare one Mac app's installed builds with a Fleet target version, build by build, and judge
each against the organization's confirmed patch rule. Pure: its callers read the database.

A build's verdict is its Jamf Patch title page's: `policy.judge` for its one Jamf title, under the
rule `Rules.for_title` picks, never a third, stricter reading (review finding BC-3). Verdicts and
reasons leave as codes, which the page words.

`_ambiguous` flags a bundle identifier more than one Fleet title shares, more than one Jamf title,
or a Jamf match on an assumed extension attribute: build by build, the three identity conditions
`patch_plans.build_snapshot` checks before it offers a Fleet target (`len(candidates) == 1`, no
`assumed` build, `len(ids) <= 1`). Where one holds, neither surface names a Fleet target until the
identity is reviewed: Patch Plans offers none, and here an older build reads `ambiguous` and the
app `review_identity`. The app-level differences between the two rules belong to #895, not here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from app.core.content_keys import app_full_key
from app.core.patch_plans import release_order
from app.core.vuln import AssessedBuild
from app.mdm.patch import policy
from app.mdm.patch.matching import BASIS_REQUIREMENTS
from app.models.schema import FleetMaintainedApp
from app.schemas.fleet_assessment import FleetAssessmentOut, FleetBuildAssessmentOut
from app.schemas.jamf_patch import PolicyVersionOut
from app.schemas.settings import PatchRule


@dataclass(frozen=True)
class _Match:
    title_id: str
    basis: str
    state: str
    first_newer: datetime | None
    missed: int | None


@dataclass
class _Build:
    app_hash: str
    bundle: str
    name: str
    version: str
    key: str
    device_count: int
    matches: list[_Match] = field(default_factory=list)


def _ambiguous(build: _Build, shared_bundle: bool) -> bool:
    return shared_bundle or len(build.matches) > 1 or any(match.basis != BASIS_REQUIREMENTS for match in build.matches)


def _policy(
    row: FleetBuildAssessmentOut, build: _Build, rules: policy.Rules, source: AssessedBuild | None, now: datetime, ambiguous: bool
) -> None:
    """Stamp `row` with the verdict for the build's one Jamf title. An exempt override reads
    `exempt` before anything is judged, where `judge` would say not judged. Unknown is not severe."""
    if len(build.matches) == 1:
        row.policy_title_id = build.matches[0].title_id
    if ambiguous or not build.matches:
        row.policy_unassessed = "identity" if ambiguous else "no_jamf_title"
        return
    match = build.matches[0]
    rule, row.policy_source = rules.for_title(match.title_id)
    if rule is None:
        row.policy_unassessed = "no_rule"
        return
    if rule.exempt:
        row.policy_state = "exempt"
        return
    severe = source.severity["critical"] + source.severity["high"] > 0 if source is not None else None
    verdict = policy.judge(match.state, match.first_newer, match.missed, rule, now=now, severe=severe)
    if verdict.state == policy.NOT_JUDGED:
        row.policy_unassessed = "not_judged"
        return
    row.policy_state = "out" if verdict.state == policy.OUT else "within"
    row.policy_rule = PatchRule.model_validate(rule.stored())
    row.policy_verdict = PolicyVersionOut.model_validate(verdict, from_attributes=True)
    if match.first_newer is not None and verdict.limit_days is not None:
        row.policy_due_at = match.first_newer + timedelta(days=verdict.limit_days)


def _summary(
    title: FleetMaintainedApp,
    target: str,
    builds: Sequence[_Build],
    *,
    shared_bundle: bool,
    answers: Mapping[str, AssessedBuild],
    as_of: date | None,
    rules: policy.Rules,
    now: datetime,
    recent: int,
    include_builds: bool,
    include_ids: bool,
) -> FleetAssessmentOut:
    """One assessment of `builds` against `target`. `answers` is keyed by `key_full`. An installed
    build's entry is its served stored answer, the one the Jamf Patch title page reads severity
    from. The target's, under `app_full_key(name, bundle, target, None)`, is the library's answer
    for the target version from the same epoch, or a scoped build's own where one carries that
    key. A key with no entry is unanswered, never clean."""
    result = FleetAssessmentOut(
        target_version=target, corpus_as_of=as_of, recent_versions=recent if title.history_read_at else None
    )
    addressed, introduced, remaining = set[str](), set[str](), set[str]()
    ambiguous_count = 0
    for build in builds:
        ambiguous = _ambiguous(build, shared_bundle)
        source = answers.get(build.key)
        after = answers.get(app_full_key(build.name, build.bundle, target, None))
        row = FleetBuildAssessmentOut(name=build.name, version=build.version, device_count=build.device_count, comparison="off")
        row.installed_kev = source.kev if source is not None else None
        _policy(row, build, rules, source, now, ambiguous)
        result.out_of_policy_builds += int(row.policy_state == "out")
        result.within_policy_builds += int(row.policy_state == "within")
        result.policy_exempt_builds += int(row.policy_state == "exempt")
        result.policy_unassessed_builds += int(row.policy_state == "unassessed")
        if not ambiguous and len(build.matches) == 1:
            match = build.matches[0]
            if match.state == "behind" and match.first_newer and match.first_newer <= now:
                result.oldest_gap_days = max(result.oldest_gap_days or 0, (now - match.first_newer).days)
        order = release_order(build.version, target)
        result.unordered_builds += int(order is None)
        if order is None or order >= 0:
            continue
        result.behind_builds += 1
        if source is not None:
            result.kev_builds = (result.kev_builds or 0) + int(source.kev > 0)
        if ambiguous:
            ambiguous_count += 1
            row.comparison = "ambiguous"
        elif as_of is not None:
            if source is None:
                row.comparison = "unknown_source"
            elif after is None:
                row.comparison = "unknown_target"
            elif source.truncated or after.truncated:
                row.comparison = "net_only"
                row.net = source.total - after.total
                result.net_only_builds += 1
            else:
                before_ids, after_ids = set(source.ids), set(after.ids)
                closes, opens, persists = before_ids - after_ids, after_ids - before_ids, before_ids & after_ids
                row.comparison = "exact"
                row.addresses, row.introduces, row.remains = len(closes), len(opens), len(persists)
                if include_builds and include_ids:
                    row.addressed_ids, row.introduced_ids, row.remaining_ids = sorted(closes), sorted(opens), sorted(persists)
                addressed.update(closes)
                introduced.update(opens)
                remaining.update(persists)
                result.exact_builds += 1
        if include_builds:
            result.builds.append(row)
    result.unknown_builds = result.behind_builds - result.exact_builds - result.net_only_builds
    if result.exact_builds:
        result.addresses, result.introduces, result.remains = len(addressed), len(introduced), len(remaining)
    if ambiguous_count:
        result.priority, result.priority_reason = "review_identity", "identity"
    elif result.behind_builds:
        result.management = "recurring" if result.recent_versions is not None and recent >= 2 else "one_time"
        if result.out_of_policy_builds:
            result.priority, result.priority_reason = "review_now", "out_of_policy"
        elif result.kev_builds:
            result.priority, result.priority_reason = "review_now", "kev"
        else:
            result.priority, result.priority_reason = "plan_update", "comparable"
    elif result.unordered_builds:
        result.priority_reason = "unordered"
    return result
