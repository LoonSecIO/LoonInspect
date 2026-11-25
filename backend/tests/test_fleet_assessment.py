"""Fleet target comparisons and patch-rule verdicts, build by build (#897). Pure; no database."""

from datetime import UTC, datetime, timedelta

import pytest

from app.core.content_keys import app_full_key
from app.core.fleet_assessment import _Build, _Match, _summary
from app.core.vuln import SEVERITY_BANDS, AssessedBuild
from app.mdm.patch.policy import NOT_JUDGED, OUT, WITHIN, Rule, Rules, judge
from app.models.schema import FleetMaintainedApp
from app.schemas.jamf_patch import PolicyVersionOut

NOW = datetime(2026, 11, 22, 12, tzinfo=UTC)
TODAY = NOW.date()
NAME, BUNDLE = "Example.app", "com.example.app"
A, B, C, D = (f"CVE-2026-{n}" for n in range(1001, 1005))


def assessed(ids=(), *, total=None, kev=0, high=0, critical=0):
    total = len(ids) if total is None else total
    bands = {**dict.fromkeys(SEVERITY_BANDS, 0), "critical": critical, "high": high}
    dated = {band: TODAY if count else None for band, count in bands.items()}
    return AssessedBuild(total, kev, bands, TODAY if total else None, dated, tuple(ids), total > len(ids))


def build(version, matches=()):
    return _Build("app", BUNDLE, NAME, version, app_full_key(NAME, BUNDLE, version, None), 5, list(matches))


def match(days_behind, title="line", basis="requirements"):
    return _Match(title, basis, "behind", NOW - timedelta(days=days_behind), 1)


def summarize(installs, evidence, *, rules=None, read=True, shared=False, date=TODAY, include_ids=True):
    title = FleetMaintainedApp(slug="example", bundle_id=BUNDLE, latest_version="3.0", history_read_at=NOW if read else None)
    context = {"shared_bundle": shared, "as_of": date, "rules": rules or Rules(), "now": NOW, "recent": 2, "include_builds": True}
    return _summary(title, "3.0", installs, answers=evidence, include_ids=include_ids, **context)


def test_exact_counts_are_unions_of_ids_across_distinct_comparable_builds():
    one, two, target = build("1.0"), build("2.0"), build("3.0")
    evidence = {one.key: assessed([A, B, C], kev=1, high=2), two.key: assessed([A, C]), target.key: assessed([C, D])}
    result = summarize([one, two, target, build("4.0")], evidence)
    assert (result.behind_builds, result.exact_builds, result.kev_builds) == (2, 2, 1)
    assert (result.addresses, result.introduces, result.remains) == (2, 1, 1)
    assert [(r.addresses, r.introduces, r.remains) for r in result.builds] == [(2, 1, 1), (1, 1, 1)]
    assert [(r.addressed_ids, r.introduced_ids, r.remaining_ids) for r in result.builds] == [([A, B], [D], [C]), ([A], [D], [C])]
    assert (result.priority, result.priority_reason, result.management) == ("review_now", "kev", "recurring")
    assert result.policy_unassessed_builds == 4 and {r.policy_unassessed for r in result.builds} == {"no_jamf_title"}
    # Without access to finding IDs, every count stays and every ID list is withheld.
    counts_only = summarize([one, two, target], evidence, include_ids=False)
    assert [(r.addresses, r.introduces, r.remains) for r in counts_only.builds] == [(2, 1, 1), (1, 1, 1)]
    assert {(r.addressed_ids, r.introduced_ids, r.remaining_ids) for r in counts_only.builds} == {(None, None, None)}


def test_net_only_missing_and_off_are_distinct_from_a_covered_zero():
    one, two, third, target = build("1"), build("2"), build("2.5"), build("3.0")
    evidence = {one.key: assessed([A], total=7), two.key: assessed(), target.key: assessed()}
    result = summarize([one, two, third], evidence, read=False)
    assert [r.comparison for r in result.builds] == ["net_only", "exact", "unknown_source"]
    assert result.builds[0].net == 7 and result.builds[0].addresses is None and result.builds[0].addressed_ids is None
    assert result.builds[1].addresses == result.builds[1].introduces == 0
    assert [r.addressed_ids for r in result.builds] == [None, [], None]
    assert (result.net_only_builds, result.exact_builds, result.unknown_builds) == (1, 1, 1)
    assert result.recent_versions is None and result.management == "one_time"
    assert (result.priority, result.priority_reason) == ("plan_update", "comparable")
    no_target = summarize([one], {one.key: assessed([A])})
    assert no_target.builds[0].comparison == "unknown_target" and no_target.addresses is None
    off = summarize([one], {}, date=None)
    assert off.builds[0].comparison == "off" and off.kev_builds is None


def test_default_override_exemption_and_each_unassessed_reason():
    default = Rule(max_days_behind=90, max_days_behind_severe=14)
    rules = Rules(default=default, overrides={"override": Rule(max_days_behind=30), "skip": Rule(exempt=True)})
    severe, override, exempt = build("1.0", [match(15)]), build("1.1", [match(2, "override")]), build("1.2", [match(40, "skip")])
    unlisted = build("1.3", [_Match("line", "requirements", "unknown", None, None)])
    result = summarize([severe, override, exempt, unlisted, build("1.4")], {severe.key: assessed([A], high=1)}, rules=rules)
    assert [(b.policy_state, b.policy_source, b.policy_unassessed, b.policy_title_id) for b in result.builds] == [
        ("out", "default", None, "line"),
        ("within", "override", None, "override"),
        ("exempt", "override", None, "skip"),
        ("unassessed", "default", "not_judged", "line"),
        ("unassessed", None, "no_jamf_title", None),
    ]
    assert [b.policy_verdict is not None for b in result.builds] == [True, True, False, False, False]
    assert [b.policy_rule and b.policy_rule.max_days_behind for b in result.builds] == [90, 30, None, None, None]
    assert [b.policy_due_at for b in result.builds[:2]] == [NOW - timedelta(days=1), NOW + timedelta(days=28)]
    counts = [result.out_of_policy_builds, result.within_policy_builds, result.policy_exempt_builds]
    assert [*counts, result.policy_unassessed_builds] == [1, 1, 1, 2]
    assert (result.priority, result.priority_reason) == ("review_now", "out_of_policy")
    # A judged build carries exactly the two inputs of main's `policySentence(verdict, rule)`.
    out = result.builds[0]
    assert out.policy_verdict == PolicyVersionOut(
        state="out", reason="days", since=NOW - timedelta(days=1), days_behind=15, releases_behind=1, limit_days=14, severe=True
    )
    wire = out.model_dump(by_alias=True)
    assert wire["policyRule"] == {"maxDaysBehind": 90, "maxReleasesBehind": None, "maxDaysBehindSevere": 14}
    unruled = summarize([build("1.0", [match(15)])], {}).builds[0]
    assert (unruled.policy_state, unruled.policy_unassessed, unruled.policy_title_id) == ("unassessed", "no_rule", "line")


@pytest.mark.parametrize(
    ("rule", "severe", "state", "behind", "missed", "expected"),
    [
        # Review finding BC-3: no limit has anything to count, and the title page reads within.
        (Rule(max_days_behind_severe=14), False, "behind", 40, 1, WITHIN),  # a severe-only rule, a build not severe
        (Rule(max_days_behind_severe=14), None, "behind", 40, 1, WITHIN),  # the same rule, a build with no answer
        (Rule(max_days_behind=14), False, "behind", None, 1, WITHIN),  # a days limit, no first-newer date
        (Rule(max_releases_behind=1), False, "behind", 40, None, WITHIN),  # a releases limit, no count missed
        (Rule(max_days_behind_severe=14), True, "behind", 40, 1, OUT),
        (Rule(max_releases_behind=1), None, "behind", 40, 2, OUT),
        (Rule(max_days_behind=14), True, "unknown", None, None, NOT_JUDGED),
    ],
)
def test_a_builds_verdict_is_what_policy_judge_says_for_the_same_inputs(rule, severe, state, behind, missed, expected):
    first_newer = None if behind is None else NOW - timedelta(days=behind)
    one = build("1.0", [_Match("line", "requirements", state, first_newer, missed)])
    answers = {} if severe is None else {one.key: assessed([A], critical=int(severe))}
    row = summarize([one], answers, rules=Rules(default=rule)).builds[0]
    verdict = judge(state, first_newer, missed, rule, now=NOW, severe=severe)
    assert verdict.state == expected
    assert row.policy_state == {WITHIN: "within", OUT: "out", NOT_JUDGED: "unassessed"}[expected]
    judged = expected != NOT_JUDGED
    assert row.policy_verdict == (PolicyVersionOut.model_validate(verdict, from_attributes=True) if judged else None)
    assert row.policy_unassessed == (None if judged else "not_judged")
    if expected == WITHIN:  # no limit had both a clock and a count to meet, so nothing falls due
        assert row.policy_due_at is None and (row.policy_verdict.days_behind is None) == (behind is None)


def test_overlapping_candidates_and_assumed_detection_withhold_target_and_management():
    for matches, shared in [([match(8), match(10, "esr")], False), ([match(8, basis="ea_assumed")], False), ([], True)]:
        one = build("1", matches)
        evidence = {one.key: assessed([A], kev=1), build("3.0").key: assessed()}
        result = summarize([one], evidence, shared=shared, rules=Rules(default=Rule(max_days_behind=1)))
        assert (result.priority, result.priority_reason, result.management) == ("review_identity", "identity", "observe")
        assert result.builds[0].comparison == "ambiguous" and result.addresses is None and result.kev_builds == 1
        assert (result.builds[0].policy_state, result.builds[0].policy_unassessed) == ("unassessed", "identity")
        assert result.builds[0].policy_title_id == (matches[0].title_id if len(matches) == 1 else None)


def test_target_equal_newer_unorderable_and_prerelease_builds_are_never_behind():
    at_target, newer = build("3.0", [match(4)]), build("4.0", [match(31)])
    installs = [at_target, newer, build("preview"), build("2.0-beta.1")]
    result = summarize(installs, {}, rules=Rules(default=Rule(max_days_behind=14)))
    assert result.behind_builds == result.unknown_builds == 0 and result.builds == []
    assert (result.unordered_builds, result.priority, result.priority_reason) == (2, "monitor", "unordered")
    # Each is still judged against its own Jamf rule, and still counts toward the oldest gap.
    assert result.out_of_policy_builds == result.within_policy_builds == 1 and result.oldest_gap_days == 31
    assert summarize([at_target], {}).priority_reason == "none_behind"
