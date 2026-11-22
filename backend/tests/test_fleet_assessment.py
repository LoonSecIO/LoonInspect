"""Evidence semantics for Fleet-to-installed build projections."""

from datetime import UTC, datetime, timedelta

from app.core.content_keys import app_full_key
from app.core.fleet_assessment import _Build, _Match, _summary
from app.core.vuln import SEVERITY_BANDS, AssessedBuild
from app.mdm.patch.policy import Rule, Rules
from app.models.schema import FleetMaintainedApp

NOW = datetime(2026, 11, 22, 12, tzinfo=UTC)
TODAY = NOW.date()
NAME, BUNDLE = "Example.app", "com.example.app"
A, B, C, D = (f"CVE-2026-{n}" for n in range(1001, 1005))


def assessed(ids=(), *, total=None, kev=0, high=0):
    total = len(ids) if total is None else total
    bands = dict.fromkeys(SEVERITY_BANDS, 0)
    bands["high"] = high
    return AssessedBuild(
        total=total,
        kev=kev,
        severity=bands,
        ids=tuple(ids),
        truncated=total > len(ids),
        oldest_published=NOW.date() if total else None,
        oldest_published_severity={band: NOW.date() if count else None for band, count in bands.items()},
    )


def build(version, matches=()):
    return _Build("app", BUNDLE, NAME, version, app_full_key(NAME, BUNDLE, version, None), 5, list(matches))


def match(days_behind, title="line", basis="requirements"):
    return _Match(title, basis, "behind", NOW - timedelta(days=days_behind), 1)


def summarize(installs, evidence, *, rules=None, read=True, shared=False, date=TODAY, include_ids=True):
    title = FleetMaintainedApp(
        slug="example",
        bundle_id=BUNDLE,
        latest_version="3.0",
        history_read_at=NOW if read else None,
        history_complete=False,
    )
    return _summary(
        title,
        "3.0",
        installs,
        shared_bundle=shared,
        answers=evidence,
        as_of=date,
        rules=rules or Rules(),
        now=NOW,
        recent=2,
        include_builds=True,
        include_ids=include_ids,
    )


def test_exact_counts_are_unions_of_ids_across_distinct_comparable_builds():
    one, two, target = build("1.0"), build("2.0"), build("3.0")
    result = summarize(
        [one, two, target, build("4.0")],
        {one.key: assessed([A, B, C], kev=1, high=2), two.key: assessed([A, C]), target.key: assessed([C, D])},
    )
    assert (result.behind_builds, result.exact_builds, result.kev_builds) == (2, 2, 1)
    assert (result.addresses, result.introduces, result.remains) == (2, 1, 1)
    assert [(r.addresses, r.introduces, r.remains) for r in result.builds] == [(2, 1, 1), (1, 1, 1)]
    assert [(r.addressed_ids, r.introduced_ids, r.remaining_ids) for r in result.builds] == [([A, B], [D], [C]), ([A], [D], [C])]
    assert result.priority == "review_now" and result.management == "recurring"
    assert result.policy_unassessed_builds == 4


def test_net_only_missing_and_off_are_distinct_from_a_covered_zero():
    one, two, third, target = build("1"), build("2"), build("2.5"), build("3.0")
    result = summarize(
        [one, two, third], {one.key: assessed([A], total=7), two.key: assessed(), target.key: assessed()}, read=False
    )
    assert [r.comparison for r in result.builds] == ["net_only", "exact", "unknown_source"]
    assert result.builds[0].net == 7 and result.builds[0].addresses is None and result.builds[0].addressed_ids is None
    assert result.builds[1].addresses == result.builds[1].introduces == 0
    assert [r.addressed_ids for r in result.builds] == [None, [], None]
    assert (result.net_only_builds, result.exact_builds, result.unknown_builds) == (1, 1, 1)
    assert result.recent_versions is None and result.management == "one_time"
    no_target = summarize([one], {one.key: assessed([A])})
    assert no_target.builds[0].comparison == "unknown_target" and no_target.addresses is None
    off = summarize([one], {}, date=None)
    assert off.builds[0].comparison == "off" and off.kev_builds is None


def test_without_id_access_an_exact_pair_exposes_counts_only():
    one, target = build("1"), build("3.0")
    answer = summarize([one], {one.key: assessed([A, B]), target.key: assessed([B, C])}, include_ids=False).builds[0]
    assert (answer.addresses, answer.introduces, answer.remains) == (1, 1, 1)
    assert (answer.addressed_ids, answer.introduced_ids, answer.remaining_ids) == (None, None, None)


def test_jamf_default_override_exemption_and_clock_require_evidence():
    default = Rule(max_days_behind=90, max_days_behind_severe=14)
    rules = Rules(default=default, overrides={"override": Rule(max_days_behind=30), "skip": Rule(exempt=True)})
    current_gap = build("1.0", [match(15)])
    override = build("1.1", [match(2, "override")])
    exempt = build("1.2", [match(40, "skip")])
    unknown_clock = build("1.3", [_Match("line", "requirements", "behind", None, None)])
    result = summarize([current_gap, override, exempt, unknown_clock], {current_gap.key: assessed([A], high=1)}, rules=rules)
    assert [(b.policy_state, b.policy_source) for b in result.builds] == [
        ("out", "default"),
        ("within", "override"),
        ("exempt", "override"),
        ("unassessed", "default"),
    ]
    assert result.builds[0].policy_due_at == NOW - timedelta(days=1)
    assert result.builds[1].policy_due_at == NOW + timedelta(days=28)
    assert (
        result.out_of_policy_builds
        == result.within_policy_builds
        == result.policy_exempt_builds
        == result.policy_unassessed_builds
        == 1
    )
    assert result.priority == "review_now"


def test_overlapping_candidates_and_assumed_detection_withhold_target_and_management():
    for matches, shared in [([match(8), match(10, "esr")], False), ([match(8, basis="ea_assumed")], False), ([], True)]:
        one = build("1", matches)
        result = summarize([one], {one.key: assessed([A], kev=1), build("3.0").key: assessed()}, shared=shared)
        assert result.priority == "review_identity" and result.management == "observe"
        assert result.builds[0].comparison == "ambiguous" and result.builds[0].policy_state == "unassessed"
        assert result.addresses is None and result.kev_builds == 1


def test_empty_current_and_unorderable_are_not_treated_as_patch_candidates():
    result = summarize([build("3.0"), build("preview")], {})
    assert result.behind_builds == result.unknown_builds == 0
    assert result.unordered_builds == 1 and result.priority == "monitor" and result.builds == []


def test_installed_at_fleet_target_can_meet_or_miss_its_own_jamf_rule():
    recent = build("3.0", [match(4)])
    old = build("4.0", [match(31)])
    result = summarize([recent, old], {}, rules=Rules(default=Rule(max_days_behind=14)))
    assert result.behind_builds == 0 and result.builds == []
    assert result.out_of_policy_builds == result.within_policy_builds == 1
    assert result.oldest_gap_days == 31


def test_prerelease_qualifiers_are_unordered_against_a_different_version():
    from app.core.fleet_migration import release_order

    assert release_order("8.10.36-beta.1", "8.10.36") is None
    assert release_order("v8.10.34", "8.10.36") < 0
    assert release_order("2.0 (124)", "2.0 (124)") == 0
    assert release_order("2.1", "2.1.0") == 0
    result = summarize([build("2.0-beta.1")], {})
    assert result.unordered_builds == 1 and result.behind_builds == 0
