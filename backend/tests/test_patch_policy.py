"""The patching rules' pure half (`app.mdm.patch.policy`): what a rule can say, what a
stored one reads back as, and the verdict for one (build, title) pair. No database."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.mdm.patch.matching import STATE_AHEAD, STATE_BEHIND, STATE_LATEST, STATE_UNKNOWN
from app.mdm.patch.policy import NOT_JUDGED, OUT, REASON_DAYS, REASON_RELEASES, WITHIN, Rule, Rules, judge, rule_from

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
TWO_WEEKS = Rule(max_days_behind=14)


def _days_ago(days: int) -> datetime:
    return NOW - timedelta(days=days)


def test_a_build_goes_out_of_policy_the_day_after_the_limit_and_says_since_when() -> None:
    assert judge(STATE_BEHIND, _days_ago(14), 1, TWO_WEEKS, now=NOW).state == WITHIN
    late = judge(STATE_BEHIND, _days_ago(40), 3, TWO_WEEKS, now=NOW)
    assert (late.state, late.reason, late.days_behind, late.releases_behind) == (OUT, REASON_DAYS, 40, 3)
    # Out since the first newer release's date plus the limit — not since today.
    assert late.since == _days_ago(40) + timedelta(days=14)


def test_the_releases_limit_counts_listed_releases_and_carries_no_date() -> None:
    one_back = Rule(max_releases_behind=1)
    assert judge(STATE_BEHIND, _days_ago(400), 1, one_back, now=NOW).state == WITHIN
    late = judge(STATE_BEHIND, _days_ago(2), 2, one_back, now=NOW)
    assert (late.state, late.reason, late.since) == (OUT, REASON_RELEASES, None)


def test_either_limit_is_enough_and_days_is_the_reason_when_both_are_past() -> None:
    both = Rule(max_days_behind=14, max_releases_behind=1)
    assert judge(STATE_BEHIND, _days_ago(40), 5, both, now=NOW).reason == REASON_DAYS
    assert judge(STATE_BEHIND, _days_ago(3), 5, both, now=NOW).reason == REASON_RELEASES
    assert judge(STATE_BEHIND, _days_ago(3), 1, both, now=NOW).state == WITHIN


def test_latest_and_ahead_are_within_and_an_unlisted_older_build_is_not_judged() -> None:
    assert judge(STATE_LATEST, None, 0, TWO_WEEKS, now=NOW).state == WITHIN
    assert judge(STATE_AHEAD, None, 0, TWO_WEEKS, now=NOW).state == WITHIN
    # `unknown` carries a date the matcher guessed from a version comparison; the rule does
    # not judge on it, as `patch.pairs_laggard_over_14d` does not.
    assert judge(STATE_UNKNOWN, _days_ago(400), 9, TWO_WEEKS, now=NOW).state == NOT_JUDGED


def test_no_rule_and_an_exempt_title_judge_nothing_and_a_missing_date_cannot_put_a_build_out() -> None:
    assert judge(STATE_BEHIND, _days_ago(400), 9, None, now=NOW).state == NOT_JUDGED
    assert judge(STATE_BEHIND, _days_ago(400), 9, Rule(exempt=True), now=NOW).state == NOT_JUDGED
    assert judge(STATE_BEHIND, None, None, Rule(max_days_behind=0, max_releases_behind=0), now=NOW).state == WITHIN


def test_a_titles_own_rule_replaces_the_organizations_and_exempt_is_named() -> None:
    rules = Rules.from_stored(
        {
            "default": {"max_days_behind": 14, "max_releases_behind": None, "exempt": False},
            "overrides": {
                "0BC": {"max_days_behind": None, "max_releases_behind": 2, "exempt": False},
                "XCODE": {"max_days_behind": None, "max_releases_behind": None, "exempt": True},
            },
        }
    )
    assert rules.for_title("ANY") == (Rule(max_days_behind=14), "default")
    # Replaced, not merged: the override's days limit is null and stays null.
    assert rules.for_title("0BC") == (Rule(max_releases_behind=2), "override")
    assert rules.for_title("XCODE") == (Rule(exempt=True), "override")
    assert rules.judges


@pytest.mark.parametrize(
    "stored",
    [None, "14 days", {"default": "14"}, {"default": {"max_days_behind": -1}}, {"default": {"max_days_behind": True}},
     {"default": {"max_days_behind": 99999}}, {"default": {"exempt": True}}, {"overrides": {"0BC": {}}}],
)  # fmt: skip
def test_a_stored_document_that_is_not_this_modules_judges_nothing_rather_than_raising(stored) -> None:
    rules = Rules.from_stored(stored)
    assert rules.for_title("0BC") == (None, None)
    assert not rules.judges


def test_a_rule_round_trips_through_its_stored_shape() -> None:
    rule = Rule(max_days_behind=30, max_releases_behind=2)
    assert rule_from(rule.stored()) == rule
    assert rule_from(Rule().stored()) is None


def test_the_request_shapes_refuse_what_cannot_be_judged() -> None:
    from app.schemas.settings import PatchRule, PatchRuleOverride

    assert PatchRule().max_days_behind is None  # both null is how the rule is cleared
    for bad in ({"maxDaysBehind": -1}, {"maxDaysBehind": 3651}, {"maxReleasesBehind": 1001}, {"maxDaysBehind": "soon"}):
        with pytest.raises(ValidationError):
            PatchRule.model_validate(bad)
    assert PatchRuleOverride.model_validate({"exempt": True}).exempt
    assert PatchRuleOverride.model_validate({"maxDaysBehind": 30}).max_days_behind == 30
    with pytest.raises(ValidationError, match="carries no limits"):
        PatchRuleOverride.model_validate({"exempt": True, "maxDaysBehind": 30})
    with pytest.raises(ValidationError, match="delete the override"):
        PatchRuleOverride.model_validate({})


# --- the severe limit ----------------------------------------------------------------------

SPLIT = Rule(max_days_behind=60, max_days_behind_severe=14)


def test_a_severe_build_takes_the_tighter_limit_and_the_verdict_says_which_limit_judged_it() -> None:
    severe = judge(STATE_BEHIND, _days_ago(30), 1, SPLIT, now=NOW, severe=True)
    assert (severe.state, severe.reason, severe.limit_days, severe.severe) == (OUT, REASON_DAYS, 14, True)
    assert severe.since == _days_ago(30) + timedelta(days=14)
    # The same build with nothing critical or high against it has 60 days, and is within.
    plain = judge(STATE_BEHIND, _days_ago(30), 1, SPLIT, now=NOW, severe=False)
    assert (plain.state, plain.limit_days, plain.severe) == (WITHIN, 60, False)


def test_a_build_the_corpus_has_not_assessed_is_not_severe_and_says_so() -> None:
    unknown = judge(STATE_BEHIND, _days_ago(30), 1, SPLIT, now=NOW, severe=None)
    assert (unknown.state, unknown.limit_days, unknown.severe) == (WITHIN, 60, None)
    assert judge(STATE_BEHIND, _days_ago(61), 1, SPLIT, now=NOW, severe=None).state == OUT


def test_a_severe_limit_alone_judges_only_severe_builds() -> None:
    only = Rule(max_days_behind_severe=14)
    assert only.judges
    assert judge(STATE_BEHIND, _days_ago(30), 1, only, now=NOW, severe=True).state == OUT
    within = judge(STATE_BEHIND, _days_ago(400), 9, only, now=NOW, severe=False)
    assert (within.state, within.limit_days) == (WITHIN, None)


def test_a_rule_with_no_severe_limit_reads_no_severity_at_all() -> None:
    verdict = judge(STATE_BEHIND, _days_ago(30), 1, TWO_WEEKS, now=NOW, severe=True)
    assert (verdict.state, verdict.limit_days, verdict.severe) == (OUT, 14, None)
    assert not Rules(default=TWO_WEEKS).reads_severity
    assert Rules(default=TWO_WEEKS, overrides={"0BC": SPLIT}).reads_severity
    assert not Rules(default=TWO_WEEKS, overrides={"0BC": Rule(exempt=True)}).reads_severity


def test_a_severe_limit_looser_than_the_ordinary_one_is_refused_and_never_read_back() -> None:
    from app.schemas.settings import PatchRule, PatchRuleOverride

    with pytest.raises(ValidationError, match="shorter of the two"):
        PatchRule.model_validate({"maxDaysBehind": 14, "maxDaysBehindSevere": 60})
    assert PatchRule.model_validate({"maxDaysBehind": 60, "maxDaysBehindSevere": 60}).max_days_behind_severe == 60
    assert PatchRuleOverride.model_validate({"maxDaysBehindSevere": 7}).max_days_behind_severe == 7
    # A stored document that says it anyway judges by the ordinary limit alone.
    assert rule_from({"max_days_behind": 14, "max_days_behind_severe": 60}) == Rule(max_days_behind=14)
    assert rule_from(SPLIT.stored()) == SPLIT
