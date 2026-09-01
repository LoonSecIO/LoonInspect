"""The smart-group cost heuristic, as pure logic.

These tests pin the *claims* the feature makes, not a performance model. Specifically:
an operator's class, the band a group lands in, the fact that the ordering is a total
and repeatable one, and — the point of the whole module — that an operator LoonInspect
does not recognise is reported as `unknown` rather than assumed to be cheap.

Nothing here asserts a duration, a multiplier, or anything about Jamf's server, because
nothing here measures one.
"""

from __future__ import annotations

import pytest

from app.mdm.jamf.group_cost import (
    DEPENDENT,
    EXACT,
    NONE,
    REGEX,
    SUBSTRING,
    UNKNOWN,
    assess_criteria,
    classify_operator,
    rank_key,
)


def criterion(search_type: str, *, name: str = "Application Title", priority: int = 0, **extra) -> dict:
    return {
        "name": name,
        "priority": priority,
        "andOr": extra.pop("andOr", "and"),
        "searchType": search_type,
        "value": extra.pop("value", "Slack"),
        **extra,
    }


@pytest.mark.parametrize(
    ("search_type", "expected"),
    [
        ("is", EXACT),
        ("is not", EXACT),
        ("current", EXACT),
        ("more than x days ago", EXACT),
        ("before (yyyy-mm-dd)", EXACT),
        ("after (yyyy-mm-dd)", EXACT),
        ("like", SUBSTRING),
        ("not like", SUBSTRING),
        ("has", SUBSTRING),
        ("does not have", SUBSTRING),
        ("matches regex", REGEX),
        ("does not match regex", REGEX),
        ("member of", DEPENDENT),
        ("not member of", DEPENDENT),
        # Jamf sends these capitalised in places and the vocabulary drifts by release.
        ("MATCHES REGEX", REGEX),
        ("matches  regex", REGEX),
    ],
)
def test_operator_classes(search_type: str, expected: str) -> None:
    assert classify_operator(search_type) == expected


@pytest.mark.parametrize("search_type", ["", None, "fuzzy matches", "is approximately"])
def test_unrecognised_operators_are_unknown_not_cheap(search_type) -> None:
    """The defect this module exists to avoid. A Jamf release that adds an operator must
    make LoonInspect say so, never quietly file it under `exact` — an operator reading a
    ranking that had silently demoted the expensive half of their fleet would be worse
    off than with no ranking at all."""
    assert classify_operator(search_type) == UNKNOWN


def test_band_is_the_heaviest_class_present() -> None:
    cost = assess_criteria(
        [
            criterion("is", priority=0),
            criterion("like", priority=1),
            criterion("matches regex", priority=2),
        ]
    )
    assert cost.band == REGEX
    assert cost.class_counts == {EXACT: 1, REGEX: 1, SUBSTRING: 1}
    assert cost.band_count == 1
    assert cost.criteria_count == 3


def test_substring_group_outranks_exact_group_and_regex_outranks_both() -> None:
    exact = assess_criteria([criterion("is", priority=i) for i in range(6)])
    substring = assess_criteria([criterion("like")])
    regex = assess_criteria([criterion("matches regex")])
    assert rank_key(regex) < rank_key(substring) < rank_key(exact), "cheapest sorts last"


def test_more_criteria_in_the_band_outranks_fewer_of_the_same_band() -> None:
    one = assess_criteria([criterion("matches regex"), criterion("is", priority=1)])
    three = assess_criteria([criterion("matches regex", priority=i) for i in range(3)])
    assert rank_key(three) < rank_key(one)


def test_member_of_keeps_its_own_band_and_breaks_ties_above_exact() -> None:
    """`member of` shares the cheap rung on purpose — it does no string matching, and
    what it costs belongs to the group it references, which is ranked on its own row."""
    dependent = assess_criteria([criterion("member of", name="Computer Group", value="All Managed")])
    exact = assess_criteria([criterion("is")])
    assert dependent.band == DEPENDENT and dependent.dependent_count == 1
    assert rank_key(dependent) < rank_key(exact)
    assert rank_key(dependent) > rank_key(assess_criteria([criterion("like")]))


def test_unknown_sits_between_exact_and_substring() -> None:
    unknown = assess_criteria([criterion("is approximately")])
    assert unknown.band == UNKNOWN
    assert rank_key(assess_criteria([criterion("like")])) < rank_key(unknown) < rank_key(assess_criteria([criterion("is")]))


def test_no_criteria_is_a_band_of_its_own_and_ranks_last() -> None:
    empty = assess_criteria([])
    assert empty.band == NONE and empty.criteria_count == 0 and empty.max_depth == 0
    assert rank_key(empty) > rank_key(assess_criteria([criterion("is")]))
    assert assess_criteria(None).band == NONE


def test_nesting_depth_counts_the_parentheses_jamf_reports() -> None:
    cost = assess_criteria(
        [
            criterion("is", priority=0, openingParen=True),
            criterion("is", priority=1, openingParen=True),
            criterion("is", priority=2, closingParen=True),
            criterion("is", priority=3, closingParen=True),
            criterion("is", priority=4),
        ]
    )
    assert cost.max_depth == 2
    assert [c.depth for c in cost.criteria] == [1, 2, 2, 1, 0]


def test_criteria_are_ordered_by_priority_whatever_order_they_arrive_in() -> None:
    cost = assess_criteria([criterion("is", priority=2), criterion("like", priority=0), criterion("has", priority=1)])
    assert [c.priority for c in cost.criteria] == [0, 1, 2]
    assert [c.operator for c in cost.criteria] == ["like", "has", "is"]


def test_ranking_is_deterministic_over_the_same_input() -> None:
    """Determinism is the property that makes the page worth looking at twice: a
    ranking that reshuffled between requests would read as churn in Jamf."""
    groups = [
        assess_criteria([criterion("like"), criterion("is", priority=1)]),
        assess_criteria([criterion("matches regex")]),
        assess_criteria([criterion("is")]),
        assess_criteria([]),
    ]
    keys = [rank_key(cost) for cost in groups]
    assert keys == [rank_key(cost) for cost in groups]
    assert sorted(keys) == [keys[1], keys[0], keys[2], keys[3]]


def test_extension_attribute_criteria_are_flagged_not_weighted() -> None:
    """The flag says the haystack is bigger (an EA value is free text the fleet supplies,
    stored here up to 1024 characters); it deliberately does not move the ranking, because
    we know the haystack differs and not by how much."""
    ea = assess_criteria([criterion("like", name="Antivirus Version")], extension_attributes=["antivirus version"])
    plain = assess_criteria([criterion("like", name="Application Title")], extension_attributes=["Antivirus Version"])
    assert ea.criteria[0].extension_attribute is True
    assert plain.criteria[0].extension_attribute is False
    assert rank_key(ea) == rank_key(plain)


def test_malformed_criteria_do_not_raise() -> None:
    """The body being read is JSONB written by an older contract version, so the shape
    is whatever was stored — a missing priority or a null value must not 500 the page."""
    cost = assess_criteria([{"searchType": "like"}, "not a mapping", {}, {"priority": "third"}])
    assert cost.criteria_count == 3
    assert cost.band == SUBSTRING
    assert cost.criteria[0].name == "" and cost.criteria[0].priority == 0
