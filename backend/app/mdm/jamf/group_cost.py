"""What a smart group probably costs Jamf to recalculate — ranked, not measured.

Every inventory submission makes Jamf recalculate the smart groups that could be
affected by it, so at fleet scale the groups an admin wrote years ago are a real part of
the server's day — and nothing in Jamf shows which of them are the expensive ones.
LoonInspect already stores every criterion of every smart group:
`app.mdm.jamf.contract._CRITERION` keeps the tested field, the evaluation priority, the
conjunction, the operator (Jamf's `searchType`), the value and the parentheses. Until
this module, nothing read the operator back.

Note what is deliberately *not* asserted anywhere here: how Jamf schedules that
recalculation, whether it parallelises it, or what any of it costs in seconds. The
ranking does not rest on any of that. It rests on one thing that is true of every
implementation of string matching — running a pattern engine over a value is more work
than scanning it for a fragment, which is more work than comparing it once.

**This is advisory.** The ranking is derived from what an operator *means*, applied to
the criteria Jamf itself reports. It is not a measurement of Jamf's engine, LoonInspect
does not time a recalculation, and no number here is a benchmark. Two consequences for
anyone extending it:

1. **Bands, never multipliers.** "A regex criterion is heavier than an equality test"
   is a statement about string matching that holds for every implementation of it. "A
   regex criterion is 12x an equality test" is a claim about Jamf's server that we have
   not made and cannot support. So a group carries a *band* — the heaviest class of
   operator it contains — and the ordering within a band is by counts, never by a
   fabricated weight. Rejected: a scalar score per group. It reads as authority the
   evidence does not carry, and the first person to compare it against a stopwatch
   would be right to throw the whole feature out.
2. **`member of` is not ranked against `matches regex`.** A criterion that tests
   membership of another group does no string matching at all; what it costs is
   whatever the referenced group costs, and that group is already ranked here on its
   own row. Ordering it against a regex would be a guess about someone else's server,
   so it shares the cheap rung, keeps its own band name, and breaks ties.

Nesting depth is reported for the same honest reason it is not weighted heavily: the
parentheses say how much boolean structure Jamf is holding, and how hard the group is
for a human to reduce, but we have no evidence that depth alone costs the server more
than the criteria it wraps. It is the last tiebreak and nothing more.

Pure: criteria documents in, a ranking out. No session, no clock, no I/O.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

# The version of the heuristic, returned with every answer. A consumer that stored
# yesterday's ranking can tell "the group changed" from "we changed our minds", which a
# bare ordering could never say.
RANKING_VERSION = "operator-class-v0"

EXACT = "exact"
SUBSTRING = "substring"
REGEX = "regex"
DEPENDENT = "dependent"
UNKNOWN = "unknown"
NONE = "none"

# Jamf's `searchType` vocabulary, lower-cased, mapped to what the operator has to do to
# one device's value. Negations sit with their positive form: `not like` still scans the
# string, `does not match regex` still runs the pattern engine.
#
# Ordering/date operators (`more than`, `before (yyyy-mm-dd)`, `more than x days ago`)
# are `exact`: like equality they compare two scalars once, and unlike `like` they can
# never walk the value. Grouping them under a name that says "exact" is the one place
# this vocabulary is loose; the alternative — a fourth class for "scalar comparison"
# that ranks identically to equality — would be a distinction with no consequence.
_OPERATORS: Mapping[str, str] = {
    "is": EXACT,
    "is not": EXACT,
    "current": EXACT,
    "not current": EXACT,
    "more than": EXACT,
    "less than": EXACT,
    "greater than": EXACT,
    "greater than or equal": EXACT,
    "less than or equal": EXACT,
    "more than x days ago": EXACT,
    "less than x days ago": EXACT,
    "like": SUBSTRING,
    "not like": SUBSTRING,
    "has": SUBSTRING,
    "does not have": SUBSTRING,
    "matches regex": REGEX,
    "does not match regex": REGEX,
    "member of": DEPENDENT,
    "not member of": DEPENDENT,
}

# Jamf spells the two date operators with the accepted format inline — "before
# (yyyy-mm-dd)" — and has changed that parenthetical before. Matched by prefix so a
# reformatting in a future Jamf release does not silently demote them to `unknown`.
_OPERATOR_PREFIXES: tuple[tuple[str, str], ...] = (("before", EXACT), ("after", EXACT))

# Cheapest first, and two classes share a rung.
#
# `unknown` sits above `exact` and below `substring` deliberately: an operator we cannot
# classify must not be reported as cheap, and must not be allowed to outrank operators
# we can actually reason about. It is flagged on the row either way, which is the part
# that matters — the ordering is a convenience, the flag is the fact.
#
# `dependent` shares `exact`'s rung rather than getting one of its own, which is the
# same refusal to guess stated at the top of this file: a `member of` criterion does no
# string matching, so the group's own work is cheap, and the expense it implies belongs
# to the group it references — which appears in this same ranking on its own row. It
# keeps a distinct band name so the page can say that, and it breaks ties above plain
# `exact`.
_LADDER: tuple[str, ...] = (NONE, EXACT, DEPENDENT, UNKNOWN, SUBSTRING, REGEX)
_WEIGHT: Mapping[str, int] = {NONE: 0, EXACT: 1, DEPENDENT: 1, UNKNOWN: 2, SUBSTRING: 3, REGEX: 4}


def classify_operator(search_type: str | None) -> str:
    """One Jamf `searchType` → the class of work it implies. Unrecognised is `unknown`,
    never a guess: Jamf adds operators, and mislabelling a new one as cheap is the
    failure mode this whole module exists to avoid."""
    if not search_type:
        return UNKNOWN
    text = " ".join(str(search_type).split()).lower()
    if text in _OPERATORS:
        return _OPERATORS[text]
    for prefix, klass in _OPERATOR_PREFIXES:
        if text.startswith(prefix):
            return klass
    return UNKNOWN


@dataclass(frozen=True, slots=True)
class CriterionCost:
    """One criterion as stored, plus the class its operator falls into."""

    name: str
    priority: int
    conjunction: str  # "and" / "or"; empty on the first criterion
    operator: str  # Jamf's searchType, verbatim — the page shows what Jamf said
    operator_class: str
    value: str
    opening_paren: bool
    closing_paren: bool
    depth: int  # nesting level this criterion is evaluated at, 0 = unparenthesised
    extension_attribute: bool


@dataclass(frozen=True, slots=True)
class GroupCost:
    band: str
    class_counts: Mapping[str, int]
    criteria_count: int
    dependent_count: int
    max_depth: int
    criteria: tuple[CriterionCost, ...]

    @property
    def band_count(self) -> int:
        """How many criteria are in the band that decided it — the only count that
        separates two groups of the same band without inventing a weight for the rest."""
        return self.class_counts.get(self.band, 0)


def _text(value: object) -> str:
    return "" if value is None else str(value)


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def assess_criteria(criteria: Sequence[Mapping] | None, *, extension_attributes: Iterable[str] = ()) -> GroupCost:
    """Rank one group's criteria. `criteria` is the list stored in the `definition`
    section, already ordered by priority by the contract; the order is re-established
    here anyway, because a caller reading a body written by an older contract version
    has no other guarantee.

    `extension_attributes` is the set of EA names the ledger has seen. A criterion whose
    tested field is one of them is flagged: an EA value is free text the fleet supplies
    (stored here up to 1024 characters), where `Operating System Version` is short and
    bounded, so a substring or regex over an EA is the same operator over a much larger
    haystack. Flagged, not weighted — we know the haystack differs, not by how much.
    """
    items = [item for item in (criteria or []) if isinstance(item, Mapping)]
    items.sort(key=lambda item: _int(item.get("priority")))

    ea_names = {name.casefold() for name in extension_attributes if name}
    counts: dict[str, int] = {}
    assessed: list[CriterionCost] = []
    depth = 0
    max_depth = 0
    for item in items:
        opening = bool(item.get("openingParen"))
        closing = bool(item.get("closingParen"))
        # Depth is counted at the criterion, so `(` on this row means this row is
        # already inside the group it opens.
        here = depth + (1 if opening else 0)
        max_depth = max(max_depth, here)
        depth = max(here - (1 if closing else 0), 0)

        name = _text(item.get("name"))
        klass = classify_operator(item.get("searchType"))
        counts[klass] = counts.get(klass, 0) + 1
        assessed.append(
            CriterionCost(
                name=name,
                priority=_int(item.get("priority")),
                conjunction=_text(item.get("andOr")).lower(),
                operator=_text(item.get("searchType")),
                operator_class=klass,
                value=_text(item.get("value")),
                opening_paren=opening,
                closing_paren=closing,
                depth=here,
                extension_attribute=name.casefold() in ea_names,
            )
        )

    # Ladder position decides the band; the ladder's own order breaks the one rung two
    # classes share, so a group carrying both `is` and `member of` is named for the
    # criterion an operator would want to look at.
    band = max(counts, key=lambda klass: (_WEIGHT[klass], _LADDER.index(klass)), default=NONE)
    return GroupCost(
        band=band,
        class_counts=dict(sorted(counts.items())),
        criteria_count=len(assessed),
        dependent_count=counts.get(DEPENDENT, 0),
        max_depth=max_depth,
        criteria=tuple(assessed),
    )


def rank_key(cost: GroupCost) -> tuple[int, int, int, int, int]:
    """Most expensive first, as a sort key negated for ascending sorts.

    Heaviest operator class present, then how many criteria are in it, then how many
    criteria depend on another group, then the criterion count, then nesting depth.
    Every term is a count of something Jamf reported; none of them is a weight.
    Callers append their own stable tail (name, connection, id) — this key alone ties.
    """
    return (
        -_WEIGHT.get(cost.band, 0),
        -cost.band_count,
        -cost.dependent_count,
        -cost.criteria_count,
        -cost.max_depth,
    )
