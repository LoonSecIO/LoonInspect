"""The org's patching policy as rules a build can be judged against. Pure; no database.

#116 gave an organization a place to *state* its policy as typed text, and ruled the text
display-only: a sentence cannot be evaluated, and a threshold nobody confirmed is an invented
compliance regime (docs/v-never.md). This module is the other half — the legitimization #116
named as a separate ruling: **rules the organization itself confirms**, from a closed
vocabulary of things the matcher already knows about every (build, title) pair. The statement
stays text for people; only a confirmed rule judges anything.

**The vocabulary is exactly what `matching.classify` stores**, so a rule can never ask for a
fact the product does not have:

* `max_days_behind` — out of policy once a newer release has been listed for more than N
  days. The clock is #68's: Jamf's release date of the earliest listed version newer than
  the installed one (`first_newer_released_at`), so "within two weeks" is 14.
* `max_releases_behind` — out of policy when more than N listed releases are newer
  (`releases_missed`); "current or one back" is 1.
* `max_days_behind_severe` — the same clock with a tighter limit, for a build that carries a
  critical or high finding: "highs and criticals within two weeks, else within 60 days" is
  14 beside 60. *Severe* is the corpus's stored answer for that exact build
  (`vuln_counts.critical + vuln_counts.high > 0` on a `covered` row the answering epoch
  wrote), so it is a fact about the installed build and never about its title. **A build the
  corpus has not assessed is not severe**: it is judged by the ordinary limit, and the
  verdict says its severity is unknown rather than implying it was looked at.

Either limit exceeded is out of policy. A title may carry its own rule, which **replaces**
the organization's for that title rather than merging with it, or be `exempt` — named as not
judged, never counted as within.

**What is judged.** Only a build Jamf lists that is behind the title's current version. On
the latest, or ahead of the catalog, is within policy. A version Jamf does not list and that
is not ahead (`unknown`) is *not judged*: its age is a guess, and the posture key that
shares this clock counts behind-only for the same reason (`patch.pairs_laggard_over_14d`).

`judge` here and `out_of_policy` in `app.api.jamf_patch` are one predicate in two dialects —
a version's verdict on the title page and the device count on the list. Change one, change
both; `tests/test_patch_policy_db.py` holds them together.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.mdm.patch.matching import STATE_AHEAD, STATE_BEHIND, STATE_LATEST

SOURCE_DEFAULT = "default"
SOURCE_OVERRIDE = "override"

WITHIN = "within"
OUT = "out"
NOT_JUDGED = "not_judged"

REASON_DAYS = "days"
REASON_RELEASES = "releases"

# Bounds a typed number has to sit inside. Ten years and a thousand releases are both "never"
# in practice; past them a number is a typo, and a typo that reads as a policy is worse than a
# refusal.
MAX_DAYS = 3650
MAX_RELEASES = 1000


@dataclass(frozen=True)
class Rule:
    max_days_behind: int | None = None
    max_releases_behind: int | None = None
    # The days limit for a build carrying a critical or high finding, in place of
    # `max_days_behind` for that build. Never looser than it: a rule that gave a severe build
    # longer would be a typo, and `rule_from` reads one as not set.
    max_days_behind_severe: int | None = None
    # A per-title override only: the title is named as not judged.
    exempt: bool = False

    @property
    def judges(self) -> bool:
        """Whether the rule can put a build out of policy at all."""
        limits = (self.max_days_behind, self.max_releases_behind, self.max_days_behind_severe)
        return not self.exempt and any(limit is not None for limit in limits)

    def days_for(self, severe: bool | None) -> int | None:
        """The days limit one build is judged by. Only a build known to be severe takes the
        severe limit; unknown is not severe."""
        if severe is True and self.max_days_behind_severe is not None:
            return self.max_days_behind_severe
        return self.max_days_behind

    def stored(self) -> dict[str, object]:
        return {
            "max_days_behind": self.max_days_behind,
            "max_releases_behind": self.max_releases_behind,
            "max_days_behind_severe": self.max_days_behind_severe,
            "exempt": self.exempt,
        }


def _limit(value: object, ceiling: int) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= ceiling else None


def rule_from(stored: object) -> Rule | None:
    """A stored rule back as a `Rule`, or `None` for one that says nothing. Anything that is
    not the shape this module writes reads as no limit rather than raising: the worst a
    hand-edited row can do is judge less, never invent a threshold."""
    if not isinstance(stored, Mapping):
        return None
    days = _limit(stored.get("max_days_behind"), MAX_DAYS)
    severe = _limit(stored.get("max_days_behind_severe"), MAX_DAYS)
    if severe is not None and days is not None and severe > days:
        severe = None
    rule = Rule(
        max_days_behind=days,
        max_releases_behind=_limit(stored.get("max_releases_behind"), MAX_RELEASES),
        max_days_behind_severe=severe,
        exempt=stored.get("exempt") is True,
    )
    return rule if rule.exempt or rule.judges else None


@dataclass(frozen=True)
class Rules:
    """The confirmed rules: the organization's, and each title's own."""

    default: Rule | None = None
    overrides: Mapping[str, Rule] = field(default_factory=dict)
    # The published requirement the organization's rule was confirmed unchanged from
    # (`policy_presets`), as its id, or None. Where the rule came from — never a claim that
    # anything is met. Read back as stored; the route decides whether it still holds.
    default_basis: str | None = None

    @classmethod
    def from_stored(cls, stored: object) -> Rules:
        if not isinstance(stored, Mapping):
            return cls()
        overrides = stored.get("overrides")
        parsed = {
            str(title_id): rule
            for title_id, raw in (overrides.items() if isinstance(overrides, Mapping) else ())
            if (rule := rule_from(raw)) is not None
        }
        default = rule_from(stored.get("default"))
        basis = stored.get("default_basis")
        # `exempt` is a per-title word; an organization that judges nothing has no rule.
        default = default if default is not None and default.judges else None
        return cls(default=default, overrides=parsed, default_basis=basis if isinstance(basis, str) and default else None)

    def for_title(self, title_id: str) -> tuple[Rule | None, str | None]:
        """The rule that judges this title, and where it came from — `(None, None)` when
        nothing does."""
        own = self.overrides.get(title_id)
        if own is not None:
            return own, SOURCE_OVERRIDE
        return (self.default, SOURCE_DEFAULT) if self.default is not None else (None, None)

    @property
    def judges(self) -> bool:
        """Whether any title can be out of policy: with neither a default nor a judging
        override, the list has no column to draw and no query to run."""
        return self.default is not None or any(rule.judges for rule in self.overrides.values())

    @property
    def reads_severity(self) -> bool:
        """Whether any rule in force has a severe limit — the only case a judgement reads the
        corpus's answer at all, so the only case that costs the read."""
        rules = [self.default, *self.overrides.values()]
        return any(rule is not None and rule.judges and rule.max_days_behind_severe is not None for rule in rules)


@dataclass(frozen=True)
class Verdict:
    state: str
    # Which limit put it out — `days` wins when both did, because it carries a date.
    reason: str | None = None
    # When the build went out of policy by the days limit: the first newer release's date
    # plus the limit. None under the releases limit, which has no single date.
    since: datetime | None = None
    days_behind: int | None = None
    releases_behind: int | None = None
    # The days limit this build was judged by — the severe one or the ordinary one — or None
    # where the rule has no days limit for it.
    limit_days: int | None = None
    # Whether the build carries a critical or high finding: True, False, or None for a build
    # the corpus has not assessed. None wherever the rule has no severe limit, since nothing
    # was read.
    severe: bool | None = None


def judge(
    state: str,
    first_newer_released_at: datetime | None,
    releases_missed: int | None,
    rule: Rule | None,
    *,
    now: datetime,
    severe: bool | None = None,
) -> Verdict:
    """One (build, title) pair against one rule, at `now`. `severe` is the corpus's answer for
    the build — True, False, or None for not assessed — and is read only by a severe limit."""
    if rule is None or not rule.judges:
        return Verdict(NOT_JUDGED)
    severity = {"severe": severe if rule.max_days_behind_severe is not None else None}
    if state in (STATE_LATEST, STATE_AHEAD):
        return Verdict(WITHIN, days_behind=0, releases_behind=0, **severity)
    if state != STATE_BEHIND:
        return Verdict(NOT_JUDGED)

    days_behind = max((now - first_newer_released_at).days, 0) if first_newer_released_at is not None else None
    limit = rule.days_for(severe)
    facts = {"days_behind": days_behind, "releases_behind": releases_missed, "limit_days": limit, **severity}
    if limit is not None and first_newer_released_at is not None:
        deadline = first_newer_released_at + timedelta(days=limit)
        if now > deadline:
            return Verdict(OUT, reason=REASON_DAYS, since=deadline, **facts)
    if rule.max_releases_behind is not None and releases_missed is not None and releases_missed > rule.max_releases_behind:
        return Verdict(OUT, reason=REASON_RELEASES, **facts)
    return Verdict(WITHIN, **facts)
