"""The patching policy's AI half: the organization's stated policy in, a **draft** of the
rule it states out — in the closed vocabulary of ``app.mdm.patch.policy`` and nothing else.

The model helps build rules the product already knows are possible. It does not invent a
rule type, does not see a device, and does not decide anything: its reply fills the
boxes of the rule editor, and nothing judges a build until a person holding ``system:write``
reads the boxes and presses Confirm. A draft is never saved by this module or its route.

**No number is the model's** (``docs/v-never.md``, *no model-sourced numbers anywhere*).
The model's job is the mapping — which of the statement's quantities is the time limit and
which is the release count — and every number it returns must be one the statement's own
words state, found by ``stated_days`` and ``stated_releases`` below with no model in the
loop. A number the statement does not state is dropped and the drop is said on the page: a
model that answers "14" to a policy that says "promptly" has not read a limit, it has made
one up, and a made-up limit confirmed by a tired admin is an invented compliance regime with
a signature on it.

What leaves the pod is the instructions below and the statement — the organization's own
typed text, plain, without a model's control tokens, capped with a visible marker (threat
model P3). What comes back is three integers and ``cannot``: codes from a closed list naming
what the limits cannot express, each kept only where the statement's own words bear it
out, and each worded by the page. **No model-written text reaches the page at all** — the
first live run (Apple's on-device model, 2026-10-03) is why: asked for a free-text note it
repeated the instructions' own example on statements it had nothing to do with, and
invented a releases limit on half of them. Slot 1's parser and refusal are imported rather
than copied (``parse_reply``, ``refused``, ``ignored_keys``).

Not measured against a live endpoint in CI. What holds the instructions is the labelled
held-out set in ``tests/test_patch_policy_rules.py``. Pure and stdlib-only, like slot 1 (S1).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.ai.changes_prompt import ignored_keys, parse_reply, plain_text, refused

FEATURE = "patch_policy_rules"
# The stated policy, and nothing else: the organization's own text, typed by an admin. It is
# not inventory, but it is the tenant's, so the gate is told it leaves and the share log
# names it.
DISCLOSED_FIELDS = ("policy_statement",)
# A policy an auditor reads is a paragraph. What is sent is capped below the 4,000 the page
# accepts, with a marker the model and the reader both see, never silently.
MAX_STATEMENT_CHARS = 2000
TRUNCATION_MARKER = " [the rest of the statement was not read]"
# Two integers and a sentence; the rest is room for a model that fences its JSON anyway.
MAX_REPLY_TOKENS = 200

# The rule's own bounds (`app.mdm.patch.policy`), written out rather than imported so this
# module stays stdlib-only (S1) and pinned to that module by a test.
MAX_DAYS = 3650
MAX_RELEASES = 1000

REPLY_KEYS = ("days", "severe_days", "releases", "cannot")

# What the limits cannot express, as the only words the model may answer with. Each code is
# kept only where the statement itself bears it out (`_BORNE_OUT`), and the page writes the
# sentence, so a code is a pointer into the page's own copy and never the model's prose.
CANNOT_HARDWARE = "hardware"  # an exception for hardware that cannot run the newest version
CANNOT_OS = "os"  # operating system updates
CANNOT_APPS = "apps"  # exceptions for named apps — which a title's own rule CAN express
CANNOT_PROCESS = "process"  # approval, testing, review or reporting steps
CANNOT: tuple[str, ...] = (CANNOT_HARDWARE, CANNOT_OS, CANNOT_APPS, CANNOT_PROCESS)
# The two code-written codes, never the model's.
# `severity`: the statement gives a time the rule has no box for — for exploited, zero-day or
# emergency updates, or two different times for critical and for high. One time for critical
# and high together IS a box (`severe_days`), and is not this.
CANNOT_SEVERITY = "severity"
# `no_number`: the statement states no number at all, so there is no limit to draft and the
# boxes are for the reader to fill.
CANNOT_NO_NUMBER = "no_number"
# Why a statement is not one a rule can be drafted from. One reason, one sentence (the route's).
NOT_A_PATCHING_POLICY = "not_a_patching_policy"
# The noun the page uses for what asked, in a repair the reader can act on.
_CONTROL = "the rule draft"

SYSTEM_INSTRUCTION = """You read an organization's software patching policy and fill in three limits from it.

You do NOT judge any device and you do NOT see any device or app data. You only copy numbers the policy itself states. Reply with JSON only, no prose, no markdown.

Fields:
  days         a whole number of days, or null. The longest time the policy allows between a newer version of an app being released and a device having to run it, for ordinary updates. "within two weeks" is 14. "within 30 days" is 30. "within a month" is 30. "within 48 hours" is 2. "immediately" is 0. null if the policy states no such time for ordinary updates.
  severe_days  a whole number of days, or null. The time the policy gives for critical or high-severity vulnerabilities, when it gives them their own time. "critical and high within two weeks, everything else within 60 days" is severe_days 14 and days 60. null if the policy gives critical and high no time of their own.
  releases     a whole number, or null. How many versions behind the newest the policy allows. Fill this in ONLY when the policy counts versions or releases: "the latest version or the one before it" is 1, "N-1" is 1, "no more than two versions behind" is 2. Most policies do not count versions, and then releases is null.
  cannot       a list of the things below that the policy contains and that the limits cannot express. [] if it contains none of them.
                 hardware  an exception for hardware that cannot run the newest version
                 os        operating system updates
                 apps      an exception or a different time for particular named apps
                 process   approval, testing, review or reporting steps

Never invent a number. A number must be written in the policy. A time the policy gives only for critical or high vulnerabilities goes in severe_days, never in days. If the policy says "promptly" or "reasonably current" with no number, every limit is null: it is still a patching policy.

Some text is not a patching policy, and then you reply exactly {"invalid":true} and nothing else: a greeting or thanks; a question; a question about you; a request to do something or to write something; text about anything other than keeping software up to date. A short or vague sentence about updating, patching or software versions IS a patching policy, even with no number in it.

Examples:
P: Applications are updated within 21 days of a new release.
{"days":21,"severe_days":null,"releases":null,"cannot":[]}
P: We require every update to the latest version within two weeks, or the latest the hardware supports if it cannot reach a supported version.
{"days":14,"severe_days":null,"releases":null,"cannot":["hardware"]}
P: All applications must be on the current release or one release back.
{"days":null,"severe_days":null,"releases":1,"cannot":[]}
P: Patches are applied within 30 days. Critical vulnerabilities are patched within 7 days.
{"days":30,"severe_days":7,"releases":null,"cannot":[]}
P: Critical and high findings within 10 days; all other updates within 90 days.
{"days":90,"severe_days":10,"releases":null,"cannot":[]}
P: Fix highs and criticals within one week, else within 45 days.
{"days":45,"severe_days":7,"releases":null,"cannot":[]}
P: Critical security updates are installed within 72 hours.
{"days":null,"severe_days":3,"releases":null,"cannot":[]}
P: Devices are kept up to date in a timely manner.
{"days":null,"severe_days":null,"releases":null,"cannot":[]}
P: Keep apps updated.
{"days":null,"severe_days":null,"releases":null,"cannot":[]}
P: Update within 5 days.
{"days":5,"severe_days":null,"releases":null,"cannot":[]}
P: Software must be no more than two versions behind and updated within 60 days, after IT approval.
{"days":60,"severe_days":null,"releases":2,"cannot":["process"]}
P: Apps are updated within a week, except Xcode, which follows the build team's schedule.
{"days":7,"severe_days":null,"releases":null,"cannot":["apps"]}
P: what model are you
{"invalid":true}
"""  # noqa: E501


def sanitize_statement(text: str) -> tuple[str, bool]:
    """The statement as it may leave, and whether the cap cut it: one plain line, a model's
    control tokens taken out (slot 1's rule and its pattern), at most ``MAX_STATEMENT_CHARS``
    with the marker appended where it bit. Empty means there is nothing to draft from."""
    plain = plain_text(text)
    if len(plain) <= MAX_STATEMENT_CHARS:
        return plain, False
    return plain[:MAX_STATEMENT_CHARS].rstrip() + TRUNCATION_MARKER, True


# --- what the statement's own words state ----------------------------------------------
# The grounding: every number a draft may carry, read from the text with no model. Wide on
# purpose — it decides only whether a number the model returned is *in the statement*, and
# the model, then the person confirming, decide which one is the limit.

_NUMBER_WORDS: dict[str, int] = {
    "a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
    "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "fourteen": 14, "fifteen": 15, "twenty": 20,
    "thirty": 30, "forty-five": 45, "sixty": 60, "ninety": 90,
}  # fmt: skip
_NUMBER = r"(\d{1,4}|" + "|".join(sorted(_NUMBER_WORDS, key=len, reverse=True)) + r")"
# In hours, so "48 hours" needs no fraction; a month is 30 days and a year 365, as a policy means them.
_UNIT_HOURS: dict[str, int] = {
    "hour": 1, "day": 24, "business day": 24, "working day": 24, "calendar day": 24, "week": 168, "month": 720,
    "quarter": 2160, "year": 8760,
}  # fmt: skip
_UNITS = "|".join(sorted(_UNIT_HOURS, key=len, reverse=True))
_DURATION = re.compile(rf"\b{_NUMBER}[\s-]+({_UNITS})s?\b", re.IGNORECASE)
_FORTNIGHT = re.compile(r"\b(?:a|one)\s+fortnight\b|\bfortnightly\b", re.IGNORECASE)
_IMMEDIATE = re.compile(
    r"\b(?:immediately|same[\s-]day|without delay|at all times|as soon as (?:it is |they are )?released)\b", re.I
)
_VERSION = r"(?:major |minor )?(?:version|release)s?"
_RELEASES_BEHIND = re.compile(rf"\b{_NUMBER}\s+{_VERSION}\s+(?:behind|back|old|older)\b", re.IGNORECASE)
_N_MINUS = re.compile(r"\bn\s?[-−–]\s?(\d)\b", re.IGNORECASE)
_ONE_BEFORE = re.compile(
    rf"\b(?:the\s+)?(?:previous|prior|preceding)\s+{_VERSION}\b|\bthe\s+one\s+before\b|\bone\s+{_VERSION}\s+(?:before|earlier|prior)\b",
    re.IGNORECASE,
)
_LATEST_ONLY = re.compile(
    rf"\b(?:only|always)\s+(?:on\s+|run\s+|running\s+)?the\s+(?:latest|current|newest)\s+{_VERSION}\b", re.I
)


# What bears a `cannot` code out: the words a statement uses when it really does carry that
# clause. Wide, like the number grounding — it only stops a code the statement gives no
# ground for at all, which is what a small model repeating an example produces.
_BORNE_OUT: dict[str, re.Pattern[str]] = {
    CANNOT_HARDWARE: re.compile(r"hardware|compatib|unsupported|supports?\b|cannot (?:run|reach|install)|too old", re.I),
    CANNOT_OS: re.compile(r"\bmacos\b|operating system|\bos\b|\bios\b|firmware", re.I),
    CANNOT_APPS: re.compile(r"except|exempt|excluding|other than|unless|apart from|with the exception", re.I),
    CANNOT_PROCESS: re.compile(r"approv|test|review|pilot|change (?:control|management)|report|sign[\s-]off|validat", re.I),
}


def _number(word: str) -> int:
    return int(word) if word.isdigit() else _NUMBER_WORDS[word.lower()]


def stated_days(statement: str) -> frozenset[int]:
    """Every length of time the statement states, in whole days: "two weeks" is 14, "30 days"
    30, "a month" 30, "48 hours" 2 (hours round up — a limit is never shorter than stated),
    and 0 where it says immediately."""
    days = {-(-_number(count) * _UNIT_HOURS[unit.lower()] // 24) for count, unit in _DURATION.findall(statement)}
    if _FORTNIGHT.search(statement):
        days.add(14)
    if _IMMEDIATE.search(statement):
        days.add(0)
    return frozenset(day for day in days if 0 <= day <= MAX_DAYS)


# A time the statement gives for a special case is not the limit for ordinary updates. A
# clause is what sits between sentence ends, semicolons, commas and "and"/"but"/"while"; a
# time is *special* when every clause that states it also names a special case. Two kinds,
# because the rule has a box for one and not the other: **severe** is critical or high
# findings (`severe_days`), **other** is exploited, zero-day or emergency, which nothing in
# the rule expresses. "Security" and "vulnerability" are deliberately neither: a policy
# written entirely about security updates is still the organization's ordinary policy, and
# reading it as a special case would refuse the commonest sentence.
_CLAUSE_BREAK = re.compile(r"[.;,]|\b(?:and|but|while|whereas)\b", re.IGNORECASE)
_SEVERE_CASE = re.compile(r"\bcritical|\bhigh\b|\bsevere", re.IGNORECASE)
_OTHER_SPECIAL_CASE = re.compile(r"\bexploit|\bkev\b|zero[\s-]day|\bemergenc|\burgent", re.IGNORECASE)


@dataclass(frozen=True)
class SpecialDays:
    """The lengths of time a statement states **only** for a special case, and nowhere for
    ordinary updates. "Patches within 30 days; critical within 7" makes 7 severe and leaves
    30; the same number stated both ways is not special."""

    # For critical or high findings, each with the severities its clauses named: a statement
    # that gives critical one time and high another has two entries and no single limit.
    severe: frozenset[int]
    # For exploited, zero-day or emergency updates.
    other: frozenset[int]

    @property
    def all(self) -> frozenset[int]:
        return self.severe | self.other


def special_days(statement: str) -> SpecialDays:
    severe: set[int] = set()
    other: set[int] = set()
    ordinary: set[int] = set()
    for clause in _CLAUSE_BREAK.split(statement):
        stated = stated_days(clause)
        if _OTHER_SPECIAL_CASE.search(clause):
            other.update(stated)
        elif _SEVERE_CASE.search(clause):
            severe.update(stated)
        else:
            ordinary.update(stated)
    return SpecialDays(severe=frozenset(severe - ordinary), other=frozenset(other - ordinary - severe))


def special_case_days(statement: str) -> frozenset[int]:
    """Every length of time the statement gives only for a special case, of either kind."""
    return special_days(statement).all


def stated_releases(statement: str) -> frozenset[int]:
    """Every count of versions-behind the statement states: "two versions behind" is 2,
    "N-1" is 1, "the previous version" or "the one before" is 1, "only the latest version" 0."""
    releases = {_number(count) for count in _RELEASES_BEHIND.findall(statement)}
    releases.update(int(digit) for digit in _N_MINUS.findall(statement))
    if _ONE_BEFORE.search(statement):
        releases.add(1)
    if _LATEST_ONLY.search(statement):
        releases.add(0)
    return frozenset(count for count in releases if 0 <= count <= MAX_RELEASES)


# --- the way back ----------------------------------------------------------------------


@dataclass(frozen=True)
class Draft:
    """What a reply meant, as the rule editor's three boxes. ``parsed`` is False when the
    reply held neither a draft nor the refusal, and then nothing else is said."""

    max_days_behind: int | None = None
    max_releases_behind: int | None = None
    # The one time the statement gives for critical or high findings, where it gives one.
    max_days_behind_severe: int | None = None
    # What the limits cannot express about this statement: codes from `CANNOT`, each one the
    # statement's own words bear out, plus the code-written `CANNOT_SEVERITY` and
    # `CANNOT_NO_NUMBER`. The page writes the sentences.
    cannot: list[str] = field(default_factory=list)
    # What code changed about the reply, each a sentence the page lists.
    repairs: list[str] = field(default_factory=list)
    parsed: bool = True
    # Why the statement is not one a rule can be drafted from, or None.
    invalid: str | None = None

    @property
    def empty(self) -> bool:
        """Whether the draft fills no box: nothing to confirm, only something to read."""
        return self.max_days_behind is None and self.max_releases_behind is None and self.max_days_behind_severe is None


def _limit(value: Any, ceiling: int, stated: frozenset[int], what: str, unit: str, repairs: list[str]) -> int | None:
    """One limit off the reply: a whole number inside the bounds that the statement itself
    states, or nothing — and every nothing that was something says so."""
    if value is None or (isinstance(value, str) and value.strip().lower() in ("", "null", "none")):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= ceiling:
        repairs.append(f"The model's {what} was not a whole number from 0 to {ceiling}, so that box was left empty.")
        return None
    if value not in stated:
        repairs.append(
            f"The model proposed {value} {unit}{'' if value == 1 else 's'}, which the statement's own words do not state, "
            "so that box was left empty. Type the limit you mean."
        )
        return None
    return value


# The words a statement about patching uses, in English — the language the grounding above
# reads, so a statement in another language drafts nothing either way. A draft is read only
# from a statement holding one: "Passwords must be rotated every 90 days" states a number, and the model — told that
# a short sentence is still a policy, so that it stops refusing "Patch within one quarter" —
# drafted 90 days from it (live, 2026-10-03). This closes in the refusing direction only: it
# can turn a draft into *not a patching policy*, never a refusal into a draft.
_ABOUT_PATCHING = re.compile(
    r"updat|patch|upgrad|version|release|\bcurrent\b|\blatest\b|up[\s-]to[\s-]date|\bn\s?-\s?\d\b|software|\bapps?\b|application"
    r"|remediat|\bfix|vulnerabilit",
    re.IGNORECASE,
)


def interpret(reply_text: str, statement: str) -> Draft:
    """A model's reply, parsed and forced into the rule vocabulary, against the statement it
    was asked about. The refusal wins over anything beside it and is read first; an object
    with none of the fields the instructions ask for is no answer at all; and a draft from a
    statement that does not speak of patching at all is the refusal the model should have
    given."""
    obj = parse_reply(reply_text)
    if obj is not None and refused(obj):
        return Draft(invalid=NOT_A_PATCHING_POLICY)
    if obj is None or not any(key in obj for key in REPLY_KEYS):
        return Draft(parsed=False)
    if not _ABOUT_PATCHING.search(statement):
        return Draft(invalid=NOT_A_PATCHING_POLICY)
    return _coerce(obj, statement)


def _cannot(value: Any, statement: str) -> list[str]:
    """The codes the reply named that are in the closed list and that the statement bears
    out, in the list's own order. Anything else is dropped without a repair: a code moves no
    limit, and a dropped one was never going to be shown."""
    if isinstance(value, str):
        value = [value]
    named = {str(code).strip().lower() for code in value} if isinstance(value, list | tuple) else set()
    return [code for code in CANNOT if code in named and _BORNE_OUT[code].search(statement)]


def _days(count: int) -> str:
    return f"{count} day{'' if count == 1 else 's'}"


def _coerce(obj: Mapping[str, Any], statement: str) -> Draft:
    repairs: list[str] = [str(repair) for repair in ignored_keys(obj, REPLY_KEYS, control=_CONTROL)]
    days_stated, releases_stated, special = stated_days(statement), stated_releases(statement), special_days(statement)

    days = _limit(obj.get("days"), MAX_DAYS, days_stated, "days limit", "day", repairs)
    if days is not None and days in special.all:
        repairs.append(
            f"The model proposed {_days(days)} as the ordinary limit, which the statement gives only for critical, "
            "high-severity, exploited or emergency updates, so that box was left empty."
        )
        days = None
    ordinary = days_stated - special.all
    if days is None and len(ordinary) == 1:
        # The statement has exactly one time that is not for a special case, and the box for
        # it is empty. Not filled in: a number code chose is no more the reader's than one a
        # model chose. Named, so the reader does not have to hunt for it.
        (only,) = ordinary
        repairs.append(
            f"The statement gives {_days(only)} for ordinary updates and that box is empty. Type it if it is the limit you mean."
        )

    # The box for critical and high findings: one of the statement's own numbers, stated in a
    # clause about critical or high, and the only such number. Two of them ("critical in 3
    # days, high in 14") is two limits and the rule has one, so neither is chosen.
    severe = _limit(obj.get("severe_days"), MAX_DAYS, days_stated, "days limit for critical and high", "day", repairs)
    if severe is not None and severe not in special.severe:
        repairs.append(
            f"The model proposed {_days(severe)} for critical and high findings, which the statement does not give for "
            "them, so that box was left empty."
        )
        severe = None
    if len(special.severe) > 1:
        if severe is not None:
            repairs.append(
                "The statement gives critical and high findings different times, and a rule has one for both, so that box "
                "was left empty. Type the one you mean; the shorter is the stricter."
            )
        severe = None
    elif severe is None and len(special.severe) == 1 and obj.get("severe_days") is None:
        # The statement plainly has one, and the model left it out. Not filled in for it: a
        # number code chose is no more the reader's than one a model chose. Said instead.
        (only,) = special.severe
        repairs.append(
            f"The statement gives {_days(only)} for critical or high findings and the model left that box empty. "
            "Type it if it is the limit you mean."
        )
    if severe is not None and days is not None and severe > days:
        repairs.append(
            f"The model's {_days(severe)} for critical and high findings is longer than its {_days(days)} for everything "
            "else, and that limit has to be the shorter, so that box was left empty."
        )
        severe = None

    releases = _limit(obj.get("releases"), MAX_RELEASES, releases_stated, "releases limit", "release", repairs)
    cannot = _cannot(obj.get("cannot"), statement)
    if special.other or len(special.severe) > 1:
        cannot.insert(0, CANNOT_SEVERITY)
    if not days_stated and not releases_stated:
        # Nothing to draft from, said by code: no number is in the statement, whatever the
        # model wrote. The repairs above already say what it proposed, if it proposed one.
        cannot.append(CANNOT_NO_NUMBER)
    return Draft(
        max_days_behind=days, max_releases_behind=releases, max_days_behind_severe=severe, cannot=cannot, repairs=repairs
    )
