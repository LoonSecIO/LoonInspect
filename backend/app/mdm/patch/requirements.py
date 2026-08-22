"""Evaluate a Jamf Patch title's `requirements` against one installed app on one device.

A title's requirements, as the catalog sync stores them (`jamf_catalog._convert_requirements`),
are OR'd groups of AND'd tests:

    [{"operator": "and", "tests": [{"name": "Application Bundle ID", "operator": "is",
                                    "value": "com.agilebits.onepassword4", "type": "recon"}, ...]}, ...]

That shape is derived from Jamf's flat list, which is a Smart Group criteria object: every
criterion carries an `and` flag that says how it joins to the criterion *before it* in the list
(`true` AND, `false` OR); the first flag is meaningless, and with no parentheses in the patch
schema AND binds tighter than OR. The flat list is the part most tooling misreads, which is why
this module only ever sees the grouped form — the flag never reaches it.

Semantics (kept in lockstep with `frontend/src/features/jamfPatch/requirementsEvaluator.ts`, the
admin's hand-check of the same rule):

* string tests are case-insensitive; `like` and `has` are substring tests — Jamf's catalog depends
  on that ("5.4.3" *is* like "4.", which is why 1Password 4 also says `not like "5.4."`);
* `matches regex` / `does not match regex` use the value as a Python regex, case-insensitive; an
  invalid pattern fails (and "does not match" then passes);
* ordered operators compare versions as integer tuples of the digit runs — "7.0.5 (81138)" reads
  as (7, 0, 5, 81138), "02.05.00.66" as (2, 5, 0, 66);
* a test whose fact is unknown here (an extension attribute the device does not carry, an OS
  version we were not given, a test name or operator we do not know) is NOT_APPLICABLE — never a
  pass. A group with a failure is not matched; a group with no failure but something not applicable
  is inconclusive; only a group whose every test passed is matched. A title matches when any group
  matches, is inconclusive when no group matches but one is inconclusive, and otherwise does not
  match.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum


class Outcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"


class Verdict(str, Enum):
    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    INCONCLUSIVE = "inconclusive"


BUNDLE_ID = "Application Bundle ID"
APPLICATION_TITLE = "Application Title"
APPLICATION_VERSION = "Application Version"
OS_VERSION = "Operating System Version"
PLATFORM = "Platform"
EXTENSION_ATTRIBUTE = "extensionAttribute"

# Tests that are about the app rather than the device. A title with none of these in any group
# (the "Apple macOS …" titles) describes the device and is not an application title.
APP_TESTS = frozenset({BUNDLE_ID, APPLICATION_TITLE, APPLICATION_VERSION})


@dataclass(frozen=True)
class Facts:
    """What is known about one app on one device. Anything None is unknown, not empty."""

    app_name: str | None = None
    bundle_id: str | None = None
    # Every version string the source carries for the app — Jamf gives the marketing version,
    # SimpleMDM gives build and marketing. "Application Version" passes if any of them does, so
    # the evaluator is indifferent to which slot a connector put which string in.
    versions: tuple[str, ...] = ()
    os_version: str | None = None
    platform: str | None = "Mac"
    # Extension-attribute name -> value, as the device reports them. Looked up case-insensitively.
    extension_attributes: Mapping[str, str | None] = field(default_factory=dict)
    # Jamf uses an extension attribute where inventory cannot tell titles apart — PyCharm
    # Community vs Professional, Firefox vs Firefox ESR — a scoping device, not a fact about
    # the app. With this set, an attribute the device does not carry resolves TRUE (Kyle's
    # practice) instead of leaving the test not applicable; one it does carry is still read.
    assume_missing_attributes: bool = False


def version_tuple(value: str | None) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value or ""))


def compare_versions(a: str | None, b: str | None) -> int:
    """Negative when a < b, zero when equal, positive when a > b — on the digit runs, with
    missing trailing components read as zero (so "4.2" == "4.2.0")."""
    av, bv = version_tuple(a), version_tuple(b)
    for index in range(max(len(av), len(bv))):
        diff = (av[index] if index < len(av) else 0) - (bv[index] if index < len(bv) else 0)
        if diff:
            return diff
    return 0


def _text(value: str | None) -> str:
    return (value or "").strip().casefold()


def compare(operator: str, actual: str | None, expected: str | None) -> bool | None:
    """One Jamf criterion operator applied to a known fact. None means the operator is not one
    this evaluator knows, which the caller treats as NOT_APPLICABLE rather than as a failure."""
    a, e = _text(actual), _text(expected)
    if operator == "is":
        return a == e
    if operator == "is not":
        return a != e
    if operator in ("like", "has"):
        return e in a
    if operator == "not like":
        return e not in a
    if operator == "matches regex":
        try:
            return re.search(expected or "", actual or "", re.IGNORECASE) is not None
        except re.error:
            return False
    if operator == "does not match regex":
        try:
            return re.search(expected or "", actual or "", re.IGNORECASE) is None
        except re.error:
            return True
    if operator == "greater than":
        return compare_versions(actual, expected) > 0
    if operator == "greater than or equal":
        return compare_versions(actual, expected) >= 0
    if operator == "less than":
        return compare_versions(actual, expected) < 0
    if operator == "less than or equal":
        return compare_versions(actual, expected) <= 0
    return None


def _outcome(result: bool | None) -> Outcome:
    if result is None:
        return Outcome.NOT_APPLICABLE
    return Outcome.PASS if result else Outcome.FAIL


def _lookup_extension_attribute(facts: Facts, name: str) -> tuple[bool, str | None]:
    wanted = _text(name)
    for key, value in facts.extension_attributes.items():
        if _text(key) == wanted:
            return True, value
    return False, None


def evaluate_test(test: Mapping, facts: Facts) -> Outcome:
    operator = str(test.get("operator") or "")
    expected = test.get("value")
    expected = None if expected is None else str(expected)
    name = str(test.get("name") or "")

    if test.get("type") == EXTENSION_ATTRIBUTE:
        present, value = _lookup_extension_attribute(facts, name)
        if not present:
            return Outcome.PASS if facts.assume_missing_attributes else Outcome.NOT_APPLICABLE
        # An attribute the device carries with no value is Jamf's empty string, not an unknown.
        return _outcome(compare(operator, value or "", expected))

    if name == BUNDLE_ID:
        if facts.bundle_id is None:
            return Outcome.NOT_APPLICABLE
        return _outcome(compare(operator, facts.bundle_id, expected))
    if name == APPLICATION_TITLE:
        if facts.app_name is None:
            return Outcome.NOT_APPLICABLE
        return _outcome(compare(operator, facts.app_name, expected))
    if name == APPLICATION_VERSION:
        if not facts.versions:
            return Outcome.NOT_APPLICABLE
        results = [compare(operator, version, expected) for version in facts.versions]
        if all(result is None for result in results):
            return Outcome.NOT_APPLICABLE
        return Outcome.PASS if any(result for result in results) else Outcome.FAIL
    if name == OS_VERSION:
        if facts.os_version is None:
            return Outcome.NOT_APPLICABLE
        return _outcome(compare(operator, facts.os_version, expected))
    if name == PLATFORM:
        if facts.platform is None:
            return Outcome.NOT_APPLICABLE
        return _outcome(compare(operator, facts.platform, expected))
    return Outcome.NOT_APPLICABLE


def evaluate_group(group: Mapping, facts: Facts) -> Verdict:
    tests = list(group.get("tests") or [])
    if not tests:
        return Verdict.NOT_MATCHED
    outcomes = [evaluate_test(test, facts) for test in tests]
    if Outcome.FAIL in outcomes:
        return Verdict.NOT_MATCHED
    if Outcome.NOT_APPLICABLE in outcomes:
        return Verdict.INCONCLUSIVE
    return Verdict.MATCHED


def evaluate(groups: Sequence[Mapping], facts: Facts) -> Verdict:
    verdicts = [evaluate_group(group, facts) for group in groups]
    if Verdict.MATCHED in verdicts:
        return Verdict.MATCHED
    if Verdict.INCONCLUSIVE in verdicts:
        return Verdict.INCONCLUSIVE
    return Verdict.NOT_MATCHED


def _tests(groups: Sequence[Mapping]):
    for group in groups:
        yield from group.get("tests") or []


def is_app_level(groups: Sequence[Mapping]) -> bool:
    """Whether the title is about an application at all: any app test, or an extension attribute
    (the `jamf-patch-*` attributes report an installed app's version)."""
    return any(test.get("type") == EXTENSION_ATTRIBUTE or test.get("name") in APP_TESTS for test in _tests(groups))


def required_bundle_ids(groups: Sequence[Mapping]) -> frozenset[str] | None:
    """The bundle IDs an app must have for the title to possibly match, or None when the title
    cannot be narrowed that way.

    A title is narrow when every group pins the bundle ID with `is`: an app whose bundle ID is
    none of those values fails every group, so it need not be evaluated. Any group without such
    a test (title-only, extension-attribute-only, `like` on the bundle ID) makes the title broad —
    it has to be evaluated for every app. The values are casefolded, as `compare` sees them.
    """
    required: set[str] = set()
    for group in groups:
        pinned = [
            _text(str(test.get("value")))
            for test in group.get("tests") or []
            if test.get("type") != EXTENSION_ATTRIBUTE and test.get("name") == BUNDLE_ID and test.get("operator") == "is"
        ]
        if not pinned:
            return None
        required.update(pinned)
    return frozenset(required) if required else None
