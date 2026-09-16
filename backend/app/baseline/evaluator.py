"""`(contract_version, section, digest)` → a verdict per rule, evaluated once per distinct document.

The ledger already stores one canonical document per distinct section content, behind a content-addressed digest that
is shared fleet-wide: `observation_sections` de-duplicates on `(tenant_id, digest)`. A fleet of 40,000 Macs holds a few
hundred distinct `security` documents, not 40,000 — so a rule is evaluated per *document* and joined per device. That
grain is the evidence report's whole performance story and it is the house pattern: cache, don't calculate.

`contract_version` is in the key because a rule's `field` is a path into *a contract*, not into JSON in general.
`CONTRACT_VERSION` is `v0` today and `observation_spans.contract_version` carries it per span, so a fleet mid-upgrade
has both on disk at once; a cache keyed without it would hand v0 answers to v1 documents. A field the named version
does not hash is `not_reported` for that version — never an exception, and never a silent `unmet`.

**Three outcomes, and the third is the reason this module is careful.** `app.mdm.jamf.contract._prune` drops every
spelling of absence, so a Jamf record that never reported `firewallEnabled` does not store `firewallEnabled: null` —
the key is not in the document at all. A two-valued evaluator reads the missing key as falsy and prints `unmet`: a Mac
nobody asked about, reported as a Mac that failed, on a document an auditor keeps for a year.

    key present, predicate true   → met
    key present, predicate false  → unmet          `false` and `0` are values; _prune keeps them deliberately
    key absent                    → not_reported

`not_reported` here is a field the aperture did not collect in a document we *do* hold. It is not #219 R5 5.2's *not
observed*, which is the gap between observations and belongs to the interval query. The artefact prints both numbers,
and conflating them here would make them inseparable downstream.

Scalar sections only. A list section stores a sorted array of entry digests rather than a document, so reading a field
out of one is a join through `observation_entries` — a second evaluator, written when a rule needs it. This one
refuses rather than answering it with an empty map.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping
from typing import Any

from app.baseline.catalogue import OPERATORS, BaselineRule, CatalogueError, Predicate, catalogue
from app.mdm.jamf.contract import CONTRACT_VERSION, SECTIONS

MET = "met"
UNMET = "unmet"
NOT_REPORTED = "not_reported"
OUTCOMES: tuple[str, ...] = (MET, UNMET, NOT_REPORTED)

#: Jamf's own sentinel for "this inventory did not collect the field", carried inside several security enums
#: (`sipStatus`, `gatekeeperStatus`, `secureBootLevel`). It is a reported absence wearing a value's costume, and
#: LI-0004's `difference` in docs/baseline-rules.yml rules that it "must not read as unmet" — printing a finding off
#: it is the same fabricated finding a missing key would be.
NOT_COLLECTED = "NOT_COLLECTED"

_ABSENT = object()

# Bounded: the key space is every distinct document the process ever sees, not one request's worth. Eviction is
# least-recently-used, and a re-evaluation costs a dict walk over ten rules, so an eviction is a slow path and never
# a wrong answer.
_CACHE_LIMIT = 4096
_CACHE: OrderedDict[tuple[str, str, str], dict[str, str]] = OrderedDict()


def evaluate(contract_version: str, section: str, digest: str, body: Mapping[str, Any] | None) -> dict[str, str]:
    """The verdict of every catalogue rule that reads `section`, keyed by rule id.

    Pure and synchronous: the caller hands over the `body` it already fetched and gets a map back. `digest` is the
    memo key and `body` is only read on a miss, so the pair must be the row the ledger holds — this function cannot
    check that a body hashes to its digest, and a mismatched pair would answer for the wrong document.

    A scalar section with no rule in the catalogue answers `{}`. A list section, or a name the contract does not know,
    raises: an empty map for those would read as "nothing to report".
    """
    spec = SECTIONS.get(section)
    if spec is None:
        raise ValueError(f"{section!r} is not a section of the Jamf contract; it knows {sorted(SECTIONS)}")
    if spec.is_list:
        raise ValueError(
            f"{section!r} is a list section: it stores sorted entry digests, not a document, so a rule reading a "
            "field out of it is a join through observation_entries. That is a second evaluator (#219 R5), not this one."
        )

    key = (contract_version, section, digest)
    cached = _CACHE.get(key)
    if cached is None:
        cached = _verdicts(contract_version, spec.name, spec.fields or {}, body)
        _CACHE[key] = cached
        while len(_CACHE) > _CACHE_LIMIT:
            _CACHE.popitem(last=False)
    else:
        _CACHE.move_to_end(key)
    # A copy, so a caller annotating its own map cannot edit an answer every other device shares.
    return dict(cached)


def clear_cache() -> None:
    """Forget every memoised verdict. For tests, and for anything that reloads the catalogue — these answers are the
    loaded rules' answers, so the two caches are cleared together."""
    _CACHE.clear()


def satisfies(predicate: Predicate, value: Any) -> bool | None:
    """Does `value` satisfy `predicate`? `None` where the predicate cannot be applied to this value at all — an
    unreadable version string, say — which the caller reads as `not_reported` rather than manufacturing an `unmet`."""
    if predicate.operator == "equals":
        return value == predicate.operand
    if predicate.operator == "in":
        operand = predicate.operand if isinstance(predicate.operand, list) else [predicate.operand]
        return value in operand
    if predicate.operator == "version_at_least":
        return version_at_least(value, predicate.operand)
    raise CatalogueError(f"unknown predicate operator {predicate.operator!r}; the catalogue knows {sorted(OPERATORS)}")


def version_at_least(value: Any, floor: Any) -> bool | None:
    """A macOS version against a floor, component by component: `14.7.1` is above `14.7` and `26.10` above `26.9`,
    which string comparison and float comparison each get wrong. `None` for anything that is not a dotted run of
    numbers — a version we cannot read is a field we cannot answer for, not a Mac below the floor."""
    left, right = _components(value), _components(floor)
    if left is None or right is None:
        return None
    return left >= right


def _components(value: Any) -> tuple[int, ...] | None:
    if not isinstance(value, str):
        return None
    parts = value.strip().split(".")
    if not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _verdicts(contract_version: str, section: str, allow: Mapping[str, Any], body: Mapping[str, Any] | None) -> dict[str, str]:
    rules = tuple(rule for rule in catalogue().rules if rule.section == section)
    if contract_version != CONTRACT_VERSION:
        # The paths are this contract version's. Another version may spell them differently or not carry them at all,
        # and guessing is how a v1 document gets v0 answers — the defect the key exists to prevent.
        return dict.fromkeys((rule.id for rule in rules), NOT_REPORTED)
    document = body if isinstance(body, Mapping) else {}
    return {rule.id: _verdict(allow, rule, document) for rule in rules}


def _verdict(allow: Mapping[str, Any], rule: BaselineRule, document: Mapping[str, Any]) -> str:
    if not _hashed_leaf(allow, rule.field_path):
        return NOT_REPORTED
    value = _read(document, rule.field_path)
    if value is _ABSENT or value == NOT_COLLECTED:
        return NOT_REPORTED
    satisfied = satisfies(rule.predicate, value)
    if satisfied is None:
        return NOT_REPORTED
    return MET if satisfied else UNMET


def _read(document: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    """The value at `path`, or `_ABSENT`. A key that is not there is not a key holding None: _prune never wrote one."""
    node: Any = document
    for step in path:
        if not isinstance(node, Mapping) or step not in node:
            return _ABSENT
        node = node[step]
    return node


def _hashed_leaf(allow: Mapping[str, Any], path: tuple[str, ...]) -> bool:
    """Does the contract hash this path as a field of the section? A path it does not is `not_reported`: nothing was
    ever stored there to read, whatever the rule says."""
    node: Any = allow
    for step in path:
        if not isinstance(node, Mapping) or step not in node:
            return False
        node = node[step]
    return not isinstance(node, Mapping)


def field_value(document: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    """The value a rule's `field` reads out of a stored section document, or `None` where the document does not carry
    it at all. `_prune` never wrote a null, so `None` here is absence and nothing else — which is what lets the
    evidence report print the field it read beside the verdict, and say so plainly when there was none (#472)."""
    value = _read(document, path)
    return None if value is _ABSENT else value
