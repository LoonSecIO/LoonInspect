"""Read docs/baseline-rules.yml into frozen objects. Read-only, by design.

The catalogue is data, so this module parses and shapes and does nothing else: no predicate is evaluated here and no
session is touched. The invariants — ids in order, every `field` still an allowlisted leaf of the Jamf contract, every
rule on a scalar section, one `difference` per rule — are asserted in tests/test_baseline_rules.py, where drift in
either file fails a build rather than a report.

Where the file lives: `.dockerignore` excludes `docs` and `pyyaml` is in pyproject's `dev` group, so the container
image carries neither, and the only caller today is the test suite. `CATALOGUE_PATHS` already looks beside the backend
root — /app in the image — so the issue that first reads the catalogue at request time adds a COPY and a dependency
move, and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

CATALOGUE_NAME = "baseline-rules.yml"
CATALOGUE_PATHS: tuple[Path, ...] = tuple(Path(__file__).resolve().parents[n] / "docs" / CATALOGUE_NAME for n in (3, 2))

#: v1's vocabularies, none of which grows without a ruling: predicate operators (`equals` a scalar, `in` a list,
#: `version_at_least` a dotted version compared component by component), how closely a cited MSCP rule matches ours,
#: and the substitutions a `witnessed` sentence may carry.
OPERATORS = frozenset({"equals", "in", "version_at_least"})
MATCHES = frozenset({"exact", "partial"})
PLACEHOLDERS = frozenset({"field", "value", "operand"})

#: The catalogue version these readers are written against. A file at another version is refused rather than read
#: on the assumption that the keys still mean what they meant: the vocabularies above are the version's, and a
#: report built from half of a catalogue it did not understand prints as a passing fleet (#473).
KNOWN_VERSION = 1


class CatalogueError(RuntimeError):
    """The catalogue could not be read, or is not shaped like a catalogue."""


@dataclass(frozen=True)
class MscpCitation:
    id: str
    branch: str  # MSCP branches per macOS release; an id without one is not checkable by the next reader
    match: str
    difference: str


@dataclass(frozen=True)
class Predicate:
    operator: str
    operand: Any


@dataclass(frozen=True)
class BaselineRule:
    id: str
    title: str
    section: str
    field: str
    predicate: Predicate
    witnessed: str
    origin: str
    mscp: MscpCitation | None
    difference: str  # the one difference, lifted from wherever the file keeps it

    @property
    def field_path(self) -> tuple[str, ...]:
        # The path inside the section's document, without the leading section token.
        return tuple(self.field.split("."))[1:]


@dataclass(frozen=True)
class BaselineCatalogue:
    version: int
    rules: tuple[BaselineRule, ...]

    def by_id(self, rule_id: str) -> BaselineRule:
        return next(rule for rule in self.rules if rule.id == rule_id)


def _rule(raw: Any, index: int) -> BaselineRule:
    """`difference` sits inside `mscp` where an id is cited and at the top level where none is; it is lifted to one."""
    try:
        mscp = MscpCitation(**raw["mscp"]) if raw["mscp"] else None
        plain = {key: value for key, value in raw.items() if key not in ("predicate", "mscp", "difference")}
        return BaselineRule(
            **plain,
            predicate=Predicate(**raw["predicate"]),
            mscp=mscp,
            difference=mscp.difference if mscp else raw["difference"],
        )
    except (AttributeError, KeyError, TypeError) as exc:
        raise CatalogueError(f"rule {index} of docs/{CATALOGUE_NAME} is not shaped like a rule: {exc!r}") from exc


def load_catalogue(path: Path | None = None) -> BaselineCatalogue:
    """Parse the catalogue. `path` overrides the search, for a caller with its own copy."""
    candidates = (path,) if path is not None else CATALOGUE_PATHS
    found = next((candidate for candidate in candidates if candidate.is_file()), None)
    if found is None:
        raise CatalogueError(
            "the baseline rule catalogue was not found. Looked for: "
            + ", ".join(str(candidate) for candidate in candidates)
            + f". It ships as docs/{CATALOGUE_NAME} in the repository, and `.dockerignore` keeps `docs` out of the "
            "image — a caller inside a container needs the file copied in first."
        )

    document = yaml.safe_load(found.read_text())
    rules = document.get("rules") if isinstance(document, dict) else None
    if not isinstance(rules, list) or not rules or "version" not in document:
        raise CatalogueError(f"{found} is not a catalogue: it is a `version:` key and a non-empty `rules:` list")
    if document["version"] != KNOWN_VERSION:
        raise CatalogueError(
            f"{found} is at version {document['version']!r} and this build reads version {KNOWN_VERSION}. The "
            "operators, the MSCP match words and the `witnessed` placeholders are that version's vocabulary, so a "
            "catalogue from another one is refused rather than read on the assumption that its keys still mean "
            "what they meant. Use a build that reads this catalogue's version."
        )
    return BaselineCatalogue(version=document["version"], rules=tuple(_rule(raw, i) for i, raw in enumerate(rules, 1)))


@lru_cache(maxsize=1)
def catalogue() -> BaselineCatalogue:
    """The shipped catalogue, parsed once. The rules are frozen, so the cache is shareable."""
    return load_catalogue()
