"""The frozen wire vocabulary against its own registry doc (#188).

The vocabulary was ruled three times, differently, because nothing mechanical held the
answer in one place. These tests are that mechanism: the registry is generated from the
read aperture (`SECTIONS`), the doc table is generated from the registry, and drift in
either direction fails the build. Pure logic; no database.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core.wire_vocabulary import (
    ADDITIVE_ONLY_CLAUSES,
    ASSERTION_SOURCETYPE,
    ENRICHMENTS,
    PRODUCER,
    SECTION_WRAPPERS,
    enrichment_rows,
    registry_rows,
    sourcetype,
)
from app.mdm.jamf.contract import SECTIONS

DOC = Path(__file__).resolve().parents[2] / "docs" / "splunk-wire-vocabulary.md"

# camelCase, with the token `ID` uppercase wherever it appears — the narrow clause ruled
# 2026-09-01. `ea` and `cert` are why the general "all initialisms uppercase" form was
# rejected, so the pattern must accept them.
_WIRE_KEY = re.compile(r"^[a-z][a-zA-Z0-9]*$")


def _doc_rows(header: str) -> list[tuple[str, ...]]:
    """Every pipe-table row under the given column header line, as tuples of the
    backtick-quoted cells."""
    rows: list[tuple[str, ...]] = []
    lines = DOC.read_text().splitlines()
    for index, line in enumerate(lines):
        if line.strip() != header:
            continue
        for row in lines[index + 2 :]:
            if not row.startswith("|"):
                break
            cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
            rows.append(tuple(cell.strip("`") for cell in cells))
        break
    return rows


def test_every_collected_section_has_a_wire_name() -> None:
    """A section cannot reach the read aperture without a name to travel under."""
    assert set(SECTION_WRAPPERS) == set(SECTIONS), (
        "app.core.wire_vocabulary.SECTION_WRAPPERS and app.mdm.jamf.contract.SECTIONS "
        "must name exactly the same sections — a section collected with no wrapper key "
        "has nowhere to land on the wire, and a wrapper key with no section is a "
        "sourcetype nothing will ever write to."
    )


def test_wrapper_keys_are_unique_and_obey_the_casing_law() -> None:
    wrappers = list(SECTION_WRAPPERS.values()) + [leaf for leaves in ENRICHMENTS.values() for leaf in leaves]
    assert len(set(wrappers)) == len(wrappers), "two sections cannot share one wrapper key"
    assert all(_WIRE_KEY.match(wrapper) for wrapper in wrappers)
    assert "Id" not in "".join(wrappers), "the token ID is uppercase (#188, 2026-09-01)"


def test_sourcetype_tree_is_producer_first_and_leaf_equals_wrapper() -> None:
    assert sourcetype("app") == "loon:jamf:mac:app"
    assert sourcetype("app", leaf="vuln") == "loon:jamf:mac:app:vuln"
    assert sourcetype("app", vendor="addigy") == "loon:addigy:mac:app"
    assert f"{PRODUCER}:run" == ASSERTION_SOURCETYPE, "LoonInspect's own assertions carry no vendor segment"
    # Ruling 5: the leaf equals the body's wrapper key, so one vocabulary serves both.
    for _section, _response_key, wrapper, stype in registry_rows():
        assert stype.rsplit(":", 1)[-1] == wrapper


def test_enrichments_hang_off_a_real_wrapper() -> None:
    wrappers = set(SECTION_WRAPPERS.values())
    for carrier in ENRICHMENTS:
        assert carrier in wrappers, f"{carrier} is not a wrapper key any section produces"


def test_doc_registry_table_is_generated_from_sections() -> None:
    documented = _doc_rows("| Contract section | Jamf response key | Wrapper key | Sourcetype |")
    assert documented == registry_rows(), (
        "docs/splunk-wire-vocabulary.md's registry table must match "
        "app.core.wire_vocabulary.registry_rows() exactly, in order. Regenerate it "
        "rather than editing it by hand."
    )


def test_doc_enrichment_table_matches_the_registry() -> None:
    documented = _doc_rows("| Carrier | Enrichment | Sourcetype |")
    assert documented == enrichment_rows()


def _prose(text: str) -> str:
    """Lowercased words only. The doc wraps, emphasises and uses typographic quotes;
    none of that is the clause, so none of it should be able to fail this test."""
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def test_doc_carries_the_additive_only_clauses() -> None:
    """Clause one verbatim is what licenses shipping patch{} and vuln{} after v0."""
    text = DOC.read_text()
    assert "**New keys may appear; consumers must ignore unknown keys.**" in text
    doc_prose = _prose(text)
    for clause in ADDITIVE_ONLY_CLAUSES:
        assert _prose(clause) in doc_prose, f"additive-only clause missing from the doc: {clause}"


def test_the_superseded_spellings_are_not_reintroduced() -> None:
    """`vulnerabilities` and `patching` were ruled out as wrapper keys on 2026-09-01."""
    wrappers = set(SECTION_WRAPPERS.values()) | {leaf for leaves in ENRICHMENTS.values() for leaf in leaves}
    assert "vulnerabilities" not in wrappers
    assert "patching" not in wrappers
    assert "vuln" in wrappers and "patch" in wrappers
