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
    CHANGE_LEAF,
    ENRICHMENTS,
    PRODUCER,
    SECTION_WRAPPERS,
    SUB_EVENT_KEYS,
    SUBJECT_WRAPPERS,
    change_rows,
    enrichment_rows,
    registry_rows,
    sourcetype,
)
from app.mdm.jamf.contract import SECTIONS
from app.schemas.payload import InventoryChangedEvent, InventorySnapshotEvent

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
    wrappers = (
        list(SECTION_WRAPPERS.values())
        + list(SUBJECT_WRAPPERS.values())
        + [leaf for leaves in ENRICHMENTS.values() for leaf in leaves]
    )
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


def test_the_change_family_is_a_marker_not_a_wrapper_key() -> None:
    """#243, 2026-09-03: ruling 5 is scoped to section and enrichment leaves.

    `device.change` already ships `change` as a scalar verb — `changed` / `added` /
    `removed` / `updated` — and clause 2 forbids changing a shipped key's type or meaning,
    so the `:change` leaf promises no `change{}` wrapper. What it buys instead is ruling
    2's trailing-compound property: `*:change` pulls every change across every subject and
    every vendor, exactly the way `*:vuln` reads.
    """
    wrappers = (
        set(SECTION_WRAPPERS.values())
        | set(SUBJECT_WRAPPERS.values())
        | {leaf for leaves in ENRICHMENTS.values() for leaf in leaves}
    )
    assert CHANGE_LEAF == "change"
    assert CHANGE_LEAF not in wrappers, (
        "`change` is a family marker, not a wrapper key — minting it as one would collide "
        "with the scalar verb device.change already ships under that name"
    )
    assert all(stype.endswith(":change") for _subject, _wrapper, stype in change_rows())


def test_every_change_subject_has_a_change_sourcetype() -> None:
    """Every section, plus every subject that is not one.

    Fifteen strings is fifteen hand-written `props.conf` stanzas in a customer's Splunk,
    because a sourcetype stanza takes no wildcards — the count #243 put on the record as
    the argument for a LoonInspect TA.
    """
    rows = change_rows()
    assert {subject for subject, _w, _s in rows} == set(SECTIONS) | set(SUBJECT_WRAPPERS)
    assert len(rows) == len(SECTIONS) + len(SUBJECT_WRAPPERS) == 15
    for _subject, wrapper, stype in rows:
        assert stype == sourcetype(wrapper, leaf=CHANGE_LEAF)
    assert ("computer_group", "computerGroup", "loon:jamf:mac:computerGroup:change") in rows


def test_the_superseded_change_spellings_are_not_reintroduced() -> None:
    """#243 refused three spellings, and each refusal is a permanent string not minted.

    `groupDefinition` says what changed and hides whose. `definition` alone collides in
    sense with `group`, which is already the device's `group_memberships` section — a group
    and the definition of a group have to stay distinguishable (ruling 4). And the
    no-vendor form `loon:change` was refused because the assertion rule's own rationale is
    that a run event is about a run rather than a fleet; a change is about the fleet.
    `vuln` is the precedent both ways — equally LoonInspect's own derivation about a Jamf
    object, and equally vendor-stamped so `loon:*:mac:app:vuln` keeps working.
    """
    wrappers = set(SECTION_WRAPPERS.values()) | set(SUBJECT_WRAPPERS.values())
    for refused in ("groupDefinition", "definition", "group_definition", "computerGroupDefinition"):
        assert refused not in wrappers, f"{refused} was ruled out on #243"
    assert SUBJECT_WRAPPERS["computer_group"] == "computerGroup"

    strings = {stype for _subject, _wrapper, stype in change_rows()}
    assert not any(stype.startswith(f"{PRODUCER}:{CHANGE_LEAF}") for stype in strings), (
        "the no-vendor assertion form was refused on #243: a change is about the fleet, "
        "not about a run"
    )
    assert all(stype.startswith(f"{PRODUCER}:jamf:mac:") for stype in strings)


def test_doc_change_table_is_generated_from_the_registry() -> None:
    documented = _doc_rows("| Subject | Wrapper key | Sourcetype |")
    assert documented == change_rows(), (
        "docs/splunk-wire-vocabulary.md's change table must match "
        "app.core.wire_vocabulary.change_rows() exactly, in order. Regenerate it rather "
        "than editing it by hand."
    )


def test_the_sub_event_keys_are_the_ruled_three() -> None:
    """#220 (D1, from #81's close-out), 2026-09-02: what survives the fan-out split.

    Pinned before the fan-out exists, which is the whole point — #242 has no sub-event to
    correct once a customer has indexed one. `event` is the snapshot's own type carried
    down, not a per-sub-event discriminator; `sourcetype` is what distinguishes an app
    from a certificate.
    """
    assert SUB_EVENT_KEYS == ("event", "jobID", "deviceMeta")
    assert all(_WIRE_KEY.match(key) for key in SUB_EVENT_KEYS), "the casing law covers these too"


def test_the_event_that_the_fan_out_expands_already_carries_all_three() -> None:
    """The bridge from the ruling to the shipped model.

    `_build_body` receives the stored payload and nothing else (`app.core.outbox`), so a
    key the fan-out is required to stamp on every sub-event has to be on the event it
    expands, or it is unreachable by the time the split happens. `jobID` at the root is
    #220's hoist; before it, this assertion would have failed on that key alone.

    Since #241 the event the fan-out expands is the snapshot, `InventorySnapshotEvent`;
    the delta is held to the same three so the two inventory families never disagree
    about what survives a split.
    """
    for model in (InventorySnapshotEvent, InventoryChangedEvent):
        wire_names = {
            info.alias or info.serialization_alias or name for name, info in model.model_fields.items()
        }
        assert set(SUB_EVENT_KEYS) <= wire_names, model.__name__


def test_doc_sub_event_table_matches_the_ruling() -> None:
    documented = _doc_rows("| Key | What it carries | Ruled |")
    assert tuple(row[0] for row in documented) == SUB_EVENT_KEYS, (
        "docs/splunk-wire-vocabulary.md §6 must name exactly the keys in "
        "app.core.wire_vocabulary.SUB_EVENT_KEYS, in order."
    )


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


def test_alert_is_singular_app_carried_and_written_by_nothing() -> None:
    """`alerts{}` — the plural #81 ruling 5 parked and #101 carries — was ruled out as a
    wrapper key on 2026-09-02 (#229). The wire slot is `alert`: an inline enrichment on
    the app sub-event beside `patch` and `vuln`, minted with no writer in v0. The posture
    tape's `alerts.open` / `alerts.opened_24h` are a different vocabulary — this one
    governs the wire only — and keep their spelling whatever their status."""
    from app.core.posture import ACTIVE_KEYS, RESERVED_KEYS

    wrappers = set(SECTION_WRAPPERS.values()) | {leaf for leaves in ENRICHMENTS.values() for leaf in leaves}
    assert "alerts" not in wrappers
    assert "alert" in ENRICHMENTS["app"]
    assert [carrier for carrier, leaves in ENRICHMENTS.items() if "alert" in leaves] == ["app"]
    assert sourcetype("app", leaf="alert") == "loon:jamf:mac:app:alert"
    assert {"alerts.open", "alerts.opened_24h"} <= set(ACTIVE_KEYS) | set(RESERVED_KEYS)


def test_the_sentinel_clause_names_the_key_that_ruled_its_clock() -> None:
    """#113, 2026-09-02: clause 4's example was `days_oldest`, minted before this
    vocabulary froze camelCase and before the vulnerability contract put the clock's
    basis in the key name. The clause is unchanged in substance; the spelling it cites
    is not. `cve_l` and `cves_truncated` were the same design record's names for the id
    list and its flag, and lost to `vulnIDs` / `vulnIDsTruncated` on the same day.

    Pinned in both directions because the refused spellings are still readable on #113,
    on #81 ruling 5 and in the 2026-08-25 design record, and a contract that lives in a
    session record is one that gets re-argued by whoever builds it — which is what
    docs/vulnerabilities.md exists to stop.
    """
    clauses = " ".join(ADDITIVE_ONLY_CLAUSES)
    assert "daysOldestPublished" in clauses
    for refused in ("days_oldest", "cve_l", "cves_truncated", "vulnerabilities{}"):
        assert refused not in clauses, f"{refused} was ruled out on #113"

    contract = (DOC.parent / "vulnerabilities.md").read_text()
    for ruled in ("daysOldestPublished", "vulnIDs", "vulnIDsTruncated", "LOCAL-YYYY-NNNNNN", "unknown_app"):
        assert ruled in contract, f"docs/vulnerabilities.md must carry the ruled name {ruled}"
    assert "loon:jamf:mac:app:vuln" in contract, (
        "the contract must say which sourcetype the lifecycle records take — the summary "
        "rides the app sub-event inline, so the compound leaf is not the summary's"
    )
