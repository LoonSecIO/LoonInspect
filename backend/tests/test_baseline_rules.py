"""The baseline rule catalogue against the Jamf contract it reads from.

docs/baseline-rules.yml is the evidence report's vocabulary, and it is permanent the day the first artefact is printed:
an auditor archives the document and next year's auditor compares against it. Each assertion pins a promise a later
session could break quietly, and the two that rot most quietly — the reason this file exists — are a `field` that
stops resolving under a contract change, and a rule that loses the `difference` explaining why it cites no MSCP id.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.baseline.catalogue import (
    CATALOGUE_NAME,
    KNOWN_VERSION,
    MATCHES,
    OPERATORS,
    PLACEHOLDERS,
    CatalogueError,
    catalogue,
    load_catalogue,
)
from app.mdm.jamf import contract

CATALOGUE = Path(__file__).resolve().parents[2] / "docs" / "baseline-rules.yml"


def _resolves(section: str, path: tuple[str, ...]) -> bool:
    """Does `path` reach a hashed leaf of `section`'s allowlist? A branch is not a field: a predicate landing on one
    would be comparing a sub-document to a scalar."""
    spec = contract.SECTIONS.get(section)
    if spec is None or spec.fields is None:
        return False
    node: Any = spec.fields
    for part in path:
        if not isinstance(node, Mapping) or part not in node:
            return False
        node = node[part]
    return not isinstance(node, Mapping)


def test_the_catalogue_is_v1_with_ten_rules_numbered_in_order() -> None:
    """Ids are flat, zero-padded and never renumbered (#219 R5 5.1): a gap or a repeat here is an archived report and
    a live one disagreeing about what a row is called."""
    loaded = catalogue()

    assert loaded.version == 1
    assert [rule.id for rule in loaded.rules] == [f"LI-{n:04d}" for n in range(1, 11)]
    assert {rule.predicate.operator for rule in loaded.rules} <= OPERATORS
    assert catalogue() is loaded, "parsed once; the rules are frozen, so the cache is shareable"
    assert loaded.version == KNOWN_VERSION, "the shipped file is the version the readers are written against"


def test_a_catalogue_at_another_version_is_refused_rather_than_read(tmp_path: Path) -> None:
    """A version is a vocabulary — the operators, the MSCP match words and the `witnessed` placeholders are v1's.
    Read on the assumption that another version's keys still mean what they meant, a catalogue half understood
    prints as a passing fleet, so it is refused with the version it found in the sentence. The evidence report turns
    that into its 503 (#473, docs/troubleshooting.md §17 step 1)."""
    written = tmp_path / CATALOGUE_NAME
    written.write_text(yaml.safe_dump({"version": 9, "rules": [{"id": "LI-0001"}]}))
    with pytest.raises(CatalogueError, match="is at version 9 and this build reads version 1"):
        load_catalogue(written)


def test_every_field_resolves_in_the_contract_allowlist_for_its_own_scalar_section() -> None:
    """The one that rots silently: a field normalized out of the contract with the catalogue still naming it, and the
    report printing "unmet" for a whole fleet because nothing was ever there to read. The section has to be scalar too
    — a list section stores sorted entry digests rather than a document, so a field read there is a join through
    `observation_entries`, i.e. a second evaluator and not v1's. And the sentence beside the verdict names the field,
    because "met" alone is a spreadsheet with better typography (#219 R5 5.1); the placeholder vocabulary is closed so
    the renderer cannot be handed one it does not know."""
    for rule in catalogue().rules:
        assert rule.field.split(".")[0] == rule.section, f"{rule.id}: `field` is section-qualified"
        assert not contract.SECTIONS[rule.section].is_list, f"{rule.id} reads {rule.section}, a list section"
        assert _resolves(rule.section, rule.field_path), f"{rule.id}: {rule.field} is not an allowlisted leaf"
        used = set(re.findall(r"\{([a-z]+)\}", rule.witnessed))
        assert used <= PLACEHOLDERS, f"{rule.id}: unknown placeholder(s) {sorted(used - PLACEHOLDERS)}"
        assert {"field", "value"} <= used, f"{rule.id}: `witnessed` names the field it read and what it said"

    # The resolver earns its assertions: a field the contract deliberately omits, and a branch
    # that is not a leaf, both have to fail it.
    assert not _resolves("security", ("lastAttestationAttempt",))
    assert not _resolves("disk_encryption", ("bootPartitionEncryptionDetails",))


def test_three_rules_cite_mscp_and_the_other_seven_say_why_not() -> None:
    """The ruling as data: an id is cited only where the proposition is the same, and a rule citing none owes the reader
    the difference in writing."""
    loaded = catalogue()
    cited = [rule for rule in loaded.rules if rule.mscp is not None]

    assert [rule.id for rule in cited] == ["LI-0005", "LI-0006", "LI-0007"]
    assert {rule.mscp.id for rule in cited if rule.mscp} == {
        "os_secure_boot_verify",
        "os_recovery_lock_enable",
        "system_settings_remote_management_disable",
    }
    for rule in cited:
        assert rule.mscp is not None and rule.mscp.match in MATCHES
        assert rule.mscp.branch, f"{rule.id}: an MSCP id without the branch it was read from is not citable"
    for rule in loaded.rules:
        assert len(rule.difference.split()) >= 10, f"{rule.id}: `difference` is a written sentence, not a token"
    # One difference per rule, and in the place the file's comment block says it belongs.
    for raw in yaml.safe_load(CATALOGUE.read_text())["rules"]:
        assert ("difference" in raw) == (raw["mscp"] is None), f"{raw['id']}: one `difference`, never both places"


def test_the_wrong_fields_that_sit_next_to_the_right_ones() -> None:
    """Each is a wrong field one line from a right one, wrong in a way that reads as plausible:
    `general.remoteManagement.managed` is Jamf's own flag for "Jamf manages this Mac" and inverted would print a
    fleet-wide failure across a correctly managed fleet; the two FileVault summary fields fold other volumes into the
    answer; `bootstrapTokenAllowed` says the Mac *may* escrow where the rule is about whether it did."""
    remote = catalogue().by_id("LI-0007")
    assert remote.field == "security.remoteDesktopEnabled"
    assert _resolves("general", ("remoteManagement", "managed")), "the wrong field is a real field; that is the trap"
    assert "remoteManagement.managed" in remote.origin

    filevault = catalogue().by_id("LI-0001")
    assert filevault.field == "disk_encryption.bootPartitionEncryptionDetails.partitionFileVault2State"
    for crosscheck in ("disk_encryption.fileVault2Enabled", "operating_system.fileVault2Status"):
        assert crosscheck in filevault.origin, f"{crosscheck} must be named as a cross-check, not left to be guessed"

    assert "bootstrapTokenAllowed" in catalogue().by_id("LI-0009").difference


def test_the_version_floor_is_a_comparison_and_prints_the_floor_it_used() -> None:
    """The one rule whose meaning drifts, because its operand is edited over time: a report printing only the verdict
    would say "met" about two different propositions a year apart, so the floor travels in the sentence."""
    floor = catalogue().by_id("LI-0010")

    assert floor.predicate.operator == "version_at_least", "a floor is a version comparison, never a string equality"
    assert isinstance(floor.predicate.operand, str), "an unquoted 26.0 is a float, and 26.10 < 26.9 as one"
    assert "{operand}" in floor.witnessed
    assert floor.mscp is None and "MSCP has no version-floor rule" in floor.difference


def test_the_rules_about_the_ids_are_written_in_the_file_that_carries_them() -> None:
    """A ruling that lives only in a closed issue is one a later tidy-up undoes."""
    prose = " ".join(CATALOGUE.read_text().replace("*", "").replace("#", "").split())

    for sentence in (
        "Ids are never renumbered.",
        "Grouping lives in `section`, never in the id.",
        "MSCP rule files carry CMMC and 800-171 mappings inside them.",
        "Most MSCP rules check the managed preference, not the effective state.",
    ):
        assert sentence in prose, f"the catalogue's own comment block must say: {sentence}"
