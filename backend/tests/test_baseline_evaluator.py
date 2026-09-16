"""`app.baseline.evaluator`: a section document in, a verdict per rule out, once per distinct document.

The documents here are the real Jamf Pro 11.31.1 record the rest of the suite reads, put through the contract's own
canonicalization, so these assertions are about values a Mac actually reported rather than a document written to pass.
The one this file exists for is the third outcome: `_prune` drops absent keys, so a two-valued evaluator prints
`unmet` for a field nobody collected — a fabricated finding, on a document an auditor keeps.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from app.baseline import evaluator as ev
from app.baseline.catalogue import CatalogueError, Predicate, catalogue
from app.mdm.jamf.contract import CONTRACT_VERSION, SectionContent, canonicalize_computer

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "jamf"
REAL = FIXTURES / "computer_inventory_detail_real.json"
OLDER = FIXTURES / "computer_inventory_detail.json"
SCALARS = ("security", "operating_system", "disk_encryption")


def _sections(path: Path = REAL) -> dict[str, SectionContent]:
    return canonicalize_computer(json.loads(path.read_text()), SCALARS).sections


def _security(drop: tuple[str, ...] = (), **edits: object) -> SectionContent:
    """One canonical `security` document, with raw Jamf fields edited or dropped before canonicalization."""
    raw = json.loads(REAL.read_text())
    raw["security"].update(edits)
    for name in drop:
        del raw["security"][name]
    return canonicalize_computer(raw, SCALARS).sections["security"]


@pytest.fixture(autouse=True)
def _fresh_cache() -> Iterator[None]:
    ev.clear_cache()
    yield
    ev.clear_cache()


def test_the_real_record_answers_all_ten_rules_from_the_values_it_reported() -> None:
    """The fixture is a real Mac, so the answers are a real mix — two unmet among eight met, and both unmet are
    `false` rather than missing, which is the pair the next tests separate."""
    sections = _sections()
    verdicts: dict[str, str] = {}
    for name in SCALARS:
        content = sections[name]
        verdicts |= ev.evaluate(CONTRACT_VERSION, name, content.digest, content.body)

    assert verdicts == {
        "LI-0001": ev.MET,  # partitionFileVault2State ENCRYPTED
        "LI-0002": ev.MET,  # gatekeeperStatus APP_STORE_AND_IDENTIFIED_DEVELOPERS, one of the two accepted
        "LI-0003": ev.UNMET,  # firewallEnabled false
        "LI-0004": ev.MET,  # sipStatus ENABLED
        "LI-0005": ev.MET,  # secureBootLevel FULL_SECURITY
        "LI-0006": ev.UNMET,  # recoveryLockEnabled false
        "LI-0007": ev.MET,  # remoteDesktopEnabled false, and the rule asks for off
        "LI-0008": ev.MET,  # autoLoginDisabled true
        "LI-0009": ev.MET,  # bootstrapTokenEscrowedStatus ESCROWED
        "LI-0010": ev.MET,  # macOS 27.0 against the shipped floor
    }
    assert set(verdicts.values()) <= set(ev.OUTCOMES)


def test_a_field_the_aperture_never_collected_is_not_reported_and_never_unmet() -> None:
    """The defect this module exists to prevent. `_prune` drops absent keys rather than storing nulls, so the three
    fields below are not in the document at all; a falsy read of a missing key would print `unmet` for a Mac nobody
    ever asked about, beside a real `unmet` for a Mac that genuinely failed."""
    content = _security(drop=("firewallEnabled", "recoveryLockEnabled", "sipStatus"))

    assert "firewallEnabled" not in content.body, "the key is absent, not present and null"
    verdicts = ev.evaluate(CONTRACT_VERSION, "security", content.digest, content.body)

    assert verdicts["LI-0003"] == ev.NOT_REPORTED
    assert verdicts["LI-0006"] == ev.NOT_REPORTED
    assert verdicts["LI-0004"] == ev.NOT_REPORTED
    assert verdicts["LI-0008"] == ev.MET, "the rules whose fields are still there still answer"


def test_false_and_zero_are_values_and_read_unmet() -> None:
    """`_prune` keeps `False` and `0` deliberately — they are states a Mac is actually in. An evaluator that folded
    them into absence would lose every finding worth printing."""
    content = _security(autoLoginDisabled=False, recoveryLockEnabled=0)

    assert content.body["autoLoginDisabled"] is False
    assert content.body["recoveryLockEnabled"] == 0
    verdicts = ev.evaluate(CONTRACT_VERSION, "security", content.digest, content.body)

    assert verdicts["LI-0008"] == ev.UNMET
    assert verdicts["LI-0006"] == ev.UNMET


def test_jamfs_not_collected_sentinel_is_an_absence_wearing_a_value() -> None:
    """LI-0004's own `difference` in docs/baseline-rules.yml: `sipStatus` carries a third value that "must not read as
    unmet". Jamf spells it in several security enums, and it is a reported absence, not a Mac with SIP off."""
    content = _security(sipStatus=ev.NOT_COLLECTED, secureBootLevel=ev.NOT_COLLECTED)
    verdicts = ev.evaluate(CONTRACT_VERSION, "security", content.digest, content.body)

    assert verdicts["LI-0004"] == ev.NOT_REPORTED
    assert verdicts["LI-0005"] == ev.NOT_REPORTED


def test_an_unknown_contract_version_answers_not_reported_rather_than_raising() -> None:
    """A rule's `field` is a path into a named contract. A version this build does not know may spell the path
    differently or not carry it at all, so every rule is not_reported for it — a refusal to answer, which the artefact
    can print, rather than an exception mid-report or a fleet of silent `unmet`."""
    content = _sections()["security"]
    security_rules = [rule.id for rule in catalogue().rules if rule.section == "security"]

    verdicts = ev.evaluate("v99", "security", content.digest, content.body)

    assert verdicts == dict.fromkeys(security_rules, ev.NOT_REPORTED)
    assert ev.evaluate(CONTRACT_VERSION, "security", content.digest, content.body)["LI-0004"] == ev.MET, (
        "the version is part of the key, so the same digest under the known version is evaluated separately"
    )


def test_a_rule_naming_a_field_this_contract_does_not_hash_is_not_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """The quiet rot: a field normalized out of the contract with the catalogue still naming it. Nothing was ever
    stored there to read, so the honest answer is not_reported — never `unmet` across a whole fleet. The stand-in is
    `lastAttestationAttempt`, which Jamf reports and the contract deliberately does not hash."""
    shipped = catalogue()
    ghost = replace(shipped.by_id("LI-0003"), id="LI-9999", field="security.lastAttestationAttempt")
    monkeypatch.setattr(ev, "catalogue", lambda: replace(shipped, rules=(ghost,)))
    content = _sections()["security"]

    assert ev.evaluate(CONTRACT_VERSION, "security", content.digest, content.body) == {"LI-9999": ev.NOT_REPORTED}


def test_what_this_evaluator_refuses_rather_than_answering() -> None:
    """An empty verdict map for `applications` would read as "nothing to report" on a report whose whole claim is that
    it says what it does not know. An operator the catalogue grew without the code is the same failure one file over."""
    with pytest.raises(ValueError, match="entry digests"):
        ev.evaluate(CONTRACT_VERSION, "applications", "sha256:0", {})
    with pytest.raises(ValueError, match="not a section of the Jamf contract"):
        ev.evaluate(CONTRACT_VERSION, "securiy", "sha256:0", {})
    with pytest.raises(CatalogueError, match="unknown predicate operator"):
        ev.satisfies(Predicate(operator="at_most", operand=1), 2)

    assert ev.evaluate(CONTRACT_VERSION, "hardware", "sha256:0", {}) == {}, "a scalar section no rule reads is empty"


def test_the_digest_is_the_key_and_a_second_call_does_not_read_the_document_again() -> None:
    """The grain: N devices sharing a digest cost one evaluation. A digest is content-addressed, so a different
    document under the same one cannot happen on disk — handing one over is the only way to see whether the second
    call looked at it, and an empty document answers not_reported everywhere, so anything else is the reused answer."""
    content = _sections()["security"]
    first = ev.evaluate(CONTRACT_VERSION, "security", content.digest, content.body)

    assert ev.evaluate(CONTRACT_VERSION, "security", content.digest, {}) == first
    assert ev.evaluate(CONTRACT_VERSION, "security", content.digest, None) == first

    first["LI-0003"] = "tampered"
    assert ev.evaluate(CONTRACT_VERSION, "security", content.digest, None)["LI-0003"] == ev.UNMET, (
        "each caller gets its own map; the shared answer is not editable through one of them"
    )

    ev.clear_cache()
    assert set(ev.evaluate(CONTRACT_VERSION, "security", content.digest, {}).values()) == {ev.NOT_REPORTED}, (
        "and the empty document really would have answered not_reported, so the cache is what answered above"
    )


def test_the_os_floor_compares_versions_and_not_strings() -> None:
    """The one rule whose operand is edited over time, and the one comparison a naive reading gets wrong in both
    directions."""
    assert ev.version_at_least("14.7.1", "14.7") is True
    assert ev.version_at_least("14.7", "14.7.1") is False
    assert ev.version_at_least("14.6.1", "14.7") is False
    assert ev.version_at_least("26.10", "26.9") is True, "a string compare reads 26.10 as below 26.9"
    assert ev.version_at_least("Not Bound", "14.7") is None, "unreadable is not the same as below the floor"

    older = _sections(OLDER)["operating_system"]
    assert older.body["version"] == "14.6.1"
    assert ev.evaluate(CONTRACT_VERSION, "operating_system", older.digest, older.body)["LI-0010"] == ev.UNMET
