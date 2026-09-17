"""The posture-snapshot key registry against its own vocabulary doc.

Definitions v1 is a frozen contract: 34 active keys, each immutable per name, plus the
reserved names whose definitions exist before their writers do, and the population
vocabulary (#230) each captured row is stamped with. The registry
(app.core.posture) and docs/posture-snapshot.md must tell the same story — a key added
to one without the other is exactly the drift these tests exist to refuse. Pure logic;
no database.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import HTTPException

DOC = Path(__file__).resolve().parents[2] / "docs" / "posture-snapshot.md"

_KEY_SHAPE = re.compile(r"^[a-z]+\.[a-z0-9_]+$")


def _documented(status: str) -> set[str]:
    """Keys the doc's definition tables carry with the given status."""
    keys = set()
    for line in DOC.read_text().splitlines():
        match = re.match(r"\|\s*`([a-z0-9_.]+)`\s*\|\s*(ACTIVE|RESERVED)\s*\|", line)
        if match and match.group(2) == status:
            keys.add(match.group(1))
    return keys


def test_active_registry_is_definitions_v1() -> None:
    from app.core.posture import ACTIVE_KEYS

    assert len(ACTIVE_KEYS) == 34
    assert len(set(ACTIVE_KEYS)) == len(ACTIVE_KEYS), "duplicate active key"
    assert all(_KEY_SHAPE.match(key) for key in ACTIVE_KEYS)


def test_the_vuln_keys_are_active_and_named_as_their_own_family() -> None:
    """#250: the four keys are in the vocabulary AND reachable as a group.

    They are the one family with a gate in front of it — a tenant nothing has assessed
    gets no rows rather than zeros — so both the recorder and every test that asserts
    "these keys are absent" need the group by name. Four literals copied into each of
    those places is how one of them silently stops matching.
    """
    from app.core.posture import ACTIVE_KEYS, VULN_KEYS

    assert set(VULN_KEYS) == {
        "vuln.apps_affected",
        "vuln.apps_kev_affected",
        "vuln.apps_unknown",
        "vuln.devices_affected",
    }
    assert set(VULN_KEYS) <= set(ACTIVE_KEYS)


def test_reserved_keys_are_named_and_disjoint() -> None:
    """Empty again since #476 activated `devices.departed_24h`, and still enforced.

    The reservation is a mechanism, not a list: a key ruled before its writer exists is
    declared in `RESERVED_KEYS`, and these assertions are what keep it out of `ACTIVE_KEYS`
    until it has rows to write. Twice now a name has gone in and come out without ever
    writing the run of zeros that would have lied about when measurement began.
    """
    from app.core.posture import ACTIVE_KEYS, RESERVED_KEYS

    assert len(set(RESERVED_KEYS)) == len(RESERVED_KEYS), "duplicate reserved key"
    assert all(_KEY_SHAPE.match(key) for key in RESERVED_KEYS)
    assert not set(ACTIVE_KEYS) & set(RESERVED_KEYS), "a key cannot be both active and reserved"


def test_doc_and_registry_tell_the_same_story() -> None:
    from app.core.posture import ACTIVE_KEYS, RESERVED_KEYS

    assert _documented("ACTIVE") == set(ACTIVE_KEYS), (
        "docs/posture-snapshot.md's ACTIVE rows must match app.core.posture.ACTIVE_KEYS exactly"
    )
    assert _documented("RESERVED") == set(RESERVED_KEYS), (
        "docs/posture-snapshot.md's RESERVED rows must match app.core.posture.RESERVED_KEYS exactly"
    )


def test_the_capture_platform_is_the_ruled_vocabulary() -> None:
    """#230: the population token is as immutable as a key name — a value's meaning is
    what its history means. `macos` is the content-key OS spelling (`os_key("macos", …)`),
    deliberately not the sourcetype segment's `mac` (Kyle, 2026-09-02), and `all` is
    reserved for a roll-up no single-platform run may write — and no read may ask for."""
    from app.api.posture import _population
    from app.core.posture import CAPTURE_PLATFORM, PLATFORM_ROLLUP, PLATFORMS

    assert CAPTURE_PLATFORM == "macos"
    assert PLATFORM_ROLLUP == "all"
    assert CAPTURE_PLATFORM in PLATFORMS and PLATFORM_ROLLUP not in PLATFORMS
    # A read filters on one of these and can never ask for a name outside them — the roll-up least
    # of all (#510), since nothing writes it and its empty page reads as "never captured". Its own
    # sentence, and the vocabulary a wrong name is handed never advertises it as a thing to try.
    assert _population(CAPTURE_PLATFORM) == CAPTURE_PLATFORM
    with pytest.raises(HTTPException) as rollup:
        _population(PLATFORM_ROLLUP)
    with pytest.raises(HTTPException) as unknown:
        _population("android")
    assert rollup.value.status_code == 422 and "roll-up" in rollup.value.detail
    assert unknown.value.status_code == 422 and PLATFORM_ROLLUP not in unknown.value.detail


def test_the_population_rules_are_written_down() -> None:
    """The column is worth nothing if the rules it carries live only in a commit message."""
    doc = DOC.read_text()

    assert "## Population" in doc
    header = doc.split("## Population")[0]
    assert "platform, value, captured_at, full_sweep_run_id" in header, "the row shape at the top of the doc must carry platform"
    for token in ("macos", "ios", "ipados", "tvos", "visionos"):
        assert f"`{token}`" in doc, f"the platform vocabulary must name {token}"
    assert "uq_posture_snapshot_capture" in doc


def test_the_no_rows_rule_is_written_down_beside_the_four_keys() -> None:
    """#250: the one rule that makes a gap in this family legible.

    A reader who finds a tenant with no `vuln.*` rows for a stretch of nights has to be
    able to learn, from the tape's own document, that the gap is a statement — "nothing was
    assessed here" — and not four lost keys. The rule living only in a docstring inside the
    recorder would fail exactly the reader it is written for.

    Asserted **inside each of the four rows**, not once across the document: a reader of a
    key meets its own cell, and a version of this test that searched the whole file passed
    while `vuln.devices_affected`'s cell said nothing about its absence — and kept passing
    when the sentence was deleted from a second cell as well. One row carrying the rule for
    four is the drift this file exists to catch.
    """
    from app.core.posture import VULN_KEYS

    doc = DOC.read_text()
    # Wrapped lines and bold markers are the doc's business, not the rule's.
    prose = " ".join(doc.replace("*", "").split())

    assert "no rows, not zeros" in prose, "the activation rule must be stated in the doc, in the contract's own words"
    for key in VULN_KEYS:
        rows = [line for line in doc.splitlines() if line.startswith(f"| `{key}` | ACTIVE |")]
        assert len(rows) == 1, f"{key} must carry exactly one ACTIVE row of its own"
        cell = " ".join(rows[0].replace("*", "").split())
        assert "never been judged" in cell, f"{key}'s own cell must say what its absence means — a neighbour's does not"


def test_notable_is_the_closed_levels_ordering_at_normal_or_above() -> None:
    from app.changes.policy import LEVELS, LOW, NORMAL
    from app.core.posture import NOTABLE_LEVELS

    assert set(NOTABLE_LEVELS) <= set(LEVELS)
    assert NORMAL in NOTABLE_LEVELS
    assert LOW not in NOTABLE_LEVELS


# --- the reader, bound to the registry it serves (#470) ---------------------------------


def test_every_key_carries_a_definition_in_the_docs_own_words() -> None:
    """`GET /api/posture/registry` must not become a second home for a definition. Every line of
    `KEY_DEFINITIONS` is a verbatim prefix of that key's row in the doc (`…` marks where the row
    goes on), so a definition cannot be paraphrased, softened or left behind when a cell is
    corrected — both directions, since a key with no line cannot be interpreted and a line with no
    key defines nothing. The whole document goes on one line, bold dropped: a table row is a
    line, so the opening of a cell is a substring of it."""
    from app.core.posture import ACTIVE_KEYS, KEY_DEFINITIONS, RESERVED_KEYS

    doc = " ".join(DOC.read_text().replace("*", "").split())
    assert set(KEY_DEFINITIONS) == set(ACTIVE_KEYS) | set(RESERVED_KEYS)
    for key, definition in KEY_DEFINITIONS.items():
        opening = " ".join(definition.replace("*", "").split()).rstrip("…").strip()
        assert len(opening) >= 20, f"{key}'s definition is too short to interpret a value with"
        assert any(f"| `{key}` | {status} | {opening}" in doc for status in ("ACTIVE", "RESERVED")), (
            f"{key}'s served definition is not how docs/posture-snapshot.md opens its row"
        )


def test_the_registry_response_is_built_from_the_registry(monkeypatch) -> None:
    """The endpoint's own answer, not a claim about it: every active key with its definition, every
    reserved name marked reserved, nothing hard-coded in between, plus the sentence that keeps a
    gap from being drawn as a zero. The reserved branch outlives the tuple — emptied again when
    #476 activated `devices.departed_24h` — because a name ruled before its writer exists is told
    so, not handed a page reading "never captured"; and a key that outruns its definition is too."""
    import asyncio

    from app.api import posture
    from app.core.posture import ACTIVE_KEYS, KEY_DEFINITIONS, RESERVED_KEYS

    out = asyncio.run(posture.posture_registry())

    assert [key.key for key in out.keys if key.status == "active"] == list(ACTIVE_KEYS)
    assert [key.key for key in out.keys if key.status == "reserved"] == list(RESERVED_KEYS)
    assert all(key.definition == KEY_DEFINITIONS[key.key] for key in out.keys)
    assert "never zero" in out.absence and "outbox.oldest_pending_age_s" in out.absence and "vuln.*" in out.absence

    monkeypatch.setattr(posture, "RESERVED_KEYS", ("devices.not_yet",))
    with pytest.raises(HTTPException) as refusal:
        posture._wanted("devices.not_yet")
    assert refusal.value.status_code == 422 and "reserved" in refusal.value.detail

    # A key the recorder gains before its definition line: served without one and named as drift,
    # never a KeyError dressed as a 500 that tells the reader nothing about which file is behind.
    monkeypatch.setattr(posture, "ACTIVE_KEYS", (*ACTIVE_KEYS, "devices.undefined"))
    assert posture.UNDEFINED in [key.definition for key in asyncio.run(posture.posture_registry()).keys]


def test_both_reads_are_behind_the_permission_the_share_log_uses() -> None:
    """The guard as the route table carries it. `AUDIT_READ` is the ruling (#470): the tape is
    durable fleet history, the auditor's question, while `SYSTEM_READ` guards this instance's own
    status — a different subject."""
    source = (Path(__file__).resolve().parents[1] / "app" / "api" / "posture.py").read_text()

    assert re.findall(r"Depends\(require\(([^)]*)\)\)", source) == ["Permission.AUDIT_READ"] * 2
