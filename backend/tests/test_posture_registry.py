"""The posture-snapshot key registry against its own vocabulary doc.

Definitions v1 is a frozen contract: 29 active keys, each immutable per name, plus the
reserved names whose definitions exist before their writers do, and the population
vocabulary (#230) each captured row is stamped with. The registry
(app.core.posture) and docs/posture-snapshot.md must tell the same story — a key added
to one without the other is exactly the drift these tests exist to refuse. Pure logic;
no database.
"""

from __future__ import annotations

import re
from pathlib import Path

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

    assert len(ACTIVE_KEYS) == 29
    assert len(set(ACTIVE_KEYS)) == len(ACTIVE_KEYS), "duplicate active key"
    assert all(_KEY_SHAPE.match(key) for key in ACTIVE_KEYS)


def test_reserved_keys_are_named_and_disjoint() -> None:
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
    reserved for a roll-up no single-platform run may write."""
    from app.core.posture import CAPTURE_PLATFORM, PLATFORM_ROLLUP

    assert CAPTURE_PLATFORM == "macos"
    assert PLATFORM_ROLLUP == "all"
    assert CAPTURE_PLATFORM != PLATFORM_ROLLUP


def test_the_population_rules_are_written_down() -> None:
    """The column is worth nothing if the rules it carries live only in a commit message."""
    doc = DOC.read_text()

    assert "## Population" in doc
    header = doc.split("## Population")[0]
    assert "platform, value, captured_at, full_sweep_run_id" in header, (
        "the row shape at the top of the doc must carry platform"
    )
    for token in ("macos", "ios", "ipados", "tvos", "visionos"):
        assert f"`{token}`" in doc, f"the platform vocabulary must name {token}"
    assert "uq_posture_snapshot_capture" in doc


def test_notable_is_the_closed_levels_ordering_at_normal_or_above() -> None:
    from app.changes.policy import LEVELS, LOW, NORMAL
    from app.core.posture import NOTABLE_LEVELS

    assert set(NOTABLE_LEVELS) <= set(LEVELS)
    assert NORMAL in NOTABLE_LEVELS
    assert LOW not in NOTABLE_LEVELS
