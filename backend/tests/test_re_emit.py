"""The re-emit's pure facts (#356): its own class, its own word, a closing event, and what
a re-emitted extension attribute carries."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]


def test_the_re_emit_has_its_own_class_its_own_word_and_a_closing_event() -> None:
    from app.core.runs import (
        COMPARISON_BASELINE,
        COMPARISON_DELTA,
        COMPARISON_RE_EMIT,
        LOCK_DEVICE_SWEEP,
        LOCK_RE_EMIT,
        RUN_COMPLETED_LOCK_CLASSES,
    )

    assert COMPARISON_RE_EMIT == "re-emit"
    assert COMPARISON_RE_EMIT not in (COMPARISON_BASELINE, COMPARISON_DELTA)
    assert LOCK_RE_EMIT == "re_emit" and LOCK_RE_EMIT != LOCK_DEVICE_SWEEP
    assert LOCK_RE_EMIT in RUN_COMPLETED_LOCK_CLASSES


def test_a_re_emitted_extension_attribute_carries_what_the_projection_holds() -> None:
    from app.mdm.reemit import _extension_attributes

    row = SimpleNamespace(definition_id="12", name="Battery Cycle Count", values=["312"], source="hardware", enabled=False)
    (item,) = _extension_attributes([row])
    dumped = item.model_dump(mode="json", by_alias=True)
    assert (dumped["definitionId"], dumped["name"], dumped["values"], dumped["source"], dumped["enabled"]) == (
        "12",
        "Battery Cycle Count",
        ["312"],
        "hardware",
        False,
    )


def test_the_docs_name_the_third_comparison() -> None:
    runs = (ROOT / "docs" / "runs.md").read_text()
    wire = (ROOT / "docs" / "splunk-wire-vocabulary.md").read_text()
    assert "`baseline` | `delta` | `re-emit`" in runs
    assert '`comparison: "re-emit"`' in wire
