"""The Changes page's list sections, held to the change policy (#437). Pure; reads a file.

A list section's entries are added, removed or updated; every other section's values are
only ever changed. The page greys out the Change kinds a chosen section never records and
names the reason under an empty table, from its own `ENTRY_SECTIONS` (`render.ts`). That
list is the third copy of one fact — the change policy's `ENTRY_RULES` is the first, the
Prompt bar's guard (`app.ai.changes_prompt.ENTRY_SECTIONS`) the second — so this reads
the page's copy rather than restating it. A section added to `ENTRY_RULES` and not to the
page would have the Change list grey out the three kinds that section does record.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.ai.changes_prompt import ENTRY_SECTIONS as PROMPT_ENTRY_SECTIONS
from app.changes.policy import ENTRY_RULES, FIELD_RULES

RENDER_TS = Path(__file__).resolve().parents[2] / "frontend" / "src" / "features" / "changes" / "render.ts"


def _declared(name: str) -> list[str]:
    # One line, by the constant's own comment: a wrapped list would still parse here if
    # this matched across lines, and the comment would stop being true.
    match = re.search(rf"^export const {name} = \[(.*)\] as const;$", RENDER_TS.read_text(), re.M)
    assert match, f"frontend/src/features/changes/render.ts no longer declares {name} on one line"
    return re.findall(r'"([^"]+)"', match.group(1))


def test_the_pages_list_sections_are_the_change_policys_entry_rule_sections():
    page = _declared("ENTRY_SECTIONS")
    assert len(page) == len(set(page)), "render.ts names a list section twice"
    assert set(page) == {rule.section for rule in ENTRY_RULES}, (
        "the Change list would grey out kinds a list section records, or offer ones it never does"
    )


def test_the_pages_list_sections_are_the_prompt_bars():
    assert set(_declared("ENTRY_SECTIONS")) == set(PROMPT_ENTRY_SECTIONS), (
        "the page and the Prompt bar's guard would disagree about which pairs can match"
    )


def test_every_other_section_the_page_offers_is_a_field_rule_section():
    """The other half: what is not a list section records only `changed`, which holds
    only while every remaining section in the page's dropdown is `FIELD_RULES`'."""
    match = re.search(r"export const SECTION_ORDER = \[(.*?)\] as const;", RENDER_TS.read_text(), re.S)
    assert match, "frontend/src/features/changes/render.ts no longer declares SECTION_ORDER"
    offered = set(re.findall(r'"([^"]+)"', match.group(1)))
    entry = set(_declared("ENTRY_SECTIONS"))
    assert entry <= offered, "a list section the page's Section dropdown does not offer"
    assert offered - entry == {rule.section for rule in FIELD_RULES}
