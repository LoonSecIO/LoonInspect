"""The published requirements a rule can be started from (`app.mdm.patch.policy_presets`,
#736): what an entry must carry before it may ship, and the page's words for each. Pure.

The catalogue is three copies of one fact — the entry here, and its explanation in `en.ts`
and `de.ts` — so the page's copy is read rather than restated: an entry added without its
words, or words left behind by a removed entry, fails here.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import pytest

from app.mdm.patch.policy import Rule, Rules
from app.mdm.patch.policy_presets import CYBER_ESSENTIALS_3_3, PRESETS, is_basis_of, preset

_I18N = Path(__file__).resolve().parents[2] / "frontend" / "src" / "i18n"
# What every entry's copy says: what the text requires, how the rule maps it, where the two
# part ways, and that starting from it is not a statement about the scheme.
_COPY_KEYS = ("requires", "maps", "differs", "notAVerdict")


def _copy_ids(language: str) -> dict[str, str]:
    """`{preset id: its block}` under `presets: { entries: { … } }` in one language file."""
    source = (_I18N / f"{language}.ts").read_text()
    start = source.index("      entries: {")
    block = source[start : source.index("\n      }\n", start)]
    return dict(re.findall(r'        "([^"]+)": \{(.*?)\n        \}', block, re.S))


@pytest.mark.parametrize("entry", PRESETS, ids=[entry.id for entry in PRESETS])
def test_an_entry_names_its_source_and_judges_something(entry) -> None:
    assert entry.rule.judges and not entry.rule.exempt
    assert entry.url.startswith("https://") and entry.document and entry.section and entry.published
    # Read, not remembered: an entry says when its text was read, and not in the future.
    assert date(2026, 10, 3) <= entry.verified_on <= date.today()
    # The id carries the document's version, so a revised document is a new entry.
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9.]+)+", entry.id) and re.search(r"\d", entry.id)


def test_ids_are_unique() -> None:
    assert len({entry.id for entry in PRESETS}) == len(PRESETS)


@pytest.mark.parametrize("language", ["en", "de"])
def test_every_entry_has_its_words_and_no_words_outlive_an_entry(language: str) -> None:
    copy = _copy_ids(language)
    assert set(copy) == {entry.id for entry in PRESETS}
    for entry_id, block in copy.items():
        for key in _COPY_KEYS:
            assert re.search(rf"\b{key}:", block), f"{language}.ts: {entry_id} has no `{key}`"


def test_no_copy_says_an_organization_meets_a_scheme() -> None:
    """The 2026-08-31 scope ruling, held by a test: an entry is where a rule came from. The
    page may say a rule was *drawn from* a requirement and nothing stronger."""
    source = (_I18N / "en.ts").read_text()
    start = source.index("    presets: {")
    block = source[start : source.index("\n    },\n", start)].lower()
    for claim in ("compliant", "complies", "certified to", "you meet", "meets the", "passes"):
        assert claim not in block, claim
    assert "not a statement" in block


def test_cyber_essentials_gives_every_update_fourteen_days() -> None:
    """Read from NCSC's v3.3 text on 2026-10-03: 14 days from release for critical or high,
    for CVSS v3 7 and above, AND for updates whose severity the vendor does not state. The
    last is why this is the ordinary limit and not the severe one."""
    assert CYBER_ESSENTIALS_3_3.rule == Rule(max_days_behind=14)
    assert "ncsc.gov.uk" in CYBER_ESSENTIALS_3_3.url


def test_a_basis_holds_only_while_the_rule_is_the_entrys_own() -> None:
    entry = CYBER_ESSENTIALS_3_3
    assert is_basis_of(entry.id, Rule(max_days_behind=14))
    assert not is_basis_of(entry.id, Rule(max_days_behind=30))
    assert not is_basis_of(entry.id, Rule(max_days_behind=14, max_releases_behind=1))
    assert not is_basis_of(entry.id, None)
    assert not is_basis_of("pci-dss-4.0.1", Rule(max_days_behind=14))  # not in the catalogue: unverified
    assert preset(None) is None and preset(14) is None


def test_the_basis_is_stored_with_the_rule_and_dropped_with_it() -> None:
    stored = {"default": Rule(max_days_behind=14).stored(), "default_basis": "cyber-essentials-3.3", "overrides": {}}
    assert Rules.from_stored(stored).default_basis == "cyber-essentials-3.3"
    assert Rules.from_stored({**stored, "default": None}).default_basis is None
    assert Rules.from_stored({**stored, "default_basis": 7}).default_basis is None
