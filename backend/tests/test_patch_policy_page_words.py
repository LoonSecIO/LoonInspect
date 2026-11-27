"""Posture > Patch policy's words, held to the words the backend answers with (#614).

The page says every state the walk routes can answer in the reader's language
(`frontend/src/features/patchPolicy/walkCopy.ts`, English and German), keyed by the state word the
instance sends, with the instance's own English sentence printed beneath it. A state word the
backend gains without a page sentence would reach a German reader as English only, and a window
cut without its words would be named by its code word. This holds the two vocabularies together,
in the spirit of `tests/test_troubleshooting_index.py`: source is read, not imported. Pure.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core import fleet_catalog
from app.core import patch_policy_feed as feed
from app.core import patch_policy_timelines as timelines
from app.core import patch_policy_views as views
from app.core import patch_policy_walk as walk

_COPY = (Path(__file__).resolve().parents[2] / "frontend" / "src" / "features" / "patchPolicy" / "walkCopy.ts").read_text()


def _blocks(name: str) -> list[set[str]]:
    """The keys of every `name: {` block in the file, in order: English first, then German."""
    found = []
    for match in re.finditer(rf"^  {name}: \{{\n(.*?)^  \}}", _COPY, re.M | re.S):
        found.append(set(re.findall(r"^    (\w+):", match.group(1), re.M)))
    return found


def test_every_state_the_walk_routes_answer_with_has_a_sentence_in_both_languages() -> None:
    words = {value for name, value in vars(walk).items() if name.startswith("REFUSED_")}
    words |= set(timelines.STATES) | {views.REFUSED_UNCHECKED}
    words |= set(feed.FEED_STATES) - {feed.STATE_CURRENT, feed.STATE_STALE}
    english, german = _blocks("reasons")
    assert words - english == set(), f"walkCopy.ts says nothing in English for {sorted(words - english)}"
    assert words - german == set(), f"walkCopy.ts says nothing in German for {sorted(words - german)}"
    assert english == german, "the English and German sentences are keyed by different words"


def test_every_window_cut_has_its_words_in_both_languages() -> None:
    cuts = {
        walk.CLOCK_COVERAGE,
        walk.TIMELINE_COVERAGE,
        walk.LINE_START,
        walk.CHANNEL_START,
        walk.COMMON_WINDOW,
        walk.LEDGER_AS_OF,
        walk.TIMELINE_AS_OF,
        walk.PROMOTION_TABLE,
    }
    english, german = _blocks("windowReasons")
    assert cuts <= english and cuts <= german, f"no words for {sorted(cuts - (english & german))}"


def test_the_fleet_flags_sentence_is_the_backends_word_for_word() -> None:
    """Plan 3.5: *Flag off* is `FLAG_OFF` verbatim, so the page prints it once, not twice."""
    assert f'    flag_off: () =>\n      "{fleet_catalog.FLAG_OFF}",' in _COPY


def test_the_page_words_for_a_catalog_read_in_part_are_in_the_runbook() -> None:
    """`catalog_partial` opens differently on the page than in the instance's sentence, so §33 step
    5 quotes both, and a reader searching the runbook for what the page says finds the step."""
    runbook = (Path(__file__).resolve().parents[2] / "docs" / "troubleshooting.md").read_text()
    step = re.sub(r"\s+", " ", runbook.split("\n## 33. ", 1)[1].split("\n6. **The window.**", 1)[0]).replace("*", "")
    english = re.search(r"^    catalog_partial: \(\{ app \}: ReasonContext\) =>\n      `([^`]*)`", _COPY, re.M)
    assert english, "walkCopy.ts has no English sentence for catalog_partial"
    opening = english.group(1).split("${app}")[0].strip()
    assert opening in step, f"§33 step 5 does not quote the page's catalog_partial words: {opening!r}"
