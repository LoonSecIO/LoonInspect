"""The runbook's front door, held to the two things it indexes.

`docs/troubleshooting.md` carries two hand-maintained indexes at its head and a routing
table in §0 that quotes the product's own sentences. All three are the shape that rots
quietly: a heading reworded, a state added, a page sentence changed — and the index still
reads plausibly while sending an operator somewhere the answer is not. This is
`tests/test_sharing.py::test_every_failure_shape_has_its_line_in_the_step_through` applied
to the index rather than to one failure path: the words and their step-through ship
together (`docs/diagnosability.md` rule 4), so rewording one without the other fails here.

Pure: no database, no app import, two files read from disk.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_DOC = (_ROOT / "docs" / "troubleshooting.md").read_text()
_EN_TS = (_ROOT / "frontend" / "src" / "i18n" / "en.ts").read_text()

_TABLE = "### What the page says, and which path answers it"

# Every sentence §0's table routes by, in the page's words. Each must be in `en.ts` — the
# one file that decides what the screen actually says — and in the table that quotes it.
_PAGE_SENTENCES = (
    "Vulnerability corpus as of",
    "Vulnerabilities: not assessed",
    "No findings",
    "Outside the corpus",
    "Not assessed",
    "A corpus is loaded and nothing here has been judged against it yet",
    "Not judged yet",
    "not reported",
    "Deliveries are failing",
    "Last sync failed",
    "AI search unavailable — the filters below still work.",
    "No Jamf Patch titles synced yet.",
    "is available, and this build does not contain it.",
)


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading: lowercased, punctuation dropped, spaces hyphenated."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def _paths() -> dict[int, str]:
    """`{number: body}` for every `## N.` path. The indexes sit above §0 and are not in it."""
    parts = re.split(r"^## (\d+)\. ", _DOC, flags=re.M)
    return {int(parts[i]): parts[i + 1] for i in range(1, len(parts), 2)}


def _index() -> str:
    """Everything above the first path, which is where both indexes live."""
    return _DOC.split("\n## 0. ", 1)[0]


def test_the_index_names_every_path_and_links_to_its_heading() -> None:
    """A path added without an index row is invisible from the top of a 1,700-line file, and
    a heading reworded without its row leaves a link that scrolls nowhere. Both fail here."""
    entries = {
        int(number): (re.sub(r"\s+", " ", title), anchor)
        for number, title, anchor in re.findall(r"^- \*\*§(\d+)\*\* \[(.+?)\]\(#([^)]+)\)", _index(), re.M | re.S)
    }
    headings = {int(number): title for number, title in re.findall(r"^## (\d+)\. (.+)$", _DOC, re.M)}

    assert set(entries) == set(headings), "the index and the path headings disagree about which paths exist"
    for number, title in headings.items():
        indexed, anchor = entries[number]
        assert indexed == title, f"§{number}'s index entry does not say what its heading says: {indexed!r}"
        assert anchor == _slug(f"{number}. {title}"), f"§{number}'s link does not reach its own heading"


def test_the_indexs_one_sub_entry_reaches_the_routing_table() -> None:
    """The index's only sub-entry is §0's routing table, and it is the one link the test above
    does not reach — that one matches `- **§N**` rows only. A `###` reworded without its entry
    leaves the front door's single deep link scrolling nowhere, silently."""
    entry = re.search(r"^  - \[(.+?)\]\(#([^)]+)\)", _index(), re.M | re.S)
    assert entry, "the index has lost its sub-entry for §0's routing table"

    title, anchor = re.sub(r"\s+", " ", entry.group(1)), entry.group(2)
    assert f"\n{_TABLE}\n" in _DOC, "§0's routing table heading has been reworded"
    assert title == _TABLE.removeprefix("### "), f"the sub-entry does not say what its heading says: {title!r}"
    assert anchor == _slug(title), "the sub-entry's link does not reach its own heading"


def test_every_reportable_state_is_indexed_at_the_path_it_lives_in() -> None:
    """The letters were assigned in writing order, so they do not run in section order — K is
    in §0 and M in §5 — and the index is the only thing mapping one to the other. It is also
    the only thing that can be quietly wrong about it, which is what this pins."""
    indexed = {letter: int(number) for letter, number in re.findall(r"^\| \*\*([A-Z])\*\* \| §(\d+) \|", _index(), re.M)}
    written = set(re.findall(r"^\*\*([A-Z])\.\*\* ", _DOC, re.M))

    assert set(indexed) == written, "a reportable state is written without an index row, or indexed without being written"
    assert set(indexed) == {chr(code) for code in range(ord("A"), ord("W") + 1)}, "the reportable states are no longer A-W"

    paths = _paths()
    for letter, number in sorted(indexed.items()):
        assert f"\n**{letter}.** " in paths[number], f"state {letter} is indexed at §{number} and is not there"


def test_every_sentence_the_routing_table_quotes_is_one_the_page_says() -> None:
    """§0's table routes by the words on the screen. A reworded page must not leave it quoting
    sentences nobody sees, and a sentence dropped from the table must not leave the screen
    saying something the runbook cannot place."""
    assert _TABLE in _DOC, "§0 has lost its routing table"
    table = _DOC.split(_TABLE, 1)[1].split("\n### ", 1)[0]

    for sentence in _PAGE_SENTENCES:
        assert sentence in _EN_TS, f"the page no longer says {sentence!r}, so §0's table quotes nothing"
        assert sentence in table, f"§0's table does not quote {sentence!r}"
