"""The docs index against the directory it indexes (#562).

`docs/README.md` is the only map of `docs/` there is, and an index nobody checks is worse
than none: a reader trusts it, so a document missing from it is invisible rather than
merely unlisted. Two assertions, both cheap. A new document must be listed — which is the
moment its author decides which class it belongs to and what its status is — and every
link the index carries must resolve, so a renamed or deleted file cannot leave a dead row
behind.

A listing is a link, not a mention: prose naming a file in passing is not an index entry,
and the regex below only accepts the Markdown link form the tables use.

The third assertion guards the drawn figures. Mermaid reads `;` as a statement separator,
so one inside a label does not fail — it silently ends the statement early and turns the
rest of the sentence into orphan states. There is no parse error to catch, only a diagram
that renders wrong, which is why this is a test and not a review note.
"""

from __future__ import annotations

import re
from pathlib import Path

DOCS = Path(__file__).resolve().parents[2] / "docs"
INDEX = DOCS / "README.md"
INDEXED_SUFFIXES = {".md", ".yml"}

# The target of a relative Markdown link, stripped of any anchor. Absolute URLs are
# somebody else's to keep alive.
_LINK = re.compile(r"\]\((?!https?://|mailto:)([^)#\s]+)")

# The body of a ```mermaid fenced block.
_FIGURE = re.compile(r"^```mermaid\n(.*?)^```", re.DOTALL | re.MULTILINE)


def _linked() -> set[str]:
    return set(_LINK.findall(INDEX.read_text(encoding="utf-8")))


def _documents() -> list[str]:
    return sorted(path.name for path in DOCS.iterdir() if path.suffix in INDEXED_SUFFIXES and path.name != INDEX.name)


def test_index_exists() -> None:
    assert INDEX.is_file(), f"{INDEX} is the index the two tests below read; without it they pass vacuously"


def test_every_document_is_listed() -> None:
    linked = _linked()
    missing = [name for name in _documents() if name not in linked]
    assert not missing, (
        f"docs/ holds {', '.join(missing)}, and docs/README.md links to none of them. "
        "Every document needs a row there — reference, design record, runbook or plan — with its own dated status."
    )


def test_every_listed_path_exists() -> None:
    absent = sorted(link for link in _linked() if not (DOCS / link).exists())
    assert not absent, (
        f"docs/README.md links to {', '.join(absent)}, which does not exist. "
        "Fix the link, or drop the row if the document is gone."
    )


def test_no_mermaid_figure_hides_a_statement_separator() -> None:
    split = [
        f"{path.name}: {line.strip()}"
        for path in sorted(DOCS.glob("*.md"))
        for figure in _FIGURE.findall(path.read_text(encoding="utf-8"))
        for line in figure.splitlines()
        if ";" in line
    ]
    assert not split, (
        "A Mermaid figure carries a ';', which Mermaid reads as the end of the statement, "
        "not as punctuation — the rest of the line becomes orphan nodes and no parse error is "
        f"raised, so the diagram renders wrong and looks fine in review. Use '·' or a comma: {split}"
    )
