"""Every large module says what it is, at the top, in one sentence (#563).

A module nine other modules point at should not be silent about itself. The rule is deliberately
coarse — over 500 lines, a module docstring, an opening line that reads as a sentence — because its
job is to stop the next 1,500-line file from arriving undescribed, not to grade prose. What the
sentence should say is what the ones already written say: what the module owns, what it does not,
and which modules are its neighbours by path. Source is parsed, not imported, in the spirit of
`tests/test_ai_structure.py`. Pure; no database, no network.
"""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_APP = _ROOT / "backend" / "app"

# Where the rule starts. Under this a module is usually one idea whose filename carries it; over it,
# a reader needs to be told what they are inside of before the first import.
_MIN_LINES = 500
# A summary line, not a paragraph: room for a clause naming a neighbour, and no room for an essay.
_MAX_SUMMARY = 200
# What closes a sentence, before any bracket or quote that trails it.
_SENTENCE_END = ".?!"
_TRAILING = "\"')]`*"


def _rel(path: Path) -> str:
    return path.relative_to(_ROOT).as_posix()


def _large_modules() -> list[Path]:
    """Every module under backend/app big enough for the rule to apply, __init__ files included: a
    package that needs 500 lines of its own owes a reader the same sentence."""
    return sorted(path for path in _APP.rglob("*.py") if len(path.read_text().splitlines()) > _MIN_LINES)


def _docstring(path: Path) -> str | None:
    return ast.get_docstring(ast.parse(path.read_text(), filename=str(path)))


def _opening(doc: str) -> tuple[str, str]:
    """(first line, opening paragraph) of a docstring. The paragraph matters because a summary that
    wraps onto a second line is still one sentence — `app/ai/changes_prompt.py` writes one — so the
    closing punctuation is looked for at the end of the paragraph, not the end of the line."""
    lines = doc.strip().splitlines()
    paragraph: list[str] = []
    for line in lines:
        if not line.strip():
            break
        paragraph.append(line.strip())
    return lines[0].strip(), " ".join(paragraph)


def test_the_scan_still_finds_the_large_modules() -> None:
    """A vacuity guard: a scan that reaches nothing would pass every assertion below."""
    found = {_rel(path) for path in _large_modules()}
    assert "backend/app/models/schema.py" in found, f"the scan no longer reaches backend/app: {sorted(found)[:5]}"
    assert len(found) >= 15, f"backend/app has {len(found)} modules over {_MIN_LINES} lines; the scan is probably broken"


def test_every_large_module_has_a_module_docstring() -> None:
    silent = [_rel(path) for path in _large_modules() if not _docstring(path)]
    assert silent == [], (
        f"a module over {_MIN_LINES} lines opens with a docstring saying what it owns, what it does not, and which "
        f"modules are its neighbours by path (app/mdm/collections.py and app/changes/diff.py are the style): {silent}"
    )


def test_every_large_module_opens_with_a_sentence() -> None:
    offences: dict[str, str] = {}
    for path in _large_modules():
        doc = _docstring(path)
        if not doc:
            continue  # the test above owns that failure
        first, paragraph = _opening(doc)
        if not first:
            offences[_rel(path)] = "the docstring opens with a blank line"
        elif len(first) > _MAX_SUMMARY:
            offences[_rel(path)] = f"the first line is {len(first)} characters; keep the summary under {_MAX_SUMMARY}"
        elif not first[0].isupper():
            offences[_rel(path)] = f"the first line starts with {first[0]!r}, not a capital letter"
        elif paragraph.rstrip(_TRAILING)[-1:] not in _SENTENCE_END:
            offences[_rel(path)] = "the opening sentence never ends; close it with a full stop"
    assert offences == {}, f"a module over {_MIN_LINES} lines opens with one sentence a reader takes in at a glance: {offences}"


def test_the_opening_is_read_as_a_sentence_that_may_wrap() -> None:
    """The wrap is the whole reason a paragraph is read rather than a line, so it is pinned both ways."""
    assert _opening("One line.\n\nA paragraph.\n") == ("One line.", "One line.")
    assert _opening("A summary that runs on\nto a second line.\n\nMore.\n")[1] == "A summary that runs on to a second line."
    assert _opening("Ends in a citation (#563).\n")[1].rstrip(_TRAILING)[-1:] == "."
    assert _opening("No stop here\n\nnext paragraph.\n")[1].rstrip(_TRAILING)[-1:] == "e"
