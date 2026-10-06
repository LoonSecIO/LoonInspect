"""The OpenAPI document, pinned whole, so a change to the contract is a diff someone reads.

`app.openapi()` is built in-process (no server, no database) and compared, normalised, with
`snapshots/openapi.json`: the contract a native client builds against, every route,
parameter, model, status code and description in it. After an intended change, regenerate it
from `backend/`, read the snapshot's diff, and commit it with the change:

    UPDATE_SNAPSHOTS=1 uv run --frozen pytest tests/test_openapi_snapshot.py

Normalised: keys sorted, two-space indent, ASCII; no `servers`; `info.title` (the APP_NAME
setting) and `info.version` written as their defaults; every `required` list sorted, since a
field moved within its model is not a contract change.
"""

from __future__ import annotations

import copy
import difflib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from app.main import app

SNAPSHOT = Path(__file__).parent / "snapshots" / "openapi.json"
REGENERATE = "UPDATE_SNAPSHOTS=1 uv run --frozen pytest tests/test_openapi_snapshot.py"
# A failure lists this many changed places and diff lines, then counts the rest.
SHOWN_PLACES, SHOWN_DIFF_LINES = 40, 200


def normalised(spec: dict[str, Any]) -> dict[str, Any]:
    document = copy.deepcopy(spec)  # app.openapi() is cached; other tests read the same dict
    document.pop("servers", None)
    document["info"] = {**document["info"], "title": "LoonInspect", "version": "0.1.0"}
    _sort_required(document)
    return document


def _sort_required(node: Any) -> None:
    if isinstance(node, dict):
        if isinstance(node.get("required"), list):
            node["required"] = sorted(node["required"])
        for value in node.values():
            _sort_required(value)
    elif isinstance(node, list):
        for value in node:
            _sort_required(value)


def rendered(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def changed_places(old: Any, new: Any, at: str = "") -> list[str]:
    """Where two documents differ, as jq paths: `+` added, `-` removed, `~` changed."""
    if isinstance(old, dict) and isinstance(new, dict):
        places = []
        for key in sorted(old.keys() | new.keys()):
            where = f"{at}.{key}" if key.isidentifier() else f"{at}[{json.dumps(key)}]"
            if key not in new:
                places.append(f"- {where}")
            elif key not in old:
                places.append(f"+ {where}")
            else:
                places += changed_places(old[key], new[key], where)
        return places
    if isinstance(old, list) and isinstance(new, list) and len(old) == len(new):
        return [place for i, (a, b) in enumerate(zip(old, new, strict=True)) for place in changed_places(a, b, f"{at}[{i}]")]
    return [] if old == new else [f"~ {at or '.'}"]


def _shown(lines: list[str], limit: int, what: str) -> list[str]:
    return lines[:limit] + ([f"... and {len(lines) - limit} more {what}"] if len(lines) > limit else [])


def test_the_openapi_document_matches_its_snapshot() -> None:
    actual = rendered(normalised(app.openapi()))
    if os.environ.get("UPDATE_SNAPSHOTS") == "1":
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(actual, encoding="utf-8", newline="\n")
        return
    if not SNAPSHOT.exists():
        pytest.fail(f"tests/snapshots/openapi.json is missing. Write it from backend/ with:\n    {REGENERATE}", pytrace=False)
    expected = SNAPSHOT.read_text(encoding="utf-8")
    if actual == expected:
        return
    try:
        places = changed_places(json.loads(expected), json.loads(actual))
    except json.JSONDecodeError:
        places = ["~ . (the snapshot is not JSON: a merge conflict left in it? Regenerate it rather than resolving by hand)"]
    places = places or ["~ . (the same document, formatted differently: regenerate it rather than editing it by hand)"]
    diff = difflib.unified_diff(
        expected.splitlines(), actual.splitlines(), "tests/snapshots/openapi.json", "app.openapi()", lineterm=""
    )
    pytest.fail(
        "\n".join(
            [
                "The OpenAPI document no longer matches tests/snapshots/openapi.json (+ new, - gone, ~ changed):",
                *(f"  {place}" for place in _shown(places, SHOWN_PLACES, "places")),
                "Intended? Regenerate the snapshot from backend/, read its diff, and commit it with the change:",
                f"    {REGENERATE}",
                "Unintended? A route, a model or a docstring moved the contract a client builds against.",
                "",
                *_shown(list(diff), SHOWN_DIFF_LINES, "diff lines"),
            ]
        ),
        pytrace=False,
    )
