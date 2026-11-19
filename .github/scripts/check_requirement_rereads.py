#!/usr/bin/env python3
"""A release re-reads every published requirement a patching rule can start from (#809, docs/BRANCHING.md §1.1).

backend/app/mdm/patch/policy_presets.py admits an entry only when its numbers were read from the publisher's own text,
and its verified_on says on which day. A pull request that sets RELEASE in backend/app/core/version.py past the newest
vMAJOR.MINOR.PATCH tag prepares a release, and fails while an entry was read on or before the day of that tag's commit,
or on a day still to come: the release would ship numbers nobody has read since the last one. Any other pull request
passes and says why. Read with ast, as check_migration_contract.py reads the models, and with its tag lookup.
"""

from __future__ import annotations

import ast
import sys
from datetime import date

from check_migration_contract import _called, _git, _key, _target, previous_release

VERSION = "backend/app/core/version.py"
CATALOGUE = "backend/app/mdm/patch/policy_presets.py"


def _written(node: ast.expr | None) -> object:
    """A value as written: a literal, or date(YYYY, M, D) of literals. None for anything this check would have to run."""
    try:
        return date(*map(ast.literal_eval, node.args)) if _called(node, "date") else ast.literal_eval(node)
    except (TypeError, ValueError):
        return None


def release_of(source: str) -> str | None:
    """The RELEASE a version.py sets, when it is a string literal."""
    values = [_written(stmt.value) for stmt in ast.parse(source).body if _target(stmt) == "RELEASE"]
    return values[-1] if values and isinstance(values[-1], str) else None


def entries(source: str) -> list[tuple[int, object, object, object]]:
    """(line of its verified_on, id, url, verified_on) for each Preset(...) the catalogue builds, each value as written."""
    found = []
    for call in (node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call) and _called(node, "Preset")):
        given = {keyword.arg: keyword.value for keyword in call.keywords}
        found.append((getattr(given.get("verified_on"), "lineno", call.lineno),
                      *(_written(given.get(name)) for name in ("id", "url", "verified_on"))))
    return found


def refusal(entry_id: object, url: object, read: object, release: str, tag: str, tag_day: date, today: date) -> str | None:
    """Why `release` may not ship this entry, or None: it was read after the day of `tag`'s commit, and not after today."""
    if not (isinstance(entry_id, str) and isinstance(url, str) and isinstance(read, date)):
        return (f"a Preset(...) here does not write out its id, url and verified_on as keywords, verified_on as date(YYYY, "
                f"M, D), so this check cannot say whether its text was read after {tag_day}, the day of {tag}'s commit: "
                "write them out.")
    if tag_day < read <= today:
        return None
    if read <= tag_day:
        why = (f"was read on {read}, on or before {tag_day}, the day of {tag}'s commit, so {release} would ship it unread "
               f"since {tag}")
    else:
        why = (f"says it was read on {read}, a day still to come, so nothing shows it was read after {tag_day}, the day of "
               f"{tag}'s commit")
    return (f"{entry_id} ({url}) {why}: read the publisher's text again and move verified_on to the day you read it "
            "(docs/jamf-patch-matching.md §8c).")


def main() -> int:
    tag = previous_release("HEAD")
    if tag is None:
        print("::error::no vMAJOR.MINOR.PATCH tag is reachable from HEAD, so there is no release to hold the published "
              "requirements' read dates to: fetch the tags (actions/checkout with fetch-depth: 0) and run it again.")
        return 1
    release = release_of(_git("show", f"HEAD:{VERSION}"))
    if _key(release) is None:
        sets = f"sets RELEASE = {release!r}" if release else "sets no RELEASE string"
        print(f"::error file={VERSION}::{VERSION} {sets}, not vMAJOR.MINOR.PATCH, so this check cannot tell whether this pull "
              f"request prepares the release after {tag}: set it to the release this tree is (docs/BRANCHING.md §1.1).")
        return 1
    if _key(release) <= _key(tag):
        print(f"RELEASE is {release} and the newest release tag is {tag}, so this pull request prepares no release: the "
              "published requirements are re-read by the one that does (docs/BRANCHING.md §1.1).")
        return 0
    tag_day, today = date.fromisoformat(_git("log", "-1", "--format=%cs", tag).strip()), date.today()
    found = entries(_git("show", f"HEAD:{CATALOGUE}"))
    refused = [(line, why) for line, *entry in found if (why := refusal(*entry, release, tag, tag_day, today))]
    for line, why in refused:
        print(f"::error file={CATALOGUE},line={line}::{why}")
    print(f"RELEASE is {release}, past {tag}, whose commit is of {tag_day}: {len(found) - len(refused)} of the "
          f"{len(found)} published requirement(s) were read after that day and not after today.")
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
