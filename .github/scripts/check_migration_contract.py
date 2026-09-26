#!/usr/bin/env python3
"""No migration since the last release drops or renames what it reads (#655, docs/BRANCHING.md §1.1).

The oracle: the tables and columns backend/app/models/schema.py names at the newest vMAJOR.MINOR.PATCH
tag reachable from HEAD, read with ast. The subject: every migration added since. What upgrade() reaches
may not drop_column, drop_table, rename_table or alter_column(new_column_name=) what the oracle names, nor
run SQL (a literal, module constant or f-string) saying DROP TABLE or ALTER TABLE <name> … DROP or RENAME
(constraints aside). Type, nullability and defaults are for review. `--notes vX.Y.Z` prints release.yml's upgrade notes.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "backend/app/models/schema.py"
VERSIONS = "backend/migrations/versions"
STABLE = re.compile(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
VERBS = {"drop_column": "drops", "drop_table": "drops", "rename_table": "renames", "alter_column": "renames"}
RAW_SQL = re.compile(r"\bDROP\s+TABLE\b|\bALTER\s+TABLE\s+(IF\s+EXISTS\s+)?(ONLY\s+)?\S+\s+([^;]*?,\s*)?(RENAME|DROP)\s+"
                     r"(?!CONSTRAINT\b)\S+", re.IGNORECASE)
RELEASE_NOTE = re.compile(r"^#\s*release-note:\s*(.+)$", re.MULTILINE)


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True, cwd=ROOT).stdout


def previous_release(ref: str, exclude: str | None = None) -> str | None:
    """The newest vMAJOR.MINOR.PATCH tag reachable from `ref`, other than `exclude`. A prerelease is not a release."""
    tags = [t for t in _git("tag", "--merged", ref, "--list", "v*").split() if STABLE.fullmatch(t) and t != exclude]
    return max(tags, key=lambda t: tuple(int(n) for n in t[1:].split(".")), default=None)


def added_migrations(since: str, ref: str) -> list[str]:
    """The migrations added after `since` and still present at `ref`, in the order they landed."""
    spec = ("--no-renames", "--diff-filter=A", "--name-only")
    present = set(_git("diff", *spec, since, ref, "--", VERSIONS).splitlines())
    landed = _git("log", "--reverse", "--format=", *spec, f"{since}..{ref}", "--", VERSIONS).splitlines()
    return [path for path in dict.fromkeys(landed) if path in present and path.endswith(".py")]


def _target(stmt: ast.stmt) -> str | None:
    target = stmt.targets[0] if isinstance(stmt, ast.Assign) else getattr(stmt, "target", None)
    return target.id if isinstance(target, ast.Name) else None


def _called(node: ast.AST | None, name: str) -> bool:
    func = node.func if isinstance(node, ast.Call) else None
    return (func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)) == name


def oracle(schema_source: str) -> dict[str, set[str]]:
    """Table name -> the column names the models in `schema_source` give it."""
    tables: dict[str, set[str]] = {}
    for cls in (node for node in ast.walk(ast.parse(schema_source)) if isinstance(node, ast.ClassDef)):
        name, columns = None, set()
        for stmt in (stmt for stmt in cls.body if _target(stmt)):
            if _target(stmt) == "__tablename__" and isinstance(stmt.value, ast.Constant):
                name = stmt.value.value
            elif isinstance(stmt, ast.AnnAssign) and not _called(stmt.value, "relationship"):
                # mapped_column("name", ...) names its column; otherwise the attribute does.
                first = stmt.value.args[0] if _called(stmt.value, "mapped_column") and stmt.value.args else None
                columns.add(first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else _target(stmt))
        if name:
            tables[name] = columns
    return tables


def _literal(call: ast.Call, index: int, keyword: str, consts: dict[str, str]) -> str | None:
    """A string argument, or a module constant naming one (TABLE = "devices" is this repo's idiom)."""
    node = call.args[index] if len(call.args) > index else next((k.value for k in call.keywords if k.arg == keyword), None)
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def refusals(migration: str, source: str, tables: dict[str, set[str]], release: str) -> list[tuple[int, str]]:
    """(line, sentence) for each drop or rename that `migration`'s upgrade() reaches and `release` reads."""
    module = ast.parse(source).body
    functions = {f.name: f for f in module if isinstance(f, ast.FunctionDef)}
    consts = {_target(s): s.value.value for s in module if _target(s) and isinstance(getattr(s, "value", None), ast.Constant)
              and isinstance(s.value.value, str)}
    reached, todo = {}, ["upgrade"]
    while todo:  # upgrade(), and every function of the module it calls
        name = todo.pop()
        if name in functions and name not in reached:
            reached[name] = functions[name]
            todo += [c.func.id for c in ast.walk(functions[name]) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)]
    found = []
    for fn in reached.values():
        docstring = fn.body[0].value if isinstance(fn.body[0], ast.Expr) else None
        for node in ast.walk(fn):
            text = ("{}".join(v.value for v in node.values if isinstance(v, ast.Constant)) if isinstance(node, ast.JoinedStr)
                    else consts.get(node.id) if isinstance(node, ast.Name) else getattr(node, "value", None))
            if isinstance(text, str) and node is not docstring:
                if sql := RAW_SQL.search(text):
                    found.append((node.lineno, f"{migration} runs SQL that says {sql.group(0)!r}, whose target this check "
                                  "cannot read: use op.drop_column, op.drop_table, op.rename_table or "
                                  f"op.alter_column(new_column_name=) so it can be held against {release}'s models."))
                continue
            verb = node.func.attr if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) else None
            if verb not in VERBS or (verb == "alter_column" and all(k.arg != "new_column_name" for k in node.keywords)):
                continue
            table = _literal(node, 0, "old_table_name" if verb == "rename_table" else "table_name", consts)
            column = _literal(node, 1, "column_name", consts) if verb in ("drop_column", "alter_column") else None
            if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "op") or table is None or (
                    column is None and verb in ("drop_column", "alter_column")):
                found.append((node.lineno, f"{migration} calls {verb} on a target that is not a string literal on op, so "
                              f"this check cannot hold it against {release}'s models: name it with literals on op."))
            elif (column is None and table in tables) or column in tables.get(table, ()):
                fix = ("add the new name in this release and drop the old one in the next" if VERBS[verb] == "renames"
                       else "take it out of the models in this release and drop it in the next")
                what = f"column {table}.{column}" if column else f"table {table}"
                found.append((node.lineno, f"{migration} {VERBS[verb]} {what}, which {release} still reads (its models name "
                              f"it), so stepping back to {release} would break: {fix} (docs/BRANCHING.md §1.1)."))
    return list(dict.fromkeys(found))  # an f-string and its literal pieces can say the same thing


def upgrade_notes(tag: str) -> str:
    """The upgrade notes release.yml appends to a release: its migrations since the previous one, warnings first."""
    if (release := previous_release(tag, exclude=tag)) is None:
        sys.exit(f"::error::no earlier vMAJOR.MINOR.PATCH release is an ancestor of {tag}, so there is nothing to list since")
    listed, warnings = [], []
    for path in added_migrations(release, tag):
        source, revision = _git("show", f"{tag}:{path}"), Path(path).name.split("_")[0]
        listed.append(f"- `{revision}` " + " ".join((ast.get_docstring(ast.parse(source)) or "").split("\n\n")[0].split()))
        warnings += [f"- `{revision}`: {note.strip()}" for note in RELEASE_NOTE.findall(source)]
    docs = f"https://github.com/LoonSecIO/LoonInspect/blob/{tag}/docs/operations.md"
    count = (f"{len(listed)} migration(s) since {release} run at the new image's first start, in this order; take the "
             f"dump first ([upgrade]({docs}#4-upgrade), [rollback]({docs}#5-rollback))." if listed
             else f"No migrations since {release}: this update leaves the database schema as it is.")
    marker = "<!-- upgrade notes: written by .github/workflows/release.yml, which replaces this section on a re-run -->"
    first = ["**Before you update:**", *warnings, ""] if warnings else []
    return "\n".join([marker, "## Upgrade notes", "", *first, count, "", *listed])


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--notes":
        print(upgrade_notes(argv[1]))
        return 0
    release = previous_release("HEAD")
    if release is None:
        print("::error::no vMAJOR.MINOR.PATCH tag is reachable from HEAD, so there is no released schema to hold the "
              "migrations to: fetch the tags (actions/checkout with fetch-depth: 0) and run it again.")
        return 1
    tables, migrations = oracle(_git("show", f"{release}:{SCHEMA}")), added_migrations(release, "HEAD")
    found = [(path, line, sentence) for path in migrations
             for line, sentence in refusals(Path(path).name, _git("show", f"HEAD:{path}"), tables, release)]
    for path, line, sentence in found:
        print(f"::error file={path},line={line}::{sentence}")
    print(f"{len(migrations)} migration(s) added since {release}, held against the {len(tables)} tables its models name: "
          + (f"{len(found)} refused." if found else "none drops or renames what it reads."))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
