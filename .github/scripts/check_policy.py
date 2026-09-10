#!/usr/bin/env python3
"""The branch and pull request policy workflow (#19): docs/BRANCHING.md §8 step 3.

Runs the controls `docs/controls.yml` marks `check: policy-workflow` against one pull
request, reading every pattern, limit, path list and exemption from that manifest — the
manifest is the register, and this script is only the hands. A control the manifest names
with no implementation here, or an implementation with no entry there, fails the
self-test, which is what keeps the two from drifting.

    Usage:  HEAD_REF=… BASE_REF=… PR_TITLE=… .github/scripts/check_policy.py
            .github/scripts/check_policy.py --self-test

Inputs arrive through the environment, never through arguments interpolated into a
workflow `run:` line: a title is contributor-controlled input. `block` controls fail the
job with `::error::`; `warn` controls annotate with `::warning::` and pass. A control
that cannot be evaluated (no `gh`, no history) is reported as skipped, never as passed.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs" / "controls.yml"
OK, FAIL, SKIP = "ok", "fail", "skip"


def load_manifest(path: Path = MANIFEST) -> dict:
    with path.open() as handle:
        return yaml.safe_load(handle)


def exempt(control_id: str, head_ref: str, manifest: dict) -> str | None:
    for rule in manifest.get("exemptions", []):
        if control_id in rule["controls"] and any(head_ref.startswith(p) for p in rule["branch_prefixes"]):
            return rule.get("why", "exempt")
    return None


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True, cwd=ROOT).stdout


def _changed_paths(base: str) -> list[str]:
    return [line for line in _git("diff", "--name-only", f"{base}...HEAD").splitlines() if line]


# ---- the controls ----------------------------------------------------------------------


def br01(control: dict, env: dict) -> tuple[str, str]:
    ref = env["HEAD_REF"]
    if re.search(control["pattern"], ref):
        return OK, f"branch `{ref}` matches the canonical pattern"
    return FAIL, f"branch `{ref}` does not match `{control['pattern']}` (docs/BRANCHING.md §2)"


def br02(control: dict, env: dict) -> tuple[str, str]:
    base = env["BASE_REF"]
    return (OK, f"base is `{base}`") if base == control["base"] else (FAIL, f"base is `{base}`, must be `{control['base']}`")


def br03(control: dict, env: dict) -> tuple[str, str]:
    base = env.get("BASE_REMOTE", "origin/main")
    stamps = _git("log", "--reverse", "--format=%ct", f"{base}..HEAD").split()
    if not stamps:
        return SKIP, "no commits beyond the base to date"
    days = (time.time() - int(stamps[0])) / 86400
    limit = control["days"]
    return (OK if days <= limit else FAIL), f"first commit is {days:.1f} days old (limit {limit})"


def br05(control: dict, env: dict) -> tuple[str, str]:
    ref = env["HEAD_REF"]
    try:
        out = subprocess.run(
            ["gh", "pr", "list", "--state", "merged", "--search", f"head:{ref}", "--json", "number,headRefName"],
            check=True, capture_output=True, text=True, cwd=ROOT,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        return SKIP, f"could not ask GitHub for merged pull requests ({exc.__class__.__name__})"
    merged = [row["number"] for row in json.loads(out or "[]") if row.get("headRefName") == ref]
    if merged:
        return FAIL, f"branch name `{ref}` already merged as #{merged[0]} — names are never reused (docs/BRANCHING.md §3)"
    return OK, f"branch name `{ref}` has not merged before"


def cm01(control: dict, env: dict) -> tuple[str, str]:
    title = env["PR_TITLE"]
    if re.search(control["pattern"], title):
        return OK, "title is a squash subject"
    return FAIL, f"title `{title}` does not match `{control['pattern']}` (docs/BRANCHING.md §5)"


def cm02(control: dict, env: dict) -> tuple[str, str]:
    base = env.get("BASE_REMOTE", "origin/main")
    subjects = _git("log", "--format=%s", f"{base}..HEAD").splitlines()
    dupes = [a for a, b in zip(subjects, subjects[1:], strict=False) if a == b]
    if dupes:
        return FAIL, f"consecutive commits share a subject: `{dupes[0]}`"
    return OK, f"{len(subjects)} commit subject(s), none consecutive duplicates"


def _paths_control(control: dict, env: dict) -> tuple[str, str]:
    base = env.get("BASE_REMOTE", "origin/main")
    hits = [p for p in _changed_paths(base) if re.search(control["paths"], p)]
    if hits:
        return FAIL, f"forbidden path(s) in the diff: {', '.join(hits[:5])}"
    return OK, "no forbidden paths in the diff"


def pr01(control: dict, env: dict) -> tuple[str, str]:
    base = env.get("BASE_REMOTE", "origin/main")
    total = 0
    for line in _git("diff", "--numstat", f"{base}...HEAD").splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        added, deleted, path = parts
        if added == "-" or deleted == "-":
            continue  # binary
        if any(fnmatch.fnmatch(path, glob) or fnmatch.fnmatch(Path(path).name, glob) for glob in control["exclude"]):
            continue
        total += int(added) + int(deleted)
    limit = control["limit"]
    return (OK if total < limit else FAIL), f"{total} changed lines outside lockfiles and generated output (limit {limit})"


IMPLEMENTATIONS = {
    "BR-01": br01,
    "BR-02": br02,
    "BR-03": br03,
    "BR-05": br05,
    "CM-01": cm01,
    "CM-02": cm02,
    "CM-03": _paths_control,
    "CM-04": _paths_control,
    "PR-01": pr01,
}


# ---- running ---------------------------------------------------------------------------


def workflow_controls(manifest: dict) -> list[dict]:
    return [c for c in manifest["controls"] if c.get("check") == "policy-workflow"]


def run(manifest: dict, env: dict) -> int:
    failed = 0
    for control in workflow_controls(manifest):
        cid, severity = control["id"], control["severity"]
        why = exempt(cid, env["HEAD_REF"], manifest)
        if why:
            print(f"{cid}: exempt ({why})")
            continue
        verdict, message = IMPLEMENTATIONS[cid](control, env)
        if verdict == OK:
            print(f"{cid}: ok — {message}")
        elif verdict == SKIP:
            print(f"::warning::{cid}: skipped — {message}")
        elif severity == "block":
            print(f"::error::{cid}: {message}")
            failed += 1
        else:
            print(f"::warning::{cid}: {message}")
    return 1 if failed else 0


def self_test() -> int:
    manifest = load_manifest()
    named = {c["id"] for c in workflow_controls(manifest)}
    assert named == set(IMPLEMENTATIONS), f"manifest and script disagree: {sorted(named ^ set(IMPLEMENTATIONS))}"
    ids = [c["id"] for c in manifest["controls"]]
    assert len(ids) == len(set(ids)), "duplicate control id"
    for c in manifest["controls"]:
        assert c["severity"] in {"block", "warn", "manual"}, c["id"]
        assert c["enforcement"] in {"ci", "ruleset", "repo-setting", "review", "scheduled"}, c["id"]
        assert c["status"] in {"active", "proposed", "blocked"}, c["id"]
    by_id = {c["id"]: c for c in manifest["controls"]}

    good = ["inspect-0019/policy-workflow", "fix/a", "chore/ruff-format", "docs/x-y", "spike/s1"]
    bad = ["INSPECT-0019/x", "inspect-19/x", "feature/x", "chore/Bad", "chore/x-", "main", "dependabot/npm_and_yarn/frontend/typescript-7.0.2"]
    for ref in good:
        assert br01(by_id["BR-01"], {"HEAD_REF": ref})[0] == OK, ref
    for ref in bad:
        assert br01(by_id["BR-01"], {"HEAD_REF": ref})[0] == FAIL, ref
    assert exempt("BR-01", "dependabot/npm_and_yarn/x", manifest)
    assert exempt("CM-01", "dependabot/npm_and_yarn/x", manifest)
    assert exempt("CM-03", "dependabot/npm_and_yarn/x", manifest) is None, "only the naming controls are exempt"
    assert exempt("BR-01", "chore/x", manifest) is None

    ok_titles = ["INSPECT-0019: the policy workflow", "chore: adopt ruff format, datetime.UTC", "docs: ten chars ok", "fix: a subject of ten"]
    bad_titles = ["INSPECT-19: x", "chore(npm): bump typescript from 6.0.3 to 7.0.2 in /frontend", "feat: something", "INSPECT-0019: short", "INSPECT-0019: " + "x" * 61]
    for title in ok_titles:
        assert cm01(by_id["CM-01"], {"PR_TITLE": title})[0] == OK, title
    for title in bad_titles:
        assert cm01(by_id["CM-01"], {"PR_TITLE": title})[0] == FAIL, title

    for path, hit in [(".env", True), ("backend/.env", True), ("x.db", True), ("backend/.env.example", False), (".envrc", False), ("docs/env.md", False)]:
        assert bool(re.search(by_id["CM-03"]["paths"], path)) == hit, path
    for path, hit in [(".idea/x.xml", True), ("frontend/.vscode/settings.json", True), ("a/.DS_Store", True), ("docs/ideas.md", False)]:
        assert bool(re.search(by_id["CM-04"]["paths"], path)) == hit, path

    excl = by_id["PR-01"]["exclude"]
    def excluded(path: str) -> bool:
        return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch(Path(path).name, g) for g in excl)
    assert excluded("frontend/package-lock.json") and excluded("backend/uv.lock") and excluded("backend/migrations/versions/abc_x.py")
    assert not excluded("backend/app/main.py") and not excluded("docs/lockstep.md")

    assert br02(by_id["BR-02"], {"BASE_REF": "main"})[0] == OK and br02(by_id["BR-02"], {"BASE_REF": "dev"})[0] == FAIL
    print(f"self-test: {len(named)} workflow controls implemented, {len(ids)} controls in the register, patterns and exemptions hold")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    env = {k: os.environ.get(k, "") for k in ("HEAD_REF", "BASE_REF", "PR_TITLE", "BASE_REMOTE")}
    missing = [k for k in ("HEAD_REF", "BASE_REF", "PR_TITLE") if not env[k]]
    if missing:
        print(f"::error::missing environment: {', '.join(missing)}")
        return 2
    env["BASE_REMOTE"] = env["BASE_REMOTE"] or f"origin/{env['BASE_REF']}"
    return run(load_manifest(), env)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
