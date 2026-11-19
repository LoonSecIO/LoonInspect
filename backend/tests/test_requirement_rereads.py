"""The release re-read check (#809): .github/scripts/check_requirement_rereads.py."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from collections import Counter
from datetime import date
from pathlib import Path

import pytest

from app.core.version import RELEASE
from app.mdm.patch.policy_presets import PRESETS

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github" / "scripts"
URL = "https://x.invalid/ce-1.pdf"
CATALOGUE = f'CE = Preset(id="ce-1", url="{URL}", verified_on=date({{read}}), rule=Rule(max_days_behind=14))\n'


def _load(name: str):
    """A script as a module, registered so that the re-read check's import of the contract check finds it."""
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = sys.modules[name] = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_load("check_migration_contract")  # the tag lookup the re-read check imports
reread = _load("check_requirement_rereads")


def test_the_check_reads_what_the_app_imports():
    """It reads with ast, so a catalogue reshaped past what it reads would pass it unread: hold the reading to the import."""
    assert reread.release_of((ROOT / reread.VERSION).read_text()) == RELEASE
    found = reread.entries((ROOT / reread.CATALOGUE).read_text())
    assert Counter(entry[1:] for entry in found) == Counter((p.id, p.url, p.verified_on) for p in PRESETS)


def test_an_entry_is_read_after_the_last_release_and_not_after_today():
    def refused(read: object) -> str | None:
        return reread.refusal("ce-1", URL, read, "v1.2.0", "v1.1.0", date(2026, 11, 17), date(2026, 11, 18))

    move = ": read the publisher's text again and move verified_on to the day you read it (docs/jamf-patch-matching.md §8c)."
    assert refused(date(2026, 10, 3)) == (
        f"ce-1 ({URL}) was read on 2026-10-03, on or before 2026-11-17, the day of v1.1.0's commit, so v1.2.0 would ship it "
        f"unread since v1.1.0{move}"
    )
    assert refused(date(2026, 11, 19)) == (
        f"ce-1 ({URL}) says it was read on 2026-11-19, a day still to come, so nothing shows it was read after 2026-11-17, "
        f"the day of v1.1.0's commit{move}"
    )
    assert "on or before" in refused(date(2026, 11, 17))  # on the tag's own day, nobody can say which came first
    assert refused(date(2026, 11, 18)) is None
    assert "does not write out its id, url and verified_on as keywords" in refused("2026-11-18")


@pytest.mark.skipif(shutil.which("git") is None, reason="builds a git repository")
def test_the_script_holds_a_release_to_the_reread_and_passes_any_other_pull_request(tmp_path):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    env |= {f"GIT_{who}_{what}": "t@t.invalid" for who in ("AUTHOR", "COMMITTER") for what in ("NAME", "EMAIL")}
    env["GIT_COMMITTER_DATE"] = "2026-01-01T12:00:00+00:00"  # every commit's day here, the tagged one's among them
    (tmp_path / ".github" / "scripts").mkdir(parents=True)
    for name in ("check_migration_contract.py", "check_requirement_rereads.py"):
        shutil.copy(SCRIPTS / name, tmp_path / ".github" / "scripts" / name)

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, env=env, check=True)

    def commit_and_check(release: str, read: str) -> subprocess.CompletedProcess[str]:
        for path, text in ((reread.VERSION, f'RELEASE = "{release}"\n'), (reread.CATALOGUE, CATALOGUE.format(read=read))):
            (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / path).write_text(text)
        for args in (("add", "."), ("commit", "-qm", f"{release}, read {read}", "--allow-empty")):
            git(*args)
        script = tmp_path / ".github" / "scripts" / "check_requirement_rereads.py"
        return subprocess.run([sys.executable, script], cwd=tmp_path, env=env, capture_output=True, text=True)

    git("init", "-q")
    untagged = commit_and_check("v1.0.0", "2025, 12, 1")
    assert untagged.returncode == 1 and "no vMAJOR.MINOR.PATCH tag is reachable from HEAD" in untagged.stdout
    git("tag", "v1.0.0")
    unbumped = commit_and_check("v1.0.0", "2025, 12, 1")
    assert unbumped.returncode == 0, unbumped.stdout
    assert "RELEASE is v1.0.0 and the newest release tag is v1.0.0, so this pull request prepares no release" in unbumped.stdout
    stale = commit_and_check("v1.1.0", "2025, 12, 1")
    assert stale.returncode == 1
    assert f"line=1::ce-1 ({URL}) was read on 2025-12-01, on or before 2026-01-01, the day of v1.0.0's commit" in stale.stdout
    moved = commit_and_check("v1.1.0", "2026, 1, 2")
    assert moved.returncode == 0, moved.stdout
    assert "1 of the 1 published requirement(s) were read after that day" in moved.stdout
    future = commit_and_check("v1.1.0", "2999, 1, 1")
    assert future.returncode == 1 and "says it was read on 2999-01-01, a day still to come" in future.stdout
