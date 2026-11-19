"""The test-stack check (#821), .github/scripts/check_test_stacks.py: planted cases in a temporary directory, and the tree."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_test_stacks", ROOT / ".github" / "scripts" / "check_test_stacks.py")
stacks = sys.modules["check_test_stacks"] = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stacks)
TRACKED = shutil.which("git") and subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True)


def _plant(tmp_path: Path, name: str, text: str) -> list:
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(text)
    return [s for s in stacks.check(tmp_path, [name]) if s.why]


@pytest.mark.skipif(not TRACKED or TRACKED.returncode, reason="lists the tracked files with git; CI's own job runs it anyway")
def test_the_tree_starts_nothing_that_would_be_counted():
    seen = stacks.check(ROOT, TRACKED.stdout.split("\0"))
    assert [f"{s.path}:{s.line}: {s.why}" for s in seen if s.why] == []
    # CI's image job starts the app six times, each with the check off; the rest are databases and a secret scanner.
    app = [s.env.get("UPDATE_CHECK") for s in seen if s.path == ".github/workflows/ci.yml" and s.image == "looninspect:ci"]
    assert app == ["false"] * 6
    assert Counter(s.passed for s in seen) == {"the setting": 6, "not the app": 4, "the comment": 2}


def test_the_smoke_instance_without_the_setting_fails_on_its_own_line(tmp_path):
    smoke, setting, ci = "--name smoke --network smoke-net \\\n", "            -e UPDATE_CHECK=false \\\n", "ci.yml"
    text = (ROOT / ".github" / "workflows" / ci).read_text()
    assert text.count(smoke + setting) == 1
    (found,) = _plant(tmp_path, f".github/workflows/{ci}", text.replace(smoke + setting, smoke))
    line = next(n for n, line in enumerate(text.splitlines(), 1) if smoke.strip(" \\\n") in line)
    assert (found.line, found.where) == (line, "job image, step Smoke test the image")
    assert found.why.startswith("docker run starts LoonInspect, looninspect:ci, with neither UPDATE_CHECK=false nor")


@pytest.mark.parametrize(
    ("script", "counted"),
    [
        ("docker run -d looninspect:ci", True),
        ("docker run -d -e UPDATE_CHECK=false looninspect:ci", False),
        ("docker run --rm --env=UPDATE_CHECK=0 ghcr.io/loonsecio/looninspect:v1.2.0", False),
        ("docker run -e UPDATE_CHECK_URL=https://API.next.loonsec.io./v1/update looninspect:ci", True),  # production
        ("docker run -e UPDATE_CHECK_URL=https://api.staging.next.loonsec.io/v1/update looninspect:ci", False),
        ("docker run -d \\\n  -e UPDATE_CHECK=false \\\n  looninspect:ci", False),
        ("KEY=$(docker run --rm other/image:1 python -c 'print(1)')", True),  # an image it does not know
        ("sh -c 'docker container create looninspect:ci'", True),
        ("docker run --rm --user postgres postgres:17-alpine", False),
        ('docker run --rm "$IMAGE"', True),
        ('# Not the app image: the db sidecar.\ndocker run --rm "$IMAGE"', False),
        ("docker run --frobnicate looninspect-db:ci", True),  # an option it does not know
        ("docker run --rm -e 'UPDATE_CHECK=false looninspect:ci", True),  # a quote that does not close
        ("docker run '' looninspect:ci", True),  # an empty word is read, not a crash
        ("# docker run looninspect:ci, in a comment", False),
        ("echo 'docker run reads as a command'", True),  # it cannot tell a sentence from sh -c '…', so it fails closed
        ("docker compose up -d", True),
        ("export UPDATE_CHECK=false\ndocker compose up -d", False),
        ("docker-compose up", True),
        ("docker compose logs app", False),
    ],
)
def test_a_planted_command_is_counted_unless_it_keeps_out(tmp_path, script, counted):
    assert bool(_plant(tmp_path, "s.sh", script + "\n")) is counted


def test_a_workflow_env_reaches_a_compose_start_and_not_a_container(tmp_path):
    steps = "      - run: docker compose up -d\n      - name: start\n        run: docker run looninspect:ci\n"
    found = _plant(tmp_path, ".github/workflows/w.yml", "env: {UPDATE_CHECK: 'false'}\njobs:\n  e2e:\n    steps:\n" + steps)
    assert [(s.line, s.where) for s in found] == [(7, "job e2e, step start")]


def test_a_test_compose_file_must_set_it_and_the_files_an_operator_runs_are_not_read(tmp_path):
    e2e = "services:\n  app:\n    environment: {LOG_LEVEL: DEBUG}\n  db:\n    build: ./ops/postgres\n"
    (found,) = _plant(tmp_path, "docker-compose.e2e.yml", e2e)
    assert (found.line, found.why.startswith("service app starts the image it builds, with neither")) == (2, True)
    assert stacks.check(ROOT, sorted(stacks.SHIPPED)) == []
