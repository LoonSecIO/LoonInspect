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


def _plant(tmp_path: Path, name: str, text: str, also: dict[str, str] | None = None) -> list:
    for path, body in {name: text, **(also or {})}.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(body)
    return [s for s in stacks.check(tmp_path, [name, *(also or {})]) if s.why]


@pytest.mark.skipif(not TRACKED or TRACKED.returncode, reason="lists the tracked files with git; CI's own job runs it anyway")
def test_the_tree_starts_nothing_that_would_be_counted():
    seen = stacks.check(ROOT, TRACKED.stdout.split("\0"))
    assert [f"{s.path}:{s.line}: {s.why}" for s in seen if s.why] == []
    app = [s.env.get("UPDATE_CHECK") for s in seen if s.path == ".github/workflows/ci.yml" and s.image == "looninspect:ci"]
    assert app == ["false"] * 6  # CI's image job starts the app six times, each with the check off; the rest are not the app
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
        ("sh -c 'docker run -e UPDATE_CHECK=false looninspect:ci'", False),  # read to the quote that closes it
        ("docker run --rm --user postgres postgres:17-alpine", False),
        ('docker run --rm "$IMAGE"', True),
        ('# Not the app image: the db sidecar.\ndocker run --rm "$IMAGE"', False),
        ("docker run --frobnicate looninspect-db:ci", True),  # an option it does not know
        ("docker run --rm -e 'UPDATE_CHECK=false looninspect:ci", True),  # a quote that does not close
        ("docker run '' looninspect:ci", True),  # an empty word is read, not a crash
        ("# docker run looninspect:ci, in a comment", False),
        ("echo 'docker run reads as a command'", True),  # it cannot tell a sentence from sh -c '…', so it fails closed
        ("docker compose up -d", True),
        ("export UPDATE_CHECK=false\nCOMPOSE_FILE='docker-compose.yml:./docker-compose.pull.yml' docker compose up -d", False),
        ('if [ -n "$CI" ]; then\n  export UPDATE_CHECK=false\nfi\ndocker compose up -d', True),  # an indented export: a branch's
        ("export UPDATE_CHECK=false\ndocker compose -f docker-compose.yml -f ./docker-compose.pull.yml up -d", False),
        ("export UPDATE_CHECK=false COMPOSE_FILE=/tmp/e2e.yml\ndocker compose watch", True),  # a file it cannot read, named 2nd
        ("export UPDATE_CHECK=false\nCOMPOSE_FILE=docker-compose.yml:/tmp/e2e.yml docker compose up -d", True),  # in front of it
        ("export UPDATE_CHECK=false\nf() { docker compose up; }\nif true; then\n  export COMPOSE_FILE=/tmp/e2e.yml\nfi\nf", True),
        ("docker-compose up", True),
        ("docker compose logs app", False),
    ],
)
def test_a_planted_command_is_counted_unless_it_keeps_out(tmp_path, script, counted):
    assert bool(_plant(tmp_path, "s.sh", script + "\n")) is counted


@pytest.mark.parametrize("name", ["docker-compose.e2e.yml", "docker-compose-e2e.yml", "compose-test.yml", "ops/e2e/stack.yaml"])
def test_a_compose_file_is_read_whatever_its_name_and_a_step_env_passes_its_start_but_not_its_app_nor_a_container(tmp_path, name):
    e2e = "services:\n  app:\n    environment: {LOG_LEVEL: DEBUG}\n  db:\n    build: ./ops/postgres\n  web: {extends: app}\n"
    steps = f"  - run: docker compose -f {name} up -d\n  - run: docker compose -f - up\n  - run: docker run looninspect:ci\n"
    steps += "  - {env: {COMPOSE_FILE: x.yml}, run: docker compose up}\n"  # a file the step's env names is read as -f's is
    found = _plant(tmp_path, ".github/workflows/w.yml", "env: {UPDATE_CHECK: '0'}\njobs:\n e2e:\n  steps:\n" + steps, {name: e2e})
    assert [(s.path == name, s.line) for s in found] == [(False, 6), (False, 7), (False, 8), (True, 2), (True, 6)]
    assert [s.why.split(",")[0].split(" starts ")[1] for s in found] == ["-", "LoonInspect", "x.yml", "its image", "its image"]
    assert stacks.check(ROOT, sorted(stacks.SHIPPED)) == []  # the files an operator runs, read only through a start's env
    assert _plant(tmp_path, "two.yml", "a: 1\n---\nb: 2\n")[0].why.startswith("this check cannot load it as YAML")
