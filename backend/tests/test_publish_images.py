"""publish-images.yml's "already published?" gate (#716, #694).

Checked once per repository, not once for both: a run that pushes the app image and then
dies before the database one must still republish exactly what ECR is missing on its next
run, rather than reading the app image's presence as "nothing to do" and skipping the
database build forever (#716). And only a genuine miss (`ImageNotFoundException`) may read
as "not published" — any other describe-images failure (a missing grant, a wrong region, a
throttle) has to stop the job instead of masquerading as a green light to build, which would
otherwise fail later at push against the immutable repository with an error that names none
of the real causes (#694, docs/troubleshooting.md §10).

Pure: no database, no app import, no registry reached — the check step's own script is
extracted from the workflow and run under bash against a stub `aws` on disk, the way the
runner would run it.
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "publish-images.yml"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _steps() -> list[dict]:
    return _workflow()["jobs"]["publish"]["steps"]


def _step_named(name: str) -> dict:
    (step,) = [s for s in _steps() if s.get("name") == name]
    return step


def _check_script() -> str:
    (step,) = [s["run"] for s in _steps() if s.get("id") == "exists"]
    return step


# --- The gate's shape: two answers, and every downstream step reads its own -----------------


def test_the_qemu_and_buildx_setup_run_if_either_repository_is_missing():
    both_missing = "steps.exists.outputs.app == 'false' || steps.exists.outputs.db == 'false'"
    for action in ("docker/setup-qemu-action", "docker/setup-buildx-action"):
        (step,) = [s for s in _steps() if str(s.get("uses", "")).startswith(action + "@")]
        assert step["if"] == both_missing, f"{action} does not run whenever either image is still missing"


def test_each_build_step_is_gated_on_its_own_repositorys_answer():
    app = _step_named("Build and push app image")
    db = _step_named("Build and push database sidecar image")
    assert app["if"] == "steps.exists.outputs.app == 'false'"
    assert db["if"] == "steps.exists.outputs.db == 'false'"
    # Gated on different outputs is only half the proof — each also has to push the
    # repository its own gate named, or a swapped condition would fail silently.
    assert app["with"]["tags"].rsplit("/", 1)[-1].startswith("looninspect:")
    assert db["with"]["tags"].rsplit("/", 1)[-1].startswith("looninspect-db:")


def test_the_check_step_asks_about_both_repositories_by_name():
    script = _check_script()
    assert "check looninspect app" in script
    assert "check looninspect-db db" in script


# --- The check script itself, run as the runner would run it --------------------------------

# $CASES_FILE has one "<repository> <status>" line per repository this test cares about.
# `status` decides what the stub does when asked to describe-images for that repository:
# `found` succeeds (the image exists); every other status fails (exit 1) with the named
# AWS error on stderr, the way the real `aws` CLI reports a service-side exception — the
# exact exit code the real CLI uses does not matter here, only zero versus nonzero does,
# since that is all the workflow's own script branches on.
FAKE_AWS = r"""#!/usr/bin/env bash
repo=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repository-name) repo="$2"; shift 2 ;;
    *) shift ;;
  esac
done
status=$(awk -v r="$repo" '$1==r{print $2}' "$CASES_FILE")
case "$status" in
  found)
    exit 0 ;;
  not-found)
    echo "An error occurred (ImageNotFoundException) when calling the DescribeImages" \
         "operation: the image with imageTag=$GITHUB_SHA does not exist within the" \
         "repository with name '$repo'" >&2
    exit 1 ;;
  denied)
    echo "An error occurred (AccessDeniedException) when calling the DescribeImages" \
         "operation: User is not authorized to perform: ecr:DescribeImages on resource: $repo" >&2
    exit 1 ;;
  throttled)
    echo "An error occurred (ThrottlingException) when calling the DescribeImages operation: Rate exceeded" >&2
    exit 1 ;;
  *)
    echo "test stub: no case recorded for repository '$repo'" >&2
    exit 1 ;;
esac
"""

needs_bash = pytest.mark.skipif(
    not __import__("shutil").which("bash"), reason="runs the check step as the runner does, under bash"
)


def _run_check(tmp_path: Path, app: str, db: str) -> tuple[subprocess.CompletedProcess, dict[str, str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    aws = bin_dir / "aws"
    aws.write_text(FAKE_AWS)
    aws.chmod(aws.stat().st_mode | stat.S_IEXEC)

    cases = tmp_path / "cases.txt"
    cases.write_text(f"looninspect {app}\nlooninspect-db {db}\n")

    output = tmp_path / "output.txt"
    output.write_text("")

    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "CASES_FILE": str(cases), "GITHUB_SHA": "deadbeef", "GITHUB_OUTPUT": str(output)}
    done = subprocess.run(["bash", "-e", "-c", _check_script()], env=env, capture_output=True, text=True, timeout=30, check=False)
    values = dict(line.split("=", 1) for line in output.read_text().splitlines() if "=" in line)
    return done, values


@needs_bash
def test_a_missing_database_image_is_rebuilt_even_when_the_app_image_already_published(tmp_path):
    # The exact shape of #716: the app image reached ECR before the run died, the database
    # one did not, and the re-run must not read the app's presence as "nothing to do".
    done, outputs = _run_check(tmp_path, app="found", db="not-found")
    assert done.returncode == 0, done.stdout + done.stderr
    assert outputs == {"app": "true", "db": "false"}


@needs_bash
def test_a_fully_published_pair_skips_both_builds(tmp_path):
    done, outputs = _run_check(tmp_path, app="found", db="found")
    assert done.returncode == 0, done.stdout + done.stderr
    assert outputs == {"app": "true", "db": "true"}
    assert done.stdout.count("::notice::") == 2


@needs_bash
def test_neither_image_published_builds_both(tmp_path):
    done, outputs = _run_check(tmp_path, app="not-found", db="not-found")
    assert done.returncode == 0, done.stdout + done.stderr
    assert outputs == {"app": "false", "db": "false"}


# --- #694: only a genuine miss reads as not published ----------------------------------------


@needs_bash
def test_a_genuine_miss_still_reads_as_not_published(tmp_path):
    # Unchanged by #694: ImageNotFoundException is the one failure that means "go ahead".
    done, outputs = _run_check(tmp_path, app="not-found", db="found")
    assert done.returncode == 0, done.stdout + done.stderr
    assert outputs == {"app": "false", "db": "true"}


@needs_bash
@pytest.mark.parametrize("status", ["denied", "throttled"])
def test_a_refused_check_stops_the_job_instead_of_reading_as_not_published(tmp_path, status):
    # The bug #694 fixes: before this, any non-zero exit — a missing grant, a throttle —
    # was silently read the same as "not published", and the job went on to build.
    done, outputs = _run_check(tmp_path, app=status, db="found")
    assert done.returncode == 1, done.stdout + done.stderr
    assert "::error::" in done.stdout
    assert "app" not in outputs, "a refused check must not write an answer, true or false"
    assert "db" not in outputs, "the job stops at the first refusal; it never asks about the second repository"


@needs_bash
def test_the_refusal_names_the_likely_causes_in_the_operators_words(tmp_path):
    done, _ = _run_check(tmp_path, app="denied", db="found")
    message = done.stdout
    assert "ecr:DescribeImages" in message
    assert "AWS_REGION" in message
    assert "throttling" in message
    assert "docs/troubleshooting.md" in message


@needs_bash
def test_a_refusal_on_the_second_repository_still_leaves_the_firsts_true_answer_written(tmp_path):
    # Downstream steps never see this (a failed step skips the rest of the job), but the
    # script itself must fail at exactly the repository that was refused, not before.
    done, outputs = _run_check(tmp_path, app="found", db="denied")
    assert done.returncode == 1, done.stdout + done.stderr
    assert outputs == {"app": "true"}
    assert "::error::" in done.stdout
