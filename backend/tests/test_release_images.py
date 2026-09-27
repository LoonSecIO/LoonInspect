"""The public images (#655): who pushes them, with which token, and what the README pulls.

A release's two images go to ghcr.io/loonsecio under the release's tag, pushed only by
`.github/workflows/release.yml` (Kyle's instruction, 2026-09-27): never by a merge to main,
and never as `latest`, so a pull names the version it gets. That workflow runs only when a
release is published, so the rules it keeps are pinned here, where a pull request can still
break them: the one job holding `packages: write`, the names it pushes, and the compose
override the README's pull commands read. The copy itself was run against two local
registries (#655's pull request); its first real push is a v2.0.0 prerelease. Its guards run
here too, under bash with a stand-in `docker`, so an edit cannot quietly let a version move.

Pure: no database, no app import; files read from disk, and no registry reached.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"
PULL_OVERRIDE = REPO / "docker-compose.pull.yml"
REGISTRY = "ghcr.io/loonsecio"


class ComposeLoader(yaml.SafeLoader):
    """SafeLoader plus Compose's `!reset`, kept as a marker: the override's whole job is one."""


ComposeLoader.add_constructor("!reset", lambda loader, node: "!reset")


def _release() -> dict:
    return yaml.safe_load(RELEASE.read_text())


def _copy_script() -> str:
    return "\n".join(step.get("run", "") for step in _release()["jobs"]["ghcr"]["steps"])


def test_only_the_release_workflow_pushes_to_the_public_registry():
    naming = sorted(p.name for p in WORKFLOWS.glob("*.yml") if REGISTRY in p.read_text())
    assert naming == ["release.yml"], f"{naming} name {REGISTRY}; only release.yml pushes there"
    asking = sorted(p.name for p in WORKFLOWS.glob("*.yml") if re.search(r"^\s*packages:", p.read_text(), re.M))
    assert asking == ["release.yml"], f"{asking} ask for a packages permission; only release.yml's copy needs one"


def test_one_job_holds_packages_write_and_it_is_the_copy_after_the_ecr_tag():
    workflow = _release()
    assert workflow["permissions"] == {}, "release.yml grants nothing at the top; each job asks for its own"
    writers = [name for name, job in workflow["jobs"].items() if job.get("permissions", {}).get("packages")]
    assert writers == ["ghcr"]
    assert workflow["jobs"]["ghcr"]["permissions"] == {"id-token": "write", "packages": "write"}
    # The copy reads the version tag the images job adds in ECR, so it cannot run before it.
    assert workflow["jobs"]["ghcr"]["needs"] == "images"


def test_the_release_tag_is_the_only_tag_pushed():
    script = _copy_script()
    assert re.findall(r"--tag (\S+)", script) == ['"$dst"']
    assert re.search(rf"\bdst={re.escape(REGISTRY)}/\$repo:\$TAG$", script, re.M), "the copy is not named for the tag"
    assert "latest" not in script


def test_the_pull_override_pulls_what_the_release_pushes_and_never_builds():
    repos = re.search(r"for repo in ([\w -]+); do", _copy_script()).group(1).split()
    services = yaml.load(PULL_OVERRIDE.read_text(), Loader=ComposeLoader)["services"]
    pulled = sorted(service["image"].split(":", 1)[0] for service in services.values())
    assert pulled == sorted(f"{REGISTRY}/{repo}" for repo in repos)
    for name, service in services.items():
        # With `build` left in, Compose builds from source whenever the pull fails, and the
        # local build then runs under the release's image name.
        assert service.get("build") == "!reset", f"{name} can still build from source"
        tag = service["image"].split(":", 1)[1]
        assert re.fullmatch(r"\$\{LOONINSPECT_VERSION:\?.+\}", tag), f"{name} pulls {tag}, not the release .env names"


# `docker buildx imagetools` for the copy step: an index is a file named for its reference,
# `create` copies the source's (or, with `garble` present, pushes something else) and logs it.
FAKE_DOCKER = r"""#!/usr/bin/env bash
at() { printf '%s/%s' "$REGISTRY_DIR" "$(printf '%s' "$1" | tr '/:' '__')"; }
case "$3" in
  inspect) cat "$(at "$5")" 2>/dev/null || { echo "$5: not found" >&2; exit 1; } ;;
  create) echo "$5" >> "$REGISTRY_DIR/pushed"
    if [ -f "$REGISTRY_DIR/garble" ]; then echo '{"manifests":[{"digest":"sha256:0"}]}'
    else cat "$(at "${@: -1}")"; fi >"$(at "$5")" ;;
  *) exit 2 ;;
esac
"""


def _index(*digests: str) -> str:
    return json.dumps({"manifests": [{"digest": digest} for digest in digests]})


REPOS = ("looninspect", "looninspect-db")
ECR_IMAGES = {f"ecr.example/{repo}:v2.0.0": _index("sha256:b", "sha256:a") for repo in REPOS}
GHCR = [f"{REGISTRY}/{repo}:v2.0.0" for repo in REPOS]
needs_bash_and_jq = pytest.mark.skipif(
    not (shutil.which("bash") and shutil.which("jq")), reason="runs the copy step as the runner does, under bash with jq"
)


def _copy(tmp_path: Path, images: dict[str, str], garble: bool = False) -> tuple[subprocess.CompletedProcess, list[str]]:
    (step,) = [s["run"] for s in _release()["jobs"]["ghcr"]["steps"] if "imagetools create" in s.get("run", "")]
    registry, bin_dir = tmp_path / "registry", tmp_path / "bin"
    registry.mkdir(parents=True)
    bin_dir.mkdir()
    for ref, index in images.items():
        (registry / ref.replace("/", "_").replace(":", "_")).write_text(index)
    if garble:
        (registry / "garble").touch()
    (bin_dir / "docker").write_text(FAKE_DOCKER)
    (bin_dir / "docker").chmod(0o755)
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "REGISTRY_DIR": str(registry), "ECR": "ecr.example"}
    env |= {"TAG": "v2.0.0", "SHA": "c0ffee", "GITHUB_REPOSITORY": "LoonSecIO/LoonInspect"}
    done = subprocess.run(["bash", "-e", "-c", step], env=env, capture_output=True, text=True, timeout=60, check=False)
    pushed = registry / "pushed"
    return done, pushed.read_text().split() if pushed.exists() else []


@needs_bash_and_jq
def test_the_copy_pushes_each_image_once_and_a_rerun_pushes_nothing(tmp_path):
    first, pushed = _copy(tmp_path / "first", ECR_IMAGES)
    assert (first.returncode, pushed) == (0, GHCR), first.stdout + first.stderr
    # The same images under the tag, listed in another order: a re-run of a job that got that far.
    again, pushed = _copy(tmp_path / "again", ECR_IMAGES | dict.fromkeys(GHCR, _index("sha256:a", "sha256:b")))
    assert (again.returncode, pushed, again.stdout.count("::notice::")) == (0, [], 2), again.stdout + again.stderr


@needs_bash_and_jq
@pytest.mark.parametrize(
    ("case", "words"),
    [
        ("moved", "a published version never moves"),
        ("garbled", "was pushed and does not name the images c0ffee built"),
        ("unread", "Could not read looninspect:v2.0.0 back from ECR"),
    ],
)
def test_the_copy_never_moves_a_version_and_checks_what_it_pushed(tmp_path, case, words):
    images = dict(ECR_IMAGES)
    if case == "moved":
        images[GHCR[0]] = _index("sha256:c")
    if case == "unread":
        del images["ecr.example/looninspect:v2.0.0"]
    done, pushed = _copy(tmp_path, images, garble=case == "garbled")
    assert done.returncode == 1 and "::error::" in done.stdout and words in done.stdout, done.stdout + done.stderr
    # Only the push that was checked and found wrong happened; the second image was never tried.
    assert pushed == (GHCR[:1] if case == "garbled" else [])
