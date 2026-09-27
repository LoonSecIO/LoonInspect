"""The public images (#655): who pushes them, with which token, and what the README pulls.

A release's two images go to ghcr.io/loonsecio under the release's tag, pushed only by
`.github/workflows/release.yml` (Kyle's instruction, 2026-09-27): never by a merge to main,
and never as `latest`, so a pull names the version it gets. That workflow runs only when a
release is published, so the rules it keeps are pinned here, where a pull request can still
break them: the one job holding `packages: write`, the names it pushes, and the compose
override the README's pull commands read. The copy itself was run against two local
registries (#655's pull request); its first real push is a v2.0.0 prerelease.

Pure: no database, no app import, files read from disk.
"""

from __future__ import annotations

import re
from pathlib import Path

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
        assert service["build"] == "!reset", f"{name} can still build from source"
        tag = service["image"].split(":", 1)[1]
        assert re.fullmatch(r"\$\{LOONINSPECT_VERSION:\?.+\}", tag), f"{name} pulls {tag}, not the release .env names"
