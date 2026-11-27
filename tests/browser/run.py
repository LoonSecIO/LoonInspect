"""Run the Chromium release smoke tests against a fresh local Compose project."""

import argparse
import base64
import os
import re
import secrets
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--app-image",
        metavar="IMAGE",
        help="test this app image, already on the Docker host, instead of building one from the checkout",
    )
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    repo = here.parents[1]
    # Only Docker client settings cross into the test. Use fresh application settings
    # even when the checkout or the calling shell is configured for a real install.
    env = {k: v for k, v in os.environ.items() if k in {"HOME", "PATH", "TMPDIR"} or k.startswith(("DOCKER_", "BUILDX_"))}
    env.update(
        POSTGRES_PASSWORD=secrets.token_hex(24),
        POSTGRES_APP_PASSWORD=secrets.token_hex(24),
        ENCRYPTION_KEY=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        SMOKE_ADMIN_PASSWORD=secrets.token_hex(24),
    )
    project = "li-browser-" + secrets.token_hex(6)
    compose = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--env-file",
        os.devnull,
        "-f",
        "docker-compose.yml",
        "-f",
        str(here / "compose.yml"),
    ]

    def run(*args, **kwargs):
        return subprocess.run([*compose, *args], cwd=repo, env=env, check=True, **kwargs)

    built = ["db", "browser"]
    if args.app_image:
        # Without the image, Compose would build the checkout under its name and the tests
        # would pass or fail on an app nobody named.
        found = subprocess.run(["docker", "image", "inspect", args.app_image], env=env, capture_output=True, text=True)
        if found.returncode:
            reason = (found.stderr.strip().splitlines() or ["docker image inspect failed without a message"])[-1]
            raise SystemExit(
                f"Docker cannot read the app image {args.app_image}: {reason}. Build or load it under "
                "that name first, or leave --app-image out to build the app from this checkout."
            )
        env["SMOKE_APP_IMAGE"] = args.app_image
    else:
        built.append("app")

    try:
        run("build", *built)
        # The images exist by now, so a start that would build one is a start on the wrong image.
        run("up", "--detach", "--wait", "--wait-timeout", "180", "--no-build", "app")
        with (here / "seed.py").open("rb") as inventory:
            run("exec", "-T", "app", "/app/.venv/bin/python", "-", stdin=inventory)
        logs = run("logs", "--no-color", "app", stdout=subprocess.PIPE, text=True).stdout
        claim = re.search(r"claim token to create the first administrator: ([A-Za-z0-9_-]+)", logs)
        if not claim:
            raise SystemExit("First-run admin setup is unavailable. Check the app bootstrap log format.")
        env["SMOKE_CLAIM_TOKEN"] = claim[1]
        run("run", "--rm", "--no-deps", "-T", "-e", "SMOKE_CLAIM_TOKEN", "-e", "SMOKE_ADMIN_PASSWORD", "browser")
    finally:
        run("down", "--volumes", "--rmi", "local")


if __name__ == "__main__":
    main()
