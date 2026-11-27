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
        "--ci-images",
        action="store_true",
        help="Use the local image tags built by the Docker image CI job.",
    )
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    repo = here.parents[1]
    # Only Docker client settings cross into the test. Use fresh application settings
    # even when the checkout or the calling shell is configured for a real install.
    env = {k: v for k, v in os.environ.items() if k in {"HOME", "PATH", "TMPDIR"} or k.startswith("DOCKER_")}
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

    try:
        if args.ci_images:
            # Compose's build-only services use <project>-<service>. Give each CI
            # image a project tag so cleanup can remove it and preserve the original.
            images = {"app": "looninspect:ci", "db": "looninspect-db:ci", "browser": "looninspect-browser:ci"}
            for service, image in images.items():
                subprocess.run(["docker", "image", "tag", image, f"{project}-{service}"], env=env, check=True)
        else:
            run("build", "db", "app", "browser")
        run("up", "--no-build", "--pull=never", "--detach", "--wait", "--wait-timeout", "180", "app")
        run("images", "app")
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
