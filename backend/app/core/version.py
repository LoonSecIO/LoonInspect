from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

# Stamped by the Dockerfile at image build time: {"version": "YYYY.MM.DD+<sha>"}.
# The file is deliberately absent from the source tree — its absence is what
# identifies a non-release build.
_BUILD_INFO_PATH = Path(__file__).resolve().parents[1] / "build_info.json"

# A dev build must never be able to masquerade as a release build, so the
# fallback is a sentinel rather than a plausible-looking date.
_DEV_VERSION = "0.0.0-dev+local"

# The release this tree is: the newest vMAJOR.MINOR.PATCH it contains (#672). An image never sees a
# tag (CI builds it before the tag exists, and .dockerignore keeps .git out of every build), and
# build_info.json names a commit, not a release, so the tree says it: the pull request that prepares a
# release sets this before the tag, and release.yml refuses to tag the images of a tag that
# disagrees. init_db compares it with a newer database's min_readable_release (docs/operations.md §5).
RELEASE = "v2.0.0"


@lru_cache
def get_app_version() -> str:
    try:
        with open(_BUILD_INFO_PATH, "rb") as f:
            version = json.load(f)["version"]
    except (OSError, KeyError, json.JSONDecodeError):
        return _DEV_VERSION
    return version if isinstance(version, str) and version else _DEV_VERSION
