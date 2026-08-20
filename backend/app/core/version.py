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


@lru_cache
def get_app_version() -> str:
    try:
        with open(_BUILD_INFO_PATH, "rb") as f:
            version = json.load(f)["version"]
    except (OSError, KeyError, json.JSONDecodeError):
        return _DEV_VERSION
    return version if isinstance(version, str) and version else _DEV_VERSION
