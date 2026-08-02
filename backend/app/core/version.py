from __future__ import annotations

import tomllib
from functools import lru_cache
from pathlib import Path

_PYPROJECT_PATH = Path(__file__).resolve().parents[2] / "pyproject.toml"


@lru_cache
def get_app_version() -> str:
    with open(_PYPROJECT_PATH, "rb") as f:
        data = tomllib.load(f)
    return data["project"]["version"]
