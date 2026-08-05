from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.schemas.payload import NormalizedApp


@dataclass
class PatchCheckResult:
    # The version hash — patch state is a property of a specific build, not of the
    # application in general.
    version_hash: str
    is_compliant: bool | None
    patch_available: bool | None


class PatchProvider(ABC):
    provider: str

    @abstractmethod
    async def check_apps(self, apps: list[NormalizedApp]) -> list[PatchCheckResult]:
        """Return compliance/patch-availability results keyed by version_hash."""
