from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.schemas.payload import NormalizedApp


@dataclass
class PatchCheckResult:
    full_hash: str
    is_compliant: bool | None
    patch_available: bool | None


class PatchProvider(ABC):
    provider: str

    @abstractmethod
    async def check_apps(self, apps: list[NormalizedApp]) -> list[PatchCheckResult]:
        """Return compliance/patch-availability results keyed by full_hash."""
