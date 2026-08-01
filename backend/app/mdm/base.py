from __future__ import annotations

from abc import ABC, abstractmethod

from app.schemas.payload import NormalizedDevice


class MdmClient(ABC):
    provider: str

    @abstractmethod
    async def fetch_devices(self) -> list[NormalizedDevice]:
        """Pull the full device + installed-app inventory from the MDM."""

    @abstractmethod
    def parse_webhook(self, payload: dict) -> NormalizedDevice:
        """Normalize a single MDM webhook payload into a NormalizedDevice."""
