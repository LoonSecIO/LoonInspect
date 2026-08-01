from __future__ import annotations

from app.mdm.base import MdmClient
from app.schemas.payload import MdmProvider, NormalizedDevice


class SimpleMdmClient(MdmClient):
    provider = MdmProvider.simplemdm.value

    async def fetch_devices(self) -> list[NormalizedDevice]:
        raise NotImplementedError("SimpleMDM support is not implemented yet")

    def parse_webhook(self, payload: dict) -> NormalizedDevice:
        raise NotImplementedError("SimpleMDM support is not implemented yet")
