from __future__ import annotations

import httpx

from app.core.config import settings
from app.mdm.base import MdmClient
from app.schemas.payload import MdmProvider, NormalizedApp, NormalizedDevice


class JamfClient(MdmClient):
    provider = MdmProvider.jamf.value

    def __init__(
        self,
        base_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> None:
        self._base_url = (base_url or settings.jamf_base_url or "").rstrip("/")
        self._client_id = client_id or settings.jamf_client_id
        self._client_secret = client_secret or settings.jamf_client_secret
        self._token: str | None = None

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        if self._token:
            return self._token

        response = await client.post(
            f"{self._base_url}/api/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
        )
        response.raise_for_status()
        self._token = response.json()["access_token"]
        return self._token

    async def fetch_devices(self) -> list[NormalizedDevice]:
        devices: list[NormalizedDevice] = []
        page_size = 100

        async with httpx.AsyncClient(timeout=30) as client:
            token = await self._authenticate(client)
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

            page = 0
            while True:
                response = await client.get(
                    f"{self._base_url}/api/v1/computers-inventory",
                    headers=headers,
                    params={"section": "GENERAL,APPLICATIONS", "page": page, "page-size": page_size},
                )
                response.raise_for_status()
                results = response.json().get("results", [])
                devices.extend(self._normalize_computer(computer) for computer in results)

                if len(results) < page_size:
                    break
                page += 1

        return devices

    def parse_webhook(self, payload: dict) -> NormalizedDevice:
        event = payload.get("event", {})
        computer = event.get("computer", event)
        return self._normalize_computer(computer)

    def _normalize_computer(self, computer: dict) -> NormalizedDevice:
        general = computer.get("general", computer)
        applications = computer.get("applications", [])

        return NormalizedDevice(
            mdm_provider=MdmProvider.jamf,
            external_id=str(general.get("id") or computer.get("id")),
            serial_number=general.get("serialNumber") or computer.get("serialNumber", ""),
            hostname=general.get("name") or computer.get("name", ""),
            apps=[
                NormalizedApp(
                    name=app.get("name", ""),
                    bundle_id=app.get("bundleId") or app.get("name", ""),
                    version=app.get("version", ""),
                )
                for app in applications
            ],
        )
