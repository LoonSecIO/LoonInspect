from __future__ import annotations

from datetime import datetime

import httpx

from app.mdm.base import MdmClient
from app.schemas.payload import (
    MdmProvider,
    NormalizedApp,
    NormalizedDevice,
    NormalizedExtensionAttribute,
)

INVENTORY_SECTIONS = "GENERAL,HARDWARE,USER_AND_LOCATION,APPLICATIONS,EXTENSION_ATTRIBUTES"


class JamfClient(MdmClient):
    provider = MdmProvider.jamf.value

    def __init__(self, base_url: str, client_id: str, client_secret: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
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
                    params={"section": INVENTORY_SECTIONS, "page": page, "page-size": page_size},
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
        # Field paths follow Jamf Pro API v1 computers-inventory; adjust against a real
        # tenant once live credentials are available (built to spec, not yet tested live).
        general = computer.get("general", computer)
        hardware = computer.get("hardware", {})
        user_and_location = computer.get("userAndLocation", {})
        applications = computer.get("applications", [])
        extension_attributes = computer.get("extensionAttributes", [])

        remote_management = general.get("remoteManagement", {})
        site = general.get("site", {})

        return NormalizedDevice(
            mdm_provider=MdmProvider.jamf,
            external_id=str(general.get("id") or computer.get("id")),
            serial_number=general.get("serialNumber") or computer.get("serialNumber", ""),
            hostname=general.get("name") or computer.get("name", ""),
            managed=remote_management.get("managed"),
            supervised=general.get("supervised"),
            os_version=hardware.get("osVersion"),
            site=site.get("name"),
            building=user_and_location.get("building"),
            department=user_and_location.get("department"),
            last_check_in=_parse_datetime(general.get("lastContactTime")),
            last_inventory_at=_parse_datetime(general.get("reportDate")),
            apps=[
                NormalizedApp(
                    name=app.get("name", ""),
                    bundle_id=app.get("bundleId") or app.get("name", ""),
                    version=app.get("version", ""),
                )
                for app in applications
            ],
            extension_attributes=[
                NormalizedExtensionAttribute(
                    key=ea.get("name", ""),
                    value=(ea.get("values") or [None])[0],
                )
                for ea in extension_attributes
                if ea.get("name")
            ],
        )


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
