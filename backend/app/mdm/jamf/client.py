from __future__ import annotations

from datetime import datetime

import httpx

from app.core.user_agent import build_user_agent
from app.mdm.base import MdmClient
from app.schemas.payload import (
    MdmProvider,
    NormalizedApp,
    NormalizedDevice,
    NormalizedExtensionAttribute,
)

# OPERATING_SYSTEM is required for os_version — it lives in its own section, not under
# HARDWARE. Omitting it meant the field could never populate regardless of the mapping.
INVENTORY_SECTIONS = (
    "GENERAL,HARDWARE,OPERATING_SYSTEM,USER_AND_LOCATION,APPLICATIONS,EXTENSION_ATTRIBUTES"
)


class JamfClient(MdmClient):
    provider = MdmProvider.jamf.value

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        user_agent_override: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._user_agent_override = user_agent_override
        self._token: str | None = None

    def _user_agent(self, comment: str) -> str:
        return build_user_agent(comment, self._user_agent_override)

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
            headers={"User-Agent": self._user_agent("auth")},
        )
        response.raise_for_status()
        self._token = response.json()["access_token"]
        return self._token

    async def test_connection(self) -> dict:
        """Attempt the OAuth client-credentials exchange. Raises on failure (the caller
        inspects the response body/status for diagnostics). Returns the token response
        with `access_token` stripped out — never surface the token itself to the UI."""
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                f"{self._base_url}/api/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                headers={"User-Agent": self._user_agent("auth")},
            )
            response.raise_for_status()
            body = response.json()
            return {key: value for key, value in body.items() if key != "access_token"}

    async def fetch_devices(self) -> list[NormalizedDevice]:
        devices: list[NormalizedDevice] = []
        page_size = 100

        async with httpx.AsyncClient(timeout=30) as client:
            token = await self._authenticate(client)
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": self._user_agent("inventory"),
            }

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
        operating_system = computer.get("operatingSystem", {})
        user_and_location = computer.get("userAndLocation", {})
        applications = computer.get("applications", [])
        extension_attributes = computer.get("extensionAttributes", [])

        remote_management = general.get("remoteManagement", {})
        site = general.get("site", {})

        return NormalizedDevice(
            mdm_provider=MdmProvider.jamf,
            external_id=str(general.get("id") or computer.get("id")),
            # Verified against a live tenant: the serial is under HARDWARE, not GENERAL,
            # and the OS version is under OPERATING_SYSTEM, not HARDWARE. The webhook
            # fallbacks stay because a HEC payload is shaped differently from an
            # inventory record.
            serial_number=(
                hardware.get("serialNumber")
                or general.get("serialNumber")
                or computer.get("serialNumber", "")
            ),
            hostname=general.get("name") or computer.get("name", ""),
            managed=remote_management.get("managed"),
            supervised=general.get("supervised"),
            os_version=operating_system.get("version") or hardware.get("osVersion"),
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
                    # Jamf's inventory APPLICATIONS section exposes a single `version`
                    # field, with no separate CFBundleVersion. Left null rather than
                    # duplicated, so the version hash isn't given false precision —
                    # a source that carries both will produce a distinct hash.
                    short_version=None,
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
