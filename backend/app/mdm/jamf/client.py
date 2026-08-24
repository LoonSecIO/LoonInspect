from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.user_agent import build_user_agent
from app.mdm.base import MdmClient
from app.mdm.jamf.contract import V0_SECTIONS, jamf_section_param, parse_jamf_datetime
from app.schemas.payload import (
    MdmProvider,
    NormalizedApp,
    NormalizedDevice,
    NormalizedExtensionAttribute,
)

logger = logging.getLogger(__name__)

_PAGE_SIZE = 100


@dataclass(frozen=True, slots=True)
class JamfWebhookEvent:
    """What a Jamf Pro computer webhook actually carries: an identity, not an inventory.

    ComputerAdded / ComputerCheckIn / ComputerInventoryCompleted payloads name the
    computer (jssID, udid, serial, a few general fields) and nothing else — no
    applications, no groups, no EAs. The ingest path therefore fetches the full record
    by id rather than normalizing the payload; treating the payload as inventory would
    diff an empty app list against the last one and report everything removed.
    """

    event_name: str | None
    jamf_id: str | None
    udid: str | None
    serial_number: str | None


def parse_webhook_event(payload: dict) -> JamfWebhookEvent:
    event = payload.get("event") if isinstance(payload.get("event"), dict) else {}
    # ComputerCheckIn nests the computer one level deeper than the others.
    computer = event.get("computer") if isinstance(event.get("computer"), dict) else event
    webhook = payload.get("webhook") if isinstance(payload.get("webhook"), dict) else {}
    jamf_id = computer.get("jssID")
    if jamf_id is None:
        jamf_id = computer.get("id")
    return JamfWebhookEvent(
        event_name=webhook.get("webhookEvent"),
        jamf_id=str(jamf_id) if jamf_id is not None else None,
        udid=computer.get("udid"),
        serial_number=computer.get("serialNumber"),
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

    @property
    def host(self) -> str:
        """The collector's identity for the aperture: the Jamf Pro hostname."""
        return urlparse(self._base_url).hostname or self._base_url

    def _user_agent(self, comment: str) -> str:
        return build_user_agent(comment, self._user_agent_override)

    # --- transport -------------------------------------------------------------------

    @asynccontextmanager
    async def http(self) -> AsyncIterator[httpx.AsyncClient]:
        """One HTTP client for one run. Every fetch below takes it as an argument so a
        sweep reuses connections and a token across thousands of requests instead of
        opening a client per call."""
        async with httpx.AsyncClient(timeout=30) as client:
            yield client

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

    async def _get(
        self, client: httpx.AsyncClient, path: str, *, comment: str, params: dict | None = None
    ) -> httpx.Response:
        """Authenticated GET with one retry on 401.

        API client tokens expire (30 minutes by default); a full sweep of a large
        tenant can outlive one. The first 401 drops the cached token, re-authenticates,
        and retries once — a second 401 is a real failure and propagates.
        """
        for attempt in (1, 2):
            token = await self._authenticate(client)
            response = await client.get(
                f"{self._base_url}{path}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "User-Agent": self._user_agent(comment),
                },
                params=params,
            )
            if response.status_code == 401 and attempt == 1:
                self._token = None
                continue
            return response
        raise AssertionError("unreachable")

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

    # --- the aperture ----------------------------------------------------------------

    async def fetch_version(self, client: httpx.AsyncClient) -> str | None:
        """Jamf Pro's own version. Part of the aperture because an upgrade can change
        what inventory contains without any device changing. Unavailable is None, not
        an error — the sweep must not depend on a read privilege the client may lack."""
        try:
            response = await self._get(client, "/api/v1/jamf-pro-version", comment="aperture")
            response.raise_for_status()
            version = response.json().get("version")
            return str(version) if version else None
        except httpx.HTTPError:
            logger.warning("jamf version unavailable for aperture", exc_info=True)
            return None

    async def fetch_inventory_collection_settings(self, client: httpx.AsyncClient) -> dict | None:
        """Jamf's inventory-collection preferences: which paths it scans for
        applications, whether it reads accounts, printers… The part of the aperture
        that decides what an app list even means. v2 of the endpoint no longer reports
        font/plugin paths (v1 did); the aperture records their absence as absence, so
        the switch reads as one honest aperture transition per tenant. Needs the "Read
        Computer Inventory Collection" privilege; without it this is None and the
        aperture records that absence."""
        try:
            response = await self._get(client, "/api/v2/computer-inventory-collection-settings", comment="aperture")
            if response.status_code in (401, 403, 404):
                logger.info(
                    "inventory collection settings not readable; aperture records absence",
                    extra={"status": response.status_code},
                )
                return None
            response.raise_for_status()
            body = response.json()
            return body if isinstance(body, dict) else None
        except httpx.HTTPError:
            logger.warning("inventory collection settings unavailable for aperture", exc_info=True)
            return None

    # --- computers -------------------------------------------------------------------

    async def iter_computers(
        self,
        client: httpx.AsyncClient,
        sections: Sequence[str] = V0_SECTIONS,
        *,
        rsql_filter: str | None = None,
        page_size: int = _PAGE_SIZE,
    ) -> AsyncIterator[dict]:
        """Page through computers-inventory, yielding raw records one at a time so a
        40,000-device tenant is never held in memory at once.

        `sections` are contract names (app.mdm.jamf.contract.SECTIONS); they are
        translated to Jamf's section parameter here. `rsql_filter` is Jamf's own RSQL
        (`general.remoteManagement.managed==true`), the hook #27's ingest profiles push
        their selector through. Sorted by id so pages stay stable while devices check in
        mid-sweep.
        """
        params: dict[str, Any] = {
            "section": jamf_section_param(sections),
            "page-size": page_size,
            "sort": "id:asc",
        }
        if rsql_filter:
            params["filter"] = rsql_filter

        page = 0
        while True:
            response = await self._get(
                client, "/api/v4/computers-inventory", comment="inventory", params={**params, "page": page}
            )
            response.raise_for_status()
            results = response.json().get("results", [])
            for computer in results:
                yield computer
            if len(results) < page_size:
                return
            page += 1

    async def fetch_computer_detail(self, client: httpx.AsyncClient, jamf_id: str) -> dict:
        """Every section of one computer. The webhook path's fetch: one device already
        known to have changed, so the full record is cheap and maximally useful."""
        response = await self._get(client, f"/api/v4/computers-inventory-detail/{jamf_id}", comment="detail")
        response.raise_for_status()
        return response.json()

    async def fetch_devices(self) -> list[NormalizedDevice]:
        """The MdmClient contract: the whole normalized inventory in one list. The Jamf
        sync path streams through iter_computers instead; this remains for callers that
        want the generic shape."""
        devices: list[NormalizedDevice] = []
        async with self.http() as client:
            async for computer in self.iter_computers(client):
                devices.append(normalize_computer(computer))
        return devices

    # --- smart groups ----------------------------------------------------------------

    async def fetch_smart_groups(self, client: httpx.AsyncClient, *, page_size: int = _PAGE_SIZE) -> list[dict]:
        """Every smart computer group with its criteria.

        The v2 list endpoint returns ids and names; criteria come from the per-group
        detail, so this is one request per group — tens to hundreds per tenant, a
        catalog read rather than a sweep. Needs "Read Smart Computer Groups"; a tenant
        without the privilege (or an older Jamf Pro without the v2 endpoint) yields an
        empty list and a log line rather than failing the device sweep it rides along
        with.
        """
        groups: list[dict] = []
        page = 0
        while True:
            response = await self._get(
                client,
                "/api/v3/computer-groups/smart-groups",
                comment="groups",
                params={"page": page, "page-size": page_size, "sort": "id:asc"},
            )
            if response.status_code in (401, 403, 404):
                logger.info(
                    "smart groups not readable; group definitions not observed",
                    extra={"status": response.status_code},
                )
                return []
            response.raise_for_status()
            results = response.json().get("results", [])
            groups.extend(item for item in results if isinstance(item, dict))
            if len(results) < page_size:
                break
            page += 1

        detailed: list[dict] = []
        for group in groups:
            group_id = group.get("id")
            if group_id is None:
                continue
            response = await self._get(client, f"/api/v3/computer-groups/smart-groups/{group_id}", comment="groups")
            if response.status_code == 404:
                continue  # deleted between the list and the read
            response.raise_for_status()
            detail = response.json()
            if isinstance(detail, dict):
                detailed.append({"id": str(group_id), **group, **detail})
        return detailed

    # --- webhooks --------------------------------------------------------------------

    def parse_webhook(self, payload: dict) -> NormalizedDevice:
        """The MdmClient contract, kept for shape only. The Jamf ingest path does not
        use it: a webhook payload identifies a computer and carries no inventory (see
        JamfWebhookEvent), so app.mdm.service.ingest_webhook fetches the record by id
        instead of normalizing the payload."""
        event = payload.get("event", {})
        computer = event.get("computer", event)
        return normalize_computer(computer)


def normalize_computer(computer: dict) -> NormalizedDevice:
    """The `devices` / `installed_apps` shape the UI reads, from a raw inventory object.

    This is the *current-state* view and is deliberately looser than the observation
    contract: it keeps telemetry the UI shows (last contact, last inventory) that the
    contract excludes from hashing.
    """
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
        external_id=str(computer.get("id") or general.get("id")),
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
        # Jamf Pro 11.31 renamed the field: `lastContact` (MDM) and `lastCheckIn`
        # (binary) replace the documented `lastContactTime`. All three are read so an
        # older server and a current one both populate the column.
        last_check_in=_parse_datetime(
            general.get("lastContactTime") or general.get("lastContact") or general.get("lastCheckIn")
        ),
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
    return parse_jamf_datetime(value)
