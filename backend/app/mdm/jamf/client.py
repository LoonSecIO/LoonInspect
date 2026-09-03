from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import AsyncIterator, Coroutine, Iterable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar

import httpx

from app.core.user_agent import build_user_agent
from app.core.wire import instance_label
from app.mdm.jamf.contract import (
    V0_SECTIONS,
    HoistedExtensionAttribute,
    hoist_extension_attributes,
    jamf_section_param,
    parse_jamf_datetime,
)
from app.schemas.payload import (
    MdmProvider,
    NormalizedApp,
    NormalizedDevice,
    NormalizedExtensionAttribute,
)

logger = logging.getLogger(__name__)

_PAGE_SIZE = 100

# Devices per computers-inventory page when the connection doesn't say otherwise.
# Field-tested at full sections; the limiter is sections, not the API — Jamf accepts
# pages up to 2000, but a full-section page that size is an enormous body for no
# latency win. The connection's sweep_page_size overrides this (#71).
DEFAULT_SWEEP_PAGE_SIZE = 400

# Pages (and smart-group detail reads) in flight at once — the ceiling. Internal
# rather than a setting: this is the knob that causes 429s, which makes it the knob
# the dynamic response (AdaptiveConcurrency, #74) owns — the admin's knob is the
# page size.
_CONCURRENCY = 4
# Clean waves in a row before a halved width earns one step back up.
_RECOVERY_WAVES = 3

# The tenant telling us to back off (429) or a hop failing transiently (502/503/504).
# Retried because a sweep is hundreds of idempotent GETs and one transient must not
# abort it; bounded because a tenant that is actually down should fail, loudly.
_TRANSIENT_STATUSES = (429, 502, 503, 504)
_MAX_TRANSIENT_RETRIES = 3
_RETRY_BASE_SECONDS = 1.0
# Retry-After is honored but capped: a sweep stalled minutes per request on a
# hostile or misconfigured header is worse than the failure it avoids.
_RETRY_AFTER_CAP_SECONDS = 30.0

# What of an OAuth token response may be shown to whoever asked for the test. See
# JamfClient.test_connection; `access_token` is absent on purpose and always will be.
_TOKEN_RESPONSE_ECHOED = ("token_type", "expires_in", "scope")

# How far ahead of its stated expiry a token is replaced. The only constant here on
# purpose: the lifetime itself is whatever the token response says, never a number
# this code believes. See _token_lifetime.
_TOKEN_REFRESH_MARGIN_SECONDS = 30.0

_T = TypeVar("_T")


@dataclass(slots=True)
class ThrottleCounters:
    """What the transport did to survive the tenant's rate limits.

    Accumulated on the client instance — one client is one run — and copied onto
    `Run.observations` by the sweep, so throttling is visible on the run an admin
    opens rather than buried in log lines, and a future dynamic tuner (#74) reads
    structured counters instead of parsing text.
    """

    throttled_429: int = 0
    retried_5xx: int = 0
    backoff_ms_total: int = 0

    def observations(self) -> dict[str, int]:
        """The nonzero counters, in Run.observations' flat integer vocabulary."""
        fields = {
            "throttled_429": self.throttled_429,
            "retried_5xx": self.retried_5xx,
            "backoff_ms_total": self.backoff_ms_total,
        }
        return {key: value for key, value in fields.items() if value}


@dataclass(slots=True)
class AdaptiveConcurrency:
    """AIMD over the sweep's in-flight width, scoped to one run (#74).

    Retry (_get) rescues the current request; this shapes the next wave. Any 429
    observed during a wave halves the width (multiplicative decrease, floor 1);
    after _RECOVERY_WAVES clean waves in a row the width steps back up by one
    (additive increase), to the ceiling. The page size is untouched — it is the
    admin's knob (#71), and the machine adjusts only the knob it owns. Nothing
    persists across runs: a fresh client starts at the ceiling.
    """

    width: int = _CONCURRENCY
    clean_waves: int = 0
    reductions: int = 0
    floor_seen: int = _CONCURRENCY
    changes: list[str] = field(default_factory=list)

    def after_wave(self, saw_429: bool) -> None:
        if saw_429:
            reduced = max(1, self.width // 2)
            if reduced < self.width:
                logger.warning(
                    "throttled by jamf; reducing sweep width",
                    extra={"width_before": self.width, "width_after": reduced},
                )
                self.changes.append(f"{self.width} → {reduced}")
                self.width = reduced
                self.reductions += 1
                self.floor_seen = min(self.floor_seen, self.width)
            self.clean_waves = 0
        else:
            self.clean_waves += 1
            if self.clean_waves >= _RECOVERY_WAVES and self.width < _CONCURRENCY:
                self.width += 1
                self.clean_waves = 0

    def observations(self) -> dict[str, int]:
        """Nonzero only, beside ThrottleCounters' keys in Run.observations."""
        if not self.reductions:
            return {}
        return {"concurrency_reductions": self.reductions, "concurrency_floor": self.floor_seen}


def _token_lifetime(body: dict) -> float | None:
    """How long a just-issued token may be used, from the token response's own
    `expires_in`; None when the response doesn't say and only a 401 can find out.

    Measured, not assumed. This module used to state that API client tokens last "30
    minutes by default"; loonsecio.jamfcloud.com on Jamf Pro 11.31.1 answered
    expires_in=179 on three consecutive samples (2026-08-31) — seconds, off by an
    order of magnitude from the comment reviewers were trusting. Whether that 179 is a
    Jamf default, a per-API-client setting, or one tenant's own configuration is not
    something this code can see — so nothing is hardcoded. 179 seconds is what one real
    tenant returned; what gets used is whatever each tenant's response says.

    The margin is subtracted so the token is replaced before it dies in flight rather
    than after a wasted 401. Halving is the floor for a lifetime shorter than the
    margin — subtracting there would put the deadline in the past and re-authenticate
    before every request, which is the amplification this whole path exists to avoid.
    """
    raw = body.get("expires_in")
    try:
        # Tolerant of the string form: it is not what Jamf sends, but a token response
        # that spells the number differently is no reason to fall back to 401s.
        seconds = float(raw)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return max(seconds - _TOKEN_REFRESH_MARGIN_SECONDS, seconds / 2)


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    """Retry-After when Jamf names a number of seconds, exponential backoff with
    jitter when it doesn't (Retry-After may also be an HTTP-date; not worth parsing
    when the fallback is a sane wait)."""
    header = response.headers.get("Retry-After", "").strip()
    if header.isdigit():
        return min(float(header), _RETRY_AFTER_CAP_SECONDS)
    return _RETRY_BASE_SECONDS * (2**attempt) + random.uniform(0, 0.5)


# The computer events that warrant the fetch: a new device, or inventory just
# submitted. Everything else is parsed, named in the log, and dropped before a run
# row or an API call exists — above all ComputerCheckIn, a heartbeat every ~15
# minutes times every active device, whose reaction would be a run and three API
# reads per heartbeat for a record whose reportDate has not moved. That load stays
# outside this container by design (#76). An allowlist rather than a CheckIn
# denylist because the question is which events warrant the reaction, and the
# answer enumerates the warranted ones.
REACTIVE_WEBHOOK_EVENTS = frozenset({"ComputerAdded", "ComputerInventoryCompleted"})


@dataclass(frozen=True, slots=True)
class JamfWebhookEvent:
    """What a Jamf Pro computer webhook actually carries: an identity, not an inventory.

    Computer webhook payloads name the computer (jssID, udid, serial, a few general
    fields) and nothing else — no applications, no groups, no EAs. The ingest path
    therefore fetches the full record by id rather than normalizing the payload;
    treating the payload as inventory would diff an empty app list against the last
    one and report everything removed. Only REACTIVE_WEBHOOK_EVENTS earn that fetch;
    ComputerCheckIn in particular is parsed (its computer nests one level deeper)
    so the drop can name what it dropped, and deliberately nothing more.
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


class JamfClient:
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
        # Monotonic, not wall clock: a sweep must not re-authenticate early (or, worse,
        # late) because NTP stepped the clock under it. None means the token response
        # named no lifetime, and only a 401 will tell us the token is gone.
        self._token_expires_at: float | None = None
        # One expiry, one token request. Without this every coroutine in a wave that
        # meets an expired token POSTs for its own — _CONCURRENCY tokens issued where
        # one was needed, all but one discarded, against a tenant that rate-limits.
        # It was never a correctness bug: _authenticate returns into a local and the
        # retry sends that, so the redundant tokens cost requests, not sweeps.
        self._auth_lock = asyncio.Lock()
        self.throttle = ThrottleCounters()
        self.adaptive = AdaptiveConcurrency()

    # Seam for tests: retry waits go through this so a scripted 429 doesn't cost the
    # suite real seconds. An attribute, not a wrapper method, so monkeypatching the
    # class reaches every instance.
    _sleep = staticmethod(asyncio.sleep)

    @property
    def host(self) -> str:
        """The collector's identity for the aperture: the Jamf Pro instance, exactly as
        Splunk's `source` names it (#226).

        Reconciled to `app.core.wire.instance_label` rather than reimplemented — the
        aperture and the HEC envelope must agree on one instance's identity, or two Jamf
        Pro instances behind one hostname on different ports (`jamf.corp.local:8443` and
        `:8444`) are two distinct `source` values in Splunk but one collector identity to
        the read aperture, silently merging their fleets there.
        """
        return instance_label(self._base_url)

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

    def _live_token(self) -> str | None:
        """The cached token, if it is still worth sending."""
        if self._token is None:
            return None
        if self._token_expires_at is not None and time.monotonic() >= self._token_expires_at:
            return None
        return self._token

    def _forget(self, token: str) -> None:
        """Drop the cached token, but only if it is still the one that just failed.

        `self._token = None` was the old line, and with a wave in flight it could wipe
        a peer's freshly issued token: one coroutine refreshes, another's 401 — carrying
        the token that already expired — lands a moment later and clears the new one.
        Comparing first makes a late 401 harmless.
        """
        if self._token == token:
            self._token = None
            self._token_expires_at = None

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        token = self._live_token()
        if token:
            return token

        async with self._auth_lock:
            # Re-checking here is the point of the lock, not belt and braces: whoever
            # waited almost always waited for a peer's refresh, and POSTing anyway
            # after acquiring it would issue exactly the tokens the lock exists to
            # stop being issued.
            token = self._live_token()
            if token:
                return token

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
            token = body["access_token"]
            lifetime = _token_lifetime(body)
            self._token_expires_at = None if lifetime is None else time.monotonic() + lifetime
            self._token = token
            return token

    async def _get(
        self, client: httpx.AsyncClient, path: str, *, comment: str, params: dict | None = None
    ) -> httpx.Response:
        """Authenticated GET with one retry on 401 and a bounded retry on transients.

        Two failure modes, two answers. An API client token is short-lived — see
        _token_lifetime for what one real tenant actually returns — and a sweep of a
        large tenant outlives several: _authenticate replaces one before it expires,
        and the 401 retry stays as the backstop for the token that dies early anyway,
        revoked or its API client disabled mid-sweep. The first 401 drops that token,
        re-authenticates, and retries once — a second 401 is a real failure and
        propagates. 429/502/503/504 are transient by definition:
        before this, one 502 anywhere in a 400-request sweep aborted the whole run,
        and with pages in flight the exposure only grows. Those are retried up to
        _MAX_TRANSIENT_RETRIES times with Retry-After honored, every wait counted on
        `self.throttle` for the run row.
        """
        reauthenticated = False
        transient_retries = 0
        while True:
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
            if response.status_code == 401 and not reauthenticated:
                self._forget(token)
                reauthenticated = True
                continue
            if response.status_code in _TRANSIENT_STATUSES and transient_retries < _MAX_TRANSIENT_RETRIES:
                delay = _retry_delay(response, transient_retries)
                if response.status_code == 429:
                    self.throttle.throttled_429 += 1
                else:
                    self.throttle.retried_5xx += 1
                self.throttle.backoff_ms_total += int(delay * 1000)
                logger.info(
                    "transient response from jamf; backing off and retrying",
                    extra={"status": response.status_code, "path": path, "delay_seconds": round(delay, 2)},
                )
                await self._sleep(delay)
                transient_retries += 1
                continue
            return response

    async def test_connection(self) -> dict:
        """Attempt the OAuth client-credentials exchange. Raises on failure (the caller
        inspects the response body/status for diagnostics). Returns only the known,
        non-secret fields of the token response — never the token itself, and never a
        key this client did not expect.

        An allowlist rather than `access_token` alone (#131): base_url is caller-chosen,
        so a 200 from anything that speaks JSON used to have its whole body handed back
        as the success detail. `expires_in` and `token_type` are what a human reads to
        confirm the exchange worked; `scope` is the one Jamf sometimes adds. A body that
        is not a JSON object is not a token response at all, and saying so is the
        caller's cue that the URL is wrong."""
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
            if not isinstance(body, dict):
                raise ValueError("the token endpoint did not return a JSON object")
            return {key: body[key] for key in _TOKEN_RESPONSE_ECHOED if key in body}

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
        the switch reads as one honest aperture transition per tenant. Needs "Read
        Computer Inventory Collection Settings" (app.mdm.jamf.privileges); without it
        this is None and the aperture records that absence."""
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

    # --- concurrency -----------------------------------------------------------------

    async def _wave(self, coroutines: Sequence[Coroutine[Any, Any, _T]]) -> list[_T]:
        """One wave of requests in flight together, results in argument order.

        Waves rather than a semaphore over everything: the consumer processes each
        device against the database, and a semaphore only bounds fetches in flight —
        completed pages would pile up behind a slow consumer without limit. A wave is
        fetched, drained, and only then is the next begun, so memory is bounded at one
        wave of pages. A failure cancels the wave's siblings and propagates — _get has
        already retried transients by the time it raises, so a wave failure is real.
        """
        try:
            async with asyncio.TaskGroup() as group:
                tasks = [group.create_task(coroutine) for coroutine in coroutines]
        except BaseExceptionGroup as eg:
            # The single real cause reads better on the run row than the group wrapper.
            if len(eg.exceptions) == 1 and isinstance(eg.exceptions[0], Exception):
                raise eg.exceptions[0] from eg
            raise
        return [task.result() for task in tasks]

    # --- computers -------------------------------------------------------------------

    async def iter_computers(
        self,
        client: httpx.AsyncClient,
        sections: Sequence[str] = V0_SECTIONS,
        *,
        rsql_filter: str | None = None,
        page_size: int = DEFAULT_SWEEP_PAGE_SIZE,
    ) -> AsyncIterator[dict]:
        """Page through computers-inventory with pages in flight, yielding raw records
        one at a time so a 40,000-device tenant is never held in memory at once.

        Page 0 is fetched alone: its totalCount sizes the fan-out. The known pages are
        then fetched _CONCURRENCY at a time in waves, and totalCount is treated as a
        floor, not gospel — after the fanned-out pages land, fetching continues
        serially until a short page, so a device enrolling mid-sweep is still picked
        up (`sort=id:asc` pins new enrollments to the tail). Records within a run are
        order-independent (the ledger keys by device), so yielding wave by wave is
        sound.

        `sections` are contract names (app.mdm.jamf.contract.SECTIONS); they are
        translated to Jamf's section parameter here. `rsql_filter` is Jamf's own RSQL
        (`general.remoteManagement.managed==true`), the hook #27's ingest profiles push
        their selector through. `page_size` is the connection's sweep_page_size — or a
        collection's override — resolved by the caller.
        """
        params: dict[str, Any] = {
            "section": jamf_section_param(sections),
            "page-size": page_size,
            "sort": "id:asc",
        }
        if rsql_filter:
            params["filter"] = rsql_filter

        async def fetch_page(page: int) -> dict:
            response = await self._get(
                client, "/api/v4/computers-inventory", comment="inventory", params={**params, "page": page}
            )
            response.raise_for_status()
            body = response.json()
            return body if isinstance(body, dict) else {}

        def page_results(body: dict) -> list[dict]:
            results = body.get("results", [])
            return results if isinstance(results, list) else []

        body = await fetch_page(0)
        first = page_results(body)
        for computer in first:
            yield computer
        if len(first) < page_size:
            return

        total = body.get("totalCount")
        known_pages = -(-total // page_size) if isinstance(total, int) and total > 0 else 1

        page = 1
        short_page_seen = False
        while page < known_pages:
            wave = range(page, min(page + self.adaptive.width, known_pages))
            throttled_before = self.throttle.throttled_429
            for wave_body in await self._wave([fetch_page(number) for number in wave]):
                results = page_results(wave_body)
                for computer in results:
                    yield computer
                if len(results) < page_size:
                    # The fleet shrank between page 0 and this wave; the serial tail
                    # below would only re-find the shrink.
                    short_page_seen = True
            self.adaptive.after_wave(self.throttle.throttled_429 > throttled_before)
            page = wave.stop

        if short_page_seen:
            return
        while True:
            results = page_results(await fetch_page(page))
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

    # --- smart groups ----------------------------------------------------------------

    async def fetch_smart_groups(self, client: httpx.AsyncClient, *, page_size: int = _PAGE_SIZE) -> list[dict]:
        """Every smart computer group with its criteria.

        The v3 list endpoint returns ids and names; criteria come from the per-group
        detail, so this is one request per group — tens to hundreds per tenant, a
        catalog read rather than a sweep, fetched _CONCURRENCY at a time because
        hundreds of serial round-trips was the slowest part of a group-heavy tenant's
        refresh. Needs "Read Smart Computer Groups"; a tenant without the privilege
        (or an older Jamf Pro without the v3 endpoint) yields an empty list and a log
        line rather than failing the device sweep it rides along with.
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

        async def fetch_detail(group: dict) -> dict | None:
            group_id = group["id"]
            response = await self._get(client, f"/api/v3/computer-groups/smart-groups/{group_id}", comment="groups")
            if response.status_code == 404:
                return None  # deleted between the list and the read
            response.raise_for_status()
            detail = response.json()
            if not isinstance(detail, dict):
                return None
            return {"id": str(group_id), **group, **detail}

        with_ids = [group for group in groups if group.get("id") is not None]
        detailed: list[dict] = []
        start = 0
        while start < len(with_ids):
            wave = with_ids[start : start + self.adaptive.width]
            throttled_before = self.throttle.throttled_429
            details = await self._wave([fetch_detail(group) for group in wave])
            detailed.extend(detail for detail in details if detail is not None)
            self.adaptive.after_wave(self.throttle.throttled_429 > throttled_before)
            start += len(wave)
        return detailed

    # --- departments and buildings ----------------------------------------------------

    async def fetch_departments(self, client: httpx.AsyncClient, *, page_size: int = _PAGE_SIZE) -> list[dict]:
        """Every department, as `{"id", "name"}`. Needs "Read Departments"."""
        return await self._fetch_named_objects(client, "/api/v1/departments", "departments", page_size)

    async def fetch_buildings(self, client: httpx.AsyncClient, *, page_size: int = _PAGE_SIZE) -> list[dict]:
        """Every building, as `{"id", "name"}`. Needs "Read Buildings"."""
        return await self._fetch_named_objects(client, "/api/v1/buildings", "buildings", page_size)

    async def _fetch_named_objects(
        self, client: httpx.AsyncClient, path: str, kind: str, page_size: int
    ) -> list[dict]:
        """One of Jamf's small id-and-name catalogs, paged.

        Departments and buildings are the two objects a computer record names by id and
        never by name, so without these reads a device's `departmentId` is an integer
        nobody can act on. Tens of rows per tenant, two requests per sweep — a catalog
        read, not a sweep, which is why it is fetched whole rather than per device.

        A tenant whose API client lacks the privilege yields an empty list and a log
        line — and so does a catalog that errors outright, which is the stronger of the
        two promises: names are display, and no missing label may cost a sweep the
        inventory it came for. An empty answer never blanks what is already cached
        (app.mdm.org_units.record_org_units upserts).
        """
        objects: list[dict] = []
        page = 0
        try:
            while True:
                response = await self._get(
                    client, path, comment="catalog", params={"page": page, "page-size": page_size, "sort": "id:asc"}
                )
                if response.status_code in (401, 403, 404):
                    logger.info(
                        "jamf catalog not readable; ids will not resolve to names",
                        extra={"status": response.status_code, "catalog": kind},
                    )
                    return []
                response.raise_for_status()
                results = response.json().get("results", [])
                if not isinstance(results, list):
                    return objects
                objects.extend(
                    {"id": str(item["id"]), "name": item.get("name") or ""}
                    for item in results
                    if isinstance(item, dict) and item.get("id") is not None
                )
                if len(results) < page_size:
                    return objects
                page += 1
        except (httpx.HTTPError, ValueError):
            # ValueError covers a 200 carrying something that is not JSON (#82).
            logger.warning(
                "jamf catalog read failed; ids will not resolve to names",
                extra={"catalog": kind},
                exc_info=True,
            )
            return []


def normalize_computer(
    computer: dict,
    sections: Sequence[str] = V0_SECTIONS,
    *,
    quarantined_extension_attributes: Iterable[str] = (),
) -> NormalizedDevice:
    """The `devices` / `installed_apps` shape the UI reads, from a raw inventory object.

    This is the *current-state* view and is deliberately looser than the observation
    contract: it keeps telemetry the UI shows (last contact, last inventory) that the
    contract excludes from hashing.

    `sections` are what the run asked Jamf for — the same read aperture the ledger
    records. Applications outside that aperture come back as None, never [], so a
    scoped read can't be mistaken for a device with no apps (#93); extension
    attributes get the same sentinel, and a section outside the aperture is not
    consumed at all, so its scalars normalize to their defaults and the returned
    `sections` tells process_sync not to write them (#98). Keyed off the request, not
    the response: Jamf omitting a key we asked for *is* an empty read, and a detail
    fetch carrying sections we did not ask for is still not an observation of them.

    Extension attributes come through `hoist_extension_attributes`, the one merge the
    observation contract also uses (#197). Jamf spreads them over six arrays — the
    top-level one and one inside each display section — and this view used to read only
    the first, so every EA an admin displayed on a section tab was invisible to the
    product and the wire while the ledger recorded it changing. Each item keeps the
    section it was found under as `source`; the quarantine is applied in the same place,
    so a quarantined definition is absent from every path rather than only the ledger.
    """
    requested = set(sections)
    hoist = hoist_extension_attributes(computer, sections=requested, quarantined=quarantined_extension_attributes)
    _report_unadmitted(hoist.unadmitted, computer_id=computer.get("id"))
    # Every section read below comes from the copy the hoist stripped, so no section
    # object still carries an `extensionAttributes` array beside the real list.
    computer = hoist.computer
    general = computer.get("general", computer) if "general" in requested else {}
    hardware = computer.get("hardware", {}) if "hardware" in requested else {}
    operating_system = computer.get("operatingSystem", {}) if "operating_system" in requested else {}
    user_and_location = computer.get("userAndLocation", {}) if "user_and_location" in requested else {}
    applications = computer.get("applications", []) if "applications" in requested else None
    extension_attributes = (
        [_extension_attribute(hoisted) for hoisted in hoist.items if _definition_id(hoisted.item) is not None]
        if "extension_attributes" in requested
        else None
    )

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
        # Ids, not names. Jamf's inventory API carries `departmentId` and `buildingId`
        # and nothing else — verified against the 11.31 record in
        # tests/fixtures/jamf/computer_inventory_detail_real.json, whose userAndLocation
        # has no `department` or `building` key at all. Those are the classic API's
        # names, which this endpoint has never returned, so unlike lastContactTime
        # below there is no older spelling to fall back to: reading them was simply
        # wrong, and both columns held NULL on every device until it was fixed.
        # app.mdm.org_units resolves the ids to names for display and filtering.
        building_id=_org_unit_id(user_and_location.get("buildingId")),
        department_id=_org_unit_id(user_and_location.get("departmentId")),
        # Jamf Pro 11.31 renamed the field: `lastContact` (MDM) and `lastCheckIn`
        # (binary) replace the documented `lastContactTime`. All three are read so an
        # older server and a current one both populate the column.
        last_check_in=_parse_datetime(
            general.get("lastContactTime") or general.get("lastContact") or general.get("lastCheckIn")
        ),
        last_inventory_at=_parse_datetime(general.get("reportDate")),
        apps=None
        if applications is None
        else [
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
        extension_attributes=extension_attributes,
        sections=frozenset(requested),
    )


def _org_unit_id(value: object) -> str | None:
    """A department or building id as a string, and absence as None.

    Jamf sends these as quoted strings, but the column is a string either way, and
    absence is absence (docs/jamf-observations.md §2.2 rule 3): "" is not a department.
    """
    if value is None or value == "":
        return None
    return str(value)


def _extension_attribute(hoisted: HoistedExtensionAttribute) -> NormalizedExtensionAttribute:
    """Jamf's EA object, typed, plus where it was found. Verbatim in spirit: nothing is
    renamed or dropped, values and options are the whole lists, and absence stays
    absence — a `description` Jamf sent as null is null, one it sent as "" is ""."""
    item = hoisted.item
    return NormalizedExtensionAttribute(
        definition_id=str(item["definitionId"]),
        name=_text(item.get("name")),
        description=_text(item.get("description")),
        enabled=_flag(item.get("enabled")),
        multi_value=_flag(item.get("multiValue")),
        values=_strings(item.get("values")),
        data_type=_text(item.get("dataType")),
        options=_strings(item.get("options")),
        input_type=_text(item.get("inputType")),
        source=hoisted.source,
    )


def _definition_id(item: Mapping[str, object]) -> str | None:
    """The EA's identity, or None for an item that has none — which is not an EA."""
    value = item.get("definitionId")
    if value is None or str(value) == "":
        return None
    return str(value)


def _text(value: object) -> str | None:
    return None if value is None else str(value)


def _flag(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]


# Sources of extension attributes the aperture did not admit, already reported. Once per
# process per source: the case this catches — a display section the contract has no
# name for — repeats on every device of every sweep, and forty thousand copies of one
# warning say less than one.
_UNADMITTED_EA_SOURCES_REPORTED: set[str] = set()


def _report_unadmitted(sources: Sequence[str], *, computer_id: object) -> None:
    new = [source for source in sources if source not in _UNADMITTED_EA_SOURCES_REPORTED]
    if not new:
        return
    _UNADMITTED_EA_SOURCES_REPORTED.update(new)
    logger.warning(
        "extension attributes found under keys outside the read aperture were not merged; a "
        "section the contract knows is admitted by requesting it (a collection that asks for "
        "extension attributes reads its five carriers automatically), one it does not know needs "
        "adding to app.mdm.jamf.contract.SECTIONS and EXTENSION_ATTRIBUTE_CARRIERS",
        extra={"sources": new, "computer_id": computer_id},
    )


def _parse_datetime(value: str | None) -> datetime | None:
    return parse_jamf_datetime(value)
