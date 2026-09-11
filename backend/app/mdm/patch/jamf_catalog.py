"""The Jamf patch catalog, and the one seam it arrives through.

`sync_catalog` reads exactly two things — the title summaries, and one changed title's
full definition — and it reads them through `CatalogSource` rather than from `httpx`
directly (#382). `JamfApiCatalogSource` is the only implementation, and every deployment
uses it; the seam exists because the vulnerability epoch format reserves a `catalog`
section (LoonVD-Internal's `sharedAssets/contract/epoch.md`, the published format
`docs/vulnerabilities.md` points at rather than defines), so a container may one day read
the catalog out of an artifact it already downloaded instead of pulling 1,554 titles from
a public server.
That is a second implementation of two methods when it comes, not a rewrite of the sync.

Nothing downstream knows about any of this: `rebuild_index`, the matcher and the Jamf
Patch page read `jamf_patch_titles`, which is written here and looks the same whatever
filled it.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import UTC, datetime
from typing import Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.user_agent import build_user_agent
from app.mdm.patch.matching import reset_catalog_cache
from app.models.schema import JamfPatchTitle

_STRIP_PATCH_KEYS = ("standalone", "minimumOperatingSystem", "reboot", "killApps", "components", "capabilities")

# How many title definitions may be in flight at once. A fresh container has no rows, so
# every title in the catalog is "changed" — 1,554 of them on 2026-09-10 — and the bare
# `asyncio.gather` this replaced handed all 1,554 to the client in one breath. It never
# opened 1,554 sockets: `jamf_api_source` builds its client with no `limits=`, so httpx's
# default pool admitted 100 connections and queued the other ~1,454 behind them — against
# `Timeout(30)`, whose *pool* component is 30 s as well. A cold start slow enough to hold
# a request in that queue past 30 s aged it out as `PoolTimeout`, and
# `return_exceptions=True` below turns that into a title silently skipped until some later
# hourly tick notices it is missing. So the old hazard was a queue we did not write and
# could not see, not a file-descriptor bill. Eight is a bound we state instead: ~195 waves
# on a job that runs hourly and has no deadline, and after the first sync a day's changes
# are a handful of titles, where the bound never binds. Not a setting: nothing an operator
# knows would tell them what to set it to. `tests/test_jamf_catalog.py` pins the 100 and
# the 30 s against the client this module actually builds, so the paragraph cannot drift
# away from the code the way its first draft did.
DETAIL_CONCURRENCY = 8


# What an operator reads when `JAMF_PATCH_BASE_URL` names something that is not an
# address. What failed, why, and what to check, in the words they typed
# (`docs/diagnosability.md` rule 3): the variable's name, the value it holds, the shape it
# must have, and the fact that removing it is a fix. Without it the value reaches httpx as
# `UnsupportedProtocol` from inside a scheduled job — a traceback that never names the
# setting that caused it.
JAMF_PATCH_BASE_URL_UNUSABLE = (
    "The Jamf patch catalog cannot be refreshed: JAMF_PATCH_BASE_URL is set to {value!r}, "
    "which is not an address this container can dial — it must begin with https:// (or http://). "
    "Correct it, or remove it from the environment to use the default "
    "https://jamf-patch.jamfcloud.com/v1, and restart the app "
    "(docs/troubleshooting.md section 6)."
)


class JamfPatchCatalogUnconfigured(RuntimeError):
    """`JAMF_PATCH_BASE_URL` holds something that is not an address.

    A type of its own so the hourly job can answer it with one sentence instead of a
    traceback; still a `RuntimeError`, so anything that caught the bare one is unbroken.
    """


class CatalogSource(Protocol):
    """Where the patch catalog comes from. Two methods, because two reads is all the sync
    does — and all a feed-shaped source would have to answer."""

    async def summaries(self) -> list[dict]:
        """Every title the source knows, each with at least `id`, `lastModified` and
        `currentVersion` — what `_needs_refresh` decides on, and nothing heavier."""
        ...

    async def detail(self, title_id: str) -> dict:
        """One title's full definition: patches, requirements, extension attributes."""
        ...


class JamfApiCatalogSource:
    """`CatalogSource` over Jamf's public patch server — the only implementation today.

    Takes an open client rather than making one, so the whole sync shares a connection
    pool: the definitions are fetched `DETAIL_CONCURRENCY` at a time against one host,
    and a client per request would pay a TLS handshake per title. `jamf_api_source()` is
    the ordinary way to get one.
    """

    def __init__(self, client: httpx.AsyncClient, base_url: str | None = None) -> None:
        self._client = client
        # Read at construction, not at import, so a test and an operator's environment can
        # both move it — and checked here for the same reason: an address an environment
        # can move is an address an environment can break, and that is a failure path this
        # module owns (`docs/troubleshooting.md` section 6). The trailing slash is trimmed
        # because a URL that ends in one is the same address and would otherwise build
        # `…/v1//software`.
        configured = base_url or settings.jamf_patch_base_url
        address = configured.rstrip("/")
        if not address.startswith(("https://", "http://")):
            raise JamfPatchCatalogUnconfigured(JAMF_PATCH_BASE_URL_UNUSABLE.format(value=configured))
        self._base_url = address

    async def summaries(self) -> list[dict]:
        response = await self._client.get(f"{self._base_url}/software")
        response.raise_for_status()
        return response.json()

    async def detail(self, title_id: str) -> dict:
        response = await self._client.get(f"{self._base_url}/patch/{title_id}")
        response.raise_for_status()
        return _remove_embedded_cert(response.text)


@asynccontextmanager
async def jamf_api_source() -> AsyncIterator[JamfApiCatalogSource]:
    """The default source with the client it needs, closed when the sync is done."""
    headers = {"User-Agent": build_user_agent("jamf-patch-sync")}
    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        yield JamfApiCatalogSource(client)


def _remove_embedded_cert(body: str) -> dict:
    """Jamf's public patch server wraps each definition in a signed envelope: bytes before the
    JSON and a certificate after it. Parse the first JSON object that starts at `{"` and ignore
    whatever follows. Trimming the tail back to the last `]}` looked equivalent and was not —
    the trailing certificate can itself contain `]}`, which silently dropped six titles."""
    decoder = json.JSONDecoder()
    start = body.find('{"')
    attempts = 0
    while start >= 0 and attempts < 8:
        attempts += 1
        try:
            parsed, _ = decoder.raw_decode(body, start)
        except json.JSONDecodeError:
            start = body.find('{"', start + 1)
            continue
        return parsed if isinstance(parsed, dict) else {}
    return {}


async def _fetch_details(source: CatalogSource, title_ids: list[str]) -> list[dict | BaseException]:
    """Every changed title's definition, at most `DETAIL_CONCURRENCY` in flight, in the
    order asked for.

    `return_exceptions=True` is load-bearing and predates the bound: one title that 404s
    or answers something unparseable is skipped by the caller, never allowed to abandon
    the other fifteen hundred."""
    in_flight = asyncio.Semaphore(DETAIL_CONCURRENCY)

    async def bounded(title_id: str) -> dict:
        async with in_flight:
            return await source.detail(title_id)

    return await asyncio.gather(*(bounded(title_id) for title_id in title_ids), return_exceptions=True)


def _strip_patch_entry(patch: dict) -> dict:
    return {key: value for key, value in patch.items() if key not in _STRIP_PATCH_KEYS}


def _extension_attributes(detail: dict) -> list[dict]:
    """The attribute definitions a title ships, without the script: the requirement names the
    `key`, Jamf Pro creates the attribute under the `displayName`, and the matcher accepts
    either name on the device."""
    return [
        {"key": ea.get("key"), "displayName": ea.get("displayName")}
        for ea in detail.get("extensionAttributes") or []
        if isinstance(ea, dict) and ea.get("key")
    ]


def _convert_requirements(requirements: list[dict]) -> list[dict]:
    """Collapse Jamf's flat, `and`-linked requirement list into OR'd groups of
    AND'd criteria (a requirement starts a new group when it isn't and-linked
    to the previous one)."""
    if not requirements:
        return []

    groups: list[dict] = []
    current: dict = {"operator": "and", "tests": []}

    for requirement in requirements:
        test = {
            "name": requirement.get("name"),
            "operator": requirement.get("operator"),
            "value": requirement.get("value"),
            "type": requirement.get("type"),
        }
        if current["tests"] and not requirement.get("and", True):
            groups.append(current)
            current = {"operator": "and", "tests": []}
        current["tests"].append(test)

    groups.append(current)
    return groups


def _needs_refresh(existing: JamfPatchTitle | None, title_summary: dict) -> bool:
    if existing is None:
        return True
    return (
        existing.last_modified != title_summary.get("lastModified")
        or existing.current_version != title_summary.get("currentVersion")
        # Fetched before extension_attributes existed: one more fetch fills it.
        or existing.extension_attributes is None
    )


async def sync_catalog(db: AsyncSession, source: CatalogSource | None = None) -> int:
    """Refresh the jamf_patch_titles cache from the patch definition catalog. Only titles
    whose lastModified/currentVersion changed (or are new) are re-fetched in full.
    Returns the number of titles synced.

    `source` defaults to Jamf's API, which is what both callers — the hourly job and the
    Sync button — use. It is a parameter so a test can serve the catalog without a
    network, and so a second source can be passed one day without this function
    changing."""

    async with AsyncExitStack() as stack:
        if source is None:
            source = await stack.enter_async_context(jamf_api_source())

        summaries = await source.summaries()

        # This `select` opens the session's transaction and the `commit()` below closes
        # it, so the session sits idle-in-transaction for the whole fan-out — a shape that
        # predates the bound and that the bound makes roughly twelve times longer on a
        # cold sync. Left alone deliberately: nothing sets `idle_in_transaction_session_
        # timeout` (Postgres leaves it off), and the only cost is that autovacuum cannot
        # collect dead tuples in `jamf_patch_titles` until the sync finishes — a table of
        # about 1,554 rows, rewritten at most hourly. Worth knowing before someone
        # rediscovers it in a lock view; not worth two transactions to avoid.
        result = await db.execute(select(JamfPatchTitle))
        existing_rows = {row.id: row for row in result.scalars().all()}

        to_refresh = [summary for summary in summaries if _needs_refresh(existing_rows.get(summary.get("id")), summary)]

        details = await _fetch_details(source, [summary["id"] for summary in to_refresh])

    now = datetime.now(UTC)
    synced = 0

    for summary, detail in zip(to_refresh, details, strict=True):
        if isinstance(detail, BaseException) or not detail:
            continue

        title_id = summary["id"]
        row = existing_rows.get(title_id)
        if row is None:
            row = JamfPatchTitle(id=title_id)
            db.add(row)

        row.name = detail.get("name", "")
        row.publisher = detail.get("publisher")
        row.app_name = detail.get("appName")
        row.bundle_id = detail.get("bundleId")
        row.current_version = detail.get("currentVersion", "")
        row.last_modified = detail.get("lastModified", "")
        row.patches = [_strip_patch_entry(patch) for patch in detail.get("patches", [])]
        row.requirements = _convert_requirements(detail.get("requirements", []))
        row.extension_attributes = _extension_attributes(detail)
        row.synced_at = now
        synced += 1

    await db.commit()
    if synced:
        # The per-device path trusts the in-process index for `CATALOG_PROBE_INTERVAL`
        # (#142); the writer forgetting it here is what makes a sync in this process
        # visible to the very next device rather than at the next probe.
        reset_catalog_cache()
    return synced
