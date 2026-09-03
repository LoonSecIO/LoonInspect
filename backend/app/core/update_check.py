"""Daily check of the provider's HEAD against this build's stamped commit (#43).

Unauthenticated api.github.com allows 60 requests per hour per source IP. Every
instance behind a shared egress address — a corporate NAT, one customer's whole
fleet — draws against that same budget without knowing it, and a 403 from it is
swallowed exactly like being offline (see `_fetch_head_sha`), so the sharing stays
invisible unless someone goes looking for it.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx

from app.core.config import settings
from app.core.user_agent import build_user_agent
from app.core.version import get_app_version

logger = logging.getLogger(__name__)

# The default provider asks GitHub for main's HEAD. Releases are commits of main
# (see #41), so "update available" is exactly "HEAD no longer matches this build".
# The destination provider is api.loonsec.io once the data layer exists — kept
# behind this module's seam so flipping it is a one-file change (#43).
_GITHUB_HEAD_URL = "https://api.github.com/repos/LoonSecIO/LoonInspect/commits/main"

_SUCCESS_TTL = timedelta(hours=24)
# Retry sooner after a failure, but not so soon that an air-gapped instance is
# hammering a wall on every page load.
_FAILURE_TTL = timedelta(hours=1)


@dataclass
class UpdateStatus:
    enabled: bool
    current_version: str
    # None means "unknown": checking is disabled, this is a dev build, or the
    # provider was unreachable. Distinct from False, which is "checked, current".
    update_available: bool | None
    latest_sha: str | None
    checked_at: datetime | None


@dataclass
class _CacheEntry:
    checked_at: datetime
    latest_sha: str | None  # None records a failed fetch, on the shorter TTL


_cache: _CacheEntry | None = None
_lock = asyncio.Lock()


def _current_sha() -> str | None:
    """The short sha this build was stamped with, or None when the version carries
    nothing comparable (dev sentinel, or an image built without GIT_SHA)."""
    version = get_app_version()
    _, _, sha = version.partition("+")
    if not sha or sha in ("local", "unknown"):
        return None
    return sha


async def _fetch_head_sha() -> str | None:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                settings.update_check_url or _GITHUB_HEAD_URL,
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": build_user_agent("update-check"),
                },
            )
            response.raise_for_status()
            sha = response.json().get("sha")
            return sha if isinstance(sha, str) and sha else None
    except (httpx.HTTPError, ValueError) as exc:
        # Debug, not warning: an offline or air-gapped deployment hits this on
        # every TTL expiry forever, and that is a configuration, not a fault.
        logger.debug("update check could not reach provider: %s", exc)
        return None


async def get_update_status() -> UpdateStatus:
    global _cache
    version = get_app_version()
    current_sha = _current_sha()

    if not settings.update_check or current_sha is None:
        return UpdateStatus(
            enabled=settings.update_check,
            current_version=version,
            update_available=None,
            latest_sha=None,
            checked_at=None,
        )

    async with _lock:
        now = datetime.now(timezone.utc)
        if _cache is not None:
            ttl = _SUCCESS_TTL if _cache.latest_sha else _FAILURE_TTL
            if now - _cache.checked_at < ttl:
                return _status_from(version, current_sha, _cache)

        _cache = _CacheEntry(checked_at=now, latest_sha=await _fetch_head_sha())
        return _status_from(version, current_sha, _cache)


def _status_from(version: str, current_sha: str, entry: _CacheEntry) -> UpdateStatus:
    # The build stamp is the short sha; GitHub returns the full one.
    available = None if entry.latest_sha is None else not entry.latest_sha.startswith(current_sha)
    return UpdateStatus(
        enabled=True,
        current_version=version,
        update_available=available,
        latest_sha=entry.latest_sha,
        checked_at=entry.checked_at,
    )
