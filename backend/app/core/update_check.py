"""Daily check of this build against the latest published release (#43, #407).

**What "update available" means.** Kyle, 2026-09-11: `main` is staging, and publishing a
GitHub Release is the release. So an update is available when this build does not contain
the latest published release's commit — never merely because `main` moved. The check
before #407 compared against `main`'s HEAD, which told every install that a newer build
existed after every merge, docs-only included, and told a pod built from a release the
same the first time anything landed after its tag.

**Two unauthenticated calls per check**, on one 24-hour cache:

1. `GET /releases/latest` — the tag and the release page. GitHub's answer skips drafts and
   prereleases, and a `404` means no release has been published yet.
2. `GET /compare/<tag>...<build sha>` — whether this build contains that tag: `ahead` or
   `identical` is current, `behind` or `diverged` is an update, and a `404` means GitHub
   does not know this build's commit (a local or forked build). Both stamp widths work
   as they are: a compose build carries the 7-character sha and CI stamps all 40 (#176).

Not by the stamp's date: the `YYYY.MM.DD` half is when the image was built, not when its
commit was made (`Dockerfile`), so an old tag built today would read as current.

**Every unknown names its reason** (`docs/diagnosability.md` rule 1). Unknown still hides
the banner — #43's rule: a check that could not answer must never look like "current" or
like "behind" — and Settings > Support's Updates block is where the reason is read.

Unauthenticated api.github.com allows 60 requests per hour per source address. Every
instance behind one egress address — a corporate NAT, one customer's whole fleet — draws
against that same budget without knowing it. Before #407 a `403` from it was swallowed
exactly like being offline; now it is `refused`, and it is logged once per retry with the
next check in it.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import quote

import httpx

from app.core.config import settings
from app.core.user_agent import build_user_agent
from app.core.version import get_app_version

logger = logging.getLogger(__name__)

# The default provider is this repository's GitHub API. The destination provider is
# api.loonsec.io once the data layer exists — behind this module's seam, and behind
# `UPDATE_CHECK_URL`, which names a base answering the same two paths (#43).
_GITHUB_REPO_API = "https://api.github.com/repos/LoonSecIO/LoonInspect"

_SUCCESS_TTL = timedelta(hours=24)
# Retry sooner after a failure, but not so soon that an air-gapped instance is
# hammering a wall on every page load. A rate-limit refusal resets within the hour too.
_FAILURE_TTL = timedelta(hours=1)

# What a stamp's sha must look like before it goes into a URL path. Anything else — the
# dev sentinel, "unknown" from an image built without GIT_SHA, a hand-typed build arg —
# is a build with nothing comparable, and is never sent anywhere.
_SHA = re.compile(r"[0-9a-f]{7,40}")

UpdateReason = Literal["disabled", "dev_build", "unreachable", "refused", "no_release", "unknown_commit"]
REASON_DISABLED: UpdateReason = "disabled"  # UPDATE_CHECK=false; nothing is asked
REASON_DEV_BUILD: UpdateReason = "dev_build"  # the build carries no comparable commit
REASON_UNREACHABLE: UpdateReason = "unreachable"  # no answer, or not one GitHub gives
REASON_REFUSED: UpdateReason = "refused"  # 403 or 429: the shared rate limit, usually
REASON_NO_RELEASE: UpdateReason = "no_release"  # releases/latest answered 404
REASON_UNKNOWN_COMMIT: UpdateReason = "unknown_commit"  # compare answered 404

# The two reasons that are a failure to get an answer, retried on the short TTL. The
# others are answers — GitHub said "no release" or "no such commit" — and keep the long one.
_RETRIED = frozenset({REASON_UNREACHABLE, REASON_REFUSED})

_CURRENT = frozenset({"ahead", "identical"})
_BEHIND = frozenset({"behind", "diverged"})


@dataclass
class UpdateStatus:
    enabled: bool
    current_version: str
    # None means "unknown", and `reason` then says which unknown it is. Distinct from
    # False, which is "checked, and this build contains the latest release".
    update_available: bool | None
    # The commit the latest release's tag points at, from the compare answer.
    latest_sha: str | None
    checked_at: datetime | None
    latest_tag: str | None = None
    release_url: str | None = None
    reason: UpdateReason | None = None


@dataclass(frozen=True)
class _Answer:
    """What one check found out, cached whole — the verdict and every name it carries."""

    update_available: bool | None
    latest_sha: str | None = None
    latest_tag: str | None = None
    release_url: str | None = None
    reason: UpdateReason | None = None


@dataclass
class _CacheEntry:
    checked_at: datetime
    answer: _Answer

    @property
    def ttl(self) -> timedelta:
        return _FAILURE_TTL if self.answer.reason in _RETRIED else _SUCCESS_TTL


_cache: _CacheEntry | None = None
_lock = asyncio.Lock()


def _current_sha() -> str | None:
    """The sha this build was stamped with, 7 or 40 characters, or None when the version
    carries nothing comparable (the dev sentinel, or an image built without GIT_SHA)."""
    _, _, sha = get_app_version().partition("+")
    sha = sha.lower()
    return sha if _SHA.fullmatch(sha) else None


def _provider_base() -> str:
    return (settings.update_check_url or _GITHUB_REPO_API).rstrip("/")


def _https_or_none(value: object) -> str | None:
    """The release page, only as an https link. It is rendered as an `href`, and the
    provider is whatever `UPDATE_CHECK_URL` names, so anything else is dropped."""
    return value if isinstance(value, str) and value.startswith("https://") else None


def _unanswered(response: httpx.Response, *, not_found: UpdateReason, **names: str | None) -> _Answer | None:
    """The reason a non-200 answer carries, or None when the answer is a 200 to read."""
    if response.status_code == 200:
        return None
    if response.status_code == 404:
        return _Answer(update_available=None, reason=not_found, **names)
    if response.status_code in (403, 429):
        logger.info(
            "update check refused by the provider (%s); unauthenticated api.github.com allows 60 requests an hour "
            "per address, shared by every instance behind it — the check asks again within the hour",
            response.status_code,
        )
        return _Answer(update_available=None, reason=REASON_REFUSED, **names)
    logger.debug("update check got %s from %s", response.status_code, response.request.url)
    return _Answer(update_available=None, reason=REASON_UNREACHABLE, **names)


async def _ask(current_sha: str) -> _Answer:
    base = _provider_base()
    headers = {"Accept": "application/vnd.github+json", "User-Agent": build_user_agent("update-check")}
    try:
        # Redirects followed: GitHub answers a renamed repository with a 301 to its new
        # name, and the rename should not read as "unreachable" for a year.
        async with httpx.AsyncClient(timeout=5.0, headers=headers, follow_redirects=True) as client:
            release = await client.get(f"{base}/releases/latest")
            refused = _unanswered(release, not_found=REASON_NO_RELEASE)
            if refused is not None:
                return refused
            body = release.json()
            tag = body.get("tag_name") if isinstance(body, dict) else None
            if not isinstance(tag, str) or not tag:
                # A 200 that is not a release: a captive portal, a proxy's page.
                logger.debug("update check: the latest-release answer carried no tag_name")
                return _Answer(update_available=None, reason=REASON_UNREACHABLE)
            names = {"latest_tag": tag, "release_url": _https_or_none(body.get("html_url"))}

            compare = await client.get(f"{base}/compare/{quote(tag, safe='')}...{current_sha}")
            refused = _unanswered(compare, not_found=REASON_UNKNOWN_COMMIT, **names)
            if refused is not None:
                return refused
            data = compare.json()
            status = data.get("status") if isinstance(data, dict) else None
            base_commit = data.get("base_commit") if isinstance(data, dict) else None
            release_sha = base_commit.get("sha") if isinstance(base_commit, dict) else None
            latest_sha = release_sha if isinstance(release_sha, str) and release_sha else None
            if status in _CURRENT:
                return _Answer(update_available=False, latest_sha=latest_sha, **names)
            if status in _BEHIND:
                return _Answer(update_available=True, latest_sha=latest_sha, **names)
            logger.debug("update check: the compare answer carried status %r", status)
            return _Answer(update_available=None, reason=REASON_UNREACHABLE, **names)
    except (httpx.HTTPError, ValueError) as exc:
        # Debug, not warning: an offline or air-gapped deployment hits this on every TTL
        # expiry forever, and that is a configuration, not a fault. The Updates block on
        # Settings > Support says `unreachable` to the operator who goes looking.
        logger.debug("update check could not reach the provider: %s", exc)
        return _Answer(update_available=None, reason=REASON_UNREACHABLE)


async def get_update_status() -> UpdateStatus:
    global _cache
    version = get_app_version()

    if not settings.update_check:
        return UpdateStatus(
            enabled=False,
            current_version=version,
            update_available=None,
            latest_sha=None,
            checked_at=None,
            reason=REASON_DISABLED,
        )
    current_sha = _current_sha()
    if current_sha is None:
        return UpdateStatus(
            enabled=True,
            current_version=version,
            update_available=None,
            latest_sha=None,
            checked_at=None,
            reason=REASON_DEV_BUILD,
        )

    async with _lock:
        now = datetime.now(UTC)
        if _cache is None or now - _cache.checked_at >= _cache.ttl:
            _cache = _CacheEntry(checked_at=now, answer=await _ask(current_sha))
        return _status_from(version, _cache)


def _status_from(version: str, entry: _CacheEntry) -> UpdateStatus:
    answer = entry.answer
    return UpdateStatus(
        enabled=True,
        current_version=version,
        update_available=answer.update_available,
        latest_sha=answer.latest_sha,
        checked_at=entry.checked_at,
        latest_tag=answer.latest_tag,
        release_url=answer.release_url,
        reason=answer.reason,
    )
