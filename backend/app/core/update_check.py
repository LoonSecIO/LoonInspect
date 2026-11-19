"""Daily check of this build against the latest published release (#43, #407), from the scheduler (#819).

**What "update available" means.** Kyle, 2026-09-11: `main` is staging, and publishing a
GitHub Release is the release. So an update is available when this build does not contain
the latest published release's commit — never merely because `main` moved. The check
before #407 compared against `main`'s HEAD, which told every install that a newer build
existed after every merge, docs-only included, and told a pod built from a release the
same the first time anything landed after its tag.

**Two unauthenticated calls per check**:

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

import logging
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import quote

import httpx
from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import unscoped_session
from app.core.user_agent import build_user_agent
from app.core.version import get_app_version
from app.models.schema import UpdateCheckState

logger = logging.getLogger(__name__)

# The default provider is this repository's GitHub API. The destination provider is
# api.loonsec.io once the data layer exists — behind this module's seam, and behind
# `UPDATE_CHECK_URL`, which names a base answering the same two paths (#43).
_GITHUB_REPO_API = "https://api.github.com/repos/LoonSecIO/LoonInspect"

# Retry sooner after a failure, but not so soon that an air-gapped instance is
# hammering a wall. A rate-limit refusal resets within the hour too.
_RETRY = timedelta(hours=1)
# No time of day belongs to an instance (#819): each moment is drawn afresh, from nothing else it holds.
_FIRST = timedelta(hours=24)  # a new instance's first check falls in its first day
_NEXT, _SPREAD = timedelta(hours=20), timedelta(hours=3)  # an answer owes the next 20 to 23 hours on
_AHEAD = timedelta(days=1)  # a moment further ahead than this means the clock went back: owed at once
_STATE = UpdateCheckState.__table__
_STORED = ("update_available", "latest_sha", "checked_at", "latest_tag", "release_url", "reason")

# What a stamp's sha must look like before it goes into a URL path. Anything else — the
# dev sentinel, "unknown" from an image built without GIT_SHA, a hand-typed build arg —
# is a build with nothing comparable, and is never sent anywhere.
_SHA = re.compile(r"[0-9a-f]{7,40}")

UpdateReason = Literal["disabled", "dev_build", "not_checked", "unreachable", "refused", "no_release", "unknown_commit"]
REASON_DISABLED: UpdateReason = "disabled"  # UPDATE_CHECK=false; nothing is asked
REASON_DEV_BUILD: UpdateReason = "dev_build"  # the build carries no comparable commit
REASON_NOT_CHECKED: UpdateReason = "not_checked"  # no check of this build is stored yet
REASON_UNREACHABLE: UpdateReason = "unreachable"  # no answer, or not one GitHub gives
REASON_REFUSED: UpdateReason = "refused"  # 403 or 429: the shared rate limit, usually
REASON_NO_RELEASE: UpdateReason = "no_release"  # releases/latest answered 404
REASON_UNKNOWN_COMMIT: UpdateReason = "unknown_commit"  # compare answered 404

# The two reasons that are a failure to get an answer, asked again an hour on. The others
# are answers — GitHub said "no release" or "no such commit" — and owe the next check.
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


def _rate_limited(response: httpx.Response) -> bool:
    """Whether a refusal is GitHub's rate limit rather than anything else that answers 403.

    GitHub's primary limit answers 403 with `x-ratelimit-remaining: 0`, its secondary limit
    403 or 429 with `retry-after`, and 429 means a limit wherever it comes from. A corporate
    proxy's "Access denied" page is a 403 with none of those, and naming it the shared 60-an-
    hour budget would send its operator to turn the check off on every instance but one —
    it is `unreachable`, whose words already name a proxy.
    """
    headers = response.headers
    return response.status_code == 429 or headers.get("x-ratelimit-remaining") == "0" or "retry-after" in headers


def _unanswered(response: httpx.Response, *, not_found: UpdateReason, **names: str | None) -> _Answer | None:
    """The reason a non-200 answer carries, or None when the answer is a 200 to read."""
    if response.status_code == 200:
        return None
    if response.status_code == 404:
        return _Answer(update_available=None, reason=not_found, **names)
    if response.status_code in (403, 429) and _rate_limited(response):
        logger.info(
            "update check refused by the provider (%s); unauthenticated api.github.com allows 60 requests an hour "
            "per address, shared by every instance behind it — the check asks again in an hour",
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
            # Only a string can be one of GitHub's four words; anything else from a provider
            # that is not GitHub is no answer, never a TypeError that surfaces as a 500.
            status = status if isinstance(status, str) else None
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


def _unasked(version: str) -> UpdateStatus | None:  # the check is off, or the build has no commit
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
    return None


async def get_update_status(now: datetime | None = None) -> UpdateStatus:
    """One check, asked now and stored nowhere; `tick` stores it, and a page reads `read_update_status`."""
    version = get_app_version()
    if (unasked := _unasked(version)) is not None:
        return unasked
    return _status_from(version, now or datetime.now(UTC), await _ask(_current_sha()))


async def read_update_status(db: AsyncSession) -> UpdateStatus:
    """What the route serves, never asking: the answer stored for this build, or `not_checked`."""
    version = get_app_version()
    if (unasked := _unasked(version)) is not None:
        return unasked
    state = await db.get(UpdateCheckState, 1)
    if state is None or state.checked_at is None or state.checked_version != version:
        return _status_from(version, None, _Answer(update_available=None, reason=REASON_NOT_CHECKED))
    return _status_from(version, state.checked_at, state)  # the row's columns carry an answer's names


def _status_from(version: str, checked_at: datetime | None, answer: _Answer | UpdateCheckState) -> UpdateStatus:
    return UpdateStatus(
        enabled=True,
        current_version=version,
        update_available=answer.update_available,
        latest_sha=answer.latest_sha,
        checked_at=checked_at,
        latest_tag=answer.latest_tag,
        release_url=answer.release_url,
        reason=answer.reason,
    )


def _draw(span: timedelta) -> timedelta:
    """An offset at random within `span`, to the microsecond, from the OS's generator: drawn afresh each time."""
    return timedelta(microseconds=secrets.randbelow(span // timedelta(microseconds=1)))


def due(state: UpdateCheckState, now: datetime) -> bool:
    """Owed from the stored moment on until a check is answered, and at once when that moment is over a day ahead."""
    return now >= state.next_check_at or state.next_check_at - now > _AHEAD


async def tick(now: datetime | None = None, draw: Callable[[timedelta], timedelta] = _draw) -> bool:
    """The scheduler's look, True when it asked. One UPDATE claims the attempt (`attempted_at` as read) and owes
    the retry an hour on, so of two processes one asks and one dying mid-check is asked again in an hour."""
    if _unasked(get_app_version()) is not None:
        return False
    now = (now or datetime.now(UTC)).astimezone(UTC)
    async with unscoped_session() as db:
        if (state := await db.get(UpdateCheckState, 1)) is None:  # its migration made it; something removed it
            await db.execute(insert(_STATE).values(id=1, next_check_at=now + draw(_FIRST)).on_conflict_do_nothing())
            await db.commit()
            state = await db.get(UpdateCheckState, 1)
        if not due(state, now):
            return False
        unchanged = _STATE.c.attempted_at.is_not_distinct_from(state.attempted_at)
        claim = update(_STATE).where(_STATE.c.id == 1, unchanged).values(attempted_at=now, next_check_at=now + _RETRY)
        claimed = await db.execute(claim)
        await db.commit()
        if claimed.rowcount != 1:
            return False
        status = await get_update_status(now)
        stored = {name: getattr(status, name) for name in _STORED} | {"checked_version": status.current_version}
        if answered := status.reason not in _RETRIED:
            stored["next_check_at"] = now + _NEXT + draw(_SPREAD)
        await db.execute(update(_STATE).where(_STATE.c.id == 1, _STATE.c.attempted_at == now).values(**stored))
        await db.commit()
    if answered:
        logger.info("update check answered", extra={"update_available": status.update_available, "latest_tag": status.latest_tag})
    return True
