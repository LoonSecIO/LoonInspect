"""Each Fleet title's version history, read from Fleet's commits (#838).

The daily check (`app.core.fleet_catalog`) keeps one step of history: the version before the
last move *this instance saw*. Fleet's repository holds the rest. Each title's manifest,
`ee/maintained-apps/outputs/<slug>/darwin.json`, has one commit per change, so reading the
manifest at each of those commits gives every version Fleet published and the date its
catalogue first carried it. Those are Fleet's dates, not a vendor's (docs/fleet-catalog.md).

**What one title costs.** One request to the GitHub API for the list of changes to its
manifest, per hundred changes (a title had 31 to 113 on 2026-11-21), then the manifest at each
change from `raw.githubusercontent.com`. Every request is a plain GET naming Fleet's files.

**Slow on purpose, and only for titles in your space.** The background reader
(`run_worker`) reads one title at a time with at least two minutes between titles, and the
manifests of a title one at a time. It reads only titles installed on a Mac in an organization
with the `fleet_maintained_apps` flag on, the most-installed first. It reads a title again only
after its version moved. It makes no API request while GitHub says 20 or fewer of the hour's
requests are left (`RESERVE`), so the daily check, Check now and every other tool behind the
same address keep theirs; it waits for the hour to reset instead. A person can read any
title's history from the tab (`read_now`), under the same reserve.

**A version is dated only where the commits show it arriving**: at a change where it
replaced another version or a missing manifest, or at the title's first change in Fleet's
history. A read that stopped at its page cap, and a manifest that could not be read at some
change, leave the version they cannot see arrive without a date, rather than give it a date
that is only an upper bound. A re-read after a move starts at the newest change the last read
reached, so the version that change carried is the one the next arrival replaced.

A failure says which one it was in the operator's words (docs/diagnosability.md rule 1):
`refused`, `unreachable` and `unexpected` are the daily check's words and sentences, and
`waiting` is the reserve. The history already held is never removed by a read.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import httpx
from sqlalchemy import and_, distinct, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import fleet_catalog as fc
from app.core.context import SYSTEM, reset_actor, set_actor
from app.core.database import unscoped_session
from app.core.tenant_jobs import operational_tenant_ids, tenant_job
from app.core.user_agent import build_user_agent
from app.models.schema import Device, FleetAppVersion, FleetMaintainedApp, InstalledApp

logger = logging.getLogger(__name__)

OUTCOME_OK = "ok"
OUTCOME_WAITING = "waiting"  # leaving the hour's last requests to the daily check and other tools
FAILED = fc.FAILED

# GitHub's largest page of commits. A title past MAX_PAGES pages is read back that far and no
# further: the oldest version in the window then has no date.
PAGE_SIZE = 100
MAX_PAGES = 10
# Requests left in the hour that the history read never spends (of 60 without a sign-in).
RESERVE = 20
# Between one background title and the next, whatever the last one cost or found.
TITLE_GAP = timedelta(minutes=2)
# Between one manifest read and the next in the background. A person waiting reads four at once.
BACKGROUND_PACE_SECONDS = 0.5
PERSON_CONCURRENCY = 4
# A re-read after a move asks GitHub for the changes from this long before the newest change
# the last read reached, so that change is in the list whatever its recorded date, and starts
# at it. One it cannot find there is read again from the title's first change.
REREAD_MARGIN = timedelta(days=7)
# After `refused` or `unreachable`, the background tries again no sooner than this.
FAILURE_PAUSE = timedelta(minutes=15)

_MAX_COMMITS_BYTES = 8 * 1024 * 1024
_MANIFEST = f"{fc.FOLDER}/outputs/{{slug}}/darwin.json"
_COMMITS = f"{fc._API}/commits"
_RAW_AT = f"https://{fc.RAW_HOST}/{fc.REPOSITORY}/{{sha}}/{_MANIFEST}"

BUSY = (
    "A version history read is already running. The background reads one title at a time and takes about a "
    "minute for one; try again then."
)


class HistoryFailed(Exception):
    """A history read that could not finish: the outcome word, and the sentence an operator reads."""

    def __init__(self, outcome: str, detail: str) -> None:
        super().__init__(detail)
        self.outcome = outcome
        self.detail = detail


class HistoryBusy(Exception):
    """A history read is already running on this instance."""


def _waiting_sentence(left: int, reset_at: datetime, *, person: bool) -> str:
    when = reset_at.strftime("%H:%M UTC")
    said = (
        f"GitHub says {left} of this address's 60 requests an hour are left, and a version history read leaves the "
        f"last {RESERVE} for the daily check, Check now and every other tool behind the same address."
    )
    if person:
        return f"Not read: {said} Try again after {when}."
    return (
        f"Paused until {when}: {said} It carries on by itself then. If it pauses every hour, something else behind "
        "this address is using GitHub's allowance (docs/troubleshooting.md §27)."
    )


def _held_back(now: datetime, *, person: bool) -> str | None:
    """The waiting sentence while GitHub says `RESERVE` or fewer requests are left this hour."""
    left, reset_at = fc.ALLOWANCE.left(now), fc.ALLOWANCE.reset_at
    if left is None or reset_at is None or left > RESERVE:
        return None
    return _waiting_sentence(left, reset_at, person=person)


def _reserve(now: datetime, *, person: bool) -> None:
    if (sentence := _held_back(now, person=person)) is not None:
        raise HistoryFailed(OUTCOME_WAITING, sentence)


# --- reading ----------------------------------------------------------------------------


def commits_url(slug: str, page: int, since: datetime | None) -> str:
    query = {"sha": fc.BRANCH, "path": _MANIFEST.format(slug=slug), "per_page": PAGE_SIZE, "page": page}
    if since is not None:
        query["since"] = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{_COMMITS}?{urlencode(query)}"


def parse_commits(body: bytes, slug: str) -> list[tuple[str, datetime]]:
    """(sha, the date GitHub records the change was committed) for each change, as listed."""
    rows = fc._json(body, host=fc.API_HOST, what=f"the list of changes to {slug}/darwin.json")
    if not isinstance(rows, list):
        raise fc._not_the_catalogue(f"the list of changes to {slug}/darwin.json is not a list")
    commits: list[tuple[str, datetime]] = []
    for row in rows:
        commit = row.get("commit") if isinstance(row, dict) else None
        committer = commit.get("committer") if isinstance(commit, dict) else None
        sha = row.get("sha") if isinstance(row, dict) else None
        stamp = committer.get("date") if isinstance(committer, dict) else None
        try:
            at = datetime.fromisoformat(stamp.replace("Z", "+00:00")) if isinstance(stamp, str) else None
        except ValueError:
            at = None
        if not (isinstance(sha, str) and fc._SHA.fullmatch(sha) and at is not None and at.tzinfo is not None):
            raise fc._not_the_catalogue(f"a change to {slug}/darwin.json has no commit and date this build can read")
        commits.append((sha, at.astimezone(UTC)))
    return commits


# A manifest that was not there at a change (deleted, or not yet added): a known absence,
# unlike None, a manifest that was there and could not be read.
ABSENT = ""


def date_versions(
    readings: list[tuple[str, datetime, str | None]], *, from_first_change: bool
) -> list[tuple[str, datetime, str, str | None]]:
    """(version, date, sha, the version it replaced) for each version whose arrival the
    readings show, oldest first. The version replaced is None at the title's first change and
    where the manifest had been missing.

    `readings` is (sha, date, the manifest's version) per change, oldest first, with the
    version `ABSENT` where the manifest was not there and None where it could not be read.
    `from_first_change` says the first reading is the title's first change in Fleet's history,
    so the version it carries arrived there. Any other first reading is the middle of the
    story, and so is a reading after one that could not be read. A version is dated at most
    once, at its first arrival: one seen before without a date is not dated by a later return.
    """
    dated: list[tuple[str, datetime, str, str | None]] = []
    seen: set[str] = set()
    start = object()
    previous: object = start
    for sha, at, version in readings:
        if version is not None and version != ABSENT:
            if previous is start:
                arrived = from_first_change
            elif previous is None:
                arrived = False
            else:
                arrived = previous != version
            if arrived and version not in seen:
                dated.append((version, at, sha, previous if isinstance(previous, str) and previous else None))
            seen.add(version)
        previous = version
    return dated


@dataclass
class _Read:
    """What one title's read found, before anything is written."""

    dated: list[tuple[str, datetime, str, str | None]] = field(default_factory=list)
    oldest: datetime | None = None
    # The newest change read: where the next re-read starts.
    newest: tuple[str, datetime] | None = None
    # Started at the last read's newest change rather than the title's first.
    resumed: bool = False
    changes: int = 0
    unreadable: int = 0
    capped: bool = False
    complete: bool = False


async def _manifests_at(
    client: httpx.AsyncClient,
    slug: str,
    shas: list[str],
    tally: fc._Tally,
    *,
    pace: float,
    concurrency: int,
) -> dict[str, str | None]:
    """sha -> the manifest's version at that change (`ABSENT`, or None when unreadable).
    A refusal or a host that stopped answering stops the read and raises its failure."""
    versions: dict[str, str | None] = {}
    stopped: list[fc.CheckFailed] = []
    gate = asyncio.Semaphore(concurrency)

    async def one(sha: str) -> None:
        async with gate:
            if stopped:
                return
            try:
                body = await fc._get(
                    client,
                    _RAW_AT.format(sha=sha, slug=slug),
                    ceiling=fc._MAX_MANIFEST_BYTES,
                    what=f"the manifest {slug}/darwin.json as of {sha[:8]}",
                    tally=tally,
                )
            except fc._Missing:
                versions[sha] = ABSENT
            except fc.CheckFailed as failed:
                if failed.outcome == fc.OUTCOME_UNEXPECTED:
                    versions[sha] = None  # this one file is wrong; the history is not
                else:
                    stopped.append(failed)
            else:
                versions[sha] = fc.parse_manifest(body)
            if pace:
                await asyncio.sleep(pace)

    await asyncio.gather(*(one(sha) for sha in shas))
    if stopped:
        raise stopped[0]
    return versions


async def _read(
    client: httpx.AsyncClient,
    slug: str,
    *,
    anchor: tuple[str, datetime] | None,
    pace: float,
    concurrency: int,
    person: bool,
    tally: fc._Tally,
) -> _Read:
    """One title's changes and the manifest at each. With an `anchor` (the newest change the
    last read reached), only that change and the ones after it; without, every change."""
    since = anchor[1] - REREAD_MARGIN if anchor is not None else None
    listed: list[tuple[str, datetime]] = []
    capped = True
    for page in range(1, MAX_PAGES + 1):
        _reserve(datetime.now(UTC), person=person)
        try:
            body = await fc._get(
                client,
                commits_url(slug, page, since),
                ceiling=_MAX_COMMITS_BYTES,
                what=f"the list of changes to {slug}/darwin.json",
                tally=tally,
            )
        except fc._Missing as missing:
            raise fc._not_the_catalogue(f"it answered 404 for {missing}") from missing
        rows = parse_commits(body, slug)
        listed.extend(rows)
        if len(rows) < PAGE_SIZE:
            capped = False
            break

    # GitHub lists the newest change first, in the history's own order. A change Fleet pushed
    # between two pages shifts the next page by one, so a change listed twice is kept once.
    newest_first = list(dict.fromkeys(listed))  # (sha, date) pairs, first listing kept, order kept
    if anchor is not None:
        position = next((i for i, (sha, _) in enumerate(newest_first) if sha == anchor[0]), None)
        if position is None:
            # Not where it should be (a rewritten history, or more changes than the cap):
            # the whole history again, which dates what this one could not.
            return await _read(client, slug, anchor=None, pace=pace, concurrency=concurrency, person=person, tally=tally)
        newest_first = newest_first[: position + 1]
    changes = list(reversed(newest_first))

    read = _Read(
        changes=len(changes),
        capped=capped and anchor is None,
        resumed=anchor is not None,
        complete=anchor is None and not capped and bool(changes),
    )
    if not changes:
        return read
    versions = await _manifests_at(client, slug, [sha for sha, _ in changes], tally, pace=pace, concurrency=concurrency)
    read.oldest, read.newest = changes[0][1], changes[-1]
    read.unreadable = sum(1 for version in versions.values() if version is None)
    read.dated = date_versions([(sha, at, versions[sha]) for sha, at in changes], from_first_change=read.complete)
    return read


def _title_sentence(read: _Read) -> str | None:
    """What a read that finished left undated, for the title's history panel."""
    said: list[str] = []
    if read.changes == 0:
        said.append(
            "GitHub lists no change to this title's manifest, so there is no history to read here. Fleet may have "
            "moved the file; the daily check still reads its current version."
        )
    if read.capped:
        said.append(
            f"Only the newest {MAX_PAGES * PAGE_SIZE} changes were read, so the history starts there and the version "
            "Fleet carried at that point has no date."
        )
    if read.unreadable:
        said.append(
            f"{read.unreadable} of the {read.changes} changes did not carry a manifest this build could read, so a "
            "version that arrived at one of them has no date."
        )
    return " ".join(said) or None


async def _record(db: AsyncSession, outcome: str, detail: str | None, now: datetime) -> None:
    state = await fc._state(db)
    state.history_checked_at, state.history_outcome, state.history_detail = now, outcome, detail
    await db.commit()


async def read_title(
    db: AsyncSession,
    slug: str,
    *,
    resume: bool,
    person: bool,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FleetMaintainedApp:
    """Read one title's history and write what it found, committed. The caller holds `_lock`.

    `resume` starts at the newest change the last read reached, when there was one; a
    person's read is always the whole history.

    Raises `HistoryFailed` for a read that could not finish, after recording it: `waiting`
    and `refused` and `unreachable` write nothing to the title, so it is read again later;
    `unexpected` marks the title read with the sentence, so a title whose history this build
    cannot read is not asked for every two minutes.
    """
    started = time.monotonic()
    now = datetime.now(UTC)
    tally = fc._Tally()
    headers = {"Accept": "application/vnd.github+json", "User-Agent": build_user_agent("fleet-catalog")}
    held = await db.get(FleetMaintainedApp, slug)
    anchor = None
    if resume and held is not None and held.history_last_sha is not None and held.history_through is not None:
        anchor = (held.history_last_sha, held.history_through)
    try:
        if transport is None:
            await fc._refuse_blocked_hosts()
        async with httpx.AsyncClient(
            timeout=fc._TIMEOUT_SECONDS, headers=headers, transport=transport, follow_redirects=False
        ) as client:
            read = await _read(
                client,
                slug,
                anchor=anchor,
                pace=0.0 if person else BACKGROUND_PACE_SECONDS,
                concurrency=PERSON_CONCURRENCY if person else 1,
                person=person,
                tally=tally,
            )
    except fc.CheckFailed as failed:
        error = HistoryFailed(failed.outcome, failed.detail)
    except HistoryFailed as failed:
        error = failed
    else:
        error = None

    facts = {
        "slug": slug,
        "api_requests": tally.api_requests,
        "raw_requests": tally.raw_requests,
        "seconds": round(time.monotonic() - started, 2),
        "by": "person" if person else "background",
    }
    if error is not None:
        if error.outcome == fc.OUTCOME_UNEXPECTED:
            async with fc._lock:  # the title's row written and committed where the check cannot remove it
                title = await db.get(FleetMaintainedApp, slug, populate_existing=True)
                if title is not None:
                    title.history_read_at, title.history_detail = now, error.detail
                await _record(db, error.outcome, error.detail, now)
        elif error.outcome != OUTCOME_WAITING or person:
            await _record(db, error.outcome, error.detail, now)
        else:
            await _record_waiting(db, error.detail, now)
        if error.outcome == OUTCOME_WAITING:
            logger.info("Fleet version history read waiting: %s", error.detail, extra=facts)
        else:
            logger.warning("Fleet version history read failed: %s", error.detail, extra={**facts, "outcome": error.outcome})
        raise error

    # The check may have removed the title while it was being read (Fleet dropped it), and
    # its removal takes the history with it: written under the check's lock, or not at all.
    async with fc._lock:
        title = await db.get(FleetMaintainedApp, slug, populate_existing=True)
        if title is None:
            await db.rollback()
            raise HistoryFailed(
                fc.OUTCOME_UNEXPECTED,
                "Fleet's catalog stopped listing this title while its history was being read, so nothing was kept.",
            )
        if read.dated:
            await db.execute(
                pg_insert(FleetAppVersion)
                .values(
                    [
                        {"slug": slug, "version": version, "seen_at": at, "commit_sha": sha, "previous_version": before}
                        for version, at, sha, before in read.dated
                    ]
                )
                # A version already held keeps the date it has: the earlier read saw further back.
                .on_conflict_do_nothing(index_elements=["slug", "version"])
            )
        title.history_read_at = now
        if read.oldest is not None and (title.history_since is None or read.oldest < title.history_since):
            title.history_since = read.oldest
        if read.newest is not None:
            title.history_last_sha, title.history_through = read.newest
        if not read.resumed:
            title.history_complete = read.complete
        title.history_detail = _title_sentence(read)
        state = await fc._state(db)
        state.history_checked_at, state.history_outcome, state.history_detail = now, OUTCOME_OK, None
        await db.commit()
    await db.refresh(title)
    logger.info(
        "Fleet version history read",
        extra={
            **facts,
            "outcome": OUTCOME_OK,
            "changes": read.changes,
            "versions_dated": len(read.dated),
            "manifests_unreadable": read.unreadable,
            "capped": read.capped,
            "from": "the last change read" if read.resumed else "the first change",
        },
    )
    return title


async def _record_waiting(db: AsyncSession, detail: str, now: datetime) -> None:
    """The background's pause, written once per pause rather than every two minutes."""
    state = await fc._state(db)
    if state.history_outcome == OUTCOME_WAITING and state.history_detail == detail:
        return
    await _record(db, OUTCOME_WAITING, detail, now)


# --- who reads what, and when -------------------------------------------------------------

_lock = asyncio.Lock()
_paused_until: datetime | None = None


async def read_now(db: AsyncSession, slug: str, *, transport: httpx.AsyncBaseTransport | None = None) -> FleetMaintainedApp:
    """A person's read of one title's whole history, from the tab. Never waits on a read in flight."""
    if _lock.locked():
        raise HistoryBusy
    async with _lock:
        return await read_title(db, slug, resume=False, person=True, transport=transport)


def _wanted():
    """A title whose history was never read, or whose version moved after the last read."""
    return or_(
        FleetMaintainedApp.history_read_at.is_(None),
        and_(
            FleetMaintainedApp.version_changed_at.is_not(None),
            FleetMaintainedApp.version_changed_at > FleetMaintainedApp.history_read_at,
        ),
    )


async def next_title() -> str | None:
    """The next title the background reads: wanted, installed on a Mac in an organization with
    the flag on, and on the most Macs of those. None when there is nothing to read."""
    async with unscoped_session() as db:
        wanted = (
            await db.execute(
                select(FleetMaintainedApp.slug, FleetMaintainedApp.bundle_id, FleetMaintainedApp.name).where(_wanted())
            )
        ).all()
    if not wanted:
        return None
    bundles = {row.bundle_id for row in wanted}
    macs: dict[str, int] = {}
    for tenant_id in await operational_tenant_ids():
        async with tenant_job(tenant_id) as db:
            if not await fc.enabled(db):
                continue
            counted = await db.execute(
                select(InstalledApp.bundle_id, func.count(distinct(InstalledApp.device_id)))
                .join(Device, Device.id == InstalledApp.device_id)
                .where(Device.platform == "macos", InstalledApp.bundle_id.in_(bundles))
                .group_by(InstalledApp.bundle_id)
            )
            for bundle_id, count in counted.all():
                macs[bundle_id] = macs.get(bundle_id, 0) + int(count)
    installed = [row for row in wanted if macs.get(row.bundle_id)]
    if not installed:
        return None
    installed.sort(key=lambda row: (-macs[row.bundle_id], row.name.casefold(), row.slug))
    return installed[0].slug


async def tick(*, transport: httpx.AsyncBaseTransport | None = None) -> str | None:
    """One step of the background read: at most one title, and none while the reserve or a
    pause after a failure holds. Returns the slug read, or None."""
    global _paused_until
    now = datetime.now(UTC)
    if _paused_until is not None and now < _paused_until:
        return None
    if not await fc.any_organization_enabled():
        return None
    actor_token = set_actor(SYSTEM)
    try:
        if (sentence := _held_back(now, person=False)) is not None:
            async with unscoped_session() as db:
                await _record_waiting(db, sentence, now)
            return None
        slug = await next_title()
        if slug is None or _lock.locked():
            return None
        async with _lock, unscoped_session() as db:
            if await db.get(FleetMaintainedApp, slug) is None:
                return None
            try:
                await read_title(db, slug, resume=True, person=False, transport=transport)
            except HistoryFailed as failed:
                if failed.outcome in (fc.OUTCOME_REFUSED, fc.OUTCOME_UNREACHABLE):
                    _paused_until = now + FAILURE_PAUSE
                return None
        return slug
    finally:
        reset_actor(actor_token)


async def run_worker() -> None:
    """The background reader: a step, then `TITLE_GAP`, so no two titles are read closer together."""
    while True:
        try:
            await tick()
        except Exception:
            logger.exception(
                "Fleet version history read could not run; the history already held stays and the next try is in two "
                "minutes. Check the database container is healthy (docker compose ps db)"
            )
        await asyncio.sleep(TITLE_GAP.total_seconds())


def reset_for_tests() -> None:
    global _paused_until
    _paused_until = None
    fc.ALLOWANCE.forget()


# What the read API and the tab show of a title's history: newest first.
async def versions_of(db: AsyncSession, slug: str) -> list[FleetAppVersion]:
    return list(
        (await db.execute(select(FleetAppVersion).where(FleetAppVersion.slug == slug).order_by(FleetAppVersion.seen_at.desc())))
        .scalars()
        .all()
    )
