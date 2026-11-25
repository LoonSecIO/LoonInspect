"""Fleet's maintained-apps catalogue, read from Fleet's repository once a day (#794).

Fleet keeps a catalogue of the Mac apps it maintains in `fleetdm/fleet`, under
`ee/maintained-apps/outputs`: an index (`apps.json`: name, slug, bundle identifier) and one
manifest per title (`<slug>/darwin.json`, whose first version entry is the current one). This
module is the monitor: it asks GitHub whether that folder moved, reads only the manifests
whose content changed, and keeps a title's name, bundle identifier and current version, with
the version before the last move it saw. Installer addresses, scripts and queries in a
manifest are parsed past and never stored (docs/fleet-catalog.md).

**What one check asks.** One request to the GitHub API for the folder's listing, which names
the `outputs` tree by its git sha. The same sha as the last reconciled read is the same content,
so the check stops there with the same coverage. A new sha costs one more API request, the tree listed whole (the
Contents API cuts a directory off at 1,000 entries and this one is past that), then the index
and each changed manifest from `raw.githubusercontent.com`. Nothing about this instance or
its organizations is sent: every request is a plain GET naming Fleet's files.

**Who decides whether it runs.** The `fleet_maintained_apps` flag, per organization. While no
organization on the instance has it on, `tick` asks GitHub nothing at all.

**A check that fails says which failure it was** (docs/diagnosability.md rule 1) and leaves
the titles already held in place. `outcome` is one of five words and `detail` is the
sentence, written for Settings and the Fleet catalog tab rather than for a log: what failed,
why, and what to check. A check cut short part-way keeps the manifests it did read and
clears the tree sha, so the next check resumes with the rest. Titles are removed only by a
complete read that no longer lists them.

Redirects are not followed. The two hosts are constants, so nothing here can be pointed
anywhere else, and a redirect is reported as an answer that was not Fleet's catalogue.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import SYSTEM, reset_actor, set_actor
from app.core.database import unscoped_session
from app.core.egress import BlockedBaseUrl, refuse_blocked_resolution
from app.core.feature_flags import FLEET_MAINTAINED_APPS_FLAG
from app.core.tenant_jobs import operational_tenant_ids, tenant_job
from app.core.update_check import _rate_limited  # GitHub's limit headers, read one way in both callers
from app.core.user_agent import build_user_agent
from app.models.schema import FeatureFlag, FleetCatalogState, FleetMaintainedApp

logger = logging.getLogger(__name__)

REPOSITORY = "fleetdm/fleet"
FOLDER = "ee/maintained-apps"
BRANCH = "main"
API_HOST = "api.github.com"
RAW_HOST = "raw.githubusercontent.com"
_API = f"https://{API_HOST}/repos/{REPOSITORY}"
_RAW = f"https://{RAW_HOST}/{REPOSITORY}/{BRANCH}/{FOLDER}/outputs"
CONTENTS_URL = f"{_API}/contents/{FOLDER}?ref={BRANCH}"

_TIMEOUT_SECONDS = 15.0
# Manifests read at once. The first read is every title (953 small files on 2026-11-15);
# eight at a time finished it in under 13 seconds without leaning on GitHub.
_CONCURRENCY = 8
# Ceilings enforced while a body streams, never after it lands. GitHub's own tree listing
# stops at 7 MB; the index is a few hundred kilobytes; a manifest carries its install and
# uninstall scripts and is a few kilobytes.
_MAX_LISTING_BYTES = 8 * 1024 * 1024
_MAX_INDEX_BYTES = 4 * 1024 * 1024
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024

# A Mac manifest's path inside the outputs tree. The slug is Fleet's directory name and
# goes into a URL path, so anything outside this alphabet is not read.
SLUG_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}"
_MANIFEST_PATH = re.compile(rf"({SLUG_PATTERN})/darwin\.json")
_SHA = re.compile(r"[0-9a-f]{40}")

OUTCOME_OK = "ok"  # the catalogue had moved and was read
OUTCOME_UNCHANGED = "unchanged"  # GitHub answered; nothing had moved
OUTCOME_REFUSED = "refused"  # GitHub's rate limit
OUTCOME_UNREACHABLE = "unreachable"  # no answer, or an address this container will not dial
OUTCOME_UNEXPECTED = "unexpected"  # an answer that was not Fleet's catalogue
FAILED = frozenset({OUTCOME_REFUSED, OUTCOME_UNREACHABLE, OUTCOME_UNEXPECTED})

# Once a day, as the update check is, with the same hour between tries after a failure: a
# rate-limit refusal resets within the hour, and an air-gapped instance is not hammering a
# wall. A little under 24 hours so an hourly tick lands on the same hour each day.
_SUCCESS_INTERVAL = timedelta(hours=23, minutes=30)
_FAILURE_INTERVAL = timedelta(minutes=55)

_KEPT = "Nothing was changed, and the titles already held stay."
_CHECK_EGRESS = (
    f"Check this container's outbound access to {API_HOST} and {RAW_HOST} on port 443: DNS, a proxy or an "
    "egress firewall in between (docs/troubleshooting.md §27)."
)
FLAG_OFF = (
    "Fleet's catalog is not read while the Fleet catalog flag is off for this organization. Turn on "
    "“Fleet catalog (maintained apps)” under Settings › Feature Flags, then check again."
)
BUSY = "A check of Fleet's catalog is already running. It finishes within a minute or two; reload this page then."


class CheckFailed(Exception):
    """A check that could not finish: the outcome word, and the sentence an operator reads."""

    def __init__(self, outcome: str, detail: str) -> None:
        super().__init__(detail)
        self.outcome = outcome
        self.detail = detail


class CheckBusy(Exception):
    """A check is already running on this instance; the caller says so and does not wait."""


class _Missing(Exception):
    """GitHub answered 404 for one file. What that means depends on which file."""


class _Blocked(BlockedBaseUrl):
    """One of GitHub's two names resolved to an address this container refuses to dial."""


@dataclass
class _Tally:
    """What one check cost and did, for its one log line."""

    api_requests: int = 0
    raw_requests: int = 0
    read: int = 0
    moved: int = 0
    added: int = 0
    removed: int = 0
    skipped: set[str] = field(default_factory=set)


class Allowance:
    """What GitHub last said is left of this address's hourly allowance for requests without a
    sign-in, from the `x-ratelimit-remaining` and `x-ratelimit-reset` headers on every answer
    `api.github.com` gives this module, a refusal's included.

    The version history read (`app.core.fleet_history`, #838) reads it to leave a reserve for
    the daily check, Check now and every other tool behind the same address. Held in memory: a
    restart forgets it, and the next answer says it again.
    """

    def __init__(self) -> None:
        self.remaining: int | None = None
        self.reset_at: datetime | None = None

    def note(self, headers: httpx.Headers) -> None:
        try:
            remaining = int(headers["x-ratelimit-remaining"])
            reset_at = datetime.fromtimestamp(int(headers["x-ratelimit-reset"]), UTC)
        except (KeyError, ValueError, OverflowError, OSError):
            return  # an answer without GitHub's headers says nothing about the allowance
        self.remaining, self.reset_at = remaining, reset_at

    def left(self, now: datetime) -> int | None:
        """Requests left before the hour resets, or None when unknown or already reset."""
        if self.remaining is None or self.reset_at is None or now >= self.reset_at:
            return None
        return self.remaining

    def forget(self) -> None:
        self.remaining = self.reset_at = None


ALLOWANCE = Allowance()


def _refused(host: str, status: int) -> CheckFailed:
    if host == API_HOST:
        why = (
            "its limit for requests without a sign-in is 60 an hour for each address, and every instance and "
            "every other tool behind the same address draws on it"
        )
    else:
        why = "GitHub limits how fast one address may read files"
    return CheckFailed(
        OUTCOME_REFUSED,
        f"{host} refused the request ({status}): {why}. {_KEPT} The next check is within the hour.",
    )


async def _get(client: httpx.AsyncClient, url: str, *, ceiling: int, what: str, tally: _Tally) -> bytes:
    """One GET, read under a ceiling. A 404 is `_Missing`; every other shortfall is a
    `CheckFailed` whose sentence names the host, what it did, and what to check."""
    host = httpx.URL(url).host
    if host == API_HOST:
        tally.api_requests += 1
    else:
        tally.raw_requests += 1
    try:
        async with client.stream("GET", url) as response:
            status = response.status_code
            if host == API_HOST:
                ALLOWANCE.note(response.headers)
            if status in (403, 429) and _rate_limited(response):
                raise _refused(host, status)
            if status == 404:
                raise _Missing(what)
            if response.is_redirect:
                raise CheckFailed(
                    OUTCOME_UNEXPECTED,
                    f"{host} answered {what} with a redirect, which this check does not follow. {_KEPT} Usually a "
                    "proxy or a sign-in page answering in GitHub's place; if not, Fleet has moved its repository "
                    "(docs/troubleshooting.md §27).",
                )
            if status != 200:
                raise CheckFailed(
                    OUTCOME_UNREACHABLE,
                    f"{host} answered {status} for {what}, where GitHub answers 200. {_KEPT} " + _CHECK_EGRESS,
                )
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > ceiling:
                    raise CheckFailed(
                        OUTCOME_UNEXPECTED,
                        f"{host} sent more than {ceiling // (1024 * 1024)} MB for {what}, far more than that file "
                        f"holds, and the read was stopped there. {_KEPT}",
                    )
                chunks.append(chunk)
            return b"".join(chunks)
    except httpx.HTTPError as exc:
        said = str(exc) or type(exc).__name__
        raise CheckFailed(OUTCOME_UNREACHABLE, f"No answer from {host} ({said}). {_KEPT} " + _CHECK_EGRESS) from exc


def _json(body: bytes, *, host: str, what: str):
    try:
        return json.loads(body)
    except ValueError as exc:
        raise CheckFailed(
            OUTCOME_UNEXPECTED,
            f"{host} answered {what} with a body that is not JSON, so something other than GitHub answered: usually "
            f"a proxy or a captive portal. {_KEPT} " + _CHECK_EGRESS,
        ) from exc


def _not_the_catalogue(what: str) -> CheckFailed:
    return CheckFailed(
        OUTCOME_UNEXPECTED,
        f"GitHub answered, but {what}, so Fleet has changed how it publishes its catalog or something else answered "
        f"in GitHub's place. {_KEPT} If the address is right, this build cannot read the new layout until it is "
        "updated (docs/troubleshooting.md §27).",
    )


def parse_contents(body: bytes) -> str:
    """The `outputs` tree's git sha, from the Contents API's listing of `ee/maintained-apps`."""
    listing = _json(body, host=API_HOST, what="the catalog folder's listing")
    if isinstance(listing, list):
        for entry in listing:
            if isinstance(entry, dict) and entry.get("name") == "outputs" and entry.get("type") == "dir":
                sha = entry.get("sha")
                if isinstance(sha, str) and _SHA.fullmatch(sha):
                    return sha
    raise _not_the_catalogue(f"the listing of {FOLDER} holds no outputs folder")


def parse_tree(body: bytes, *, skipped: set[str] | None = None) -> dict[str, str]:
    """slug -> the git blob sha of its Mac manifest, from the tree listed whole.

    A listing GitHub cut short is refused: titles missing from half a listing would be
    removed as if Fleet had dropped them.
    """
    tree = _json(body, host=API_HOST, what="the catalog's file listing")
    entries = tree.get("tree") if isinstance(tree, dict) else None
    if not isinstance(entries, list):
        raise _not_the_catalogue("the catalog's file listing is not a list of files")
    if tree.get("truncated"):
        raise CheckFailed(
            OUTCOME_UNEXPECTED,
            "GitHub cut its listing of Fleet's catalog short, which it does past 100,000 files or 7 MB, so the "
            f"listing is not the whole catalog. {_KEPT} This build cannot read a catalog that large "
            "(docs/troubleshooting.md §27).",
        )
    manifests: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") != "blob":
            continue
        path, sha = entry.get("path"), entry.get("sha")
        match = _MANIFEST_PATH.fullmatch(path) if isinstance(path, str) else None
        if match and isinstance(sha, str) and _SHA.fullmatch(sha):
            manifests[match.group(1)] = sha
        elif skipped is not None and isinstance(path, str) and path.count("/") == 1 and path.endswith("/darwin.json"):
            skipped.add(match.group(1) if match else "unrecognized Mac manifest path")
    if not manifests:
        raise _not_the_catalogue("the catalog's file listing holds no Mac manifest")
    return manifests


def parse_index(body: bytes, *, skipped: set[str] | None = None) -> dict[str, tuple[str, str]]:
    """slug -> (name, bundle identifier) for the Mac titles `apps.json` lists.

    A row this container could not hold whole (a name or identifier past the column, or
    missing) is left out rather than cut to fit, and its manifest is then reported skipped.
    So is a slug listed twice with a different name or identifier: no copy is taken as
    Fleet's, so a title held already keeps its row and a new one stays unlisted (#927). Two
    copies that agree are one title.
    """
    index = _json(body, host=RAW_HOST, what="the catalog's index (apps.json)")
    apps = index.get("apps") if isinstance(index, dict) else None
    if not isinstance(apps, list):
        raise _not_the_catalogue("the catalog's index (apps.json) holds no list of apps")
    titles: dict[str, tuple[str, str]] = {}
    unsettled: set[str] = set()  # a slug with a row this container cannot hold, or copies that disagree
    for app in apps:
        if not isinstance(app, dict) or app.get("platform") != "darwin":
            continue
        slug, name, identifier = app.get("slug"), app.get("name"), app.get("unique_identifier")
        key = slug.removesuffix("/darwin") if isinstance(slug, str) and slug.endswith("/darwin") else ""
        if not re.fullmatch(SLUG_PATTERN, key):
            if skipped is not None:
                skipped.add("unrecognized Mac index entry")
            continue
        name = name.strip() if isinstance(name, str) else ""
        identifier = identifier.strip() if isinstance(identifier, str) else ""
        title = (name, identifier)
        whole = bool(name and identifier) and len(name) <= 255 and len(identifier) <= 255
        # Held the first time the slug is seen; a later copy that differs unsettles it.
        if not whole or titles.setdefault(key, title) != title:
            unsettled.add(key)
    if skipped is not None:
        skipped.update(unsettled)
    titles = {key: title for key, title in titles.items() if key not in unsettled}
    if not titles:
        raise _not_the_catalogue("the catalog's index (apps.json) lists no Mac app")
    return titles


def parse_manifest(body: bytes) -> str | None:
    """A manifest's current version, or None when it does not carry one this container can
    hold. Nothing else in the manifest is read: not the installer address, not the scripts
    under `refs`, not the queries."""
    try:
        manifest = json.loads(body)
    except ValueError:
        return None
    versions = manifest.get("versions") if isinstance(manifest, dict) else None
    first = versions[0] if isinstance(versions, list) and versions else None
    version = first.get("version") if isinstance(first, dict) else None
    if not isinstance(version, str):
        return None
    version = version.strip()
    return version if version and len(version) <= 64 else None


async def _read_manifests(
    client: httpx.AsyncClient, slugs: list[str], tally: _Tally
) -> tuple[dict[str, str | None], CheckFailed | None]:
    """slug -> its current version (None: answered, and not readable) for each manifest
    read, and the failure that stopped the reading, if one did. After a refusal or a host
    that stopped answering, the manifests not yet asked for are left for the next check."""
    versions: dict[str, str | None] = {}
    stopped: list[CheckFailed] = []
    gate = asyncio.Semaphore(_CONCURRENCY)

    async def one(slug: str) -> None:
        async with gate:
            if stopped:
                return
            try:
                body = await _get(
                    client,
                    f"{_RAW}/{slug}/darwin.json",
                    ceiling=_MAX_MANIFEST_BYTES,
                    what=f"the manifest {slug}/darwin.json",
                    tally=tally,
                )
            except _Missing:
                versions[slug] = None  # listed a moment ago and gone now: Fleet committed in between
            except CheckFailed as failed:
                if failed.outcome == OUTCOME_UNEXPECTED:
                    versions[slug] = None  # this one file is wrong; the catalogue is not
                else:
                    stopped.append(failed)
            else:
                versions[slug] = parse_manifest(body)

    await asyncio.gather(*(one(slug) for slug in slugs))
    return versions, (stopped[0] if stopped else None)


def _skipped_sentence(skipped: Collection[str]) -> str | None:
    if not skipped:
        return None
    named = ", ".join(sorted(skipped)[:5])
    more = f" and {len(skipped) - 5} more" if len(skipped) > 5 else ""
    count = "1 of Fleet's Mac manifests" if len(skipped) == 1 else f"{len(skipped)} of Fleet's Mac manifests"
    return (
        f"{count} could not be read as a title with a current version and "
        f"{'was' if len(skipped) == 1 else 'were'} left as held: {named}{more}. "
        "They are read again when Fleet next changes its catalog."
    )


async def _refuse_blocked_hosts() -> None:
    """The egress rule every other outbound caller's host passes (`app.core.egress`): a name
    that resolves to loopback or link-local is not dialled, whatever it is called."""
    for url in (_API, _RAW):
        try:
            await refuse_blocked_resolution(url, field="The Fleet catalog check", refusal=_Blocked)
        except _Blocked as exc:
            raise CheckFailed(
                OUTCOME_UNREACHABLE,
                f"{exc}, so this container did not dial it. {_KEPT} Check the container's DNS and its hosts file.",
            ) from exc


async def _state(db: AsyncSession) -> FleetCatalogState:
    state = await db.get(FleetCatalogState, 1)
    if state is None:
        state = FleetCatalogState(id=1, app_count=0)
        db.add(state)
    return state


async def check(db: AsyncSession, *, transport: httpx.AsyncBaseTransport | None = None) -> FleetCatalogState:
    """One check of Fleet's catalogue, committed: the state row says what it found, and on a
    read that got anywhere the titles are what Fleet publishes now. Never raises for a
    failure GitHub or the network caused; that is the row's `outcome` and `detail`.

    The caller holds `_lock` (`check_now` and `tick` both do), and decides whether a check
    is wanted at all: the flag is theirs to read, not this function's.
    """
    started = time.monotonic()
    now = datetime.now(UTC)
    tally = _Tally()
    state = await _state(db)
    headers = {"Accept": "application/vnd.github+json", "User-Agent": build_user_agent("fleet-catalog")}
    try:
        if transport is None:
            # A test's transport answers for both names itself; there is no resolver to ask.
            await _refuse_blocked_hosts()
        async with httpx.AsyncClient(
            timeout=_TIMEOUT_SECONDS, headers=headers, transport=transport, follow_redirects=False
        ) as client:
            outcome, detail = await _read(db, client, state, now, tally)
    except CheckFailed as failed:
        outcome, detail = failed.outcome, failed.detail
    except _Missing as missing:
        failed = _not_the_catalogue(f"it answered 404 for {missing}")
        outcome, detail = failed.outcome, failed.detail

    state.checked_at = now
    state.outcome = outcome
    state.detail = detail
    await db.flush()  # the titles this check added are counted whether or not the session autoflushes
    state.app_count = (await db.execute(select(func.count()).select_from(FleetMaintainedApp))).scalar_one()
    await db.commit()
    await db.refresh(state)

    facts = {
        "outcome": outcome,
        "titles": state.app_count,
        "manifests_read": tally.read,
        "versions_moved": tally.moved,
        "titles_added": tally.added,
        "titles_removed": tally.removed,
        "manifests_skipped": len(tally.skipped),
        "api_requests": tally.api_requests,
        "raw_requests": tally.raw_requests,
        "seconds": round(time.monotonic() - started, 2),
    }
    if outcome in FAILED:
        # The sentence, because the container log is a surface an operator reads
        # (docs/diagnosability.md §4) and a failed check has no page of its own until
        # someone opens the tab.
        logger.warning("Fleet catalog check failed: %s", detail, extra=facts)
    else:
        logger.info("Fleet catalog checked", extra=facts)
    return state


async def _read(
    db: AsyncSession, client: httpx.AsyncClient, state: FleetCatalogState, now: datetime, tally: _Tally
) -> tuple[str, str | None]:
    """The reading itself: (outcome, detail). Raises `CheckFailed` before anything is
    written, or returns a failure's words after keeping the manifests it did read."""
    tree_sha = parse_contents(
        await _get(client, CONTENTS_URL, ceiling=_MAX_LISTING_BYTES, what=f"the folder {FOLDER}", tally=tally)
    )
    if tree_sha == state.tree_sha:
        detail = (
            None
            if state.snapshot_status == "complete"
            else (
                "The catalog tree is unchanged. The held snapshot still has unread Mac titles. "
                "They are checked again when Fleet changes its catalog."
            )
        )
        return OUTCOME_UNCHANGED, detail

    manifests = parse_tree(
        await _get(
            client,
            f"{_API}/git/trees/{tree_sha}?recursive=1",
            ceiling=_MAX_LISTING_BYTES,
            what="the catalog's file listing",
            tally=tally,
        ),
        skipped=tally.skipped,
    )
    index = parse_index(
        await _get(client, f"{_RAW}/apps.json", ceiling=_MAX_INDEX_BYTES, what="the catalog's index (apps.json)", tally=tally),
        skipped=tally.skipped,
    )

    held = {row.slug: row for row in (await db.execute(select(FleetMaintainedApp))).scalars().all()}
    listed = sorted(slug for slug in manifests if slug in index)
    # Either direction leaves an unverified Mac title. Retain any previously held
    # copy while the manifest and index disagree.
    tally.skipped.update(manifests.keys() ^ index.keys())
    wanted = [slug for slug in listed if slug not in held or held[slug].manifest_sha != manifests[slug]]
    versions, stopped = await _read_manifests(client, wanted, tally)

    changed = False
    for slug in listed:
        name, bundle_id = index[slug]
        row = held.get(slug)
        if slug in versions:
            version = versions[slug]
            if version is None:
                tally.skipped.add(slug)
                continue
            tally.read += 1
            if row is None:
                db.add(
                    FleetMaintainedApp(
                        slug=slug,
                        name=name,
                        bundle_id=bundle_id,
                        latest_version=version,
                        first_seen_at=now,
                        manifest_sha=manifests[slug],
                        updated_at=now,
                    )
                )
                tally.added += 1
                changed = True
                continue
            if version != row.latest_version:
                row.previous_version = row.latest_version
                row.latest_version = version
                row.version_changed_at = now
                tally.moved += 1
                changed = True
            row.manifest_sha = manifests[slug]
            row.updated_at = now
        if row is not None and (row.name, row.bundle_id) != (name, bundle_id):
            # The index renamed a title whose manifest did not move.
            row.name, row.bundle_id, row.updated_at = name, bundle_id, now
            changed = True

    if stopped is not None:
        # Once any rows have moved, they no longer represent the previous tree.
        # Clear its SHA so a remote revert cannot short-circuit reconciliation.
        if not tally.read and not changed:
            return stopped.outcome, stopped.detail
        state.tree_sha = None
        state.snapshot_status = "partial"
        if changed:
            state.changed_at = now
        return stopped.outcome, (
            f"{stopped.detail.replace(_KEPT + ' ', '')} {tally.read} of the {len(wanted)} manifests that had changed "
            "were read and kept; the next check reads the rest."
        )

    gone = held.keys() - manifests.keys() - index.keys() - tally.skipped
    if gone:
        await db.execute(delete(FleetMaintainedApp).where(FleetMaintainedApp.slug.in_(gone)))
        tally.removed = len(gone)
        changed = True
    state.tree_sha = tree_sha
    state.snapshot_status = "partial" if tally.skipped else "complete"
    if changed or state.changed_at is None:
        state.changed_at = now
    return OUTCOME_OK, _skipped_sentence(tally.skipped)


# --- who may ask, and when ------------------------------------------------------------

_lock = asyncio.Lock()


async def enabled(db: AsyncSession) -> bool:
    """Whether this session's organization has the flag on, read the way the flags API reads
    it: an absent row is off."""
    flag = (
        await db.execute(select(FeatureFlag.enabled).where(FeatureFlag.key == FLEET_MAINTAINED_APPS_FLAG))
    ).scalar_one_or_none()
    return bool(flag)


async def any_organization_enabled() -> bool:
    """Whether any organization on this instance has the flag on. The catalogue is one global
    copy, so one organization wanting it is enough to read it, and none is the rule that
    keeps an instance that never asked for this from calling GitHub about it."""
    for tenant_id in await operational_tenant_ids():
        async with tenant_job(tenant_id) as db:
            if await enabled(db):
                return True
    return False


def due(state: FleetCatalogState | None, now: datetime) -> bool:
    """Once a day after a check that got an answer, and within the hour after one that did not."""
    if state is None or state.checked_at is None:
        return True
    if state.tree_sha is None and state.snapshot_status == "partial" and state.outcome not in FAILED:
        return True  # upgrade invalidated the old listing, and its last check did not fail
    interval = _FAILURE_INTERVAL if state.outcome in FAILED else _SUCCESS_INTERVAL
    return now - state.checked_at >= interval


async def check_now(db: AsyncSession, *, transport: httpx.AsyncBaseTransport | None = None) -> FleetCatalogState:
    """A person's check, from the Fleet catalog tab. Never waits on a check in flight: the
    one running writes the row this one would, so the caller is told it is running."""
    if _lock.locked():
        raise CheckBusy
    async with _lock:
        return await check(db, transport=transport)


async def tick(*, transport: httpx.AsyncBaseTransport | None = None) -> FleetCatalogState | None:
    """The scheduler's hourly look: a check when one is due and some organization has the
    flag on, and otherwise nothing, with no request made. Returns the state a check wrote,
    or None when it did not check."""
    if not await any_organization_enabled():
        return None
    # Tested and then entered with no await in between, which on one event loop is an atomic
    # claim (the exchange's lock is taken the same way, `app.core.sharing.exchange_lock`).
    if _lock.locked():
        return None
    async with _lock:
        # The catalogue is global, like Jamf's patch catalogue: no tenant, the system actor.
        actor_token = set_actor(SYSTEM)
        try:
            async with unscoped_session() as db:
                if not due(await db.get(FleetCatalogState, 1), datetime.now(UTC)):
                    return None
                return await check(db, transport=transport)
        finally:
            reset_actor(actor_token)
