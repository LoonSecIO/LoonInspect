"""Snapshot assembly for community data sharing (docs/data-sharing.md).

Builds the exact request body the v1 exchange sends — which is also what the
Settings page's "show exactly what would be sent now" button renders. One code
path for both is the point: the preview cannot drift from the wire.

The exchange job itself (scheduling, transport, the share log) landed as
INSPECT-0048 and lives in the second half of this file — main.py's
sharing_exchange_tick drives it. Since INSPECT-0408 an administrator's **Send now**
drives it too, through the same `run_exchange`, so the module has three callers: the
preview endpoint, the scheduler, and the button.

The conversation carries a second half now (#248): the response may point at the
published vulnerability corpus, and `run_exchange` hands that pointer to
`app.core.vuln_library`, which downloads and verifies an epoch only when its signature
has moved. That is where the reciprocity in the paragraph above stops being a claim —
the feed and the sharing are literally one request.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatch
from urllib.parse import urlsplit

import httpx
from sqlalchemy import delete, distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.content_keys import os_key
from app.core.tenancy import get_tenant_id
from app.core.user_agent import build_user_agent
from app.core.version import get_app_version
from app.core.vuln import install_tenant_tier
from app.core.vuln_library import CorpusPointer, corpus_pointer, load_epoch_if_new
from app.models.schema import DataSharingSettings, Device, InstalledApp, ShareLog

CONTRACT_VERSION = "v1"

# The population every snapshot row came from (#231) is read off `devices.platform` per
# row since #233 — the constant that stood in while the column did not exist was deleted
# rather than edited, as its own comment said it would be. Both row kinds group by the
# column, so one submission states a platform per row and can never state it two ways.
#
# Spelling is the content-key OS domain's, not the sourcetype segment's (Kyle, 2026-09-02):
# `macos` in the column, `mac` in `app.core.wire_vocabulary`. Both are frozen, they are
# different namespaces, and neither was renamed to match the other.


async def get_or_create_settings(db: AsyncSession) -> DataSharingSettings:
    """The tenant's consent row, created with the defaults on first access.

    Lazy creation mirrors FeatureFlag: an absent row and the defaults are the same
    state, and materializing it on first touch gives the submission UUID a single
    stable birth rather than a special case in every reader.

    Which is exactly why the default has to be `off` (see the column's comment): this
    runs from `exchange_due` on the scheduler tick, so on any install nobody has
    answered for, the first thing that touches consent is the machinery that acts on
    it. A permissive default here is consent manufactured by the reader.
    """
    row = (await db.execute(select(DataSharingSettings))).scalar_one_or_none()
    if row is None:
        row = DataSharingSettings()
        db.add(row)
        await db.commit()
        await db.refresh(row)
    remember_tier(row)
    return row


def remember_tier(row: DataSharingSettings) -> None:
    """Tell the corpus gate what this tenant's consent row now says (#248, §8).

    Called wherever the row is read and again wherever it is written, so a tier changed in
    this process takes effect on the next page rather than at the next exchange. The gate
    itself is `app.core.vuln.loaded_corpus`, and it is fail-closed: forgetting this call
    costs a tenant its summary until the next read, never the other way round.
    """
    tenant_id = get_tenant_id()
    if tenant_id is not None:
        install_tenant_tier(tenant_id, row.tier)


async def record_setup_choice(db: AsyncSession, *, share: bool) -> None:
    """Write the first-run wizard's answer, including when the answer is yes.

    A "yes" used to be recorded by writing nothing at all — the box was pre-checked,
    the default was "reveal", so a checked box and an unanswered install were the same
    row. That is the whole finding: it made the two indistinguishable in the one place
    that decides whether bytes leave. Now both answers are written, and `updated_at` is
    stamped either way, so the row says *someone answered* and not merely *what it
    says today*.

    Called by the setup endpoint after the account commit rather than folded into it:
    `get_or_create_settings` commits, and hoisting that above `create_session` would
    land the first administrator without the session that signs them in if anything
    below it failed.
    """
    row = await get_or_create_settings(db)
    row.tier = "reveal" if share else "off"
    row.updated_at = datetime.now(UTC)
    await db.commit()
    remember_tier(row)


def _excluded(bundle_id: str, globs: list[str]) -> bool:
    return any(fnmatch(bundle_id, pattern) for pattern in globs)


async def build_exchange_request(db: AsyncSession, settings_row: DataSharingSettings) -> dict:
    """The v1 exchange request body, aggregated in SQL: distinct tuples with counts,
    never per-device rows. `reveals` is always empty here — answers to reveal
    requests are assembled by the exchange job (`build_reveals`, below), because they
    depend on the previous response, which a preview does not have.

    Every snapshot row names its platform (#231). The cloud corpus tables are partitioned
    by platform (Kyle, R4), so the content key alone cannot route a row to a table — and a
    sha256 is not a routing token even when the platform was hashed into it. Per row rather
    than once per submission because one container will read computers *and* mobile from a
    single connection (docs/mobile-devices.md §2), at which point an envelope field would
    have to be deprecated rather than extended.

    Stating it is additive and costs one key. Not stating it means the cloud holds older
    rows with no platform and newer rows with one, and nothing but the container release
    history to date the boundary — the same argument #230 made at `posture_snapshot`, here
    with someone else's data and no way to backfill summed counts."""
    globs = list(settings_row.exclude_globs or [])

    app_rows = (
        await db.execute(
            select(
                InstalledApp.key_title,
                InstalledApp.key_full,
                Device.platform,
                func.max(InstalledApp.bundle_id).label("bundle_id"),
                func.count(distinct(InstalledApp.device_id)).label("count"),
            )
            .join(Device, Device.id == InstalledApp.device_id)
            .group_by(InstalledApp.key_title, InstalledApp.key_full, Device.platform)
        )
    ).all()

    apps = [
        {
            "title": row.key_title,
            "full": row.key_full,
            "count": row.count,
            "platform": row.platform,
        }
        for row in app_rows
        if not _excluded(row.bundle_id, globs)
    ]

    # Devices carry os_version today but no build, model, or arch — those columns
    # don't exist yet. The os key hashes what we have (missing fields are the empty
    # string, per the canonicalization contract) and hardware stays an empty list
    # until the inventory grows the fields; the contract's shape doesn't change.
    os_rows = (
        await db.execute(
            select(Device.platform, Device.os_version, func.count(Device.id).label("count"))
            .where(Device.os_version.is_not(None))
            .group_by(Device.platform, Device.os_version)
        )
    ).all()
    # The os key already hashes the platform, and the row states it anyway: the hash is not
    # reversible into a partition name, so a reader routing os rows would otherwise have to
    # guess-and-check the whole OS vocabulary against every key. The same column as the app
    # rows above, so a row's key and its stated platform cannot disagree.
    os_tuples = [
        {
            "key": os_key(row.platform, row.os_version, None),
            "count": row.count,
            "platform": row.platform,
        }
        for row in os_rows
    ]

    return {
        "contract": CONTRACT_VERSION,
        "submission": str(settings_row.submission_uuid),
        "tier": settings_row.tier,
        "build": get_app_version(),
        "snapshot": {"apps": apps, "os": os_tuples, "hardware": []},
        "reveals": [],
    }


# --- The daily exchange -----------------------------------------------------------
#
# One conversation per tenant per day (docs/data-sharing.md): the snapshot above goes
# up, whatever the server currently implements comes back. Reveal requests are stored
# and answered in the NEXT exchange; a collector answering {} is a valid peer.

logger = logging.getLogger(__name__)

_RETRY_DELAYS = (2, 8, 30)
_TIMEOUT_SECONDS = 10.0
_LOG_RETENTION = timedelta(days=90)

# What started an exchange, on its share-log row (#408). `manual` is the runs table's word
# for an operator's click; the scheduled case is `scheduled`, the contract's word, because
# `sweep` — what runs call it — would name the wrong job. AI rows share the log and carry
# neither: they are not exchanges.
TRIGGER_SCHEDULED = "scheduled"
TRIGGER_MANUAL = "manual"


async def build_reveals(db: AsyncSession, settings_row: DataSharingSettings) -> list[dict]:
    """Answers to the previous response's requests — plaintext for the title keys the
    server asked about, version tuples included. Empty unless the tier permits."""
    pending = list(settings_row.pending_reveal_keys or [])
    if settings_row.tier != "reveal" or not pending:
        return []

    # The exclude list has to be applied here too, and this is the path where it
    # actually matters: the snapshot sends content-hash keys, while this one sends the
    # plaintext name. An operator who excluded com.acme.* and watched it drop out of
    # the preview would otherwise still have those names cross the wire the moment the
    # server asked about the title (INSPECT-0174).
    globs = list(settings_row.exclude_globs or [])

    rows = (
        await db.execute(
            select(
                InstalledApp.key_title,
                InstalledApp.name,
                InstalledApp.bundle_id,
                InstalledApp.version,
                InstalledApp.short_version,
                func.count(distinct(InstalledApp.device_id)).label("count"),
            )
            .where(InstalledApp.key_title.in_(pending))
            .group_by(
                InstalledApp.key_title,
                InstalledApp.name,
                InstalledApp.bundle_id,
                InstalledApp.version,
                InstalledApp.short_version,
            )
        )
    ).all()

    by_title: dict[str, dict] = {}
    for row in rows:
        if _excluded(row.bundle_id, globs):
            continue
        entry = by_title.setdefault(
            row.key_title,
            {"title": row.key_title, "app_name": row.name, "bundle_id": row.bundle_id, "versions": []},
        )
        entry["versions"].append({"version": row.version, "short_version": row.short_version, "count": row.count})
    return list(by_title.values())


def apply_response(settings_row: DataSharingSettings, response: dict) -> CorpusPointer | None:
    """Response semantics, tolerant by contract: every field optional, unknown fields
    ignored, absent capabilities mean "nothing today" — never an error.

    Returns the response's **corpus pointer** (#248) — `{signature, asof, url}`, where the
    vulnerability library is and whether it moved — or `None` for a response that names
    none, which is every response a V0 collector sends. Returned rather than acted on:
    this function is pure and synchronous, and importing an epoch is a download and a
    transaction. `run_exchange` does that below, once the day's share-log row is durable.
    """
    if response.get("revoke") is True:
        # Server-side kill switch: stop sharing until an admin re-consents. No corpus is
        # imported on a revoke day — a container told to stop sharing does not then help
        # itself to the half of the exchange that sharing pays for.
        settings_row.tier = "off"
        settings_row.pending_reveal_keys = []
        # And the corpus this tenant already holds stops answering for it from here (§8).
        # The rows stay — they are a global artifact other tenants are entitled to — but a
        # tenant that has been told to stop sharing reads `assessment: off` again.
        remember_tier(settings_row)
        return None

    requests = response.get("reveal_requests")
    if settings_row.tier == "reveal" and isinstance(requests, list):
        settings_row.pending_reveal_keys = [k for k in requests if isinstance(k, str)][:1000]
    else:
        # Answered (or tier forbids answering); either way yesterday's asks are done.
        settings_row.pending_reveal_keys = []

    # response["verdicts"] is deliberately untouched: reserved in the v1 contract,
    # schema unsettled, activated server-side post-V0. Parsing it here would freeze
    # a shape the design doc explicitly leaves open. The Jamf-derived corpus below is a
    # SEPARATE channel and does not touch that reservation (Kyle, 2026-09-10): it ships
    # complete, keyed by content key, while `verdicts` stays the per-key community half.
    return corpus_pointer(response.get("corpus"))


@dataclass(frozen=True)
class ExchangeResult:
    """What came back, and whether the reveals had to be shed to get it.

    The response body alone cannot tell the caller that: a 200 to a reveal-less retry
    is byte-identical to a 200 to the whole submission. The share log needs the
    difference, because on a shed day the row's payload is a superset of the body the
    server actually accepted (docs/data-sharing.md, "The share log")."""

    response: dict
    reveals_shed: bool = False


async def post_exchange(request_body: dict, *, transport: httpx.AsyncBaseTransport | None = None) -> ExchangeResult:
    """POST with in-run backoff. A 413 sheds the reveals and resends on the next
    attempt in the same schedule, per the contract; anything else exhausts the delays
    and raises to the caller, whose job is to log a failed attempt and wait for
    tomorrow. The snapshot is never shrunk — shedding the reveals is the only relief
    the container has, which is why the contract requires the server never to 413 a
    reveal-less body.

    "Anything else" includes a 200 whose body is not JSON — a captive portal or a
    misconfigured CDN answering with text/html. `response.json()` raises
    `json.JSONDecodeError`, a `ValueError` and not an `httpx.HTTPError`, so it is
    caught alongside one here (the same pairing `update_check._fetch_head_sha` uses
    against the same hazard). Without it the decode error escaped the loop and the
    caller both, and the day's attempt was never logged."""
    headers = {"User-Agent": build_user_agent("exchange")}
    async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS, transport=transport) as client:
        body = request_body
        # Sticky rather than recomputed from `body`: it is the record of what this run
        # gave up, and it has to survive into the result that reports the eventual 200.
        reveals_shed = False
        last_error: Exception | None = None
        for delay in (0, *_RETRY_DELAYS):
            if delay:
                await asyncio.sleep(delay)
            try:
                response = await client.post(app_settings.sharing_endpoint, json=body, headers=headers)
                if response.status_code == 413 and body.get("reveals"):
                    body = {**body, "reveals": []}
                    reveals_shed = True
                    continue
                response.raise_for_status()
                return ExchangeResult(response.json() if response.content else {}, reveals_shed)
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
        raise last_error if last_error else RuntimeError("exchange failed")


def _failure_sentence(exc: Exception) -> str:
    """A failed attempt's `error`, in the operator's words: who failed, and the detail
    that says why (docs/troubleshooting.md §5, step 6 maps each shape to the next check).

    It used to be `str(exc)` — httpx's vocabulary, read only by someone who downloaded the
    NDJSON. Send now (#408) puts it on the page, so it is written for the page: the host
    rather than the whole URL, the collector's own reason where it gave one, and how many
    times the run tried, since every shape below is the *last* attempt's.
    """
    host = urlsplit(app_settings.sharing_endpoint).hostname or app_settings.sharing_endpoint
    tried = f" Tried {len(_RETRY_DELAYS) + 1} times."
    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        said = f"The collector at {host} answered {response.status_code} {response.reason_phrase}"
        if response.has_redirect_location:
            # Where to, by host only: a captive portal's redirect can carry a session in
            # its query string, and the host is the part that names who is answering.
            said += f", redirecting to {urlsplit(response.headers['location']).hostname or 'another address'}"
        else:
            # The collector's reason where it gave one (the Support collector answers a 400
            # with {"error": …}), collapsed to one line and bounded: this is untrusted text
            # from the far end, stored and shown as text, never as markup.
            reason = " ".join(response.text.split())[:200]
            if reason:
                said += f": {reason}"
        return said + "." + tried
    if isinstance(exc, httpx.TimeoutException):
        return f"No answer from {host} within {_TIMEOUT_SECONDS:g} seconds." + tried
    if isinstance(exc, httpx.ConnectError):
        # DNS, a refused connection and a TLS failure all arrive here; httpx's text names
        # which (`Name or service not known`, `CERTIFICATE_VERIFY_FAILED`, …).
        return f"Could not connect to {host}: {exc}." + tried
    if isinstance(exc, ValueError):
        # post_exchange's undecodable-200 case (#82).
        return (
            f"{host} answered 200 with a body that is not JSON, so something other than the collector "
            "answered — usually a proxy or a captive portal." + tried
        )
    return f"The exchange to {host} failed: {type(exc).__name__}: {exc}." + tried


def _jitter_minute_of_day(settings_row: DataSharingSettings) -> int:
    """Stable per-tenant minute in [0, 1440): the herd-prevention the contract
    promises, derived from the submission UUID so operators never schedule to the
    minute themselves."""
    return settings_row.submission_uuid.int % 1440


async def _last_attempt_at(db: AsyncSession) -> datetime | None:
    # AI-inference rows share the log (app.core.ai writes tier "ai" — one log is the
    # point) but are not exchange attempts: without this filter, one permitted
    # inference call after the day's slot would suppress the community exchange.
    # The literal rather than ai.AI_SHARE_TIER because ai imports this module.
    row = (await db.execute(select(func.max(ShareLog.occurred_at)).where(ShareLog.tier != "ai"))).scalar_one_or_none()
    return row


def _due(now: datetime, last: datetime | None, minute_of_day: int) -> bool:
    """Due once per day, at or after the jittered minute. A container that was down
    at its slot sends at the first tick after it; one that already attempted today
    (any outcome) waits for tomorrow.

    A Send now counts like any other attempt (#408), which is what keeps the button from
    moving the schedule: one sent after today's slot is that day's exchange, and one sent
    before the slot leaves the slot owed, so the scheduled exchange still runs."""
    target = now.replace(hour=minute_of_day // 60, minute=minute_of_day % 60, second=0, microsecond=0)
    if now < target:
        return False
    return last is None or last < target


async def run_exchange(
    db: AsyncSession,
    *,
    trigger: str = TRIGGER_SCHEDULED,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ShareLog | None:
    """One tenant's exchange, with a tenant-bound session: from the scheduler tick, which
    has already decided it is due, or from Send now (`trigger="manual"`, #408), which does
    not ask. Either way the caller holds the tenant's `exchange_lock`.

    Returns the share-log row it wrote — the button shows it — or None when the tier is
    off and nothing was attempted."""
    settings_row = await get_or_create_settings(db)
    if settings_row.tier == "off":
        return None

    now = datetime.now(UTC)

    if not app_settings.community_sharing:
        # The env override wins, visibly: one skipped row per day keeps the share
        # log honest about why nothing is leaving.
        skipped = ShareLog(
            occurred_at=now,
            tier=settings_row.tier,
            trigger=trigger,
            endpoint=app_settings.sharing_endpoint,
            outcome="skipped_env",
        )
        db.add(skipped)
        await db.commit()
        return skipped

    request_body = await build_exchange_request(db, settings_row)
    request_body["reveals"] = await build_reveals(db, settings_row)

    pointer: CorpusPointer | None = None
    log = ShareLog(
        occurred_at=now,
        tier=settings_row.tier,
        trigger=trigger,
        endpoint=app_settings.sharing_endpoint,
        # The body this run assembled, which on a 413 day is a superset of the one the
        # server accepted — `reveals_shed` below is what records the difference.
        payload=request_body,
        outcome="failed",
        reveals_shed=False,
    )
    try:
        result = await post_exchange(request_body, transport=transport)
    except (httpx.HTTPError, ValueError) as exc:
        # Debug, not warning: an air-gapped instance with sharing left on is a
        # supported configuration, not a daily fault.
        #
        # ValueError is post_exchange's undecodable-body case (see its docstring),
        # and it has to be caught *here* too or the row below is never added: an
        # unlogged attempt is also an unconsumed day, so `exchange_due` would say
        # yes again on the next tick and a persistently bad upstream would become a
        # crash loop instead of one logged failure a day.
        logger.debug("exchange failed: %s", exc)
        log.error = _failure_sentence(exc)[:2000]
    else:
        response = result.response
        log.outcome = "sent"
        # Only ever true on the success path: a run that shed and then failed anyway
        # sent nothing the server kept, so "failed" is the whole story of that row.
        log.reveals_shed = result.reveals_shed
        log.reveal_requests = response.get("reveal_requests") if isinstance(response, dict) else None
        pointer = apply_response(settings_row, response if isinstance(response, dict) else {})

    db.add(log)
    await db.execute(delete(ShareLog).where(ShareLog.occurred_at < now - _LOG_RETENTION))
    await db.commit()

    # The corpus channel, after the day's row is durable and in its own transaction
    # (#248). Deliberately last and deliberately separate: a download and a whole-library
    # replacement must not be able to roll back the record of what left the box, and a
    # refused epoch is a logged sentence rather than an exception — the previous epoch
    # keeps answering and tomorrow's exchange tries again. An unmoved signature does not
    # download at all, which is what makes this affordable daily.
    if pointer is not None:
        await load_epoch_if_new(db, pointer, transport=transport)
    return log


async def exchange_due(db: AsyncSession) -> bool:
    settings_row = await get_or_create_settings(db)
    if settings_row.tier == "off":
        return False
    return _due(
        datetime.now(UTC),
        await _last_attempt_at(db),
        _jitter_minute_of_day(settings_row),
    )


# --- Send now (#408) ---------------------------------------------------------------
#
# Until #408 the tick was the only caller of `run_exchange`, and APScheduler's default
# max_instances=1 kept it from overlapping itself. The button is a second caller, and the
# two must not overlap for one tenant: both would POST, and both could reach
# `load_epoch_if_new`, whose replacement is delete-then-insert. The container is one
# process with one event loop (app/serve.py starts uvicorn with no workers), so a lock per
# tenant is the whole of the serialization. Neither caller ever waits on it: the tick
# skips a tenant whose lock is held — the send in flight writes the row that decides
# whether today's slot is still owed — and the button answers busy.

_exchange_locks: dict[uuid.UUID | None, asyncio.Lock] = {}


def exchange_lock(tenant_id: uuid.UUID | None) -> asyncio.Lock:
    """The tenant's exchange lock, shared by the tick and Send now. Callers test
    `locked()` and then enter it with no await in between, which on one event loop is an
    atomic claim: an uncontended `acquire` does not yield."""
    return _exchange_locks.setdefault(tenant_id, asyncio.Lock())


class ExchangeRefused(Exception):
    """Send now said no, and why, in the operator's words. The API answers 409 with the
    sentence; the page shows its own copy of the first two under a disabled button, so a
    click only ever meets the third."""


REFUSED_ENV = (
    "Nothing can be sent while COMMUNITY_SHARING=false is set in the environment (the .env file beside "
    "docker-compose.yml). Remove that line and restart the container to send."
)
REFUSED_OFF = "Sharing is off for this organization, so there is nothing to send. Choose a tier under Participation first."
REFUSED_BUSY = (
    "An exchange is already running for this organization. Its row lands in the share log when it finishes; "
    "send again after that if you still need to."
)


async def send_exchange_now(db: AsyncSession, *, transport: httpx.AsyncBaseTransport | None = None) -> ShareLog:
    """Send now (#408): this tenant's exchange, immediately, through `run_exchange` — the
    body, the 413 handling, the share-log row and the corpus import that follows are the
    daily run's, because a second builder would break the preview's promise that it
    cannot drift from the wire.

    Refuses in words rather than writing a row: under the environment override nothing is
    attempted, so there is nothing to log (the daily `skipped_env` row stays the day's
    record), and an off tier has nothing to send. The schedule does not move — see `_due`.
    """
    settings_row = await get_or_create_settings(db)
    if not app_settings.community_sharing:
        raise ExchangeRefused(REFUSED_ENV)
    if settings_row.tier == "off":
        raise ExchangeRefused(REFUSED_OFF)

    lock = exchange_lock(get_tenant_id())
    if lock.locked():
        raise ExchangeRefused(REFUSED_BUSY)
    async with lock:
        row = await run_exchange(db, trigger=TRIGGER_MANUAL, transport=transport)
    if row is None:
        # The tier was turned off between the check above and the run's own read of it.
        raise ExchangeRefused(REFUSED_OFF)
    return row
