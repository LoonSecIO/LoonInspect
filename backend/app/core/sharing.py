"""Snapshot assembly for community data sharing (docs/data-sharing.md).

Builds the exact request body the v1 exchange sends — which is also what the
Settings page's "show exactly what would be sent now" button renders. One code
path for both is the point: the preview cannot drift from the wire.

The exchange job itself (scheduling, transport, the share log) landed as
INSPECT-0048 and lives in the second half of this file — main.py's
sharing_exchange_tick drives it, so the module now has two callers: the preview
endpoint and the scheduler.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch

import httpx
from sqlalchemy import delete, distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.content_keys import os_key
from app.core.user_agent import build_user_agent
from app.core.version import get_app_version
from app.models.schema import DataSharingSettings, Device, InstalledApp, ShareLog

CONTRACT_VERSION = "v1"


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
    return row


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
    row.updated_at = datetime.now(timezone.utc)
    await db.commit()


def _excluded(bundle_id: str, globs: list[str]) -> bool:
    return any(fnmatch(bundle_id, pattern) for pattern in globs)


async def build_exchange_request(db: AsyncSession, settings_row: DataSharingSettings) -> dict:
    """The v1 exchange request body, aggregated in SQL: distinct tuples with counts,
    never per-device rows. `reveals` is always empty here — answers to reveal
    requests are assembled by the exchange job (`build_reveals`, below), because they
    depend on the previous response, which a preview does not have."""
    globs = list(settings_row.exclude_globs or [])

    app_rows = (
        await db.execute(
            select(
                InstalledApp.key_title,
                InstalledApp.key_full,
                func.max(InstalledApp.bundle_id).label("bundle_id"),
                func.count(distinct(InstalledApp.device_id)).label("count"),
            ).group_by(InstalledApp.key_title, InstalledApp.key_full)
        )
    ).all()

    apps = [
        {"title": row.key_title, "full": row.key_full, "count": row.count}
        for row in app_rows
        if not _excluded(row.bundle_id, globs)
    ]

    # Devices carry os_version today but no build, model, or arch — those columns
    # don't exist yet. The os key hashes what we have (missing fields are the empty
    # string, per the canonicalization contract) and hardware stays an empty list
    # until the inventory grows the fields; the contract's shape doesn't change.
    os_rows = (
        await db.execute(
            select(Device.os_version, func.count(Device.id).label("count"))
            .where(Device.os_version.is_not(None))
            .group_by(Device.os_version)
        )
    ).all()
    os_tuples = [
        {"key": os_key("macos", row.os_version, None), "count": row.count} for row in os_rows
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
_LOG_RETENTION = timedelta(days=90)


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
        entry["versions"].append(
            {"version": row.version, "short_version": row.short_version, "count": row.count}
        )
    return list(by_title.values())


def apply_response(settings_row: DataSharingSettings, response: dict) -> None:
    """Response semantics, tolerant by contract: every field optional, unknown fields
    ignored, absent capabilities mean "nothing today" — never an error."""
    if response.get("revoke") is True:
        # Server-side kill switch: stop sharing until an admin re-consents.
        settings_row.tier = "off"
        settings_row.pending_reveal_keys = []
        return

    requests = response.get("reveal_requests")
    if settings_row.tier == "reveal" and isinstance(requests, list):
        settings_row.pending_reveal_keys = [k for k in requests if isinstance(k, str)][:1000]
    else:
        # Answered (or tier forbids answering); either way yesterday's asks are done.
        settings_row.pending_reveal_keys = []

    # response["verdicts"] is deliberately untouched: reserved in the v1 contract,
    # schema unsettled, activated server-side post-V0. Parsing it here would freeze
    # a shape the design doc explicitly leaves open.


@dataclass(frozen=True)
class ExchangeResult:
    """What came back, and whether the reveals had to be shed to get it.

    The response body alone cannot tell the caller that: a 200 to a reveal-less retry
    is byte-identical to a 200 to the whole submission. The share log needs the
    difference, because on a shed day the row's payload is a superset of the body the
    server actually accepted (docs/data-sharing.md, "The share log")."""

    response: dict
    reveals_shed: bool = False


async def post_exchange(
    request_body: dict, *, transport: httpx.AsyncBaseTransport | None = None
) -> ExchangeResult:
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
    async with httpx.AsyncClient(timeout=10.0, transport=transport) as client:
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
    row = (
        await db.execute(select(func.max(ShareLog.occurred_at)).where(ShareLog.tier != "ai"))
    ).scalar_one_or_none()
    return row


def _due(now: datetime, last: datetime | None, minute_of_day: int) -> bool:
    """Due once per day, at or after the jittered minute. A container that was down
    at its slot sends at the first tick after it; one that already attempted today
    (any outcome) waits for tomorrow."""
    target = now.replace(hour=minute_of_day // 60, minute=minute_of_day % 60, second=0, microsecond=0)
    if now < target:
        return False
    return last is None or last < target


async def run_exchange(db: AsyncSession, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
    """One tenant's daily exchange, called from the scheduler tick with a
    tenant-bound session. Assumes due-ness was already decided."""
    settings_row = await get_or_create_settings(db)
    if settings_row.tier == "off":
        return

    now = datetime.now(timezone.utc)

    if not app_settings.community_sharing:
        # The env override wins, visibly: one skipped row per day keeps the share
        # log honest about why nothing is leaving.
        db.add(
            ShareLog(
                occurred_at=now,
                tier=settings_row.tier,
                endpoint=app_settings.sharing_endpoint,
                outcome="skipped_env",
            )
        )
        await db.commit()
        return

    request_body = await build_exchange_request(db, settings_row)
    request_body["reveals"] = await build_reveals(db, settings_row)

    log = ShareLog(
        occurred_at=now,
        tier=settings_row.tier,
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
        log.error = str(exc)[:2000]
    else:
        response = result.response
        log.outcome = "sent"
        # Only ever true on the success path: a run that shed and then failed anyway
        # sent nothing the server kept, so "failed" is the whole story of that row.
        log.reveals_shed = result.reveals_shed
        log.reveal_requests = response.get("reveal_requests") if isinstance(response, dict) else None
        apply_response(settings_row, response if isinstance(response, dict) else {})

    db.add(log)
    await db.execute(delete(ShareLog).where(ShareLog.occurred_at < now - _LOG_RETENTION))
    await db.commit()


async def exchange_due(db: AsyncSession) -> bool:
    settings_row = await get_or_create_settings(db)
    if settings_row.tier == "off":
        return False
    return _due(
        datetime.now(timezone.utc),
        await _last_attempt_at(db),
        _jitter_minute_of_day(settings_row),
    )
