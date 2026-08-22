"""Collections — what to collect from a connection, and when (#27).

The connection carries credentials; a collection carries the rest. This module owns the
defaults a connection starts with, the run of a single collection, the connection-level
"run everything" entry point, and the minute tick's claim-and-run loop. The schedule
arithmetic is app.core.scheduling; the Jamf primitives are app.mdm.service.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.scheduling import (
    KIND_CATALOG,
    KIND_DEVICE_SWEEP,
    KIND_WEBHOOK,
    RUNNABLE_KINDS,
    Schedule,
    next_due,
    validate_schedule,
    within_rate_floor,
)
from app.mdm.jamf.contract import V0_SECTIONS
from app.mdm.service import (
    TRIGGER_SWEEP,
    ConnectionSyncResult,
    run_jamf,
    run_jamf_catalog,
    set_sync_status,
)
from app.models.schema import Collection, MdmConnection, MdmSyncState
from app.schemas.payload import MdmProvider, SyncStatus

logger = logging.getLogger(__name__)

DEFAULT_SWEEP_NAME = "Full device sweep"
DEFAULT_CATALOG_NAME = "Smart group definitions"
DEFAULT_WEBHOOK_NAME = "Webhook"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def schedule_of(collection: Collection) -> Schedule:
    return Schedule(
        frequency=collection.frequency,
        timezone=collection.timezone,
        at_hour=collection.at_hour,
        at_minute=collection.at_minute,
        weekday=collection.weekday,
        interval_n=collection.interval_n,
    )


def apply_schedule(collection: Collection, now: datetime | None = None) -> None:
    """Validate the row's schedule against its kind and materialise next_due_at."""
    schedule = schedule_of(collection)
    validate_schedule(collection.kind, schedule)
    collection.next_due_at = next_due(schedule, now or _utcnow(), anchor=collection.last_run_at)


def default_collections(connection: MdmConnection, now: datetime | None = None) -> list[Collection]:
    """The rows a Jamf connection starts with. Real, visible, editable, deletable — a
    default with no row behind it is a support ticket (docs/ingest-scheduling.md §3.2).

    The full sweep inherits the old global SYNC_HOUR / SYNC_MINUTE / SYNC_TIMEZONE as
    its own schedule, so those settings become first-run defaults rather than a cron.
    The catalog's minute is spread by connection id so thirty connections do not all
    read their groups on the same minute.
    """
    now = now or _utcnow()
    sweep = Collection(
        mdm_connection_id=connection.id,
        name=DEFAULT_SWEEP_NAME,
        kind=KIND_DEVICE_SWEEP,
        enabled=True,
        sections=list(V0_SECTIONS),
        selector=None,
        quarantined_extension_attributes=[],
        frequency="daily",
        at_hour=settings.sync_hour,
        at_minute=settings.sync_minute,
        timezone=settings.sync_timezone,
    )
    catalog = Collection(
        mdm_connection_id=connection.id,
        name=DEFAULT_CATALOG_NAME,
        kind=KIND_CATALOG,
        enabled=True,
        sections=[],
        quarantined_extension_attributes=[],
        frequency="hourly",
        at_minute=(connection.id * 7 + 11) % 60,
        timezone=settings.sync_timezone,
    )
    webhook = Collection(
        mdm_connection_id=connection.id,
        name=DEFAULT_WEBHOOK_NAME,
        kind=KIND_WEBHOOK,
        enabled=True,
        sections=list(V0_SECTIONS),
        quarantined_extension_attributes=[],
        frequency=None,
    )
    for collection in (sweep, catalog, webhook):
        apply_schedule(collection, now)
    return [sweep, catalog, webhook]


async def list_collections(db: AsyncSession, connection_id: int) -> list[Collection]:
    result = await db.execute(
        select(Collection).where(Collection.mdm_connection_id == connection_id).order_by(Collection.id)
    )
    return list(result.scalars().all())


async def ensure_default_collections(db: AsyncSession, connection: MdmConnection) -> list[Collection]:
    """Add whichever default kinds the connection is missing. Flushes, does not commit.
    Only Jamf connections have collections; other providers keep the generic path."""
    if connection.provider != MdmProvider.jamf.value:
        return []
    existing = await list_collections(db, connection.id)
    present = {row.kind for row in existing}
    added = [row for row in default_collections(connection) if row.kind not in present]
    for row in added:
        db.add(row)
    if added:
        await db.flush()
    return added


# --- running ------------------------------------------------------------------------


async def run_collection(db: AsyncSession, collection: Collection, *, trigger: str) -> ConnectionSyncResult:
    """Run one collection now and record the outcome on its row."""
    connection = await db.get(MdmConnection, collection.mdm_connection_id)
    if connection is None:
        return ConnectionSyncResult(connection_id=collection.mdm_connection_id, ok=False, error="connection missing")

    started = _utcnow()
    if collection.kind == KIND_DEVICE_SWEEP:
        await set_sync_status(db, connection, SyncStatus.syncing)
        result = await run_jamf(
            db,
            connection,
            trigger=trigger,
            sections=collection.sections or V0_SECTIONS,
            selector=collection.selector,
            quarantined_extension_attributes=collection.quarantined_extension_attributes or (),
            include_catalog=True,
            collection_id=collection.id,
        )
    elif collection.kind == KIND_CATALOG:
        result = await run_jamf_catalog(db, connection, trigger=trigger, collection_id=collection.id)
    else:
        return ConnectionSyncResult(connection_id=connection.id, skipped=True, collection_id=collection.id)

    collection.last_run_at = started
    collection.last_run_status = "ok" if result.ok else "failed"
    collection.last_run_summary = {
        "trigger": trigger,
        "deviceCount": result.device_count,
        "groupCount": result.group_count,
        "observations": dict(result.observations),
        "error": result.error,
        "seconds": round((_utcnow() - started).total_seconds(), 1),
    }
    await db.commit()
    return result


async def run_connection(db: AsyncSession, connection: MdmConnection, *, trigger: str) -> ConnectionSyncResult:
    """The connection-level "run now": every enabled device sweep the connection has,
    in order. Each sweep ends with a catalog refresh, so catalog collections are not run
    here — they keep their own cadence between sweeps."""
    await ensure_default_collections(db, connection)
    await db.commit()
    sweeps = [
        row for row in await list_collections(db, connection.id) if row.kind == KIND_DEVICE_SWEEP and row.enabled
    ]
    if not sweeps:
        logger.info("connection has no enabled device sweep", extra={"connection_id": connection.id})
        return ConnectionSyncResult(connection_id=connection.id, skipped=True)

    results = [await run_collection(db, row, trigger=trigger) for row in sweeps]
    observations: dict[str, int] = {}
    for result in results:
        for key, value in result.observations.items():
            observations[key] = observations.get(key, 0) + value
    failed = [r for r in results if not r.ok]
    return ConnectionSyncResult(
        connection_id=connection.id,
        device_count=sum(r.device_count for r in results),
        ok=not failed,
        error="; ".join(r.error for r in failed if r.error) or None,
        observations=observations,
        group_count=sum(r.group_count for r in results),
        collection_id=sweeps[0].id if len(sweeps) == 1 else None,
    )


# --- the tick -----------------------------------------------------------------------


async def claim_due(db: AsyncSession, now: datetime | None = None) -> list[Collection]:
    """Claim every collection that is due in this tenant.

    The claim is one conditional UPDATE per row — `WHERE next_due_at <= now` — that
    advances next_due_at to the following occurrence. Two processes racing on the same
    row both issue it; one changes a row and runs, the other changes nothing and moves
    on. A device sweep whose connection is mid-sync is left unclaimed and retried next
    minute rather than skipped for a day; a collection inside its rate floor (a manual
    run just happened) is claimed and marked skipped, which is the floor doing its job.
    """
    now = now or _utcnow()
    candidates = (
        await db.execute(
            select(Collection).where(
                Collection.enabled.is_(True),
                Collection.kind.in_(RUNNABLE_KINDS),
                Collection.next_due_at.isnot(None),
                Collection.next_due_at <= now,
            )
        )
    ).scalars().all()
    if not candidates:
        return []

    busy = set(
        (
            await db.execute(
                select(MdmSyncState.mdm_connection_id).where(MdmSyncState.status == SyncStatus.syncing.value)
            )
        ).scalars().all()
    )

    claimed: list[Collection] = []
    for collection in candidates:
        if collection.kind == KIND_DEVICE_SWEEP and collection.mdm_connection_id in busy:
            continue
        following = next_due(schedule_of(collection), now, anchor=collection.last_run_at)
        won = (
            await db.execute(
                update(Collection)
                .where(Collection.id == collection.id, Collection.next_due_at <= now)
                .values(last_claimed_at=now, next_due_at=following)
                .returning(Collection.id)
            )
        ).scalar_one_or_none()
        if won is not None:
            claimed.append(collection)
    await db.commit()
    return claimed


async def tick_tenant(db: AsyncSession, now: datetime | None = None) -> list[ConnectionSyncResult]:
    """One tenant's slice of the minute tick: claim what is due, run it in turn."""
    now = now or _utcnow()
    results: list[ConnectionSyncResult] = []
    for collection in await claim_due(db, now):
        if within_rate_floor(collection.kind, collection.last_run_at, now):
            collection.last_run_status = "skipped"
            collection.last_run_summary = {"trigger": TRIGGER_SWEEP, "reason": "within rate floor"}
            await db.commit()
            logger.info(
                "collection skipped: within rate floor",
                extra={"collection_id": collection.id, "kind": collection.kind, "last_run_at": collection.last_run_at},
            )
            continue
        results.append(await run_collection(db, collection, trigger=TRIGGER_SWEEP))
    return results


def schedule_fields(collection: Collection) -> dict:
    return asdict(schedule_of(collection))
