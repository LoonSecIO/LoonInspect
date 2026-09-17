from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require
from app.core.config import settings
from app.core.database import get_db
from app.core.outbox import next_purge_at
from app.core.permissions import Permission
from app.models.schema import Destination, EventOutbox, OutboxDelivery
from app.schemas.outbox import DeadLetteredDeliveries, HeldEvents, OutboxDepthOut, OutboxRetention, PendingDeliveries

router = APIRouter(prefix="/api/outbox", tags=["outbox"])


def _age_seconds(oldest: datetime | None, now: datetime) -> int | None:
    return None if oldest is None else max(int((now - oldest).total_seconds()), 0)


async def _by_status(db: AsyncSession, status: str) -> tuple[int, datetime | None]:
    """Delivery rows in one state, aged from the `created_at` of the oldest event behind them
    — the same quantity the held set reports and the posture tape records."""
    row = (
        await db.execute(
            select(func.count(OutboxDelivery.id), func.min(EventOutbox.created_at))
            .select_from(OutboxDelivery)
            .join(EventOutbox, EventOutbox.id == OutboxDelivery.outbox_event_id)
            .where(OutboxDelivery.status == status)
        )
    ).one()
    return int(row[0]), row[1]


@router.get("", response_model=OutboxDepthOut, dependencies=[Depends(require(Permission.DESTINATION_READ))])
async def outbox_depth(db: AsyncSession = Depends(get_db)) -> OutboxDepthOut:
    """How deep this tenant's queue is, in the three states `app.schemas.outbox` names.

    The one thing no destination row can say: every other read path counts delivery rows and a
    held event has none, so a destination-less pod's week of baseline went unnamed, unwarned and
    purged on day seven, with `psql` the only answer — the defect `docs/diagnosability.md` says
    to file rather than write around. Tenant-scoped by the session.
    """
    now = datetime.now(UTC)
    held = select(func.count(EventOutbox.id), func.min(EventOutbox.created_at)).where(EventOutbox.fanned_out.is_(False))
    held_count, held_oldest = (await db.execute(held)).one()
    # Only asked when something is waiting: reporting a zero must not walk a second table.
    reason = None
    if held_count and not await db.scalar(select(exists().where(Destination.enabled.is_(True)))):
        reason = "no_enabled_destination"

    pending_count, pending_oldest = await _by_status(db, "pending")
    dead_count, dead_oldest = await _by_status(db, "failed")
    # When `purge_delivered_events` stops protecting it: an event is kept while it is younger
    # than the dead-letter window, so the oldest becomes purgeable one window after it was
    # produced. `nextPurgeAt` is when the row actually goes.
    expires = None if dead_oldest is None else dead_oldest + timedelta(days=settings.dead_letter_retention_days)
    return OutboxDepthOut(
        held=HeldEvents(events=int(held_count), oldest_age_seconds=_age_seconds(held_oldest, now), reason=reason),
        pending=PendingDeliveries(deliveries=pending_count, oldest_age_seconds=_age_seconds(pending_oldest, now)),
        dead_lettered=DeadLetteredDeliveries(deliveries=dead_count, oldest_expires_at=expires),
        retention=OutboxRetention(
            event_retention_days=settings.event_outbox_retention_days,
            dead_letter_retention_days=settings.dead_letter_retention_days,
            next_purge_at=next_purge_at(now),
        ),
    )
