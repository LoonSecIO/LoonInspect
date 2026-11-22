"""Metadata-only daily inference and summary workload accounting."""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert

from app.core.database import bound_tenant_id, session_for_tenant
from app.models.schema import AIUsageDaily as Daily
from app.models.schema import InventorySummaryJob as Job

RETENTION_DAYS = 90
logger = logging.getLogger(__name__)
MEASURES = (
    "events",
    "request_ms",
    "input_tokens",
    "input_reports",
    "output_tokens",
    "output_reports",
    "cached_tokens",
    "cache_reports",
    "provider_ms",
    "provider_reports",
    "queue_wait_ms",
    "max_queue_wait_ms",
)


async def add(db, *, feature, provider, outcome, kind, requested="", reported="", at=None, **measurements):
    values = {"events": 1, **measurements}
    statement = insert(Daily).values(
        day=(at or datetime.now(UTC)).date(),
        feature=feature,
        provider=provider,
        requested=requested[:200],
        reported=reported[:200],
        outcome=outcome,
        kind=kind,
        **values,
    )
    update = {k: getattr(Daily, k) + getattr(statement.excluded, k) for k in values}
    if "max_queue_wait_ms" in values:
        update["max_queue_wait_ms"] = func.greatest(Daily.max_queue_wait_ms, statement.excluded.max_queue_wait_ms)
    await db.execute(statement.on_conflict_do_update(index_elements=list(Daily.__table__.primary_key), set_=update))


def recorder(db, feature, provider, requested):
    async def write(outcome, result, elapsed_ms):
        values = {"request_ms": elapsed_ms}
        for field, coverage in (
            ("input_tokens", "input_reports"),
            ("completion_tokens", "output_reports"),
            ("cached_tokens", "cache_reports"),
            ("provider_ms", "provider_reports"),
        ):
            value = getattr(result, field, None)
            if value is not None:
                values["output_tokens" if field == "completion_tokens" else field] = value
                values[coverage] = 1
        try:
            async with session_for_tenant(bound_tenant_id(db)) as session:
                await add(
                    session,
                    feature=feature,
                    provider=provider,
                    requested=requested,
                    reported=(result.model or "") if result else "",
                    outcome=outcome,
                    kind="call",
                    **values,
                )
                await session.commit()
        except Exception:
            logger.exception("AI usage could not be saved. Check database availability and the AI usage migration.")

    return write


async def queue_event(db, provider, outcome, at, wait_ms=None):
    measures = {} if wait_ms is None else {"queue_wait_ms": wait_ms, "max_queue_wait_ms": wait_ms}
    await add(db, feature="inventory_summary", provider=provider, kind="queue", outcome=outcome, at=at, **measures)


async def prune(db, today):
    # retention-clock: ai-usage — daily counts expire even while the feature is switched off.
    await db.execute(delete(Daily).where(Daily.day < today - timedelta(days=RETENTION_DAYS - 1)))


async def usage_report(db, start, end):
    first = await db.scalar(select(func.min(Daily.day)))
    names = ("feature", "provider", "requested", "reported", "outcome")
    dimensions = [getattr(Daily, n) for n in names]
    window = (Daily.day >= start, Daily.day <= end)
    measures = [func.sum(getattr(Daily, k)).label(k) for k in MEASURES[:10]]
    calls = (
        (
            await db.execute(
                select(*dimensions, *measures).where(*window, Daily.kind == "call").group_by(*dimensions).order_by(*dimensions)
            )
        )
        .mappings()
        .all()
    )
    queue = (
        (
            await db.execute(
                select(Daily.day, Daily.provider, Daily.outcome, Daily.events, Daily.queue_wait_ms, Daily.max_queue_wait_ms)
                .where(*window, Daily.kind == "queue")
                .order_by(Daily.day, Daily.provider, Daily.outcome)
            )
        )
        .mappings()
        .all()
    )
    pending, oldest = (
        await db.execute(select(func.count(), func.min(Job.created_at)).where(Job.status.in_(("pending", "processing"))))
    ).one()
    now = datetime.now(UTC)
    return {
        "firstMeasured": first,
        "retentionDays": RETENTION_DAYS,
        "calls": calls,
        "queue": queue,
        "pending": pending,
        "oldestPendingSeconds": max(0, (now - oldest).total_seconds()) if oldest else None,
    }
