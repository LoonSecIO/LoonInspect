from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.schema import Destination, EventOutbox, OutboxDelivery

logger = logging.getLogger(__name__)

# Extend this as new producers land (group membership changes, enrichment results).
# Validated against in schemas/destinations.py so a typo in subscribedEvents doesn't
# silently create a destination that never receives anything.
KNOWN_EVENT_TYPES = frozenset({"device.inventory.changed", "device.change", "run.completed", "run.failed"})

# Same shape as the login lockout backoff: exponential, capped, with a hard ceiling on
# total attempts so a permanently dead destination doesn't retry forever.
_BASE_BACKOFF_SECONDS = 30
_MAX_BACKOFF_SECONDS = 3600
_MAX_ATTEMPTS = 10
_MAX_BACKOFF_EXPONENT = 10  # guards against an unbounded 2**n


async def enqueue_event(
    db: AsyncSession, event_type: str, payload: dict, *, request_id: str | None = None
) -> EventOutbox:
    """Record that an event happened. Call sites add this to the session and let the
    caller commit — it must land in the same transaction as whatever state change
    produced it, so the two can never drift apart from a partial failure.

    Delivery happens later, on the outbox worker's own schedule, not here — a slow or
    down destination must never be able to block the caller. The inbound webhook
    handler (app/api/webhooks.py) is where that matters most: it needs to ACK its
    sender fast, and synchronous delivery in the request path would put a flaky SIEM
    between it and that ACK.
    """
    event = EventOutbox(event_type=event_type, payload=payload, request_id=request_id)
    db.add(event)
    await db.flush()
    return event


def _build_headers(destination: Destination) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    secret = destination.auth_secret_encrypted  # decrypted transparently on read

    if destination.auth_type == "bearer" and secret:
        headers["Authorization"] = f"Bearer {secret}"
    elif destination.auth_type == "splunk_hec" and secret:
        headers["Authorization"] = f"Splunk {secret}"
    elif destination.auth_type == "header" and destination.auth_header_name and secret:
        headers[destination.auth_header_name] = secret

    return headers


def _build_body(destination: Destination, payload: dict) -> dict:
    if destination.type == "splunk_hec":
        # HEC's raw-JSON collector endpoint expects the event wrapped, not posted
        # bare — without this, "Splunk support" would silently fail to ingest.
        return {"event": payload}
    return payload


def _next_backoff(attempt_count: int) -> datetime:
    exponent = min(attempt_count, _MAX_BACKOFF_EXPONENT)
    delay = min(_BASE_BACKOFF_SECONDS * (2**exponent), _MAX_BACKOFF_SECONDS)
    return datetime.now(timezone.utc) + timedelta(seconds=delay)


async def fan_out_pending(db: AsyncSession) -> int:
    """Create delivery rows for events that haven't been fanned out yet.

    The only place that needs to know which destinations exist and what they're
    subscribed to — keeping that logic in one spot rather than duplicating it at every
    event-producing call site is the point of splitting fan-out from delivery.
    """
    result = await db.execute(select(EventOutbox).where(EventOutbox.fanned_out.is_(False)))
    pending_events = result.scalars().all()
    if not pending_events:
        return 0

    result = await db.execute(select(Destination).where(Destination.enabled.is_(True)))
    destinations = result.scalars().all()

    created = 0
    for event in pending_events:
        for destination in destinations:
            subscribed = destination.subscribed_events
            if subscribed and event.event_type not in subscribed:
                continue
            db.add(OutboxDelivery(outbox_event_id=event.id, destination_id=destination.id))
            created += 1
        event.fanned_out = True

    await db.commit()
    return created


async def _attempt_delivery(
    client: httpx.AsyncClient, destination: Destination, event: EventOutbox
) -> tuple[bool, str | None]:
    try:
        response = await client.post(
            destination.url,
            json=_build_body(destination, event.payload),
            headers=_build_headers(destination),
            timeout=10,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        return False, f"HTTP {exc.response.status_code}: {exc.response.text[:500]}"
    except httpx.HTTPError as exc:
        return False, str(exc)[:500]
    return True, None


async def deliver_pending(db: AsyncSession) -> None:
    """Attempt every delivery that's due. Runs on its own scheduler tick, decoupled
    from whatever produced the event — a down destination here can never slow down a
    device sync or an inbound webhook's ACK."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(OutboxDelivery).where(
            OutboxDelivery.status == "pending", OutboxDelivery.next_attempt_at <= now
        )
    )
    due = result.scalars().all()
    if not due:
        return

    event_ids = {row.outbox_event_id for row in due}
    events = {
        e.id: e
        for e in (await db.execute(select(EventOutbox).where(EventOutbox.id.in_(event_ids)))).scalars().all()
    }
    destination_ids = {row.destination_id for row in due}
    destinations = {
        d.id: d
        for d in (
            await db.execute(select(Destination).where(Destination.id.in_(destination_ids)))
        ).scalars().all()
    }

    async with httpx.AsyncClient() as client:
        for delivery in due:
            destination = destinations.get(delivery.destination_id)
            event = events.get(delivery.outbox_event_id)

            if destination is None or event is None:
                # Destination was deleted (event should not be possible, but the row
                # is otherwise stuck forever if it happens).
                delivery.status = "failed"
                delivery.last_error = "destination or event no longer exists"
                continue

            if not destination.enabled:
                # Disabled after fan-out but before delivery. Left pending rather than
                # dead-lettered, so it resumes automatically if re-enabled instead of
                # failing something the operator never actually wanted attempted.
                continue

            ok, error = await _attempt_delivery(client, destination, event)
            delivery.attempt_count += 1
            delivery.last_attempted_at = now

            if ok:
                delivery.status = "delivered"
                delivery.delivered_at = now
                destination.last_success_at = now
            else:
                delivery.last_error = error
                destination.last_failure_at = now
                if delivery.attempt_count >= _MAX_ATTEMPTS:
                    delivery.status = "failed"
                    logger.warning(
                        "event delivery dead-lettered",
                        extra={
                            "destination_id": destination.id,
                            "destination_name": destination.name,
                            "event_type": event.event_type,
                            "attempts": delivery.attempt_count,
                            "error": error,
                        },
                    )
                else:
                    delivery.next_attempt_at = _next_backoff(delivery.attempt_count)

    await db.commit()


async def purge_delivered_events(db: AsyncSession, retention_days: int) -> int:
    """Deletes outbox events whose deliveries are all terminal and old enough. Without
    this the table grows without bound now that events are continuous (webhooks)
    rather than nightly-batched."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    result = await db.execute(
        select(EventOutbox.id).where(EventOutbox.created_at < cutoff, EventOutbox.fanned_out.is_(True))
    )
    candidate_ids = set(result.scalars().all())
    if not candidate_ids:
        return 0

    # Never purge an event with a delivery still mid-retry, however old it is —
    # correctness here matters more than tidiness.
    result = await db.execute(
        select(OutboxDelivery.outbox_event_id).where(
            OutboxDelivery.outbox_event_id.in_(candidate_ids),
            OutboxDelivery.status == "pending",
        )
    )
    still_pending = set(result.scalars().all())
    purge_ids = candidate_ids - still_pending
    if not purge_ids:
        return 0

    await db.execute(sa_delete(OutboxDelivery).where(OutboxDelivery.outbox_event_id.in_(purge_ids)))
    await db.execute(sa_delete(EventOutbox).where(EventOutbox.id.in_(purge_ids)))
    await db.commit()
    return len(purge_ids)
