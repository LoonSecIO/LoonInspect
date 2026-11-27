"""Durable Snowflake delivery for the tenant-locked outbox worker and test button.

One active batch per destination freezes bytes before authentication or append. A
checkpoint plus exact counter deltas proves acceptance/rejection. Mixed batches are
replayed as single rows with unchanged source keys; the supplied analyst view dedups
rows accepted before that replay. HTTP acknowledgements alone never complete delivery.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.egress import BlockedDestinationUrl
from app.core.snowflake_transport import ChannelStatus, SnowflakeClient, SnowflakeError
from app.core.tenancy import get_tenant_id
from app.models.schema import Destination, EventOutbox, OutboxDelivery, SnowflakeBatch, SnowflakeSource
from app.schemas.snowflake import SnowflakeConfig
from app.snowflake_export import ExportBatch, account_for, event_row

logger = logging.getLogger(__name__)
MAX_BATCH_BYTES = 3 * 1024 * 1024  # Below Snowflake REST's 4 MB request ceiling, including newlines.
MAX_BATCH_ROWS = 250
MAX_DESTINATIONS_PER_TICK = 4
POLL_SECONDS = 30
DRAIN_SECONDS = 20


async def source_namespace(db: AsyncSession) -> uuid.UUID:
    await db.execute(insert(SnowflakeSource).values(source_id=uuid.uuid4()).on_conflict_do_nothing())
    return (await db.execute(select(SnowflakeSource.source_id))).scalar_one()


def _channel(source_id: uuid.UUID, destination_id: int) -> str:
    return f"LI_{source_id.hex}_{destination_id}"


async def _new_batch(
    db: AsyncSession, destination: Destination, source_id: uuid.UUID, eligible_ids: list[int] | None = None
) -> SnowflakeBatch | None:
    now = datetime.now(UTC)
    rows = (
        await db.execute(
            select(OutboxDelivery, EventOutbox)
            .join(EventOutbox, EventOutbox.id == OutboxDelivery.outbox_event_id)
            .where(
                OutboxDelivery.destination_id == destination.id,
                OutboxDelivery.status == "pending",
                OutboxDelivery.next_attempt_at <= now,
                OutboxDelivery.id.in_(eligible_ids) if eligible_ids is not None else True,
            )
            .order_by(OutboxDelivery.next_attempt_at, OutboxDelivery.id)
            .limit(MAX_BATCH_ROWS)
        )
    ).all()
    ids, keys, bodies = [], [], []
    size = 0
    for delivery, event in rows:
        if ids and delivery.snowflake_single_row:
            break
        try:
            if event.export_event_id is None:
                event.export_event_id = uuid.uuid4()
            row = event_row(
                event.payload,
                source_id=str(source_id),
                tenant_id=str(event.tenant_id),
                event_id=str(event.export_event_id),
                event_type=event.event_type,
                queued_at=event.created_at,
            )
            if len(row.ndjson) > MAX_BATCH_BYTES:
                raise ValueError("oversized event")
        except (TypeError, ValueError, OverflowError, OSError):
            delivery.status = "failed"
            delivery.last_attempted_at = now
            delivery.last_error = (
                "Snowflake event cannot be encoded or exceeds the 3 MiB row limit. The event is retained as "
                "a dead letter; check event size and timestamps before Redrive."
            )
            destination.last_failure_at = now
            continue
        if ids and size + len(row.ndjson) > MAX_BATCH_BYTES:
            break
        ids.append(delivery.id)
        keys.append(row.key)
        bodies.append(row.ndjson)
        size += len(row.ndjson)
        if delivery.snowflake_single_row:
            break
    if not ids:
        await db.commit()
        return None
    batch = SnowflakeBatch(destination_id=destination.id, delivery_ids=ids, source_keys=keys, body=b"".join(bodies).decode())
    db.add(batch)
    await db.commit()  # Immutable membership and bytes must survive a lost append response.
    return batch


def verdict(batch: SnowflakeBatch, status: ChannelStatus) -> str:
    """Return accepted/rejected/mixed only at our offset with exact complete counts."""
    if status.offset != str(batch.id) or batch.baseline is None:
        return "unresolved"
    inserted = status.inserted - batch.baseline["inserted"]
    rejected = status.rejected - batch.baseline["rejected"]
    if inserted < 0 or rejected < 0 or inserted + rejected != len(batch.source_keys):
        return "unresolved"
    if rejected == 0:
        return "accepted"
    return "rejected" if inserted == 0 else "mixed"


async def _settle(db: AsyncSession, destination: Destination, batch: SnowflakeBatch, state: str) -> None:
    now = datetime.now(UTC)
    deliveries = (await db.execute(select(OutboxDelivery).where(OutboxDelivery.id.in_(batch.delivery_ids)))).scalars().all()
    if len(deliveries) != len(batch.delivery_ids) or any(d.status != "pending" for d in deliveries):
        raise SnowflakeError(
            "Snowflake batch membership changed. Delivery remains unresolved; restore the matching "
            "database backup or contact support."
        )
    exported = ExportBatch(tuple(batch.source_keys), batch.body.encode())
    reason = (
        "Snowflake rejected this event. Check the pipe transformation, target column types and "
        "Snowflake ingestion errors, then use Redrive."
    )
    outcome = account_for(
        exported,
        accepted=exported.keys if state == "accepted" else (),
        rejected=dict.fromkeys(exported.keys, reason) if state == "rejected" else {},
    )
    for delivery in deliveries:
        delivery.last_attempted_at = now
        if state == "accepted":
            assert outcome.delivered
            delivery.status, delivery.delivered_at, delivery.last_error = "delivered", now, None
        elif state == "rejected":
            delivery.status, delivery.last_error = "failed", reason
        else:
            # Counts prove a mixed result, not which source rows were accepted. Each
            # member remains unresolved until its own singleton checkpoint proves it.
            delivery.snowflake_single_row = True
            delivery.next_attempt_at = now
            delivery.last_error = (
                "Snowflake accepted part of a batch. Each event will be checked separately; the analyst "
                "view removes replay duplicates."
            )
    if state == "accepted":
        destination.last_success_at = now
    else:
        destination.last_failure_at = now
    await db.delete(batch)
    await db.commit()  # Accounting and release of the sole in-flight batch are atomic.


async def _hold(db: AsyncSession, destination: Destination, batch: SnowflakeBatch, detail: str) -> None:
    now = datetime.now(UTC)
    deliveries = (await db.execute(select(OutboxDelivery).where(OutboxDelivery.id.in_(batch.delivery_ids)))).scalars().all()
    for delivery in deliveries:
        delivery.last_error = detail
        delivery.last_attempted_at = now
        # An unresolved acknowledgement must never exhaust a retry budget and be
        # purged as a dead letter; its immutable batch remains the recovery evidence.
        delay = min(300, POLL_SECONDS * max(1, delivery.attempt_count))
        delivery.next_attempt_at = now + timedelta(seconds=delay)
    destination.last_failure_at = now
    await db.commit()
    logger.warning(
        "Snowflake delivery remains unresolved; check Destinations for the next action",
        extra={"destination_id": destination.id, "batch_id": str(batch.id), "detail": detail},
    )


async def deliver_destination(
    db: AsyncSession, destination: Destination, eligible_ids: list[int] | None = None, *, deadline: float | None = None
) -> int:
    """Run one bounded batch while the caller holds this tenant's outbox advisory lock."""
    source_id = await source_namespace(db)
    batch = (await db.execute(select(SnowflakeBatch).where(SnowflakeBatch.destination_id == destination.id))).scalar_one_or_none()
    if batch is not None and eligible_ids is not None:
        # Later queued rows can select this destination while its active batch backs
        # off. Once due, recover it even if those older rows filled the tick selection.
        retry_at = await db.scalar(
            select(OutboxDelivery.next_attempt_at)
            .where(OutboxDelivery.id.in_(batch.delivery_ids))
            .order_by(OutboxDelivery.next_attempt_at)
            .limit(1)
        )
        if retry_at is not None and retry_at > datetime.now(UTC):
            return 0
    if batch is None:
        batch = await _new_batch(db, destination, source_id, eligible_ids)
    if batch is None:
        return 0
    channel = _channel(source_id, destination.id)
    try:
        config = SnowflakeConfig.model_validate(destination.snowflake_config)
        async with httpx.AsyncClient(trust_env=False) as transport:
            client = SnowflakeClient(
                transport, config, destination.url, destination.auth_secret_encrypted or "", deadline=deadline
            )
            await client.authenticate()
            current, continuation = await client.open(channel)
            state = verdict(batch, current)
            if state != "unresolved":
                await _settle(db, destination, batch, state)
                return len(batch.delivery_ids)
            if current.offset == str(batch.id):
                raise SnowflakeError(
                    "Snowflake committed the checkpoint without complete matching row counts. Delivery remains "
                    "unresolved; check channel counters and ingestion errors."
                )
            if batch.baseline is not None and current.baseline() != batch.baseline and current != ChannelStatus(0, 0, None):
                raise SnowflakeError(
                    "Snowflake channel changed outside this pending batch. Delivery remains unresolved; "
                    "check for another writer or a mismatched database restore."
                )
            # Idle channels expire after 30 days. An empty channel can receive the
            # retained bytes again; SOURCE_EVENT_KEY still dedups earlier history.
            batch.baseline = current.baseline()
            deliveries = (
                (await db.execute(select(OutboxDelivery).where(OutboxDelivery.id.in_(batch.delivery_ids)))).scalars().all()
            )
            if len(deliveries) != len(batch.delivery_ids) or any(d.status != "pending" for d in deliveries):
                raise SnowflakeError(
                    "Snowflake batch membership changed. Delivery remains unresolved; restore the matching "
                    "database backup or contact support."
                )
            for delivery in deliveries:
                delivery.attempt_count += 1
            await db.commit()  # Counter baseline is durable before the append can happen.
            await client.append(channel, continuation, str(batch.id), batch.body)
            state = verdict(batch, await client.status(channel))
            for delay in (0.5, 1.0):
                if state != "unresolved":
                    break
                await asyncio.sleep(delay)
                state = verdict(batch, await client.status(channel))
            if state != "unresolved":
                await _settle(db, destination, batch, state)
                return len(batch.delivery_ids)
            detail = (
                "Snowflake received the request; committed row counts are still pending. Queued events are "
                "retained and will be checked again."
            )
    except SnowflakeError as exc:
        detail = str(exc)  # This typed boundary contains only our fixed safe diagnostics.
    except BlockedDestinationUrl as exc:
        detail = f"Snowflake outbound policy refused the request. {exc}"
    except ValueError:
        detail = (
            "Snowflake configuration or key is invalid. Check the account URL, names and RSA private "
            "key in Destinations; queued events are retained."
        )
    await _hold(db, destination, batch, detail)
    return 0


async def drain_destination(db: AsyncSession, destination: Destination, eligible_ids: list[int]) -> None:
    """Recover a due frozen batch, then drain selected rows within the time budget."""
    remaining = len(eligible_ids)
    deadline = time.monotonic() + DRAIN_SECONDS
    while remaining > 0 and time.monotonic() < deadline:
        accounted = await deliver_destination(db, destination, eligible_ids, deadline=deadline)
        if not accounted:
            return
        remaining -= accounted


async def test_destination(db: AsyncSession, destination: Destination) -> tuple[bool, bool, str, str]:
    """Queue a targeted test durably, then attempt it under the regular worker lock."""
    from app.core.outbox import TEST_EVENT_TYPE, outbox_tick_lock

    event = EventOutbox(
        event_type=TEST_EVENT_TYPE,
        payload={
            "event": TEST_EVENT_TYPE,
            "message": "LoonInspect Snowflake destination test",
            "occurredAt": datetime.now(UTC).isoformat(),
        },
        fanned_out=True,
        only_destination_id=destination.id,
    )
    db.add(event)
    await db.flush()
    delivery = OutboxDelivery(destination_id=destination.id, outbox_event_id=event.id)
    db.add(delivery)
    source_id = await source_namespace(db)
    key = event_row(
        event.payload,
        source_id=str(source_id),
        tenant_id=str(event.tenant_id),
        event_id=str(event.export_event_id),
        event_type=event.event_type,
        queued_at=event.created_at,
    ).key
    await db.commit()
    async with outbox_tick_lock(get_tenant_id()) as held:
        if held:
            await deliver_destination(db, destination)
    await db.refresh(delivery)
    ok = delivery.status == "delivered"
    pending = delivery.status == "pending"
    detail = (
        "Delivered. Snowflake committed the test row."
        if ok
        else delivery.last_error
        or ("Test event queued. The delivery worker will check Snowflake; enable this destination for background retries.")
    )
    if pending and not destination.enabled:
        detail += " Enable this destination for background retries."
    return ok, pending, detail, key
