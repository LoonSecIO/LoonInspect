from __future__ import annotations

import json
import logging
from collections.abc import Collection, Iterator
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.wire import ENVELOPE
from app.core.wire_vocabulary import change_sourcetype
from app.models.schema import Destination, EventOutbox, OutboxDelivery

logger = logging.getLogger(__name__)

# Extend this as new producers land (group membership changes, enrichment results).
# Validated against in schemas/destinations.py so a typo in subscribedEvents doesn't
# silently create a destination that never receives anything.
KNOWN_EVENT_TYPES = frozenset({"device.inventory.changed", "device.change", "run.completed", "run.failed"})

# Not in KNOWN_EVENT_TYPES: nothing produces it and nothing can subscribe to it. It
# exists only so the destination test button sends something identifiable rather than a
# fabricated device event that would land in a customer's index looking real.
TEST_EVENT_TYPE = "destination.test"

# Same shape as the login lockout backoff: exponential, capped, with a hard ceiling on
# total attempts so a permanently dead destination doesn't retry forever.
# asyncpg caps a statement at 32767 bind parameters. One baseline sweep of a large fleet
# produces more outbox ids than that in a single night — 40,000 at 40k devices — so the
# unbatched `IN (...)` this function used to build raised rather than ran, and the nightly
# purge never completed even once. Same cap, same answer as `observations/ledger.py`.
_PURGE_BATCH = 1000


def _in_batches(values: Collection, size: int = _PURGE_BATCH) -> Iterator[list]:
    """`values` in chunks small enough to survive one statement's bind-parameter budget."""
    items = list(values)
    for start in range(0, len(items), size):
        yield items[start : start + size]


# One tick's ceiling, on both scheduler passes. A baseline sweep of a 40,000-device
# fleet lands 40,000 events at once and both passes used to load every matching row —
# 3.7GB resident for 100,000 events, on a 30-second timer.
#
# The rejected alternative was to leave the passes whole and make the rows cheaper:
# defer the JSONB payload, select only the columns each pass actually reads. That
# shrinks the constant but leaves a tick's cost proportional to the backlog, so the
# same fleet one size larger is the same incident again. A ceiling makes it
# proportional to the ceiling. Nothing is dropped — what a tick does not reach is
# simply the head of the next tick's set, thirty seconds later.
#
# Deliberately NOT shared with _PURGE_BATCH above, which is the same number for an
# unrelated reason (asyncpg's bind-parameter cap). Tuning the tick ceiling must not
# silently move a hard protocol limit.
_TICK_LIMIT = 1000

_BASE_BACKOFF_SECONDS = 30
_MAX_BACKOFF_SECONDS = 3600
_MAX_ATTEMPTS = 10
_MAX_BACKOFF_EXPONENT = 10  # guards against an unbounded 2**n

# What an Elastic destination writes to when no index is configured. Data-stream
# naming (logs-<dataset>-<namespace>) on purpose: it matches Elastic's built-in
# `logs-*-*` index template, so a fresh cluster accepts the very first bulk POST
# with sensible mappings instead of needing setup on the Elastic side first.
ELASTIC_DEFAULT_INDEX = "logs-looninspect.events-default"


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
    elif destination.auth_type == "elastic_api_key" and secret:
        # The secret is the base64 `id:api_key` string Elastic hands out on key
        # creation — stored and sent as-is, never decoded or re-encoded here.
        headers["Authorization"] = f"ApiKey {secret}"
    elif destination.auth_type == "header" and destination.auth_header_name and secret:
        headers[destination.auth_header_name] = secret

    return headers


def _build_body(destination: Destination, payload: dict) -> dict:
    # The envelope hints are a transport detail, computed at enqueue because nothing
    # here can reach a run or a Device (app.core.wire). Popped for EVERY destination
    # type, not just Splunk, so the key never reaches a customer's index or a generic
    # webhook receiver.
    payload = dict(payload)
    hints = payload.pop(ENVELOPE, None) or {}

    if destination.type == "splunk_hec":
        # HEC's raw-JSON collector endpoint expects the event wrapped, not posted
        # bare — without this, "Splunk support" would silently fail to ingest.
        body: dict = {"event": payload}
        # `time`, `host` and `source` ride beside the body as indexed metadata: they
        # cost no licence volume and are faster to search than the same string in `_raw`.
        # That is why the instance URL is envelope-ONLY and never a deviceMeta key.
        #
        # `host` is the deliberate exception: the hostname is carried in BOTH places
        # (Kyle's ruling, 2026-08-31). A Splunk admin can silently override `host` at the
        # HEC input, and envelope fields may not survive a summary index or an export
        # into a case file, whereas the body always travels — so the one identity that
        # joins outward to EDR, DHCP and identity logs is not left somewhere a customer
        # can quietly take away. It is a duplicate on purpose, not an oversight.
        #
        # `sourcetype`, for the `:change` family and nothing else (#243, ruled
        # 2026-09-03; stamped by #223). This is the first sourcetype the product ever
        # sends, and it is sent HERE rather than carried from the producer for two
        # reasons: this is the one place a HEC body is assembled, so "HEC only" is
        # structural rather than a convention; and the outbox holds events for the whole
        # retention window, so a change enqueued before the stamp existed still arrives
        # stamped instead of splitting the family across a deploy.
        #
        # Every other family is still deliberately unstamped. The ruled section tree names
        # fan-out sub-events (`loon:jamf:mac:app`) that are not built, and minting a string
        # for a shape that is about to change would create a permanent props.conf stanza
        # for it — that is #222, absorbed by the fan-out (#242). `device.change` was never
        # blocked that way: it is already at sub-event grain, one event per kept change
        # row. The string itself comes from `app.core.wire_vocabulary` and nowhere else,
        # which is #222's own acceptance criterion.
        stamped = change_sourcetype(
            payload.get("event"), subject_kind=payload.get("subjectKind"), section=payload.get("section")
        )
        if stamped is not None:
            body["sourcetype"] = stamped
        body.update(hints)
        return body

    # "runreveal" deliberately falls through: their webhook source ingests the same
    # bare JSON a generic webhook receives. The preset exists for the UI (prefilled
    # ingest-URL shape, bearer auth locked in), not for a different wire format.
    return payload


def _elastic_bulk_url(destination: Destination) -> str:
    """`{base_url}/{index}/_bulk` — the destination URL is the cluster, not the
    endpoint, so the index stays a per-destination setting instead of something the
    admin has to bake into a URL by hand."""
    index = destination.elastic_index or ELASTIC_DEFAULT_INDEX
    return f"{destination.url.rstrip('/')}/{index}/_bulk"


def _elastic_bulk_body(event: EventOutbox) -> str:
    """One `create` action line plus one source line, NDJSON. `create` rather than
    `index` because the default index name is a data stream, and data streams accept
    nothing else."""
    document = dict(event.payload)
    # Never index the outbox's own envelope hints — they are Splunk transport, not data.
    document.pop(ENVELOPE, None)
    # @timestamp is the time axis of every Elastic index. The event's own occurredAt
    # is authoritative (sweeps back-date to the run's window, webhooks carry Jamf's
    # reportDate — see app.core.runs.event_time); enqueue time is only the fallback
    # for a payload that somehow lacks it, so the document always maps.
    #
    # Both spellings are read, and the fallback IS transitional now. `occurredAt` is the
    # camelCase key ruled in #188, and every producer that has an occurrence time now
    # emits it — device.inventory.changed and run.completed alike. `occurred_at` is kept
    # only for the pre-rename backlog, which retention keeps deliverable for seven days;
    # after that it is dead code and can go. Removing it in the same change as the rename
    # would have silently re-dated a week of undelivered events to their drain time.
    # device.change still carries neither (it has `observedAt`, which is a different
    # fact) and falls through to enqueue time — untouched here, and noted in #188.
    if "@timestamp" not in document:
        occurred_at = document.get("occurredAt") or document.get("occurred_at")
        created_at = event.created_at or datetime.now(timezone.utc)
        document["@timestamp"] = occurred_at or created_at.isoformat()
    return json.dumps({"create": {}}) + "\n" + json.dumps(document, default=str) + "\n"


def _elastic_bulk_error(response: httpx.Response) -> str | None:
    """The bulk API's trap: HTTP 200 with per-item failures buried in the body.
    `errors: true` must surface as a delivery failure — swallow it and an Elastic
    destination with a bad mapping or index permission fails silently forever.
    Returns the error to record, or None when every item was accepted."""
    try:
        body = response.json()
    except ValueError:
        return f"bulk response was not JSON: {response.text[:200]}"
    if not isinstance(body, dict):
        return f"bulk response was not an object: {response.text[:200]}"
    if not body.get("errors"):
        return None
    for item in body.get("items") or []:
        # Each item is keyed by its action ({"create": {...}}); the value carries
        # the per-item status and error.
        result = next(iter(item.values()), None) if isinstance(item, dict) else None
        if not isinstance(result, dict) or not result.get("error"):
            continue
        error = result["error"]
        detail = f"{error.get('type', 'error')}: {error.get('reason', '')}" if isinstance(error, dict) else str(error)
        return f"bulk item rejected (status {result.get('status')}): {detail}"
    return "bulk response reported errors=true"


async def _attempt_elastic_delivery(
    client: httpx.AsyncClient, destination: Destination, event: EventOutbox
) -> tuple[bool, str | None]:
    headers = _build_headers(destination)
    # The bulk endpoint requires NDJSON and rejects application/json outright.
    headers["Content-Type"] = "application/x-ndjson"
    try:
        response = await client.post(
            _elastic_bulk_url(destination),
            content=_elastic_bulk_body(event).encode("utf-8"),
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        return False, f"HTTP {exc.response.status_code}: {exc.response.text[:500]}"
    except httpx.HTTPError as exc:
        return False, str(exc)[:500]

    error = _elastic_bulk_error(response)
    if error is not None:
        return False, error[:500]
    return True, None


def _next_backoff(attempt_count: int) -> datetime:
    exponent = min(attempt_count, _MAX_BACKOFF_EXPONENT)
    delay = min(_BASE_BACKOFF_SECONDS * (2**exponent), _MAX_BACKOFF_SECONDS)
    return datetime.now(timezone.utc) + timedelta(seconds=delay)


async def fan_out_pending(db: AsyncSession) -> int:
    """Create delivery rows for events that haven't been fanned out yet, oldest first,
    at most _TICK_LIMIT events per call.

    The only place that needs to know which destinations exist and what they're
    subscribed to — keeping that logic in one spot rather than duplicating it at every
    event-producing call site is the point of splitting fan-out from delivery.
    """
    # Destinations first, and the order is load-bearing now that events are held. The
    # events select below is still every column of every un-fanned row it reads, JSONB
    # payload included to flip a boolean (§2 of the characterization tests; #81's to
    # fix) — _TICK_LIMIT caps how many of those rows land in the worker at once, not
    # how wide each one is. While events were burned on the first tick that set could
    # never outgrow one tick's production. Held, it grows for the whole retention
    # window in exactly the state the stepper calls optional — so asking the cheap
    # indexed question first is what keeps a destination-less pod from dragging a
    # thousand payloads through the worker every 30 seconds to discover it has nothing
    # to do.
    result = await db.execute(select(Destination).where(Destination.enabled.is_(True)))
    destinations = result.scalars().all()

    if not destinations:
        # Hold, don't burn. `fanned_out` means "this event was considered against the
        # destinations that existed" — with none enabled there was nothing to consider,
        # so the events wait for the next pass instead of being consumed unsent. This is
        # the ruled onboarding path, not an edge case: the setup stepper calls the
        # destination step optional, so a whole baseline sweep normally lands before any
        # destination exists. Holding is also all the re-fan machinery needed — the
        # ordinary pass picks these up the moment a destination is added.
        #
        # The guard is "at least one enabled destination existed", never "at least one
        # delivery row was created": a destination that exists but is not subscribed to
        # this event type correctly produces no row, and that event *was* considered, so
        # it must still be marked. Held events are aged out by purge_delivered_events on
        # the same `event_outbox_retention_days` window as everything else.
        return 0

    # Oldest first, and by `id` rather than `created_at`: the sequence is the true
    # arrival order and cannot tie, while created_at is a Python-side default that two
    # rows flushed in one transaction can share. A tie under a ceiling is not a lost
    # row, but a total order is what makes "the next tick opens where this one stopped"
    # a fact rather than a hope.
    #
    # Whatever the ceiling leaves behind keeps fanned_out false — the state it was
    # already in — so being deferred is indistinguishable from never having been
    # looked at, which is the point.
    result = await db.execute(
        select(EventOutbox).where(EventOutbox.fanned_out.is_(False)).order_by(EventOutbox.id).limit(_TICK_LIMIT)
    )
    pending_events = result.scalars().all()
    if not pending_events:
        return 0

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
    if destination.type == "elastic":
        # Different enough to branch whole: NDJSON body, the index in the URL, and a
        # success status that still has to be read for per-item failures.
        return await _attempt_elastic_delivery(client, destination, event)
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
    """Attempt the deliveries that are due, oldest first, at most _TICK_LIMIT of them.
    Runs on its own scheduler tick, decoupled from whatever produced the event — a
    down destination here can never slow down a device sync or an inbound webhook's
    ACK."""
    now = datetime.now(timezone.utc)
    # Most-overdue first, ordered by `next_attempt_at` rather than `id` on purpose.
    # By id a row that has already failed twice sorts ahead of every event produced
    # since, so under a ceiling a backlog of retries would starve new events for as
    # long as it lasted. By due time a retry takes its place behind the events produced
    # while it was backing off, which is what the backoff was asking for.
    # ix_outbox_deliveries_next_attempt_at already orders this; `id` is only the
    # tiebreak that makes the order total.
    #
    # Rows past the ceiling are never read, and attempt_count / next_attempt_at are
    # only ever written inside the loop below — so a delivery this tick did not reach
    # is untouched, not attempted-and-failed. Getting that backwards would spend the
    # retry budget of a perfectly healthy destination on the worker being busy, which
    # is a worse failure than the unbounded load this ceiling replaces.
    result = await db.execute(
        select(OutboxDelivery)
        .where(OutboxDelivery.status == "pending", OutboxDelivery.next_attempt_at <= now)
        .order_by(OutboxDelivery.next_attempt_at, OutboxDelivery.id)
        .limit(_TICK_LIMIT)
    )
    due = result.scalars().all()
    if not due:
        return

    # Batched for the same reason the purge is. `due` is now capped at _TICK_LIMIT, so
    # this is one statement in practice — kept because the two bounds are independent:
    # the tick ceiling is a memory and tick-length judgement that may be tuned, while
    # the batch size is asyncpg's hard bind-parameter cap. Raising the former must not
    # quietly reintroduce the crash the latter exists to prevent.
    # `destination_ids` below is bounded by the destination count and needs no batching.
    event_ids = {row.outbox_event_id for row in due}
    events: dict = {}
    for batch in _in_batches(event_ids):
        result = await db.execute(select(EventOutbox).where(EventOutbox.id.in_(batch)))
        events.update({e.id: e for e in result.scalars().all()})
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
                # Every failed attempt, not only the last one. Before this the log was
                # silent until a delivery had burned all ten attempts over four hours,
                # so an operator watching `docker compose logs` during setup saw
                # nothing at all while a misconfigured destination 401ed on every
                # event — the diagnosis existed, in a database column nobody reads.
                logger.warning(
                    "event delivery failed",
                    extra={
                        "destination_id": destination.id,
                        "destination_name": destination.name,
                        "event_type": event.event_type,
                        "attempt": delivery.attempt_count,
                        "max_attempts": _MAX_ATTEMPTS,
                        "error": error,
                    },
                )
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


async def send_test_event(destination: Destination) -> tuple[bool, str | None]:
    """One synthetic event down the real delivery path, synchronously, for the
    `POST /api/destinations/{id}/test` button.

    Deliberately the same `_attempt_delivery` the scheduler uses rather than a bespoke
    ping: a test that exercises a different code path can pass while delivery fails,
    which is worse than no test. The event is never added to a session, so nothing is
    persisted and no retry is scheduled — the caller gets the upstream verdict directly.
    """
    event = EventOutbox(
        event_type=TEST_EVENT_TYPE,
        payload={
            "event": TEST_EVENT_TYPE,
            "message": "LoonInspect destination test. If you can read this, delivery works.",
            "destinationId": destination.id,
            "destinationName": destination.name,
        },
    )
    async with httpx.AsyncClient() as client:
        return await _attempt_delivery(client, destination, event)


async def purge_delivered_events(db: AsyncSession, retention_days: int) -> int:
    """Deletes outbox events old enough and holding no delivery still mid-retry. Without
    this the table grows without bound now that events are continuous (webhooks)
    rather than nightly-batched.

    Age, not fan-out state, is the candidate test. An event held by `fan_out_pending`
    because no destination was enabled yet has no delivery rows at all, so the
    still-pending guard below cannot see it and a `fanned_out` filter here would keep it
    for ever — turning the held-events fix into unbounded growth on a pod that never
    adds a destination. Held events therefore age out on the same
    `event_outbox_retention_days` window as delivered ones: seven days to configure a
    destination and collect the baseline, then the queue stops being a queue.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    result = await db.execute(select(EventOutbox.id).where(EventOutbox.created_at < cutoff))
    candidate_ids = set(result.scalars().all())
    if not candidate_ids:
        return 0

    # Never purge an event with a delivery still mid-retry, however old it is —
    # correctness here matters more than tidiness.
    still_pending: set = set()
    for batch in _in_batches(candidate_ids):
        result = await db.execute(
            select(OutboxDelivery.outbox_event_id).where(
                OutboxDelivery.outbox_event_id.in_(batch),
                OutboxDelivery.status == "pending",
            )
        )
        still_pending.update(result.scalars().all())
    purge_ids = candidate_ids - still_pending
    if not purge_ids:
        return 0

    for batch in _in_batches(purge_ids):
        await db.execute(sa_delete(OutboxDelivery).where(OutboxDelivery.outbox_event_id.in_(batch)))
        await db.execute(sa_delete(EventOutbox).where(EventOutbox.id.in_(batch)))
    await db.commit()
    return len(purge_ids)
