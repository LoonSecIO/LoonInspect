from __future__ import annotations

import json
import logging
from collections.abc import Collection, Iterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

import httpx
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.egress import BlockedDestinationUrl, refuse_blocked_resolution
from app.core.hec_fanout import fan_out
from app.core.wire import ENVELOPE, hec_event
from app.core.wire_vocabulary import (
    ASSERTION_EVENT_TYPES,
    ASSERTION_SOURCETYPE,
    DELTA_SOURCETYPE,
    change_sourcetype,
    ordered_event_keys,
)
from app.fanout import elastic_bulk_bodies, record_events, webhook_request_bodies
from app.models.schema import Destination, EventOutbox, OutboxDelivery
from app.schemas.payload import INVENTORY_EVENT_TYPE

logger = logging.getLogger(__name__)

# Extend this as new producers land (group membership changes, enrichment results).
# Validated against in schemas/destinations.py so a typo in subscribedEvents doesn't
# silently create a destination that never receives anything.
#
# `device.inventory` (#241) joined on the subscription default the type was born under:
# null/empty `subscribed_events` keeps meaning every event, so a destination on the
# default receives one ~30 KB snapshot per device per pass from the day this ships;
# explicit lists were NOT appended to, unlike `run.failed` (migration a9d4c7e1f3b8),
# because a destination that curated its list never asked for a state stream and the
# reason a failure must be loud has no analogue for a per-device snapshot. Opting out is
# `subscribed_events` on the API (docs/splunk-setup.md §7).
#
# That per-device cost is now the fanned-out one on every destination type, not just
# Splunk (#306): ~84 KB of records for the reference device against the ~28 KB the nested
# snapshot weighed, in one request rather than one document. The trade is the issue's
# own — 3x the bytes for a shape the receiver can actually query — and it is why the
# subscription, not a shape flag, is the place a destination declines the snapshot.
KNOWN_EVENT_TYPES = frozenset({"device.inventory", "device.inventory.changed", "device.change", "run.completed", "run.failed"})

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
# simply the head of the next tick's set, thirty seconds later. (#244 later narrowed
# the fan-out pass's select as well, once the row itself grew to a ~28 KB snapshot:
# the two compose — the ceiling bounds how many rows a tick holds, the narrowing
# bounds how wide each one is. The delivery pass still needs the payload to POST.)
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
    db: AsyncSession,
    event_type: str,
    payload: dict,
    *,
    request_id: str | None = None,
    only_destination_id: int | None = None,
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
    event = EventOutbox(event_type=event_type, payload=payload, request_id=request_id, only_destination_id=only_destination_id)
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


def _single_event_sourcetype(payload: Mapping[str, object]) -> str | None:
    """The string one single-event payload is stamped with on Splunk, or None.

    Decided by `app.core.wire_vocabulary` and stamped here — #222's rule, "`sourcetype`
    comes from `app.core.wire_vocabulary` and nowhere else" — on the `splunk_hec`
    destination type only. Three single-event families carry one:

    * `device.change` — `loon:jamf:mac:<wrapper>:change` (#243, stamped by #223). It was
      never blocked on the fan-out: it is already at sub-event grain, one event per kept
      change row. A subject with no wrapper is delivered unstamped rather than failing.
    * `run.completed` / `run.failed` — `loon:run` (#242 item 6, carrying #81's close-out:
      "`loon:run` on the run family in the same change"). The "shape about to change"
      reason that held the section tree back never applied to a run event.
    * `device.inventory.changed` — `DELTA_SOURCETYPE`, `loon:inventory:changed` (#277,
      2026-09-03, stamped the day before the flip so a customer's saved search never has
      to move under it after). The delta is LoonInspect's own derivation, not a wrapper
      around a Jamf object, so it takes #188 ruling 3's no-vendor assertion form the way
      `loon:run` does, rather than a leaf under `sourcetype()`.

    Only `destination.test` carries none — it is meant to be identifiable rather than
    routed, and lands under the sourcetype the operator set on the HEC input, exactly as
    every event did before any string was stamped.

    The snapshot, `device.inventory`, is not a single event: `hec_events` fans it out and
    stamps each sub-event from the registry.
    """
    event = payload.get("event")
    if event in ASSERTION_EVENT_TYPES:
        return ASSERTION_SOURCETYPE
    if event == "device.inventory.changed":
        return DELTA_SOURCETYPE
    return change_sourcetype(event, subject_kind=payload.get("subjectKind"), section=payload.get("section"))


def hec_events(payload: Mapping[str, object]) -> list[dict[str, object]]:
    """Every HEC event object one stored payload becomes on a `splunk_hec` destination.

    N for `device.inventory` — the fan-out, `app.core.hec_fanout` — and exactly one for
    every other family. The envelope hints are popped from a COPY of the payload: delivery
    is retried against the same row up to ten times, and stripping the row's own dict on
    the first attempt would deliver every retry without `time`, `host` or `source`.

    The stamp happens HERE, at delivery, rather than being carried from the producer, for
    two reasons worth keeping (#223's argument): this is the one place a HEC body is
    assembled, so "Splunk only" is structural rather than a convention; and the outbox
    holds events for the whole retention window, so an event enqueued before a stamp
    existed still arrives stamped instead of splitting its family across a deploy.
    """
    body = dict(payload)
    hints = body.pop(ENVELOPE, None) or {}
    if body.get("event") == INVENTORY_EVENT_TYPE:
        return fan_out(body, hints)
    # `ordered_event_keys` here and not inside `hec_event`: the fan-out builds its own
    # layout key by key and is already right, so ordering there would be a second pass
    # over N sub-events to reach the order they were constructed in (#286).
    return [hec_event(ordered_event_keys(body), hints, sourcetype=_single_event_sourcetype(body))]


def _build_body(destination: Destination, payload: dict) -> dict:
    """The one JSON document a delivery sends — for the destination types, and the
    families, whose delivery IS one document.

    Generic webhooks and the `runreveal` preset get the canonical event, envelope key
    removed, exactly as enqueued; the preset exists for the UI (prefilled ingest-URL
    shape, bearer auth locked in), not for a different wire format. A `splunk_hec`
    destination gets the one HEC event object of a single-event family — the wrapped
    body, the ruled sourcetype where the family has one, the envelope hints beside it.

    `device.inventory` has no one-document form on ANY destination type, which is what
    #306 changed: on Splunk it is N HEC events (`hec_events`, sent through
    `hec_request_bodies`), and on the other three it is N records (`record_events`, sent
    through `record_request_bodies` or `_elastic_bulk_requests`). None of those call this.
    Asking this function for a snapshot is a programming error and raises — deliberately
    not a silent whole-snapshot body, which is what this function returned to Splunk
    between #241 and #242, and to the other three types until #306. Unreachable from the
    delivery path, so it spends no retry budget.

    The envelope hints are popped for EVERY destination type, not just Splunk, so the
    key never reaches a customer's index or a generic webhook receiver.
    """
    if payload.get("event") == INVENTORY_EVENT_TYPE:
        raise ValueError(
            f"{INVENTORY_EVENT_TYPE} has no one-document body on any destination type: it is fanned "
            "out into one event per section item (app.core.outbox.hec_request_bodies for splunk_hec, "
            "record_request_bodies for every other type)"
        )
    if destination.type == "splunk_hec":
        (event,) = hec_events(payload)
        return event
    body = dict(payload)
    body.pop(ENVELOPE, None)
    # A webhook receiver reads the same document a HEC consumer does, so it gets the same
    # reading order (#286). Splunk is where the cost was noticed; it is not where it is.
    return ordered_event_keys(body)


def _encode_hec_event(event: Mapping[str, object]) -> bytes:
    """Compact UTF-8 JSON — the encoding httpx applies to `json=`, reproduced here so the
    request body a single-event family sends is byte-identical to the one it sent before
    the fan-out existed. Pinned against httpx itself in tests/test_hec_fanout.py."""
    return json.dumps(event, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _chunk(lines: Sequence[bytes], max_bytes: int) -> list[bytes]:
    """Newline-concatenated request bodies of at most `max_bytes` each, whole lines only.

    HEC's collector endpoint indexes each concatenated JSON object in a request body as
    its own event, so the unit that may be split across requests is the event and never a
    byte range: a line longer than the ceiling on its own is sent alone rather than cut.
    Order is preserved and nothing is dropped — the ceiling bounds what one request
    carries, not what the delivery carries.
    """
    bodies: list[bytes] = []
    current: list[bytes] = []
    size = 0
    for line in lines:
        added = len(line) + (1 if current else 0)
        if current and size + added > max_bytes:
            bodies.append(b"\n".join(current))
            current, size, added = [], 0, len(line)
        current.append(line)
        size += added
    if current:
        bodies.append(b"\n".join(current))
    return bodies


def hec_request_bodies(payload: Mapping[str, object], *, max_bytes: int) -> list[bytes]:
    """The request bodies one delivery to a `splunk_hec` destination sends, in order.

    One body for every single-event family and, for a snapshot, one request carrying all
    of a device's sub-events concatenated — #242's per-event expansion, not cross-event
    batching: two devices' snapshots are two deliveries and two requests. A snapshot whose
    expansion exceeds `max_bytes` (`settings.splunk_hec_max_request_bytes`; the real
    fixture's 83-app Mac is ~90 KB against a 900,000-byte default) is sent as consecutive
    requests of at most that size. A snapshot that expands to nothing — every section it
    read was empty, which only a scoped read can produce — sends no request at all.
    """
    return _chunk([_encode_hec_event(event) for event in hec_events(payload)], max_bytes)


def record_request_bodies(payload: Mapping[str, object], *, max_bytes: int) -> list[bytes]:
    """The request bodies one delivery to a `runreveal` or `generic_webhook` destination
    sends, in order — the record fan-out's half of `hec_request_bodies` (#306).

    One request carrying a JSON array of the device's records, split into consecutive
    requests only when the encoding exceeds `max_bytes`
    (`settings.record_fanout_max_request_bytes`). A snapshot that expands to nothing sends
    no request at all, which is the same answer HEC gives and for the same reason.

    Only `device.inventory` reaches this: every other family is one document and goes
    through `_build_body` exactly as it did before, unchanged and unfanned.
    """
    return webhook_request_bodies(record_events(payload), max_bytes=max_bytes)


def _elastic_bulk_url(destination: Destination) -> str:
    """`{base_url}/{index}/_bulk` — the destination URL is the cluster, not the
    endpoint, so the index stays a per-destination setting instead of something the
    admin has to bake into a URL by hand."""
    index = destination.elastic_index or ELASTIC_DEFAULT_INDEX
    return f"{destination.url.rstrip('/')}/{index}/_bulk"


def _envelope_timestamp(hints: Mapping[str, object]) -> str | None:
    """The envelope's occurrence as an ISO-8601 instant, or None if it carries none.

    **Converted, never forwarded.** `envelope()` stores `time` as epoch *seconds*, which
    is what HEC expects; Elastic's default mapping for a date field is
    `strict_date_optional_time||epoch_millis`, so handing it `1788480942.45` would be read
    as milliseconds and file the document in **January 1970** — a worse failure than the
    drain-time skew this fixes, because it is silent and the document still indexes.

    Always UTC and always offset-aware, so `@timestamp` has one spelling across every
    family whether it came from a body key or from here.
    """
    moment = hints.get("time")
    if not isinstance(moment, (int, float)) or isinstance(moment, bool):
        return None
    return datetime.fromtimestamp(moment, UTC).isoformat()


def _elastic_bulk_body(event: EventOutbox) -> str:
    """One `create` action line plus one source line, NDJSON. `create` rather than
    `index` because the default index name is a data stream, and data streams accept
    nothing else."""
    document = dict(event.payload)
    # Never index the outbox's own envelope hints — they are Splunk transport, not data.
    # Kept rather than discarded, because `time` is the occurrence every producer already
    # computed and it is the only place two of the four families carry it (#218).
    hints = document.pop(ENVELOPE, None) or {}
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
    # `run.failed` and `device.change` carry NEITHER body key — `windowStart`/`windowEnd`
    # and `observedAt`/`collectedAt` are different facts — so before #218 both took the
    # fallback on every delivery and landed at drain time. `run.failed` is the alarm,
    # default-on for every destination (#103): a sweep that dies at 01:00 and drains at
    # 09:00 indexed at 09:00, so an alert with a one-hour window never saw it.
    #
    # The envelope is the fix because it was already right. Every producer builds it with
    # the occurrence it computed — `window_end` for a failure, `event_time(observed_at)`
    # for a change — and HEC has read it all along. Reading it here fixes all four
    # families at once, fixes any family added later, and needs no new body key, so it is
    # not blocked on #188 naming one.
    if "@timestamp" not in document:
        occurred_at = document.get("occurredAt") or document.get("occurred_at") or _envelope_timestamp(hints)
        created_at = event.created_at or datetime.now(UTC)
        document["@timestamp"] = occurred_at or created_at.isoformat()
    return json.dumps({"create": {}}) + "\n" + json.dumps(document, default=str) + "\n"


def _elastic_bulk_requests(event: EventOutbox) -> list[bytes]:
    """The `_bulk` request bodies one Elastic delivery sends, in order.

    A snapshot is fanned out (#306): one `create`/source pair per record, chunked on whole
    records at `settings.record_fanout_max_request_bytes`. Elastic was the least visible
    of the three types the fan-out reached — a nested snapshot indexes without complaint —
    and the most costly, because a `logs-*` data stream's dynamic mapping grows a field
    for every path in the document it is handed.

    Every other family keeps exactly the body it had: one action line, one source line,
    built by `_elastic_bulk_body` and untouched by this change.

    The `@timestamp` fallback is resolved HERE rather than inside the fan-out, so both
    paths answer the question the same way — the event's own occurrence, then the
    envelope's `time` converted out of epoch seconds, then enqueue time — and the pure
    half stays free of the clock.
    """
    payload = event.payload or {}
    if payload.get("event") != INVENTORY_EVENT_TYPE:
        return [_elastic_bulk_body(event).encode("utf-8")]
    hints = payload.get(ENVELOPE) or {}
    created_at = event.created_at or datetime.now(UTC)
    timestamp = _envelope_timestamp(hints if isinstance(hints, Mapping) else {}) or created_at.isoformat()
    return elastic_bulk_bodies(record_events(payload), max_bytes=settings.record_fanout_max_request_bytes, timestamp=timestamp)


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
    """One POST per bulk body, in order, stopping at the first failure.

    A single-event family is one body and this is the request it always was. A snapshot is
    N records and may be more than one request (#306), and then the same at-least-once
    story HEC has applies: any non-2xx, transport error or `errors=true` fails the whole
    delivery, which backs off and retries EVERY body rebuilt from the same row, leaving an
    earlier request's documents already indexed. `create` is what makes that survivable —
    a data stream rejects a duplicate `_id` where `index` would overwrite — and the dedup
    key on a fanned-out record is the pull plus the item, never `deviceMeta.eventID`
    alone.
    """
    headers = _build_headers(destination)
    # The bulk endpoint requires NDJSON and rejects application/json outright.
    headers["Content-Type"] = "application/x-ndjson"
    for body in _elastic_bulk_requests(event):
        try:
            response = await client.post(
                _elastic_bulk_url(destination),
                content=body,
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


async def blocked_delivery_reason(destination: Destination) -> str | None:
    """Why this destination may not be dialled right now, or None (#131).

    The write-time rule in `app.schemas.destinations` binds new rows; this is the check
    on the row as it stands at delivery, which is the only place a row stored before the
    rule — or a hostname whose record has since moved to 169.254.169.254 — can be
    refused. Literals are judged too, for the same reason. Fails open on a resolver that
    does not answer, as the write-time pass does: an air-gapped SIEM is a supported
    destination, and a dead resolver must not turn into a dead outbox.
    """
    try:
        await refuse_blocked_resolution(destination.url, field="url", refusal=BlockedDestinationUrl, judge_literals=True)
    except BlockedDestinationUrl as exc:
        return str(exc)[:500]
    return None


def _next_backoff(attempt_count: int) -> datetime:
    exponent = min(attempt_count, _MAX_BACKOFF_EXPONENT)
    delay = min(_BASE_BACKOFF_SECONDS * (2**exponent), _MAX_BACKOFF_SECONDS)
    return datetime.now(UTC) + timedelta(seconds=delay)


async def fan_out_pending(db: AsyncSession) -> int:
    """Create delivery rows for events that haven't been fanned out yet, oldest first,
    at most _TICK_LIMIT events per call.

    The only place that needs to know which destinations exist and what they're
    subscribed to — keeping that logic in one spot rather than duplicating it at every
    event-producing call site is the point of splitting fan-out from delivery.
    """
    # Destinations first, and the order is load-bearing now that events are held. While
    # events were burned on the first tick the un-fanned set could never outgrow one
    # tick's production. Held, it grows for the whole retention window in exactly the
    # state the stepper calls optional — so asking the cheap indexed question first is
    # what keeps a destination-less pod from touching `event_outbox` at all, every 30
    # seconds, to discover it has nothing to do.
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
    #
    # Two columns, not the row (#244). This pass reads `event_type` and writes
    # `fanned_out`; it never needs the payload, and since #241 the payload is a ~28 KB
    # snapshot per device per pass — a thousand of them a tick was ~28 MB through the
    # ORM every thirty seconds, for the twenty minutes a 40,000-device backlog takes,
    # to flip a boolean. Measured with `tracemalloc` around one call at 20,000 un-fanned
    # events: the numbers are in the #244 PR. `deliver_pending` keeps the full row — it
    # has to POST the payload.
    result = await db.execute(
        select(EventOutbox.id, EventOutbox.event_type, EventOutbox.only_destination_id)
        .where(EventOutbox.fanned_out.is_(False))
        .order_by(EventOutbox.id)
        .limit(_TICK_LIMIT)
    )
    pending_events = result.all()
    if not pending_events:
        return 0

    created = 0
    for event_id, event_type, only_destination_id in pending_events:
        for destination in destinations:
            # A scoped re-emit (#356) is for one destination and no other; a destination
            # that is gone leaves the event considered, fanned out, and undelivered.
            if only_destination_id is not None and destination.id != only_destination_id:
                continue
            subscribed = destination.subscribed_events
            if subscribed and event_type not in subscribed:
                continue
            db.add(OutboxDelivery(outbox_event_id=event_id, destination_id=destination.id))
            created += 1

    # One UPDATE for the tick rather than one per row at flush. Batched for the reason
    # the purge is: _TICK_LIMIT and _PURGE_BATCH are the same number for unrelated
    # reasons, and raising the tick ceiling must not quietly reintroduce asyncpg's
    # bind-parameter crash. The same transaction as the delivery rows, so "considered"
    # and "has a delivery row" commit together or not at all.
    for batch in _in_batches([event_id for event_id, _event_type, _only in pending_events]):
        await db.execute(sa_update(EventOutbox).where(EventOutbox.id.in_(batch)).values(fanned_out=True))

    await db.commit()
    return created


async def _attempt_hec_delivery(
    client: httpx.AsyncClient, destination: Destination, event: EventOutbox
) -> tuple[bool, str | None]:
    """A `splunk_hec` delivery: one POST per request body, in order, stopping at the
    first failure.

    One request of N events either lands or fails as one, from the outbox's point of
    view: any non-2xx or transport error fails the delivery, which stays pending, backs
    off and retries the WHOLE delivery — every request body, rebuilt from the same row —
    until it lands or dead-letters after ten attempts (`deliver_pending`). What HEC does
    inside one request is its own: it parses the body in order and, on a malformed event,
    reports its position (`invalid-event-number`, HTTP 400) having already indexed the
    events before it. Nothing built here can produce a malformed event — every sub-event
    is JSON the producer's model validated — so that 400 would be a producer bug, and it
    takes the ordinary retry path rather than a bespoke one. Across chunks the same holds:
    a failed second request leaves the first request's events indexed, and the retry
    re-sends both. That is the outbox's existing at-least-once story one level down — a
    device's sub-events duplicate together, and the dedup key on a fan-out sourcetype is
    the pull plus the item (`deviceMeta.eventID` with the item's own identity), never
    `deviceMeta.eventID` alone (docs/splunk-setup.md §7). Redrive of a dead-lettered
    delivery is #91, not built.
    """
    headers = _build_headers(destination)
    bodies = hec_request_bodies(event.payload, max_bytes=settings.splunk_hec_max_request_bytes)
    for body in bodies:
        try:
            response = await client.post(destination.url, content=body, headers=headers, timeout=10)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            return False, f"HTTP {exc.response.status_code}: {exc.response.text[:500]}"
        except httpx.HTTPError as exc:
            return False, str(exc)[:500]
    return True, None


async def _attempt_record_delivery(
    client: httpx.AsyncClient, destination: Destination, event: EventOutbox
) -> tuple[bool, str | None]:
    """A snapshot delivery to a `runreveal` or `generic_webhook` destination: one POST per
    request body, in order, stopping at the first failure (#306).

    The same shape as `_attempt_hec_delivery` and for the same reasons — one request of N
    records lands or fails as one, a failure retries the WHOLE delivery from the same row,
    and a device's records duplicate together on a partial success. It is a separate
    function rather than a flag on that one because the body differs: a JSON array under
    `application/json`, against HEC's concatenated objects.

    `content=` rather than `json=` because the body is already encoded — the fan-out
    produced the bytes, and re-encoding a parsed array here would make the delivered bytes
    depend on a round trip through Python. The Content-Type header `_build_headers` sets
    is unchanged, so the receiver sees the same content type it always did.
    """
    headers = _build_headers(destination)
    bodies = record_request_bodies(event.payload, max_bytes=settings.record_fanout_max_request_bytes)
    for body in bodies:
        try:
            response = await client.post(destination.url, content=body, headers=headers, timeout=10)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            return False, f"HTTP {exc.response.status_code}: {exc.response.text[:500]}"
        except httpx.HTTPError as exc:
            return False, str(exc)[:500]
    return True, None


async def _attempt_delivery(client: httpx.AsyncClient, destination: Destination, event: EventOutbox) -> tuple[bool, str | None]:
    if destination.type == "elastic":
        # Different enough to branch whole: NDJSON body, the index in the URL, and a
        # success status that still has to be read for per-item failures.
        return await _attempt_elastic_delivery(client, destination, event)
    if destination.type == "splunk_hec":
        # Its own branch for the same reason: the body is bytes rather than one JSON
        # document — N concatenated HEC events for a snapshot (#242) — and a delivery may
        # be more than one request.
        return await _attempt_hec_delivery(client, destination, event)
    if (event.payload or {}).get("event") == INVENTORY_EVENT_TYPE:
        # `runreveal` and `generic_webhook`: the snapshot fans out here too (#306), so its
        # body is a JSON array of records rather than the one nested document every other
        # family still sends below. Keyed on the event type rather than the destination
        # type, because these two types differ only in the UI — `runreveal` is a preset
        # over this delivery path (prefilled ingest URL, bearer auth locked in), and a
        # second branch here would be the place the two silently drifted apart.
        return await _attempt_record_delivery(client, destination, event)
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
    now = datetime.now(UTC)
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
        d.id: d for d in (await db.execute(select(Destination).where(Destination.id.in_(destination_ids)))).scalars().all()
    }

    # One resolver pass per destination per tick, not per delivery: a sweep of forty
    # thousand devices is forty thousand deliveries to the same handful of URLs, and the
    # answer for a destination cannot change between two rows of the same tick.
    blocked: dict[int, str] = {}
    for destination in destinations.values():
        reason = await blocked_delivery_reason(destination)
        if reason is not None:
            blocked[destination.id] = reason

    async with httpx.AsyncClient() as client:
        for delivery in due:
            destination = destinations.get(delivery.destination_id)
            event = events.get(delivery.outbox_event_id)

            if destination is None or event is None:
                # Destination was deleted (event should not be possible, but the row
                # is otherwise stuck forever if it happens).
                delivery.status = "failed"
                delivery.last_error = "destination or event no longer exists"
                await db.commit()
                continue

            if not destination.enabled:
                # Disabled after fan-out but before delivery. Left pending rather than
                # dead-lettered, so it resumes automatically if re-enabled instead of
                # failing something the operator never actually wanted attempted.
                continue

            if destination.id in blocked:
                # Counted as a failed attempt, with the reason on the row the
                # Destinations page reads, and never dialled: it backs off and
                # dead-letters like any other refusal, and the fix is the URL.
                ok, error = False, blocked[destination.id]
            else:
                ok, error = await _attempt_delivery(client, destination, event)
            delivery.attempt_count += 1
            delivery.last_attempted_at = now

            if ok:
                delivery.status = "delivered"
                delivery.delivered_at = now
                # A delivered row carries no diagnosis. The Destinations page reads the
                # newest attempted row's error as the destination's; after a redrive
                # succeeds (#91), that row is this one, and it must say nothing.
                delivery.last_error = None
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
            # Committed per delivery, not once per tick (#91). Delivery is at-least-once
            # either way — a POST that landed just before a crash is re-sent when the
            # worker returns — but a tick-wide commit made the duplicate window the whole
            # tick: a crash after 999 accepted POSTs re-sent all 999. Now it is one. The
            # session does not expire on commit, so the rows in hand stay usable.
            await db.commit()

    await db.commit()


async def redrive_failed(db: AsyncSession, destination_id: int) -> int:
    """Return a destination's dead letters to the queue (#91). Returns how many.

    Flipping `status` alone would be a no-op with extra steps: `attempt_count` is at the
    ceiling, so the next tick would dead-letter the row again after one attempt. So the
    count is zeroed and the row is due now; `deliver_pending`'s ordering then paces the
    drain behind whatever is already due. `last_error` is kept on purpose — the row is
    pending again *because* of that error, and the diagnosis stays on the Destinations
    page until the next attempt overwrites it or a delivery clears it.

    What it re-sends is what still exists: a delivery whose event the purge has already
    taken is not here to redrive (`purge_delivered_events`, `dead_letter_retention_days`).
    Restoring *that* half of an outage needs a re-emit of current state, which is a
    different thing from this and its own issue. The caller commits.
    """
    result = await db.execute(
        sa_update(OutboxDelivery)
        .where(OutboxDelivery.destination_id == destination_id, OutboxDelivery.status == "failed")
        .values(status="pending", attempt_count=0, next_attempt_at=datetime.now(UTC))
    )
    return int(result.rowcount or 0)


class DeliveryOutcome(NamedTuple):
    """What the test button learns from one synthetic delivery.

    `ok` and `error` are `_attempt_delivery`'s own verdict, unchanged. `status_code` is
    the HTTP status the destination answered with, or None when no response came back at
    all — DNS, connection refused, timeout, TLS — which is a different diagnosis from any
    status code and must not be dressed up as one. It is its own field because `error` is
    a human sentence: "HTTP 403: …" is in it today for a refusal, but a caller that parsed
    the number out would break the day the sentence is reworded, and on success there is
    no sentence to parse (#305).
    """

    ok: bool
    error: str | None
    status_code: int | None


async def send_test_event(destination: Destination) -> DeliveryOutcome:
    """One synthetic event down the real delivery path, synchronously, for the
    `POST /api/destinations/{id}/test` button.

    Deliberately the same `_attempt_delivery` the scheduler uses rather than a bespoke
    ping: a test that exercises a different code path can pass while delivery fails,
    which is worse than no test. The event is never added to a session, so nothing is
    persisted and no retry is scheduled — the caller gets the upstream verdict directly.

    The status code is read off the response by a client hook rather than threaded
    through `_attempt_delivery`'s return value, so the path the scheduler runs is the one
    this exercises, unchanged — a hook observes and cannot alter the verdict. The last
    response of the attempt is the one reported: a test is a single request, and for a
    refusal that is the request that was refused. Elastic's bulk API can answer 200 and
    still reject the item (`_elastic_bulk_error`); that reads as `ok=False` beside
    `status_code=200`, which is the truth of it.
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
    reason = await blocked_delivery_reason(destination)
    if reason is not None:
        return DeliveryOutcome(False, reason, None)

    statuses: list[int] = []

    async def remember(response: httpx.Response) -> None:
        statuses.append(response.status_code)

    async with httpx.AsyncClient(event_hooks={"response": [remember]}) as client:
        ok, error = await _attempt_delivery(client, destination, event)
    return DeliveryOutcome(ok, error, statuses[-1] if statuses else None)


async def purge_delivered_events(db: AsyncSession, retention_days: int, dead_letter_retention_days: int | None = None) -> int:
    """Deletes outbox events old enough and holding no delivery still mid-retry. Without
    this the table grows without bound now that events are continuous (webhooks)
    rather than nightly-batched.

    A dead-lettered delivery keeps its event for `dead_letter_retention_days` rather than
    `retention_days` (#91): a delivery that spent its ten attempts is the evidence of a
    gap in the trail and the thing a redrive re-sends, and purging it with everything
    else at seven days made every destination outage longer than an afternoon a
    permanent, invisible gap. Its own window rather than none, because a destination
    nobody fixes would otherwise pin its events for ever. `None` means the ordinary
    window, which is what a caller that has not thought about dead letters gets.

    Age, not fan-out state, is the candidate test. An event held by `fan_out_pending`
    because no destination was enabled yet has no delivery rows at all, so the
    still-pending guard below cannot see it and a `fanned_out` filter here would keep it
    for ever — turning the held-events fix into unbounded growth on a pod that never
    adds a destination. Held events therefore age out on the same
    `event_outbox_retention_days` window as delivered ones: seven days to configure a
    destination and collect the baseline, then the queue stops being a queue.
    """
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=retention_days)
    dead_letter_cutoff = now - timedelta(days=dead_letter_retention_days or retention_days)

    result = await db.execute(select(EventOutbox.id).where(EventOutbox.created_at < cutoff))
    candidate_ids = set(result.scalars().all())
    if not candidate_ids:
        return 0

    # Never purge an event with a delivery still mid-retry, however old it is —
    # correctness here matters more than tidiness. Nor one a dead letter still holds
    # inside its own window.
    protected: set = set()
    for batch in _in_batches(candidate_ids):
        result = await db.execute(
            select(OutboxDelivery.outbox_event_id).where(
                OutboxDelivery.outbox_event_id.in_(batch),
                OutboxDelivery.status == "pending",
            )
        )
        protected.update(result.scalars().all())
        result = await db.execute(
            select(OutboxDelivery.outbox_event_id)
            .join(EventOutbox, EventOutbox.id == OutboxDelivery.outbox_event_id)
            .where(
                OutboxDelivery.outbox_event_id.in_(batch),
                OutboxDelivery.status == "failed",
                EventOutbox.created_at >= dead_letter_cutoff,
            )
        )
        protected.update(result.scalars().all())
    purge_ids = candidate_ids - protected
    if not purge_ids:
        return 0

    for batch in _in_batches(purge_ids):
        await db.execute(sa_delete(OutboxDelivery).where(OutboxDelivery.outbox_event_id.in_(batch)))
        await db.execute(sa_delete(EventOutbox).where(EventOutbox.id.in_(batch)))
    await db.commit()
    return len(purge_ids)
