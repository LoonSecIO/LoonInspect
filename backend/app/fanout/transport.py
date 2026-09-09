"""Request bodies — how N records reach a destination that expects one document (#306).

The fan-out's cost is not the expansion, it is the shipping. 107 records per device at
3,000 devices is 321,000 records a sweep, and the naive delivery — one POST per record —
would turn one device's pass into 107 requests and a fleet's into a rate-limit incident.
So the shape here is the same one HEC settled on: **one request carrying a device's
records**, split into consecutive requests only when the encoding exceeds a byte ceiling.
Per-event expansion, never cross-event batching — two devices' snapshots stay two
deliveries and two requests (#242).

Two encodings, because the two families of receiver read differently:

* **`generic_webhook` and `runreveal`** get a JSON **array** of records. This is the
  change a receiver sees: a snapshot delivery used to be one object and is now a list of
  them, while every other event type is untouched and still arrives as one object. An
  array rather than NDJSON because the body is still `application/json` and the delivery
  still goes through the same POST as every other webhook — RunReveal's ingest endpoint
  takes an array, and a receiver that only knew objects would have had to change for any
  shape that carries 107 of anything.
* **`elastic`** gets `_bulk` NDJSON — one `create` action line and one source line per
  record, which is the encoding that path already spoke for a single document. `create`
  rather than `index` because the default index name is a data stream, and data streams
  accept nothing else.

Chunking is whole-records-only, in both encodings: the unit that may be split across
requests is the record and never a byte range, so a record longer than the ceiling on its
own is sent alone rather than cut. Order is preserved and nothing is dropped — the ceiling
bounds what one request carries, not what the delivery carries.

At-least-once is unchanged and is now one level down, exactly as it is for HEC: a failed
second request leaves the first request's records delivered, and the retry re-sends both.
A device's records duplicate together, so the dedup key on a fanned-out record is the pull
plus the item (`deviceMeta.eventID` with the item's own identity), never
`deviceMeta.eventID` alone (docs/splunk-setup.md §7).

Pure: records in, bytes out. No session, no clock, no I/O.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

# The bulk action line, constant for every record: the index is in the URL, so the action
# carries no metadata of its own.
_BULK_ACTION = json.dumps({"create": {}})

# `[` and `]`. Counted against the ceiling so a chunk sized right up to it still encodes
# within it once the brackets are added.
_BRACKETS = 2


def _encode_record(record: Mapping[str, object]) -> bytes:
    """Compact UTF-8 JSON — the encoding httpx applies to `json=`, reproduced here so a
    fanned-out record is byte-identical to the one a single-event family sends through
    `json=`. Pinned against httpx itself in tests/test_record_fanout.py."""
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _chunk(lines: Sequence[bytes], max_bytes: int, *, overhead: int, joiner: bytes) -> list[list[bytes]]:
    """Groups of whole lines, each group encoding to at most `max_bytes` once `overhead`
    and the joiners between its lines are counted."""
    groups: list[list[bytes]] = []
    current: list[bytes] = []
    size = overhead
    for line in lines:
        added = len(line) + (len(joiner) if current else 0)
        if current and size + added > max_bytes:
            groups.append(current)
            current, size, added = [], overhead, len(line)
        current.append(line)
        size += added
    if current:
        groups.append(current)
    return groups


def webhook_request_bodies(records: Sequence[Mapping[str, object]], *, max_bytes: int) -> list[bytes]:
    """The request bodies one snapshot delivery to a webhook-shaped destination sends.

    A JSON array per request. A snapshot that expands to nothing — every section it read
    was empty, which only a scoped read can produce — sends no request at all, rather than
    an empty array a receiver would have to treat as a device with no anything.
    """
    lines = [_encode_record(record) for record in records]
    return [b"[" + b",".join(group) + b"]" for group in _chunk(lines, max_bytes, overhead=_BRACKETS, joiner=b",")]


def elastic_bulk_bodies(records: Sequence[Mapping[str, object]], *, max_bytes: int, timestamp: str) -> list[bytes]:
    """The `_bulk` request bodies one snapshot delivery to an `elastic` destination sends.

    `@timestamp` is the time axis of every Elastic index, so every source line carries
    one. The record's own `occurredAt` is authoritative — it is the snapshot head's key,
    which sweeps back-date to the run's window and webhooks carry Jamf's `reportDate` from
    (`app.core.runs.event_time`) — and `timestamp` is the fallback the caller resolved the
    same way the single-document path does, for a payload that somehow lacks it.

    **Converted, never forwarded**, and that is the caller's job: `envelope()` stores
    `time` as epoch *seconds*, and Elastic's default date mapping is
    `strict_date_optional_time||epoch_millis`, so a raw `1788480942.45` files the document
    in January 1970 — silently, and it still indexes.
    """
    lines: list[bytes] = []
    for record in records:
        document = dict(record)
        if "@timestamp" not in document:
            document["@timestamp"] = document.get("occurredAt") or timestamp
        lines.append((_BULK_ACTION + "\n" + json.dumps(document, default=str) + "\n").encode("utf-8"))
    # NDJSON lines already end in "\n", so they are concatenated with no joiner and the
    # body carries no overhead of its own.
    return [b"".join(group) for group in _chunk(lines, max_bytes, overhead=0, joiner=b"")]
