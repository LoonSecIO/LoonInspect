"""The record shape — what one fanned-out sub-event looks like on a destination that has
no HEC envelope to hide transport in (#306).

`splunk_hec` receives 107 events for the reference device and `runreveal`,
`generic_webhook` and `elastic` received 1: the whole ~28 KB nested snapshot, which a
record-oriented consumer must unnest before it can ask "which Macs have Wireshark". That
asymmetry was deliberate and in writing, and #306 is the ruling that it should not
survive: every argument that justified the fan-out for Splunk applies to any consumer that
indexes records. All three types now fan out, and the destination *type* decides the shape
exactly as it does for Splunk — no per-destination flag, nothing to turn on (Kyle,
2026-09-09).

A record is the HEC sub-event with the transport taken out and put back as data:

    {…the section item…, "event": …, "jobID": …, "occurredAt": …,
     "sourcetype": "loon:jamf:mac:app", "deviceMeta": {…}}

Three differences from the HEC sub-event, each of them a ruling the HEC module already
made in the other direction:

**`sourcetype` is an ordinary body key.** On HEC it rides the envelope beside the body,
where it costs no licence volume and is Splunk's routing dimension (#81 ruling 7). A
webhook receiver has no envelope, so the string that says an event is an app rather than a
certificate would simply be lost — and it is the only thing that says so, because `event`
is `device.inventory` on all 107 (#188 ruling 5; nothing mints `device.inventory.app`).
It is carried under its own name rather than a second spelling, so one vocabulary covers
both wires and a customer moving from a webhook to Splunk keeps their predicate.

**`occurredAt` rides.** The HEC sub-event drops it on the explicit ground that "the same
instant travels beside every sub-event as the envelope's `time`" (#220, PR #247). On a
record destination it does not travel: the outbox pops `_envelope` for every type, so
without this a record would carry no time at all. This mints nothing — `occurredAt` is the
snapshot's own head key (`SNAPSHOT_HEAD_KEYS`), copied verbatim — so it is the ruling's
intent applied where its premise is false, not an exception to it.

**No `-1` sentinel.** `app.core.vuln.mint_hec_sentinels` turns a null `daysOldestPublished`
into `-1` on the HEC wire, and `hec_fanout` is explicit that the conversion "belongs to the
HEC shaping and to nothing upstream, which is why the canonical payload keeps `None`, so
the stored row, a generic webhook and an Elastic document can all render it natively as
SQL `NULL`" (docs/vulnerabilities.md §4c). That reasoning names these three destinations by
name, so a record keeps `None` and the sentinel stays where it was ruled to live.

Everything else is the sub-event unchanged: `event` and `jobID` from `SUB_EVENT_KEYS`,
`deviceMeta` copied whole — minting nothing into it and dropping nothing from it (#81
ruling 3) — and Jamf's object untouched inside the item.

Key order follows #286 from its one implementation: the section object leads, the search
keys follow, `deviceMeta` trails. The two record-only keys join the search keys rather
than the content, for #286's own reason — they are the same values repeated on all 107
rows, so they earn no screen space ahead of the thing you opened the record to read.

Pure, and deterministic for the same reason the HEC fan-out is: delivery retries the same
stored row up to ten times, and the bytes must not move between attempts.
"""

from __future__ import annotations

from collections.abc import Mapping

from app.core.wire import ENVELOPE
from app.core.wire_vocabulary import SUB_EVENT_KEYS, ordered_event_keys
from app.fanout.expand import expand
from app.schemas.payload import SNAPSHOT_HEAD_KEYS

# The routing string as a body key. Spelled the same as Splunk's envelope field on
# purpose: one vocabulary across both wires, so a saved search moving from a webhook to
# HEC keeps its predicate.
SOURCETYPE_KEY = "sourcetype"

_DEVICE_META = "deviceMeta"
_OCCURRED_AT = "occurredAt"

# The head a record carries, derived rather than spelled: the frozen sub-event keys
# (#220) minus the block that trails, plus the snapshot's own occurrence. Read off
# `SNAPSHOT_HEAD_KEYS` so a head key added under an additive clause reaches this wire
# without an edit here.
_RECORD_HEAD_KEYS: tuple[str, ...] = tuple(
    key for key in SNAPSHOT_HEAD_KEYS if key != _DEVICE_META and (key in SUB_EVENT_KEYS or key == _OCCURRED_AT)
)


def _ordered_record(body: Mapping[str, object], extras: Mapping[str, object]) -> dict[str, object]:
    """#286's order, with the record-only keys inserted immediately before `deviceMeta`.

    Routed through `ordered_event_keys` rather than rebuilt here so the frozen three keep
    exactly one implementation of their order and the two wires cannot drift into
    agreeing-until-they-don't layouts. A body carrying no `deviceMeta` — nothing produces
    one today, but a scoped read could — takes the extras at the end rather than losing
    them.
    """
    ordered = ordered_event_keys(body)
    record: dict[str, object] = {}
    for key, value in ordered.items():
        if key == _DEVICE_META:
            record.update(extras)
        record[key] = value
    for key, value in extras.items():
        record.setdefault(key, value)
    return record


def record_events(payload: Mapping[str, object]) -> list[dict[str, object]]:
    """Every record one stored `device.inventory` payload becomes, in order.

    The envelope is popped from a COPY: delivery is retried against the same row up to ten
    times, and stripping the row's own dict on the first attempt would deliver every
    retry — and every other destination's — without it.
    """
    body = dict(payload)
    body.pop(ENVELOPE, None)

    head = {key: body[key] for key in _RECORD_HEAD_KEYS if key in body}
    occurred_at = {key: head.pop(key) for key in (_OCCURRED_AT,) if key in head}
    meta = body.get(_DEVICE_META)

    records: list[dict[str, object]] = []
    for item, sourcetype in expand(body):
        record: dict[str, object] = {**head, **item}
        if isinstance(meta, Mapping):
            record[_DEVICE_META] = dict(meta)
        extras = dict(occurred_at)
        if sourcetype is not None:
            extras[SOURCETYPE_KEY] = sourcetype
        records.append(_ordered_record(record, extras))
    return records
