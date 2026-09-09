"""The record fan-out — the Splunk expansion, for the three destination types that are not
Splunk (#306).

`splunk_hec` delivered 107 events for the reference device; `runreveal`, `generic_webhook`
and `elastic` delivered 1, the whole ~28 KB nested snapshot. Nothing was failing — the test
button went green on all four and the transport was fine — but the shape differed by two
orders of magnitude in record count, and a security data platform that ingests records
cannot ask "which Macs have Wireshark" of a document it has to unnest first. #306 ruled
that the picker must not offer four types and deliver a usable shape to one.

This package is a service of its own rather than a branch inside `app.core.hec_fanout`,
and the split is deliberate:

* `expand` — the section walk. Which items, in which order, under which string. A copy of
  the HEC traversal, kept honest by a test that pins the two against the real fixture.
* `records` — what one record is. The sub-event with `sourcetype` moved out of the
  envelope into the body, `occurredAt` carried because no envelope carries it, and no
  `-1` sentinel because that conversion was ruled to belong to HEC shaping alone.
* `transport` — how N records reach a receiver that expects one document: a JSON array
  for the webhook-shaped types, `_bulk` NDJSON for Elastic, both chunked on whole records.

`app.core.hec_fanout` is untouched by this change, on purpose. The Splunk wire is frozen
(#188) and pinned item-for-item against a captured Jamf Pro 11.31 record; a fix for
`runreveal` must not be able to move a byte on the one wire that already has a customer.

The seam the outbox uses is `record_events` plus the two body builders. Which destination
types reach it is `app.core.outbox`'s decision, not this package's — the shape belongs to
the type, exactly as it does for Splunk, with no per-destination flag to set (Kyle,
2026-09-09).
"""

from app.fanout.expand import SubEvent, expand
from app.fanout.records import SOURCETYPE_KEY, record_events
from app.fanout.transport import elastic_bulk_bodies, webhook_request_bodies

__all__ = [
    "SOURCETYPE_KEY",
    "SubEvent",
    "elastic_bulk_bodies",
    "expand",
    "record_events",
    "webhook_request_bodies",
]
