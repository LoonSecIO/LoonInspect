"""The record fan-out over the real fixture (#306). Pure; no database.

`splunk_hec` received 107 events for the reference device and `runreveal`,
`generic_webhook` and `elastic` received 1 — the whole ~28 KB nested snapshot. Nothing was
failing: the test button went green on all four and the transport was fine. What differed
was the shape, by two orders of magnitude in record count, and a security data platform
that indexes records cannot ask "which Macs have Wireshark" of a document it must unnest
first. This suite is the golden for what those three types receive now.

It holds the record wire to the same captured Jamf Pro 11.31 record the HEC suite uses:

* the count and the per-section split — the same 107, from the same fixture, because the
  walk is the same walk;
* **the two walks pinned against each other**, item for item, in order, under the same
  strings. `app.fanout.expand` is a deliberate copy of `app.core.hec_fanout.fan_out` — the
  Splunk wire is frozen and a fix for `runreveal` must not be able to move a byte on it —
  and this is the assertion that makes the copy honest rather than a fork waiting to
  happen;
* the three ruled differences from the HEC sub-event, each of them a decision the HEC
  module made in the other direction: `sourcetype` in the body rather than the envelope,
  `occurredAt` riding because no envelope carries it, and no `-1` sentinel;
* the shape otherwise identical — `deviceMeta` verbatim and on every record, Jamf's object
  untouched, #286's reading order, a byte-identical rebuild that never mutates the row;
* the request: ONE per device, a JSON array for the webhook-shaped types and `_bulk`
  NDJSON for Elastic, the measured sizes pinned as ceilings, and the chunk boundary when
  the ceiling is lowered;
* delivery down the real `_attempt_delivery`, for all three types, and every other family
  still one document exactly as before.

The HEC lane is tests/test_hec_fanout.py, and its fixture helpers are imported rather than
restated so the two suites cannot disagree about what the stored row holds.
"""

from __future__ import annotations

import json
import logging
from copy import deepcopy

import httpx
import pytest

from app.core import outbox
from app.core.config import Settings
from app.core.hec_fanout import fan_out
from app.core.outbox import (
    _attempt_delivery,
    _elastic_bulk_requests,
    hec_events,
    record_request_bodies,
)
from app.core.vuln import NEVER
from app.core.wire import ENVELOPE
from app.core.wire_vocabulary import SECTION_WRAPPERS, SUB_EVENT_KEYS, sourcetype
from app.fanout import SOURCETYPE_KEY, expand, record_events
from app.fanout.transport import elastic_bulk_bodies, webhook_request_bodies
from app.models.schema import Destination, EventOutbox
from app.schemas.payload import INVENTORY_EVENT_TYPE
from tests.test_hec_fanout import (
    ANCHORS,
    FIXTURE_ITEMS,
    FIXTURE_SUB_EVENTS,
    SOURCE,
    _stored,
    _wrapper_of,
)
from tests.test_hec_fanout import payload as payload
from tests.test_hec_fanout import raw as raw
from tests.test_hec_fanout import run as run

# The whole request for the fixture's device, measured 2026-09-09 as the compact JSON array
# of its 107 records: 78,787 bytes, 2.74 times the 28,789-byte snapshot. SMALLER than the
# HEC request's 84,135 despite carrying two extra keys per record, because HEC repeats
# `time`, `host` and `source` on every event and a record repeats only `occurredAt` and
# `sourcetype`. Pinned as a ceiling with ~1.5% headroom so the next byte added to the
# most-multiplied object on this wire is loud.
ARRAY_CEILING = 80_000
# The same 107 records as `_bulk` NDJSON: 90,111 bytes. Larger than the array for three
# reasons that are all encoding — a `{"create": {}}` action line per record, a newline
# after each of the 214 lines, and `json.dumps` defaults with spaces after `:` and `,`
# rather than the compact separators, which is what the single-document Elastic path has
# always sent.
BULK_CEILING = 91_500

RUNREVEAL = Destination(name="rr", type="runreveal", url="https://ingest.runreveal.com/hook", auth_type="bearer")
WEBHOOK = Destination(name="siem", type="generic_webhook", url="https://siem.example/hook", auth_type="none")
ELASTIC = Destination(name="es", type="elastic", url="https://es.example:9200", auth_type="none")


@pytest.fixture
def records(payload: dict) -> list[dict]:
    return record_events(payload)


# --- the count, the split, and the copy that must not drift --------------------------


def test_the_fixture_fans_out_to_the_same_107_records_in_the_same_split(records: list[dict]) -> None:
    """One record per list item, one per scalar section: 99 + 7. The same number the HEC
    suite pins, from the same fixture and the same contract — if these two ever disagree,
    one of the two walks has changed and the next test says which."""
    assert len(records) == FIXTURE_SUB_EVENTS
    by_sourcetype: dict[str, int] = {}
    for record in records:
        by_sourcetype[record[SOURCETYPE_KEY]] = by_sourcetype.get(record[SOURCETYPE_KEY], 0) + 1
    assert by_sourcetype == {
        **{sourcetype(wrapper): 1 for wrapper in ANCHORS},
        **{sourcetype(wrapper): count for wrapper, count in FIXTURE_ITEMS.items()},
    }


def test_the_two_walks_select_the_same_items_in_the_same_order_under_the_same_strings(payload: dict) -> None:
    """**The drift test.** `app.fanout.expand` is a copy of `app.core.hec_fanout.fan_out`'s
    traversal, taken deliberately: the Splunk wire is frozen (#188) and pinned item-for-item
    against this fixture, and #306 is a change for the other three destination types, so the
    fix must not be able to move a byte on the one wire that already has a customer.

    A copy's cost is drift, and this is where it is paid. Item for item, in order, under the
    same registry string — so a section added to the contract, a cardinality corrected, or an
    ordering changed shows up here as a failure naming both sides, rather than as two wires
    that quietly stopped agreeing about what a device is."""
    hec = fan_out({key: value for key, value in payload.items() if key != ENVELOPE}, {})
    walked = expand({key: value for key, value in payload.items() if key != ENVELOPE})
    assert len(walked) == len(hec) == FIXTURE_SUB_EVENTS

    for index, (sub_event, event) in enumerate(zip(walked, hec, strict=True)):
        body = event["event"]
        assert sub_event.sourcetype == event.get("sourcetype"), f"item {index} routes differently"
        # The HEC body is the item plus the three sub-event keys; strip those and the
        # remainder is the item this walk selected, from the same position in the payload.
        assert dict(sub_event.item) == {k: v for k, v in body.items() if k not in SUB_EVENT_KEYS}, (
            f"item {index} is not the same item"
        )


# --- the three ruled differences from a HEC sub-event --------------------------------


def test_a_record_is_the_hec_sub_event_with_the_two_envelope_facts_folded_into_the_body(
    payload: dict,
    records: list[dict],
) -> None:
    """The whole shape, in one assertion. A record is the HEC sub-event body — item,
    `event`, `jobID`, `deviceMeta` — plus exactly the two facts HEC keeps in an envelope a
    webhook receiver does not have: the routing string and the instant. Nothing else is
    added, nothing is dropped, and no key is renamed."""
    occurred_at = payload["occurredAt"]
    for record, event in zip(records, hec_events(payload), strict=True):
        assert record == {**event["event"], "occurredAt": occurred_at, SOURCETYPE_KEY: event["sourcetype"]}


def test_the_routing_string_rides_the_body_because_a_record_has_no_envelope(records: list[dict]) -> None:
    """On HEC `sourcetype` is the envelope's routing dimension (#81 ruling 7) and costs no
    licence volume. A webhook receiver has no envelope, so it would simply be lost — and it
    is the ONLY thing that says an event is an app rather than a certificate, because
    `event` is `device.inventory` on all 107 and nothing mints `device.inventory.app`
    (#188 ruling 5, D1).

    Carried under its own name rather than a second spelling, and equal to the registry's
    string for the record's own wrapper — so one vocabulary covers both wires and a
    customer moving a saved search from a webhook to Splunk keeps their predicate."""
    for record in records:
        assert record[SOURCETYPE_KEY] == sourcetype(_wrapper_of(record))
    assert len({record[SOURCETYPE_KEY] for record in records}) == len(SECTION_WRAPPERS)


def test_occurred_at_rides_every_record_because_no_envelope_carries_the_instant(
    payload: dict,
    records: list[dict],
) -> None:
    """#220 dropped `occurredAt` from the HEC sub-event on the explicit ground that "the
    same instant travels beside every sub-event as the envelope's `time`". On a record
    destination it does not travel: the outbox pops `_envelope` for every type, so without
    this a record would carry no time at all — and a record with no time is not a record a
    platform can put on an axis.

    This mints nothing. `occurredAt` is the snapshot's own head key, copied verbatim from
    the row, which is why it is the ruling's intent applied where its premise is false
    rather than an exception to it."""
    assert payload["occurredAt"]
    assert all(record["occurredAt"] == payload["occurredAt"] for record in records)
    # And it is the snapshot's, not the envelope's: same instant, but read from the body.
    assert all("occurredAt" not in event["event"] for event in hec_events(payload))


def test_no_hec_sentinel_is_minted_on_a_record(payload: dict) -> None:
    """`-1` for "no finding in this band" is the ONE thing the HEC seam mints, and
    docs/vulnerabilities.md §4c names these three destinations when it rules where the
    sentinel lives: "The canonical layer keeps `None`, and other destination dialects may
    render it natively — SQL `NULL`." So a record keeps `None` and Elastic files a null,
    while the same app on the same pull reaches Splunk as `-1`.

    The fixture's apps are all `off`/`unknown_app`, where the mint is a no-op, so this
    plants a populated band rather than asserting a difference the fixture cannot show."""
    payload = deepcopy(payload)
    index, app = next((i, item) for i, item in enumerate(payload["app"]) if "vuln" in item)
    app["vuln"] = {**app["vuln"], "daysOldestPublished": {"critical": None, "high": 12}}

    record = [r for r in record_events(payload) if "app" in r][index]
    assert record["vuln"]["daysOldestPublished"] == {"critical": None, "high": 12}

    event = [e for e in hec_events(payload) if "app" in e["event"]][index]
    assert event["event"]["vuln"]["daysOldestPublished"] == {"critical": NEVER, "high": 12}


# --- everything else is the sub-event, unchanged -------------------------------------


def test_device_meta_is_copied_verbatim_and_identical_on_every_record(
    payload: dict,
    records: list[dict],
) -> None:
    """#189's block, whole — minting nothing into it and dropping nothing from it (#81
    ruling 3), and the same object on all 107, which is what makes it the expensive key."""
    for record in records:
        assert record["deviceMeta"] == payload["deviceMeta"]
    assert all(record["deviceMeta"] == records[0]["deviceMeta"] for record in records)


def test_key_order_is_the_content_then_the_search_keys_then_device_meta(records: list[dict]) -> None:
    """#286's rule, extended over the two record-only keys rather than around them. The
    thing you opened the record to read leads; `event`, `jobID`, `occurredAt` and
    `sourcetype` are the same values repeated on all 107 rows, so they earn no space ahead
    of it; `deviceMeta` trails because it is the largest block and identical on every one.

    Key order is semantically nothing — JSON objects are unordered — which is exactly why
    it is safe to impose and worth imposing: it costs no consumer anything and it is the
    difference between a readable record and one whose first screen is boilerplate."""
    for record in records:
        keys = list(record)
        assert keys[-1] == "deviceMeta"
        head = ("event", "jobID", "occurredAt", SOURCETYPE_KEY)
        assert keys[-5:-1] == list(head), keys
        assert set(keys[:-5]).isdisjoint(head), "the section object leads"


def test_a_rebuild_is_byte_identical_and_never_mutates_the_stored_row(payload: dict) -> None:
    """Delivery retries the same row up to ten times: the second attempt must build
    exactly what the first did, and neither may leave a mark on the row it read. The
    envelope in particular is popped from a COPY — strip the row's own dict once and every
    later attempt, and every OTHER destination's delivery, loses it."""
    before = deepcopy(payload)
    first = json.dumps(record_events(payload), sort_keys=False)
    second = json.dumps(record_events(payload), sort_keys=False)
    assert first == second
    assert payload == before
    assert ENVELOPE in payload


def test_the_envelope_key_never_reaches_a_receiver(records: list[dict]) -> None:
    """`_envelope` is the outbox's own transport detail and no part of the vocabulary a
    customer writes against. It is popped for every destination type — and it must not
    come back as a section, which is what the unknown-wrapper path would do with it."""
    assert all(ENVELOPE not in record for record in records)
    assert all(SOURCE not in json.dumps(record) for record in records), "`source` is envelope-only"


def test_outside_a_run_job_id_is_absent_on_every_record_not_null(raw: dict) -> None:
    """A webhook-triggered pull carries no run. `jobID` is then absent rather than null —
    the rule the block itself follows, and the one that keeps `jobID=*` meaning "from a
    sweep" rather than matching every record ever sent."""
    records = record_events(_stored(raw))
    assert records and all("jobID" not in record for record in records)
    assert all(record["event"] == INVENTORY_EVENT_TYPE for record in records)


def test_a_wrapper_the_registry_does_not_name_is_delivered_unstamped_not_dropped(
    payload: dict,
    caplog,
) -> None:
    """Version skew, not a producer bug: a section a newer producer added, replayed on an
    older worker. Dropping it loses data silently and raising burns ten retries and
    dead-letters the device's whole pass, so it is delivered with no `sourcetype` — which
    on this wire means the key is simply absent, the record's own equivalent of landing
    under the HEC input's default."""
    payload = {**payload, "hypervisor": [{"name": "one"}, {"name": "two"}], "telemetry": {"enrolled": True}}
    with caplog.at_level(logging.WARNING):
        records = record_events(payload)
    assert len(records) == FIXTURE_SUB_EVENTS + 3
    unstamped = [record for record in records if SOURCETYPE_KEY not in record]
    assert [r.get("name") or r.get("telemetry") for r in unstamped] == ["one", "two", {"enrolled": True}]
    assert all("deviceMeta" in record and record["event"] == INVENTORY_EVENT_TYPE for record in unstamped)
    assert {r.wrapper for r in caplog.records if hasattr(r, "wrapper")} == {"hypervisor", "telemetry"}


# --- the request ---------------------------------------------------------------------


def test_one_request_of_one_json_array_and_the_measured_size_ceiling(records: list[dict]) -> None:
    """The assertion that refuses one POST per record. 107 records at 3,000 devices is
    321,000 requests a sweep if each one is its own POST; it is 3,000 if a device's records
    travel together, which is the number HEC settled on for the same reason (#242).

    The size is pinned because this is the highest-volume object the product emits: 2.74x
    the snapshot's bytes, which is the trade #306 named and accepted — more bytes for a
    shape the receiver can query."""
    (body,) = webhook_request_bodies(records, max_bytes=900_000)
    assert json.loads(body) == records
    assert len(body) < ARRAY_CEILING, f"the record request grew to {len(body)} bytes"


def test_a_record_is_byte_identical_to_the_encoding_httpx_would_have_applied(records: list[dict]) -> None:
    """The array is assembled from pre-encoded records rather than handed to httpx's
    `json=`, so the encoding is reproduced here and pinned against httpx itself — a
    receiver must not be able to tell that the bytes stopped going through the library."""
    request = httpx.Request("POST", "https://siem.example/hook", json=records)
    (body,) = webhook_request_bodies(records, max_bytes=900_000)
    assert body == request.content


def test_the_chunk_boundary_splits_on_whole_records(records: list[dict]) -> None:
    """The unit that may be split across requests is the record, never a byte range, and
    order is preserved and nothing is dropped — the ceiling bounds what one request
    carries, not what the delivery carries. Every chunk is a valid array on its own, which
    is the property that lets a receiver parse each request independently."""
    bodies = webhook_request_bodies(records, max_bytes=20_000)
    assert len(bodies) > 1
    assert all(len(body) <= 20_000 for body in bodies)
    assert [record for body in bodies for record in json.loads(body)] == records

    # A record larger than the ceiling on its own is sent alone rather than cut. Below
    # every record's own size the split is total: 107 requests of one record each, still
    # in order and still valid arrays, and every one of them over the ceiling. That is the
    # ceiling doing what it promises — bounding what a request carries where it can, never
    # truncating a record to fit.
    alone = webhook_request_bodies(records, max_bytes=100)
    assert [json.loads(body) for body in alone] == [[record] for record in records]
    assert all(len(body) > 100 for body in alone)


def test_a_snapshot_that_expands_to_nothing_sends_no_request(payload: dict) -> None:
    """Every section read was empty, which only a scoped read can produce. No request at
    all rather than an empty array a receiver would have to read as a device with no
    anything — the same answer HEC gives, for the same reason."""
    head = {key: value for key, value in payload.items() if key not in SECTION_WRAPPERS.values()}
    assert record_events(head) == []
    assert record_request_bodies(head, max_bytes=900_000) == []


def test_elastic_gets_one_bulk_pair_per_record_each_on_the_events_own_time_axis(
    payload: dict,
    records: list[dict],
) -> None:
    """`create` action line plus source line, per record — the encoding that path already
    spoke for a single document, now spoken 107 times. `@timestamp` is the record's own
    `occurredAt`, not the drain time: a sweep that runs at 01:00 and drains at 09:00 files
    at 01:00, which is the fix #218 made for the single-document path and this inherits."""
    (body,) = elastic_bulk_bodies(records, max_bytes=900_000, timestamp="1970-01-01T00:00:00+00:00")
    lines = body.decode().splitlines()
    assert len(lines) == 2 * FIXTURE_SUB_EVENTS
    assert all(json.loads(line) == {"create": {}} for line in lines[::2])
    documents = [json.loads(line) for line in lines[1::2]]
    assert documents == [{**record, "@timestamp": payload["occurredAt"]} for record in records]
    assert len(body) < BULK_CEILING, f"the bulk request grew to {len(body)} bytes"

    # The fallback is only for a payload that somehow lacks the head key.
    undated = [{key: value for key, value in record.items() if key != "occurredAt"} for record in records]
    (fallback,) = elastic_bulk_bodies(undated, max_bytes=900_000, timestamp="1970-01-01T00:00:00+00:00")
    assert json.loads(fallback.decode().splitlines()[1])["@timestamp"] == "1970-01-01T00:00:00+00:00"


def test_the_record_ceiling_is_a_validated_setting_with_the_documented_default() -> None:
    """Its own knob rather than a reuse of the Splunk one: an operator tuning a RunReveal
    ingest limit should not have to set a setting named for a product they do not run."""
    assert Settings().record_fanout_max_request_bytes == 900_000
    assert Settings(record_fanout_max_request_bytes=4_096).record_fanout_max_request_bytes == 4_096
    for bad in (4_095, 838_860_801):
        with pytest.raises(ValueError, match="record_fanout_max_request_bytes"):
            Settings(record_fanout_max_request_bytes=bad)


# --- delivery ------------------------------------------------------------------------


async def _deliver(destination: Destination, payload: dict, handler) -> tuple[list[httpx.Request], tuple]:
    seen: list[httpx.Request] = []

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(_record)) as client:
        verdict = await _attempt_delivery(client, destination, EventOutbox(event_type=payload["event"], payload=payload))
    return seen, verdict


def _accepted(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"errors": False, "items": []})


@pytest.mark.parametrize("destination", [RUNREVEAL, WEBHOOK], ids=["runreveal", "generic_webhook"])
async def test_a_webhook_shaped_delivery_posts_one_request_of_n_records(
    destination: Destination,
    payload: dict,
    records: list[dict],
) -> None:
    """The issue's own number, the other way round: one full device sweep used to put one
    event on a RunReveal destination and now puts 107, in one request. `runreveal` and
    `generic_webhook` are asserted together because they are one delivery path — the preset
    exists for the form, not for the wire — and a second branch would be where they
    silently drifted apart."""
    requests, verdict = await _deliver(destination, payload, _accepted)
    assert verdict == (True, None)
    assert len(requests) == 1
    (request,) = requests
    assert str(request.url) == destination.url
    assert request.headers["Content-Type"] == "application/json"
    assert json.loads(request.content) == records
    assert len(json.loads(request.content)) == FIXTURE_SUB_EVENTS


async def test_an_elastic_delivery_posts_one_bulk_request_of_n_documents(payload: dict) -> None:
    """Elastic was the least visible of the three — a nested snapshot indexes without
    complaint — and the most costly, because a data stream's dynamic mapping grows a field
    for every path in the document it is handed."""
    requests, verdict = await _deliver(ELASTIC, payload, _accepted)
    assert verdict == (True, None)
    assert len(requests) == 1
    (request,) = requests
    assert str(request.url) == "https://es.example:9200/logs-looninspect.events-default/_bulk"
    assert request.headers["Content-Type"] == "application/x-ndjson"
    assert len(request.content.decode().splitlines()) == 2 * FIXTURE_SUB_EVENTS


async def test_a_failed_request_fails_the_whole_delivery_and_stops_sending(
    payload: dict,
    monkeypatch,
) -> None:
    """One request of N records lands or fails as one. A failure fails the DELIVERY, which
    backs off and retries every body rebuilt from the same row — so a device's records
    duplicate together, and the dedup key on a fanned-out record is the pull plus the item,
    never `deviceMeta.eventID` alone."""
    monkeypatch.setattr(outbox.settings, "record_fanout_max_request_bytes", 20_000)
    calls: list[int] = []

    def _refuse_the_second(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200 if len(calls) == 1 else 413, text="too large")

    requests, verdict = await _deliver(WEBHOOK, payload, _refuse_the_second)
    ok, error = verdict
    assert ok is False and "413" in error
    assert len(requests) == 2, "stopped at the first failure rather than sending the rest"


async def test_every_other_family_is_still_one_document_on_every_type() -> None:
    """The blast radius, stated as a test. #306 changed the snapshot and nothing else: a
    change event, a run event and the test event all still travel as the one canonical
    document they always did, on all three types."""
    for event_type in ("device.change", "run.completed", "run.failed", "device.inventory.changed"):
        body = {"event": event_type, "subjectKind": "computer", "section": "applications"}
        for destination in (RUNREVEAL, WEBHOOK):
            requests, verdict = await _deliver(destination, body, _accepted)
            assert verdict == (True, None) and len(requests) == 1
            assert json.loads(requests[0].content) == body
        assert len(_elastic_bulk_requests(EventOutbox(event_type=event_type, payload=body))) == 1
