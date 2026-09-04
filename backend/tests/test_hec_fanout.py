"""The Splunk HEC fan-out over the real fixture (#242, absorbing #222). Pure; no database.

One `device.inventory` snapshot in, N HEC event objects out, each under the registry's
string for its wrapper — the moment a customer's `props.conf` stanzas become real, and
the highest-volume object the product will ever emit. So this suite holds the emitted
sub-events to the rulings on a captured Jamf Pro 11.31 record rather than on a
hand-written payload:

* the count and the per-section split — 107 for the fixture: 83 apps, 3 extension
  attributes, 1 group, 5 profiles, 2 local user accounts, 5 certificates, 1 software
  update, plus the seven one-per-device anchors;
* every sub-event's `sourcetype` is `wire_vocabulary.sourcetype(wrapper)`, the set emitted
  under the full aperture is exactly the registry's fourteen, and no enrichment string is
  ever stamped (#81 ruling 7, #222, #242 item 6);
* `deviceMeta` is #189's block, verbatim and identical on every sub-event; `event` and
  `jobID` ride every one (#220's three); the enrichment blocks ride the app sub-event
  inline and nowhere else; no minted identity field, no `occurredAt`; labels ride;
* the wrapper object deep-equals the payload's entry, the anchor is one sub-event per
  scalar section, order is registry order then payload order, and a rebuild is
  byte-identical without mutating the stored row;
* the request: one body of N concatenated JSON objects, byte-identical to httpx's own
  `json=` encoding for the single-event families, the measured size pinned as a ceiling,
  and the chunk boundary when the ceiling is lowered;
* every other family and every other destination type keep today's body, except the run
  families, which gain `loon:run`.

The database lane — the real fixture through `sync_connection`, both worker passes and a
mocked HEC — is `tests/test_hec_fanout_db.py`.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from app.core import outbox
from app.core.config import Settings, settings
from app.core.hec_fanout import fan_out
from app.core.outbox import (
    TEST_EVENT_TYPE,
    _attempt_delivery,
    _build_body,
    _chunk,
    _elastic_bulk_body,
    _encode_hec_event,
    hec_events,
    hec_request_bodies,
    send_test_event,
)
from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, RunContext, reset_run
from app.core.runs import set_run as _set_run
from app.core.wire import ENVELOPE, envelope
from app.core.wire_vocabulary import (
    ASSERTION_EVENT_TYPES,
    ASSERTION_SOURCETYPE,
    DELTA_SOURCETYPE,
    ENRICHMENTS,
    SECTION_WRAPPERS,
    SUB_EVENT_KEYS,
    enrichment_rows,
    registry_rows,
    sourcetype,
)
from app.mdm.jamf.contract import SECTIONS
from app.models.schema import Destination, EventOutbox
from app.schemas.payload import INVENTORY_EVENT_TYPE, SNAPSHOT_HEAD_KEYS, InventorySnapshotEvent
from tests.test_device_meta import SHIPPED_ELEVEN
from tests.test_inventory_snapshot import _RUN_ID, _WINDOW, MINTED_KEYS, _snapshot

FIXTURE = Path(__file__).parent / "fixtures" / "jamf" / "computer_inventory_detail_real.json"
SOURCE = "e2e.jamfcloud.com"
SPLUNK = SimpleNamespace(type="splunk_hec")
WEBHOOK = SimpleNamespace(type="webhook")
ELASTIC = SimpleNamespace(type="elastic")

# The device anchor (#81; #242 "The ruled design"): the seven one-per-device sections, one
# sub-event each. Written out rather than derived so the registry's cardinality is checked
# against an independent statement of it, and asserted equal to `SectionSpec.is_list` below.
ANCHORS = ("general", "hardware", "operatingSystem", "userAndLocation", "purchasing", "security", "diskEncryption")
# The fixture's list sections, item by item. 99 items plus the seven anchors is 107 — the
# number #242 quotes and PR #273's verify pass settled (three EAs, since #197's hoist).
FIXTURE_ITEMS = {"app": 83, "ea": 3, "group": 1, "profile": 5, "localUserAccount": 2, "cert": 5, "update": 1}
FIXTURE_SUB_EVENTS = 107

# The whole request for the fixture's device, measured on 2026-09-03 as the newline-joined
# compact JSON of its 107 sub-events under the real eleven-key meta block: 84,135 bytes, 2.92
# times the 28,783-byte snapshot. Pinned as a ceiling with ~1% headroom so the next byte added to the
# most-multiplied object on the wire is loud, the way #241 pinned the snapshot (29,000).
REQUEST_CEILING = 85_000

_CAMEL = re.compile(r"^[a-z][A-Za-z0-9]*$")
_LOWERCASE_ID_TOKEN = re.compile(r"Id(?:[A-Z]|$)")


@pytest.fixture
def run() -> Iterator[RunContext]:
    context = RunContext(
        id=_RUN_ID,
        connection_id=1,
        collection_id=4,
        trigger=TRIGGER_SWEEP,
        comparison="delta",
        lock_class=LOCK_DEVICE_SWEEP,
        window_start=_WINDOW,
    )
    token = _set_run(context)
    try:
        yield context
    finally:
        reset_run(token)


@pytest.fixture
def raw() -> dict:
    return json.loads(FIXTURE.read_text())


def _stored(raw: dict, sections=None) -> dict:
    """The outbox row's payload exactly as `process_sync` stores it: the snapshot the
    #241 builder produced (the same helper `test_inventory_snapshot.py` pins) plus the
    envelope hints under the reserved key."""
    payload = _snapshot(raw, sections) if sections is not None else _snapshot(raw)
    payload[ENVELOPE] = envelope(occurred_at=_WINDOW, host=raw["general"]["name"], source=SOURCE)
    return payload


@pytest.fixture
def payload(raw: dict, run: RunContext) -> dict:
    return _stored(raw)


@pytest.fixture
def events(payload: dict) -> list[dict]:
    return hec_events(payload)


def _wrapper_of(body: dict) -> str:
    """The one registry wrapper key a sub-event body carries."""
    (wrapper,) = set(body) & set(SECTION_WRAPPERS.values())
    return wrapper


def _minted_keys(body: dict) -> set[str]:
    """Every key on one sub-event that LoonInspect minted: the top level, `deviceMeta`,
    and the enrichment blocks. The wrapper OBJECT is Jamf's and is not descended into —
    `bundleId` inside `app{}` is Jamf's spelling — except for the one key LoonInspect
    mints inside a Jamf object, `ea.source` (#197)."""
    keys = set(body)
    for block in ("deviceMeta", *ENRICHMENTS["app"]):
        value = body.get(block)
        if isinstance(value, dict):
            keys |= set(value)
    if "ea" in body:
        assert "source" in body["ea"], "the ea item carries the minted `source` key"
        keys.add("source")
    return keys


# --- the count, the split, the strings ----------------------------------------------


def test_the_fixture_fans_out_to_107_sub_events_in_the_ruled_split(events: list[dict]) -> None:
    """One sub-event per list item, one per scalar section: 99 + 7. The cardinality comes
    from the contract's `SectionSpec.is_list` — `localUserAccount` is a list whatever the
    registry's "one per device — long" naming comment says — and the anchor is exactly the
    seven scalar sections, in both directions."""
    assert len(events) == FIXTURE_SUB_EVENTS
    by_sourcetype: dict[str, int] = {}
    for event in events:
        by_sourcetype[event["sourcetype"]] = by_sourcetype.get(event["sourcetype"], 0) + 1
    expected = {sourcetype(wrapper): 1 for wrapper in ANCHORS}
    expected |= {sourcetype(wrapper): count for wrapper, count in FIXTURE_ITEMS.items()}
    assert by_sourcetype == expected
    assert set(ANCHORS) == {SECTION_WRAPPERS[name] for name, spec in SECTIONS.items() if not spec.is_list}
    assert set(FIXTURE_ITEMS) == {SECTION_WRAPPERS[name] for name, spec in SECTIONS.items() if spec.is_list}


def test_every_sub_event_carries_the_registry_string_for_its_wrapper_and_nothing_else_is_stamped(
    events: list[dict],
) -> None:
    """#81 ruling 7 — the sourcetype tree is the routing dimension — and #222's acceptance:
    the string is `wire_vocabulary.sourcetype(wrapper)` and nothing else. Both directions:
    every sub-event carries its wrapper's string, and the set emitted under the full
    aperture is the registry's fourteen — never an enrichment string, which stays minted
    with no writer (#242 item 6), and never a string a table in this file could invent."""
    registry = {stype for _section, _key, _wrapper, stype in registry_rows()}
    for event in events:
        wrapper = _wrapper_of(event["event"])
        assert event["sourcetype"] == sourcetype(wrapper)
        assert event["sourcetype"].rsplit(":", 1)[-1] == wrapper, "the leaf is the wrapper key (#188 ruling 5)"
    assert {event["sourcetype"] for event in events} == registry
    assert len(registry) == 14
    reserved = {stype for _carrier, _leaf, stype in enrichment_rows()}
    assert reserved == {"loon:jamf:mac:app:patch", "loon:jamf:mac:app:vuln", "loon:jamf:mac:app:alert"}
    assert not reserved & {event["sourcetype"] for event in events}
    # The HEC object is the wrapped body, the string, and the three envelope hints — no
    # `index` (the token alone decides where events land), no `_envelope`.
    for event in events:
        assert set(event) == {"event", "sourcetype", "time", "host", "source"}


# --- the sub-event body ---------------------------------------------------------------


def test_a_list_sub_event_is_the_item_plus_the_three_ruled_keys(payload: dict, events: list[dict]) -> None:
    """#241 property 2, read by #242 as PR #273's verify pass settled it: the list item is
    already the sub-event body minus `SUB_EVENT_KEYS`, so the fan-out is iteration —
    `{**item, event, jobID, deviceMeta}` — and the wrapper object deep-equals
    `payload[wrapper][i][wrapper]`, byte for byte, nothing added, renamed or removed
    inside it (Kyle, 2026-09-02: "Use Jamf's v4 Names Verbatim")."""
    for wrapper in FIXTURE_ITEMS:
        subs = [event["event"] for event in events if _wrapper_of(event["event"]) == wrapper]
        items = payload[wrapper]
        assert len(subs) == len(items) == FIXTURE_ITEMS[wrapper]
        for body, item in zip(subs, items, strict=True):
            assert body[wrapper] == item[wrapper]
            assert set(body) == set(item) | set(SUB_EVENT_KEYS)
            # The snapshot's own layout, one level down: the head first, the block last.
            assert list(body)[:2] == ["event", "jobID"]
            assert list(body)[-1] == "deviceMeta"


def test_the_anchor_is_one_sub_event_per_scalar_section_carrying_jamfs_object_whole(
    payload: dict, events: list[dict], raw: dict
) -> None:
    """The device anchor as #242 specifies it — not a combined event: seven sub-events,
    each `{event, jobID, <wrapper>: Jamf's object, deviceMeta}` under its own string. A
    section read and genuinely empty (`userAndLocation` is `{}` on the real record, every
    user field null) is still one sub-event, so a full read always produces its seven."""
    anchors = {
        _wrapper_of(event["event"]): event for event in events if _wrapper_of(event["event"]) in ANCHORS
    }
    assert set(anchors) == set(ANCHORS)
    for wrapper, event in anchors.items():
        body = event["event"]
        assert set(body) == {*SUB_EVENT_KEYS, wrapper}
        assert body[wrapper] == payload[wrapper]
        assert event["sourcetype"] == sourcetype(wrapper)
    general = anchors["general"]["event"]
    assert general["general"]["name"] == raw["general"]["name"]
    assert general["event"] == INVENTORY_EVENT_TYPE
    assert anchors["userAndLocation"]["event"]["userAndLocation"] == {}
    assert anchors["hardware"]["event"]["hardware"]["serialNumber"] == raw["hardware"]["serialNumber"]


def test_device_meta_is_copied_verbatim_and_identical_on_every_sub_event(payload: dict, events: list[dict]) -> None:
    """#81 ruling 3, now #189's block: copied onto every sub-event whole, the fan-out
    minting nothing into it and dropping nothing from it. The twelve ruled keys are the
    eleven that ship plus the reserved name; `eventID` is inside it already, derived at
    enqueue, so `deviceMeta.eventID` selects one device's whole pass across every
    sourcetype — the selector `runs.py` teaches for a fan-out sourcetype."""
    meta = payload["deviceMeta"]
    assert set(meta) == set(SHIPPED_ELEVEN)
    for event in events:
        body = event["event"]
        assert body["deviceMeta"] == meta
        assert body["deviceMeta"] is not meta, "a copy, so no sub-event can reach the stored row's block"
        assert body["deviceMeta"]["eventID"] == meta["eventID"]
        assert body["jobID"] == meta["jobID"] == payload["jobID"], "#220: at the root and inside the block"
        assert body["event"] == payload["event"] == INVENTORY_EVENT_TYPE, "D1: the snapshot's type, verbatim"
    assert {event["event"]["deviceMeta"]["eventID"] for event in events} == {meta["eventID"]}


def test_the_enrichment_blocks_ride_the_app_sub_event_inline_and_nowhere_else(payload: dict, events: list[dict]) -> None:
    """#242 item 6 and item 3: `patch{}` and `vuln{}` are always present on the app
    sub-event — by pass-through, not by stamping — and on no other; `alert` is name-only
    in v0 and rides nothing; and no enrichment becomes a sub-event of its own."""
    apps = [event["event"] for event in events if _wrapper_of(event["event"]) == "app"]
    assert len(apps) == FIXTURE_ITEMS["app"]
    for body, item in zip(apps, payload["app"], strict=True):
        assert set(body) == {*SUB_EVENT_KEYS, "app", "patch", "vuln"}
        assert body["patch"] == item["patch"] == {"supported": False}
        assert body["vuln"] == item["vuln"] == {"assessment": "off"}
        assert "alert" not in body
    for event in events:
        body = event["event"]
        if _wrapper_of(body) != "app":
            assert not set(body) & set(ENRICHMENTS["app"])
    assert set(ENRICHMENTS["app"]) == {"patch", "vuln", "alert"}


def test_no_minted_identity_field_and_no_occurred_at_ride_a_sub_event(events: list[dict]) -> None:
    """Kyle, 2026-09-02: "leave them out for now we can add them in the future. We can add
    keys later but we can't take them away." — `appHash`, `versionHash`, `keyTitle`,
    `keyFull` on no app object. And `occurredAt` does not ride the sub-event: #220's three
    are the ruled complete answer to what survives the split, the same instant travels as
    the envelope's `time`, and under additive-only clause 3 omitting is the reversible
    direction (recorded as such in the #242 PR)."""
    for event in events:
        body = event["event"]
        assert "occurredAt" not in body
        assert ENVELOPE not in body
        assert set(SNAPSHOT_HEAD_KEYS) - set(body) == {"occurredAt"}
        if "app" in body:
            assert not set(body["app"]) & MINTED_KEYS
            assert "bundleId" in body["app"], "Jamf's spelling, untouched"


def test_labels_ride_under_jamfs_key(events: list[dict], raw: dict) -> None:
    """Kyle, 2026-09-03 (on PR #273): labels ride — `group.groupName`,
    `profile.displayName`, `ea.name` beside the allowlisted body, permanently."""
    (group,) = [event["event"] for event in events if _wrapper_of(event["event"]) == "group"]
    assert group["group"]["groupName"] == raw["groupMemberships"][0]["groupName"]
    profiles = [event["event"]["profile"] for event in events if _wrapper_of(event["event"]) == "profile"]
    assert {profile["displayName"] for profile in profiles} == {p["displayName"] for p in raw["configurationProfiles"]}
    eas = [event["event"]["ea"] for event in events if _wrapper_of(event["event"]) == "ea"]
    assert all(ea["name"] and ea["source"] for ea in eas)


def test_the_envelope_rides_every_sub_event_with_the_same_values(payload: dict, events: list[dict]) -> None:
    """#242 item 5: `time`, `host` and `source` lifted from the hints once and copied onto
    each HEC event object — a sweep's sub-events share the run's window."""
    hints = payload[ENVELOPE]
    assert set(hints) == {"time", "host", "source"}
    for event in events:
        assert (event["time"], event["host"], event["source"]) == (hints["time"], hints["host"], hints["source"])
    assert hints["time"] == _WINDOW.timestamp()


def test_every_key_looninspect_minted_on_a_sub_event_obeys_the_casing_law(events: list[dict]) -> None:
    """The wire-casing net for what the builder EMITS — `test_wire_casing.py` judges outbox
    rows and never descends into `app[]`, so `patch.supported` and `vuln.assessment` were
    minted keys no net judged until here. camelCase with `ID` uppercase on the top level,
    `deviceMeta`, `patch`, `vuln` and `ea.source`; the wrapper objects are Jamf's."""
    offences = {
        key
        for event in events
        for key in _minted_keys(event["event"])
        if not _CAMEL.match(key) or _LOWERCASE_ID_TOKEN.search(key)
    }
    assert offences == set()
    assert {key for event in events for key in event} == {"event", "sourcetype", "time", "host", "source"}


# --- order, determinism, aperture ---------------------------------------------------


def test_order_is_registry_order_then_payload_order(payload: dict, events: list[dict]) -> None:
    """D2: the order is fixed — `registry_rows()` (anchors first, in the contract's
    declaration order), items in payload order — so a partial acceptance can be reasoned
    about by position."""
    expected: list[str] = []
    for section, _key, wrapper, stype in registry_rows():
        expected.extend([stype] * (len(payload[wrapper]) if SECTIONS[section].is_list else 1))
    assert [event["sourcetype"] for event in events] == expected
    assert [event["event"]["app"]["name"] for event in events if "app" in event["event"]] == [
        item["app"]["name"] for item in payload["app"]
    ]


def test_a_rebuild_is_byte_identical_and_never_mutates_the_stored_row(payload: dict) -> None:
    """Delivery is retried against the same row up to ten times. `test_wire.py` pins that
    building a body never mutates the row; the expansion inherits that duty, and adds
    that two expansions of one row are the same bytes in the same order."""
    before = deepcopy(payload)
    first = hec_request_bodies(payload, max_bytes=settings.splunk_hec_max_request_bytes)
    second = hec_request_bodies(payload, max_bytes=settings.splunk_hec_max_request_bytes)
    assert first == second
    assert payload == before
    assert ENVELOPE in payload


def test_a_scoped_read_fans_out_only_the_wrappers_it_read(raw: dict, run: RunContext) -> None:
    """The 2026-08-29 ruling, per section: a wrapper absent from the snapshot is outside
    the read's aperture and fans out nothing. Three scalar sections read: three anchors,
    no app sub-event — never an empty one."""
    events = hec_events(_stored(raw, ("general", "hardware", "operating_system")))
    assert [event["sourcetype"] for event in events] == [
        sourcetype("general"), sourcetype("hardware"), sourcetype("operatingSystem"),
    ]
    assert all(set(event["event"]) == {*SUB_EVENT_KEYS, _wrapper_of(event["event"])} for event in events)


def test_a_read_and_empty_list_section_fans_out_nothing_for_it(raw: dict, run: RunContext) -> None:
    """`[]` is a real read of a device with no apps: no app sub-event, the other 24 intact.
    On the wire that is indistinguishable from an unread section — the gap #242 records
    and does not fill; the payload keeps the distinction, the fan-out loses it."""
    raw["applications"] = []
    events = hec_events(_stored(raw))
    assert len(events) == FIXTURE_SUB_EVENTS - FIXTURE_ITEMS["app"]
    assert sourcetype("app") not in {event["sourcetype"] for event in events}


def test_outside_a_run_job_id_is_absent_on_every_sub_event_not_null(raw: dict) -> None:
    """The block drops its nulls, the root copy follows it, and so does the sub-event: a
    run-less snapshot fans out with no `jobID` anywhere rather than 107 nulls."""
    events = hec_events(_stored(raw))
    assert len(events) == FIXTURE_SUB_EVENTS
    for event in events:
        body = event["event"]
        assert "jobID" not in body and "jobID" not in body["deviceMeta"] and "eventID" not in body["deviceMeta"]
        assert body["event"] == INVENTORY_EVENT_TYPE and next(iter(body)) == "event"


def test_a_wrapper_the_registry_does_not_name_is_delivered_unstamped_not_dropped(
    payload: dict, caplog: pytest.LogCaptureFixture
) -> None:
    """Version skew, not a producer bug — `InventorySnapshotEvent` refuses unknown wrappers
    at enqueue — so a section a newer producer added, replayed on an older worker, costs
    unstamped sub-events under the HEC input's default (where every event was before any
    stamp existed), a warning, and never a raise that would burn ten retries."""
    skewed = {**payload, "fonts": [{"fonts": {"name": "Menlo"}}, {"fonts": {"name": "Monaco"}}], "storage": {"disks": []}}
    with caplog.at_level(logging.WARNING, logger="app.core.hec_fanout"):
        events = hec_events(skewed)
    assert len(events) == FIXTURE_SUB_EVENTS + 3
    unstamped = [event for event in events if "sourcetype" not in event]
    assert [event["event"].get("fonts") or event["event"].get("storage") for event in unstamped] == [
        {"name": "Menlo"}, {"name": "Monaco"}, {"disks": []},
    ]
    for event in unstamped:
        assert set(SUB_EVENT_KEYS) <= set(event["event"])
        assert set(event) == {"event", "time", "host", "source"}
    assert sum("registry does not name" in record.message for record in caplog.records) == 2


def test_the_fan_out_reads_the_vocabulary_not_a_second_table() -> None:
    """The invariant `fan_out` relies on: no wrapper key and no enrichment leaf collides
    with the three sub-event keys, so `{**item, event, jobID, deviceMeta}` can never
    overwrite the head or be overwritten by it."""
    wrappers = set(SECTION_WRAPPERS.values()) | {leaf for leaves in ENRICHMENTS.values() for leaf in leaves}
    assert not wrappers & set(SUB_EVENT_KEYS)
    assert not wrappers & set(SNAPSHOT_HEAD_KEYS)
    assert fan_out is outbox.fan_out


# --- the request --------------------------------------------------------------------


def test_one_request_of_n_events_and_the_measured_size_ceiling(payload: dict, events: list[dict]) -> None:
    """One `OutboxDelivery` row, one POST, N indexed events: the body is the 107 HEC event
    objects as newline-concatenated compact JSON, which `/services/collector/event`
    accepts. The size is measured, not estimated — #242 asked for the number — and pinned
    as a ceiling so growth on the most-multiplied object is loud."""
    bodies = hec_request_bodies(payload, max_bytes=settings.splunk_hec_max_request_bytes)
    assert len(bodies) == 1
    (body,) = bodies
    lines = body.split(b"\n")
    assert len(lines) == FIXTURE_SUB_EVENTS
    assert [json.loads(line) for line in lines] == events
    assert not body.endswith(b"\n")
    assert len(body) <= REQUEST_CEILING, f"the fixture's request grew to {len(body)} bytes; say why in the PR"
    # And it fits Splunk Cloud Platform's documented 1 MB `max_content_length` many times
    # over — the ceiling the default setting is set under.
    assert len(body) < settings.splunk_hec_max_request_bytes / 8


def test_the_chunk_boundary(payload: dict) -> None:
    """The ceiling bounds one request, never the delivery: whole events only, in order,
    nothing dropped, and a single event over the ceiling goes alone rather than cut."""
    lines = [_encode_hec_event(event) for event in hec_events(payload)]
    exactly_three = len(lines[0]) + 1 + len(lines[1]) + 1 + len(lines[2])

    bodies = hec_request_bodies(payload, max_bytes=exactly_three)
    assert bodies[0] == b"\n".join(lines[:3]), "three lines that exactly fill the ceiling share one request"
    assert all(len(body) <= exactly_three for body in bodies)
    assert b"\n".join(bodies) == b"\n".join(lines), "every line, once, in order, across the requests"

    shy = hec_request_bodies(payload, max_bytes=exactly_three - 1)
    assert shy[0] == b"\n".join(lines[:2]), "one byte short, and the third line starts the next request"

    alone = hec_request_bodies(payload, max_bytes=1)
    assert alone == lines, "a ceiling below one event sends each event alone rather than splitting it"

    assert _chunk([], 10) == []
    assert _chunk([b"12345", b"12345", b"1234567890123"], 11) == [b"12345\n12345", b"1234567890123"]


def test_a_single_event_family_is_byte_identical_to_the_json_encoding_httpx_used() -> None:
    """The other families keep today's body byte for byte. Before the fan-out they were
    sent with `json=`; now every Splunk request is bytes, so the encoding is pinned
    against httpx's own rather than assumed: compact separators, `ensure_ascii=False`."""
    occurred = _WINDOW
    payloads = [
        {"event": "device.inventory.changed", "deviceMeta": {"hostName": "Loon’s Mac mini"}, "addedApps": [],
         ENVELOPE: envelope(occurred_at=occurred, host="Loon’s Mac mini", source=SOURCE)},
        {"event": "run.completed", "jobID": str(_RUN_ID), "devicesTotal": 2,
         ENVELOPE: envelope(occurred_at=occurred, host=None, source=SOURCE)},
        {"event": "device.change", "subjectKind": "computer", "section": "security", "change": "changed",
         ENVELOPE: envelope(occurred_at=occurred, host="mbp-ada", source=SOURCE)},
        {"event": TEST_EVENT_TYPE, "message": "LoonInspect destination test. Ünïcode survives."},
    ]
    for payload in payloads:
        (body,) = hec_request_bodies(payload, max_bytes=settings.splunk_hec_max_request_bytes)
        request = httpx.Request("POST", "https://splunk.example/services/collector", json=_build_body(SPLUNK, payload))
        assert body == request.content
        assert json.loads(body) == _build_body(SPLUNK, payload)


def test_the_run_family_carries_loon_run_the_delta_carries_its_own_and_the_test_event_carries_nothing() -> None:
    """#242 item 6: `run.completed` and `run.failed` carry `ASSERTION_SOURCETYPE` in the
    same change as the section tree — one mapping in the body builder, no fan-out
    involved. The delta family carries `DELTA_SOURCETYPE` since #277, stamped the day
    before the flip. Still under the operator's input default: only the test event
    (deliberately identifiable)."""
    for event in sorted(ASSERTION_EVENT_TYPES):
        assert _build_body(SPLUNK, {"event": event, "jobID": "x"})["sourcetype"] == ASSERTION_SOURCETYPE == "loon:run"
    assert {"run.completed", "run.failed"} == ASSERTION_EVENT_TYPES
    delta_body = _build_body(SPLUNK, {"event": "device.inventory.changed"})
    assert delta_body["sourcetype"] == DELTA_SOURCETYPE == "loon:inventory:changed"
    assert "sourcetype" not in _build_body(SPLUNK, {"event": TEST_EVENT_TYPE})
    # A generic webhook never sees a sourcetype, whatever the family.
    assert _build_body(WEBHOOK, {"event": "run.completed", "jobID": "x"}) == {"event": "run.completed", "jobID": "x"}


def test_the_snapshot_has_no_one_document_hec_body_but_every_other_destination_gets_it_whole(payload: dict) -> None:
    """`_build_body` is the one-document view, and on Splunk the snapshot is not one
    document: asking is a programming error, refused loudly rather than answered with
    the whole nested snapshot #241 shipped between the two issues. Every non-Splunk
    destination keeps the canonical snapshot, unstamped, exactly as before."""
    with pytest.raises(ValueError, match="fanned out"):
        _build_body(SPLUNK, payload)
    canonical = {key: value for key, value in payload.items() if key != ENVELOPE}
    assert _build_body(WEBHOOK, payload) == canonical
    assert _build_body(ELASTIC, payload) == canonical
    assert set(canonical) - set(SNAPSHOT_HEAD_KEYS) == set(SECTION_WRAPPERS.values())
    document = json.loads(_elastic_bulk_body(EventOutbox(event_type=INVENTORY_EVENT_TYPE, payload=payload)).splitlines()[1])
    assert "sourcetype" not in document and ENVELOPE not in document
    assert len(document["app"]) == FIXTURE_ITEMS["app"]


# --- delivery ------------------------------------------------------------------------


def _splunk_destination() -> Destination:
    return Destination(
        name="splunk",
        type="splunk_hec",
        url="https://splunk.example.com:8088/services/collector/event",
        auth_type="splunk_hec",
        auth_secret_encrypted="00000000-1111-2222-3333-444444444444",
    )


def _webhook_destination() -> Destination:
    return Destination(name="siem", type="generic_webhook", url="https://siem.example/hook", auth_type="none")


async def _deliver(destination: Destination, payload: dict, handler) -> list[httpx.Request]:
    seen: list[httpx.Request] = []

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(_record)) as client:
        ok, error = await _attempt_delivery(client, destination, EventOutbox(event_type=payload["event"], payload=payload))
    seen.append(SimpleNamespace(verdict=(ok, error)))  # type: ignore[arg-type]
    return seen


def _accepted(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"text": "Success", "code": 0})


async def test_a_splunk_delivery_posts_one_request_of_n_objects_and_a_webhook_gets_one_dict(payload: dict) -> None:
    """The assertion that refuses one POST per sub-event (#242 "Delivery mechanics"): one
    delivery of one snapshot to a `splunk_hec` destination is exactly one request whose
    body decodes as N concatenated JSON objects; the same event to a generic webhook is
    one request of one canonical dict."""
    splunk = _splunk_destination()
    *requests, verdict = await _deliver(splunk, payload, _accepted)
    assert verdict.verdict == (True, None)
    assert len(requests) == 1
    (request,) = requests
    assert str(request.url) == splunk.url
    assert request.headers["Content-Type"] == "application/json"
    assert request.headers["Authorization"] == "Splunk 00000000-1111-2222-3333-444444444444"
    assert request.headers["Content-Length"] == str(len(request.content))
    objects = [json.loads(line) for line in request.content.split(b"\n")]
    assert len(objects) == FIXTURE_SUB_EVENTS
    assert objects == hec_events(payload)

    *requests, verdict = await _deliver(_webhook_destination(), payload, _accepted)
    assert verdict.verdict == (True, None) and len(requests) == 1
    assert json.loads(requests[0].content) == {key: value for key, value in payload.items() if key != ENVELOPE}


async def test_a_lowered_ceiling_splits_the_delivery_into_consecutive_requests(payload: dict, monkeypatch) -> None:
    """The setting is read at delivery time. Under a 20,000-byte ceiling the fixture's
    ~100 KB expansion is several requests, each under the ceiling, whole events only,
    all of them accepted before the delivery is called delivered."""
    monkeypatch.setattr(settings, "splunk_hec_max_request_bytes", 20_000)
    expected = hec_request_bodies(payload, max_bytes=20_000)
    assert len(expected) > 1
    *requests, verdict = await _deliver(_splunk_destination(), payload, _accepted)
    assert verdict.verdict == (True, None)
    assert [request.content for request in requests] == expected
    assert all(len(request.content) <= 20_000 for request in requests)
    assert sum(request.content.count(b"\n") + 1 for request in requests) == FIXTURE_SUB_EVENTS


async def test_a_failed_request_fails_the_whole_delivery_and_stops_sending(payload: dict, monkeypatch) -> None:
    """One request either lands or fails as one, and a delivery is every one of its
    requests: the first non-2xx fails the delivery with HEC's own text, nothing after it
    is sent, and the retry (the outbox's ordinary backoff) re-sends the whole delivery —
    the already-indexed first request included, deduplicated downstream on
    `deviceMeta.eventID` plus the item's identity."""
    monkeypatch.setattr(settings, "splunk_hec_max_request_bytes", 20_000)
    calls = 0

    def _second_fails(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 2:
            return httpx.Response(400, json={"text": "Invalid data format", "code": 6, "invalid-event-number": 3})
        return _accepted(request)

    *requests, verdict = await _deliver(_splunk_destination(), payload, _second_fails)
    ok, error = verdict.verdict
    assert ok is False and error is not None
    assert error.startswith("HTTP 400") and "invalid-event-number" in error
    assert len(requests) == 2, "stop at the first failure; the delivery row is what retries"


async def test_a_snapshot_that_expands_to_nothing_sends_no_request_and_is_delivered(run: RunContext) -> None:
    """Only a scoped read can produce it: a snapshot whose every section is a read-empty
    list. There is nothing to index, so no request is made and the delivery completes
    rather than pending for ever on a body that cannot exist."""
    payload = InventorySnapshotEvent(occurredAt=_WINDOW, deviceMeta={"jamfProID": "7"}, app=[], cert=[]).to_payload()
    payload[ENVELOPE] = envelope(occurred_at=_WINDOW, host="mbp-ada", source=SOURCE)
    assert hec_request_bodies(payload, max_bytes=settings.splunk_hec_max_request_bytes) == []
    *requests, verdict = await _deliver(_splunk_destination(), payload, _accepted)
    assert requests == [] and verdict.verdict == (True, None)


async def test_the_destination_test_event_is_one_unstamped_object(monkeypatch) -> None:
    """`destination.test` keeps today's body: one object, no sourcetype, no envelope — it
    is meant to be identifiable in the index, not routed."""
    seen: list[httpx.Request] = []

    class _Mocked(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(lambda request: (seen.append(request), _accepted(request))[1])
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(outbox.httpx, "AsyncClient", _Mocked)
    destination = _splunk_destination()
    destination.id = 7
    assert await send_test_event(destination) == (True, None)
    (request,) = seen
    body = json.loads(request.content)
    assert set(body) == {"event"} and body["event"]["event"] == TEST_EVENT_TYPE
    assert body["event"]["destinationId"] == 7


# --- the setting -----------------------------------------------------------------------


def test_the_request_ceiling_is_a_validated_setting_with_the_documented_default() -> None:
    """900,000 bytes: 10% under the 1,000,000 that is both Splunk Cloud Platform's
    documented HEC `max_content_length` and Splunk Enterprise's pre-7.x default, with the
    upper bound at Enterprise's shipped default. The floor is one sub-event with room."""
    assert settings.splunk_hec_max_request_bytes == 900_000
    assert Settings(_env_file=None).splunk_hec_max_request_bytes == 900_000
    assert Settings(_env_file=None, splunk_hec_max_request_bytes=4_096).splunk_hec_max_request_bytes == 4_096
    for bad in (0, 4_095, 838_860_801):
        with pytest.raises(ValidationError, match="splunk_hec_max_request_bytes"):
            Settings(_env_file=None, splunk_hec_max_request_bytes=bad)


# --- #286: the designed key order on the families the fan-out does not build -----------
#
# Every other assertion in this suite compares `set(body)`, which is order-blind by
# construction — so before #286 nothing anywhere pinned the order of a delivered event,
# in either direction. These are the tests that make the order a contract rather than
# whatever `dict(payload)` happened to yield.

# The exact key order Postgres returned for a real `device.inventory.changed` row on
# 2026-09-04 (main 8e6f0d6), copied verbatim: `jsonb` normalises by key length, then
# bytewise. `deviceMeta` sits mid-content, between `addedApps` and `occurredAt`, which is
# the defect #286 was filed for.
_JSONB_SCRAMBLED_DELTA = (
    "event", "jobID", "provider", "addedApps", "deviceMeta",
    "occurredAt", "removedApps", "deviceExternalID",
)


def test_the_head_leads_and_device_meta_trails_every_single_event_family() -> None:
    """`event`, `jobID`, the family's own keys, `deviceMeta` last — the layout `fan_out`
    already builds by hand, now obeyed by the three families it does not touch.

    Asserted as a list. `set(body)` — which every older assertion in this file uses —
    passes identically whatever the order is, and is why this went unnoticed until
    someone read the events in Splunk.
    """
    delta = {
        "occurredAt": "2026-09-04T00:00:00Z",
        "deviceMeta": {"hostName": "mbp-ada"},
        "addedApps": [],
        "jobID": "01a0-JOB",
        "event": "device.inventory.changed",
    }
    body = _build_body(SPLUNK, delta)["event"]
    assert list(body) == ["event", "jobID", "occurredAt", "addedApps", "deviceMeta"]

    run = {
        "status": "succeeded",
        "devicesTotal": 2,
        "connectionID": 1,
        "jobID": "01a0-JOB",
        "event": "run.completed",
    }
    assert list(_build_body(SPLUNK, run)["event"]) == [
        "event", "jobID", "status", "devicesTotal", "connectionID",
    ]

    # A family carrying no `deviceMeta` simply has no trailer; the head still leads.
    change = {"section": "security", "change": "changed", "jobID": "x", "event": "device.change"}
    assert list(_build_body(SPLUNK, change)["event"])[:2] == ["event", "jobID"]
    assert "deviceMeta" not in _build_body(SPLUNK, change)["event"]


def test_the_designed_order_survives_the_jsonb_scramble() -> None:
    """The regression this exists to catch, reproduced from its cause.

    The order a producer writes never reaches delivery: `event_outbox.payload` is `jsonb`
    and Postgres hands back its own. Feeding that exact scrambled order in must still
    yield the designed one — otherwise the fix only works on dicts Python happened to
    build in a friendly order, which is every dict in a unit test and no dict in
    production.
    """
    stored = {key: key for key in _JSONB_SCRAMBLED_DELTA}
    stored["event"] = "device.inventory.changed"
    body = _build_body(SPLUNK, stored)["event"]

    assert list(body)[:2] == ["event", "jobID"]
    assert list(body)[-1] == "deviceMeta"
    # Nothing was dropped, renamed or revalued on the way through — this reorders only.
    assert body == stored


def test_the_webhook_body_reads_in_the_same_order_as_the_hec_body() -> None:
    """Splunk is where the cost was noticed; it is not where it is. A generic webhook
    receiver reads the same JSON document, so it gets the same reading order."""
    stored = {key: key for key in _JSONB_SCRAMBLED_DELTA}
    stored["event"] = "device.inventory.changed"
    assert list(_build_body(WEBHOOK, stored)) == list(_build_body(SPLUNK, stored)["event"])


def test_the_order_is_deterministic_so_a_retry_stays_byte_identical() -> None:
    """Delivery retries the same stored row up to ten times and the bytes must not move
    between attempts — the property `_encode_hec_event` exists to hold. Ordering is a pure
    function of the row, so it does not disturb it."""
    stored = {key: key for key in _JSONB_SCRAMBLED_DELTA}
    stored["event"] = "device.inventory.changed"
    stored[ENVELOPE] = envelope(occurred_at=_WINDOW, host="mbp-ada", source=SOURCE)

    first, *rest = [hec_request_bodies(stored, max_bytes=settings.splunk_hec_max_request_bytes) for _ in range(3)]
    assert all(attempt == first for attempt in rest)
    # And the stored row itself is untouched, scrambled order and all.
    assert tuple(key for key in stored if key != ENVELOPE) == _JSONB_SCRAMBLED_DELTA


def test_the_fan_out_already_obeyed_the_rule_and_still_does(payload: dict) -> None:
    """#286 lifted the rule out of `fan_out`; it did not change it. Every sub-event still
    leads with the head and trails with `deviceMeta`, which is what made it the rule worth
    generalising rather than a fourth opinion."""
    for event in fan_out(dict(payload), {}):
        keys = list(event["event"])
        assert keys[:2] == ["event", "jobID"]
        assert keys[-1] == "deviceMeta"
