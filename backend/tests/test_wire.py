"""The delivered envelope — `time`, `host`, `source` (#188, #189).

These four fields ride beside the event body rather than inside it. Splunk meters licence
on the event value, not the envelope, so a string that fits here is free where the same
string in `deviceMeta` is paid for on every one of a device's sub-events. That makes the
envelope's correctness worth its own tests: it is load-bearing for `_time` meaning *when
the device changed*, and nothing else in the suite covers app.core.wire.

The last section pins the other half of the contract: which producers have a `host` and
which deliberately do not. Three of the four event families shipped with no envelope at
all until they were given one, and the fix would be half-made if "a run has no host" or
"a group is not a Mac" were left as an accident of a code path rather than a ruling with
a test behind it.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest

from app.changes.derive import EVENT_TYPE as CHANGE_EVENT
from app.changes.derive import _change_device_meta, _event_payload
from app.core.outbox import _attempt_delivery, _build_body, _elastic_bulk_body
from app.core.wire import ENVELOPE, envelope, instance_label
from app.core.wire_vocabulary import SUBJECT_WRAPPERS, change_rows, change_sourcetype
from app.mdm.jamf.contract import GROUP_DEFINITION_SECTION, SUBJECT_COMPUTER, SUBJECT_COMPUTER_GROUP, Observation
from app.models.schema import Destination, DeviceChange, EventOutbox

SPLUNK = SimpleNamespace(type="splunk_hec")
WEBHOOK = SimpleNamespace(type="webhook")
ELASTIC = SimpleNamespace(type="elastic")
CONNECTION = SimpleNamespace(id=1, base_url="https://acme.jamfcloud.com")


@pytest.mark.parametrize(
    ("base_url", "expected"),
    [
        # Cloud: the scheme is a constant and carries nothing.
        ("https://acme.jamfcloud.com", "acme.jamfcloud.com"),
        ("https://acme.jamfcloud.com/", "acme.jamfcloud.com"),
        # On-prem: the port IS identifying — :8443 and :8444 are two different servers,
        # and merging them would union two fleets under one `source`.
        ("https://jamf.corp.local:8443", "jamf.corp.local:8443"),
        ("https://jamf.corp.local:8444", "jamf.corp.local:8444"),
        # An explicitly-written default port is still the default, so it is dropped —
        # otherwise one instance reachable by two spellings becomes two sources.
        ("https://acme.jamfcloud.com:443", "acme.jamfcloud.com"),
        ("http://legacy.corp.local:80", "legacy.corp.local"),
        # Hostnames are case-insensitive; Splunk's `source` matching is not.
        ("https://ACME.JamfCloud.com", "acme.jamfcloud.com"),
        # A bare host is accepted rather than mangled into a path.
        ("acme.jamfcloud.com", "acme.jamfcloud.com"),
        # Credentials never reach indexed metadata — .netloc would have carried them.
        ("https://admin:hunter2@jamf.corp.local:8443", "jamf.corp.local:8443"),
    ],
)
def test_the_instance_label_is_the_host_and_only_a_meaningful_port(base_url, expected) -> None:
    assert instance_label(base_url) == expected


def test_a_malformed_port_degrades_to_the_host_rather_than_failing_the_sync() -> None:
    """A cosmetic defect in a base URL must not raise out of the ingest path."""
    assert instance_label("https://jamf.corp.local:notaport") == "jamf.corp.local"


def test_the_envelope_carries_occurrence_time_not_delivery_time() -> None:
    """The whole point of setting HEC `time`.

    A sweep back-dates every event to the run's window (app.core.runs.event_time), so an
    event delivered at 09:00 for a 01:00 sweep must land at 01:00. Asserted exactly: a
    tolerance wide enough to absorb the difference would also absorb the bug.
    """
    delivered = datetime.now(timezone.utc)
    occurred = delivered - timedelta(days=3)
    hints = envelope(occurred_at=occurred, host="kyle-mbp", source="acme.jamfcloud.com")

    assert hints["time"] == occurred.timestamp()
    # The gap is the assertion: an outbox that stamped delivery time would land three
    # days late, which is exactly the drained-backlog case the retention window allows.
    assert delivered.timestamp() - hints["time"] == pytest.approx(timedelta(days=3).total_seconds())


def test_an_absent_host_is_dropped_rather_than_sent_empty() -> None:
    """HEC falls back to the input's own default host for a blank one, which collapses
    every affected device onto a single phantom host where `dc(serialNumber)` counts
    them all as one. Absent is recoverable; wrong is not."""
    hints = envelope(occurred_at=datetime.now(timezone.utc), host="", source=None)
    assert "host" not in hints
    assert "source" not in hints
    assert "time" in hints


def test_the_envelope_is_lifted_beside_the_body_and_never_into_it() -> None:
    occurred = datetime(2026, 8, 31, 1, 0, tzinfo=timezone.utc)
    payload = {
        "event": "device.inventory.changed",
        "deviceMeta": {"serialNumber": "C02XL0THJGH5"},
        ENVELOPE: envelope(occurred_at=occurred, host="kyle-mbp", source="acme.jamfcloud.com"),
    }
    body = _build_body(SPLUNK, payload)

    assert body["time"] == occurred.timestamp()
    assert body["host"] == "kyle-mbp"
    assert body["source"] == "acme.jamfcloud.com"
    assert ENVELOPE not in body["event"]
    # Still absent on the inventory family, and on every family but `device.change`: the
    # ruled section tree names fan-out sub-events that do not exist yet, and a sourcetype
    # is a permanent props.conf stanza (#188, #222 — absorbed by the fan-out, #242). The
    # `:change` family is the stated exception and is asserted below.
    assert "sourcetype" not in body


def test_no_index_is_sent_so_the_hec_token_alone_decides_where_events_land() -> None:
    """docs/splunk-setup.md tells the operator to scope the token to exactly one index,
    on the grounds that the token's own index list is the *only* thing choosing the
    destination index. Start sending `index` here and that instruction silently becomes
    wrong: a token allowed several indexes would write wherever the body said, and the
    least-privilege setup the doc asks for would stop being the control it claims to be.
    """
    payload = {
        "event": "device.inventory.changed",
        ENVELOPE: envelope(
            occurred_at=datetime(2026, 8, 31, tzinfo=timezone.utc),
            host="kyle-mbp",
            source="acme.jamfcloud.com",
        ),
    }
    body = _build_body(SPLUNK, payload)

    assert "index" not in body
    # Nor smuggled in beside the envelope hints: the body is the wrapper plus exactly
    # the three fields wire.envelope() produces.
    assert set(body) == {"event", "time", "host", "source"}


def test_the_envelope_never_reaches_a_non_splunk_destination() -> None:
    """It is outbox transport, not vocabulary. A generic webhook receiver must never see
    it, or the reserved key becomes part of the contract by accident."""
    payload = {"event": "device.inventory.changed", ENVELOPE: {"host": "kyle-mbp"}}
    assert _build_body(WEBHOOK, payload) == {"event": "device.inventory.changed"}


async def test_a_splunk_delivery_posts_the_configured_url_verbatim() -> None:
    """docs/splunk-setup.md tells the operator to type the whole HEC endpoint, path
    included, because delivery appends nothing to it — the Elastic branch is the one that
    assembles `{url}/{index}/_bulk`. If that ever stopped being true, the documented URL
    would 404 for every reader who followed the instruction, and the doc is the only
    place the `/services/collector` path is written down.

    The `Splunk <token>` header rides along here for the same reason: the field is
    labelled "Secret" in the UI, and the doc's claim that it takes the bare HEC token
    with no scheme prefix is only true while `_build_headers` adds the prefix itself.
    """
    destination = Destination(
        name="splunk",
        type="splunk_hec",
        url="https://splunk.example.com:8088/services/collector",
        auth_type="splunk_hec",
        auth_secret_encrypted="00000000-1111-2222-3333-444444444444",
    )
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"text": "Success", "code": 0})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        ok, error = await _attempt_delivery(
            client, destination, EventOutbox(event_type="device.inventory.changed", payload={"event": "x"})
        )

    assert (ok, error) == (True, None)
    assert str(seen[0].url) == "https://splunk.example.com:8088/services/collector"
    assert seen[0].headers["Authorization"] == "Splunk 00000000-1111-2222-3333-444444444444"


def test_building_a_body_does_not_mutate_the_stored_payload() -> None:
    """Delivery is retried against the same EventOutbox row up to ten times. If the first
    attempt stripped the envelope from the row's own dict, every retry after it would be
    delivered without `time`, `host` or `source` — and the events that landed would be
    the ones a destination outage had already delayed the most."""
    payload = {"event": "device.inventory.changed", ENVELOPE: {"host": "kyle-mbp"}}
    _build_body(SPLUNK, payload)
    assert ENVELOPE in payload
    assert _build_body(SPLUNK, payload)["host"] == "kyle-mbp"


# --- who gets a `host`, and who does not -------------------------------------------


def test_an_absent_host_is_a_ruling_the_run_family_relies_on() -> None:
    """`host` means "the Mac this event is about" — one thing, on every event type.

    A run is about a connection, not a device, so it passes `host=None` rather than
    filling the slot with the Jamf server (that is already `source`, and counting it as
    a Mac breaks every `dc(host)`) or the worker's container (infrastructure naming a
    customer's SPL cannot join to anything). HEC then applies the input's own default,
    which a Splunk admin can see and override — unlike a value the product asserted.
    """
    hints = envelope(occurred_at=datetime.now(timezone.utc), host=None, source="acme.jamfcloud.com")
    body = _build_body(SPLUNK, {"event": "run.completed", ENVELOPE: hints})

    assert "host" not in body
    assert body["source"] == "acme.jamfcloud.com"
    assert "time" in body


def test_a_group_change_carries_no_host_because_a_group_is_not_a_mac() -> None:
    """`derive_and_record` runs for computer_group subjects too, and a group's
    `subject_label` is a group name. Shipping it as `host` would invent Macs called
    "Devices out of Checkin Compliance" and corrupt `dc(host)` across the index. The
    instance is still known, so `source` stays."""
    connection = CONNECTION
    observed = datetime(2026, 8, 23, 9, 0, tzinfo=timezone.utc)

    def _row(subject_kind: str, subject_label: str) -> DeviceChange:
        return DeviceChange(
            subject_kind=subject_kind,
            subject_id="12",
            subject_label=subject_label,
            observed_at=observed,
            collected_at=observed,
            trigger="sweep",
            section="definition",
            change="changed",
            level="normal",
            policy_version="v0",
        )

    group = _event_payload(_row(SUBJECT_COMPUTER_GROUP, "Devices out of Checkin Compliance"), connection, {})
    assert "host" not in group[ENVELOPE]
    assert group[ENVELOPE]["source"] == "acme.jamfcloud.com"

    # A computer subject does get one: its label IS the hostname — both are Jamf's
    # general.name — so the change family and the inventory family name one `host`.
    computer = _event_payload(_row(SUBJECT_COMPUTER, "mbp-ada"), connection, {})
    assert computer[ENVELOPE]["host"] == "mbp-ada"
    # Outside a run, `event_time` is now; the row's own observed_at is what a run
    # back-dates to, and either way the time is the event's, never the delivery's.
    assert computer[ENVELOPE]["time"] >= observed.timestamp()


# --- the `:change` sourcetype (#223, on the family #243 ruled) -----------------------


def _change_payload(*, subject_kind: str, section: str) -> dict:
    """One `device.change` exactly as `changes/derive.py` enqueues it, for one subject.

    Driven through the real producer rather than hand-written: what is under test is that
    the section names the derivation actually writes are the registry's own keys, and a
    literal payload here would assert that against itself.
    """
    observed = datetime(2026, 8, 23, 9, 0, tzinfo=timezone.utc)
    observation = Observation(
        subject_kind=subject_kind,
        subject_id="12",
        sections={},
        observed_at=observed,
        serial_number="C02XL0THJGH5",
        label="mbp-ada",
    )
    row = DeviceChange(
        subject_kind=subject_kind,
        subject_id="12",
        subject_label="mbp-ada",
        observed_at=observed,
        collected_at=observed,
        trigger="sweep",
        section=section,
        change="changed",
        level="normal",
        policy_version="v0",
    )
    return _event_payload(row, CONNECTION, _change_device_meta(observation))


def _subject_of(subject: str) -> tuple[str, str]:
    """A registry row's subject as the `(subject_kind, section)` a real change row carries.

    The fifteenth is the one that is not a section: a smart group's definition is its own
    ledger subject, whose section is `definition` and whose entity segment names the
    subject (`computerGroup`) rather than the section — #243's ruling on question 5.
    """
    if subject in SUBJECT_WRAPPERS:
        return SUBJECT_COMPUTER_GROUP, GROUP_DEFINITION_SECTION
    return SUBJECT_COMPUTER, subject


@pytest.mark.parametrize(("subject", "wrapper", "expected"), change_rows())
def test_every_change_subject_carries_the_string_the_registry_generates(subject, wrapper, expected) -> None:
    """One assertion per minted string, over an event the producer built.

    A sourcetype is permanent (clause 5) and a `props.conf` stanza keys on it exactly, so
    the string a subject arrives under is the whole contract — a wrong one is a stanza that
    matches nothing, silently.
    """
    subject_kind, section = _subject_of(subject)
    body = _build_body(SPLUNK, _change_payload(subject_kind=subject_kind, section=section))

    assert body["sourcetype"] == expected
    assert body["sourcetype"].endswith(f":{wrapper}:change")


def test_the_stamped_strings_are_the_registrys_fifteen_and_no_others() -> None:
    """Coverage in both directions, which the per-row test above cannot give on its own:
    no subject is left unstamped, and nothing is stamped that the registry does not
    generate. Fifteen strings is fifteen hand-written stanzas in a customer's Splunk."""
    stamped = {
        _build_body(SPLUNK, _change_payload(subject_kind=kind, section=section))["sourcetype"]
        for kind, section in (_subject_of(subject) for subject, _wrapper, _stype in change_rows())
    }
    assert stamped == {stype for _subject, _wrapper, stype in change_rows()}
    assert len(stamped) == 15


def test_no_destination_but_splunk_gets_a_sourcetype() -> None:
    """A sourcetype is Splunk's routing dimension, not part of the event. Every other
    destination keeps the canonical body — a generic webhook receiver and an Elastic
    document must not gain a Splunk field because the same payload happened to be
    subscribed twice."""
    payload = _change_payload(subject_kind=SUBJECT_COMPUTER, section="applications")
    canonical = {key: value for key, value in payload.items() if key != ENVELOPE}

    assert _build_body(WEBHOOK, payload) == canonical
    assert _build_body(ELASTIC, payload) == canonical
    # The real Elastic path does not go through `_build_body` at all, so it is asserted on
    # its own document rather than by implication.
    document = json.loads(_elastic_bulk_body(EventOutbox(event_type=CHANGE_EVENT, payload=payload)).splitlines()[1])
    assert "sourcetype" not in document


def test_only_the_change_family_is_stamped() -> None:
    """#242's job is not done here. The section tree names fan-out sub-events that do not
    exist, so minting one of those strings now would be a permanent stanza for a shape
    about to change (#222). The per-device snapshot (#241) passes through unstamped for
    the same reason: it is the whole device in one event, and the strings name the
    sub-events #242 splits it into. The guard is on the event type, so a family added
    later is unstamped until it is ruled."""
    for event in ("device.inventory", "device.inventory.changed", "run.completed", "run.failed", "destination.test"):
        body = _build_body(SPLUNK, {"event": event, "subjectKind": "computer", "section": "applications"})
        assert "sourcetype" not in body, f"{event} must not be stamped by the change family's rule"


def test_the_snapshot_passes_through_the_body_builder_whole_and_unstamped() -> None:
    """Between #241 and #242 a `splunk_hec` destination receives the snapshot as one nested
    HEC event under the input's own sourcetype: wrapped, with the three envelope hints
    beside it and nothing else, and every wrapper key intact — `_build_body` reshapes
    nothing for this family."""
    occurred = datetime(2026, 9, 2, 2, 0, tzinfo=timezone.utc)
    payload = {
        "event": "device.inventory",
        "jobID": "0199a5c4-7b2e-7c3a-9f1e-3c2b1a0d9e8f",
        "occurredAt": occurred.isoformat(),
        "deviceMeta": {"jobID": "0199a5c4-7b2e-7c3a-9f1e-3c2b1a0d9e8f", "serialNumber": "LOONMINI0M4"},
        "general": {"name": "Loon's Mac mini"},
        "app": [{"app": {"name": "Maps.app"}, "patch": {"supported": False}, "vuln": {"assessment": "off"}}],
        ENVELOPE: envelope(occurred_at=occurred, host="Loon's Mac mini", source="e2e.jamfcloud.com"),
    }
    body = _build_body(SPLUNK, payload)
    assert set(body) == {"event", "time", "host", "source"}
    assert body["event"] == {key: value for key, value in payload.items() if key != ENVELOPE}
    assert body["time"] == occurred.timestamp()
    assert _build_body(WEBHOOK, payload) == body["event"]


def test_an_unknown_section_costs_one_unstamped_event_not_a_dead_letter() -> None:
    """The delivery path's failure mode. `_build_body` runs inside `_attempt_delivery`,
    where a raise is retried ten times and then dead-lettered, so a payload whose section
    has no wrapper — a shape from a newer aperture, replayed on an older worker — must
    degrade to the HEC input's own sourcetype, which is where every event was before this
    stamp existed."""
    assert change_sourcetype(CHANGE_EVENT, subject_kind="computer", section="quantum_state") is None
    assert change_sourcetype(CHANGE_EVENT, subject_kind=None, section=None) is None
    body = _build_body(SPLUNK, {"event": CHANGE_EVENT, "subjectKind": "computer", "section": "quantum_state"})
    assert "sourcetype" not in body

    # And the subject decides before the section: a group's own section is `definition`,
    # which no wrapper answers to, so reading the section first would leave the one subject
    # #243 minted a string for as the only one with no stamp at all.
    assert (
        change_sourcetype(CHANGE_EVENT, subject_kind=SUBJECT_COMPUTER_GROUP, section=GROUP_DEFINITION_SECTION)
        == "loon:jamf:mac:computerGroup:change"
    )
