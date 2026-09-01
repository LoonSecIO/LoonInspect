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

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.core.outbox import _build_body
from app.core.wire import ENVELOPE, envelope, instance_label

SPLUNK = SimpleNamespace(type="splunk_hec")
WEBHOOK = SimpleNamespace(type="webhook")


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
    # Ruled absent until the fan-out lands: a sourcetype is a permanent props.conf
    # stanza, and the ruled tree names sub-events that do not exist yet (#188).
    assert "sourcetype" not in body


def test_the_envelope_never_reaches_a_non_splunk_destination() -> None:
    """It is outbox transport, not vocabulary. A generic webhook receiver must never see
    it, or the reserved key becomes part of the contract by accident."""
    payload = {"event": "device.inventory.changed", ENVELOPE: {"host": "kyle-mbp"}}
    assert _build_body(WEBHOOK, payload) == {"event": "device.inventory.changed"}


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
    from app.changes.derive import _event_payload
    from app.mdm.jamf.contract import SUBJECT_COMPUTER, SUBJECT_COMPUTER_GROUP
    from app.models.schema import DeviceChange

    connection = SimpleNamespace(id=1, base_url="https://acme.jamfcloud.com")
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

    group = _event_payload(_row(SUBJECT_COMPUTER_GROUP, "Devices out of Checkin Compliance"), connection)
    assert "host" not in group[ENVELOPE]
    assert group[ENVELOPE]["source"] == "acme.jamfcloud.com"

    # A computer subject does get one: its label IS the hostname — both are Jamf's
    # general.name — so the change family and the inventory family name one `host`.
    computer = _event_payload(_row(SUBJECT_COMPUTER, "mbp-ada"), connection)
    assert computer[ENVELOPE]["host"] == "mbp-ada"
    # Outside a run, `event_time` is now; the row's own observed_at is what a run
    # back-dates to, and either way the time is the event's, never the delivery's.
    assert computer[ENVELOPE]["time"] >= observed.timestamp()
