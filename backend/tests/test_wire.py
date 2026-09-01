"""The delivered envelope — `time`, `host`, `source` (#188, #189).

These four fields ride beside the event body rather than inside it. Splunk meters licence
on the event value, not the envelope, so a string that fits here is free where the same
string in `deviceMeta` is paid for on every one of a device's sub-events. That makes the
envelope's correctness worth its own tests: it is load-bearing for `_time` meaning *when
the device changed*, and nothing else in the suite covers app.core.wire.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest

from app.core.outbox import _attempt_delivery, _build_body
from app.core.wire import ENVELOPE, envelope, instance_label
from app.models.schema import Destination, EventOutbox

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
