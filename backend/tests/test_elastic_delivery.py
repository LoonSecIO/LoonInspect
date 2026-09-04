"""The Elastic destination's delivery contract, and the RunReveal preset's.

Elastic speaks the bulk API: an NDJSON body (`{"create": {}}` action lines) POSTed to
`{base_url}/{index}/_bulk`, `Authorization: ApiKey <base64>`, `@timestamp` mapped from
the event's `occurred_at`. The trap these tests pin hardest: the bulk API answers
HTTP 200 with per-item failures buried in the body — `errors: true` must surface as a
delivery failure in the outbox, or an Elastic destination with a bad mapping or index
permission fails silently forever.

RunReveal rides the generic-webhook delivery path unchanged — bare JSON, bearer auth.
The preset exists for the UI; these tests prove the wire format did not fork.

All pure-lane: the destination and event rows are built in memory and HTTP is
httpx.MockTransport, so nothing here needs a database.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest
from pydantic import ValidationError

from app.core.outbox import (
    ELASTIC_DEFAULT_INDEX,
    _attempt_delivery,
    _build_body,
    _build_headers,
    _elastic_bulk_body,
    _elastic_bulk_url,
)
from app.core.wire import ENVELOPE, envelope
from app.models.schema import Destination, EventOutbox

# Deliberately the PRE-#188 spelling, which no producer emits any more. What this
# fixture pins is the `occurred_at` fallback in `_elastic_bulk_body`: the outbox keeps up
# to seven days of undelivered events, so a backlog enqueued before the casing rename
# must still map to `@timestamp` rather than silently re-dating to its drain time. Once
# that window has passed the fallback is dead code and this payload goes with it.
_PAYLOAD = {
    "event": "device.inventory.changed",
    "occurred_at": "2026-08-29T12:00:00+00:00",
    "added_apps": [{"name": "Wireshark", "version": "3.4.0"}],
}


def _elastic_destination(**overrides) -> Destination:
    values = {
        "name": "elastic",
        "type": "elastic",
        "url": "https://cluster.es.example:9243",
        "auth_type": "elastic_api_key",
        "auth_secret_encrypted": "aWQ6a2V5",
        "elastic_index": None,
    }
    values.update(overrides)
    return Destination(**values)


def _event(payload: dict | None = None) -> EventOutbox:
    return EventOutbox(event_type="device.inventory.changed", payload=payload or dict(_PAYLOAD))


# --- URL: the index is a destination setting, not a URL the admin assembles ---------


def test_bulk_url_uses_data_stream_default() -> None:
    assert _elastic_bulk_url(_elastic_destination()) == (
        f"https://cluster.es.example:9243/{ELASTIC_DEFAULT_INDEX}/_bulk"
    )
    # And the default itself stays data-stream shaped (logs-<dataset>-<namespace>),
    # so a fresh cluster's built-in logs-*-* template accepts the first POST.
    assert ELASTIC_DEFAULT_INDEX == "logs-looninspect.events-default"


def test_bulk_url_honours_configured_index_and_trailing_slash() -> None:
    destination = _elastic_destination(url="https://cluster.es.example:9243/", elastic_index="logs-custom-prod")
    assert _elastic_bulk_url(destination) == "https://cluster.es.example:9243/logs-custom-prod/_bulk"


# --- Body: NDJSON, create action lines, @timestamp from occurred_at ----------------


def test_bulk_body_is_create_ndjson_with_timestamp_from_occurred_at() -> None:
    body = _elastic_bulk_body(_event())
    assert body.endswith("\n")
    action_line, source_line = body.strip().split("\n")
    # `create`, not `index`: the default index is a data stream, which accepts
    # nothing else.
    assert json.loads(action_line) == {"create": {}}
    document = json.loads(source_line)
    assert document["@timestamp"] == _PAYLOAD["occurred_at"]
    assert document["event"] == "device.inventory.changed"
    assert document["added_apps"] == _PAYLOAD["added_apps"]


def test_bulk_body_does_not_mutate_the_stored_payload() -> None:
    event = _event()
    _elastic_bulk_body(event)
    assert "@timestamp" not in event.payload


def test_bulk_body_survives_a_payload_with_no_occurrence_anywhere() -> None:
    """The genuine fallback: no body key AND no envelope. Enqueue time, so a document is
    never unmappable.

    **This test used to prove nothing.** Its fixture was `{"event": "run.completed"}` — a
    family that *does* carry `occurredAt` — and it asserted only that `@timestamp` was
    truthy, which passes on enqueue time. It was named for the fallback and never
    exercised it, while the two families that really took the fallback went untested
    (#218). Now the fixture genuinely lacks an occurrence and the assertion is exact.
    """
    event = EventOutbox(event_type="run.failed", payload={"event": "run.failed"})
    event.created_at = datetime(2026, 9, 4, 9, 0, tzinfo=timezone.utc)
    document = json.loads(_elastic_bulk_body(event).strip().split("\n")[1])
    assert document["@timestamp"] == "2026-09-04T09:00:00+00:00"


# --- #218: the occurrence lives in the envelope for two of the four families ----------

# The instant the event happened, and the much later instant the outbox drained it. The
# gap is the whole bug: a sweep that dies at 01:00 and is delivered at 09:00 must index
# at 01:00, or an alert with a one-hour window never sees the alarm that #103 made
# default-on for every destination.
_OCCURRED = datetime(2026, 9, 4, 1, 0, tzinfo=timezone.utc)
_DRAINED = datetime(2026, 9, 4, 9, 0, tzinfo=timezone.utc)


def _event_at(event_type: str, payload: dict) -> EventOutbox:
    """One stored row: a body with no occurrence key, an envelope that has one, and a
    created_at eight hours later."""
    event = EventOutbox(
        event_type=event_type,
        payload={**payload, ENVELOPE: envelope(occurred_at=_OCCURRED, host=None, source="jamf.example")},
    )
    event.created_at = _DRAINED
    return event


@pytest.mark.parametrize(
    ("event_type", "payload"),
    [
        # Neither family carries occurredAt: run.failed has windowStart/windowEnd, and
        # device.change has observedAt/collectedAt — different facts, not this one.
        ("run.failed", {"event": "run.failed", "jobID": "01a0", "windowEnd": _OCCURRED.isoformat()}),
        ("device.change", {"event": "device.change", "section": "security", "observedAt": _OCCURRED.isoformat()}),
    ],
)
def test_a_family_with_no_body_occurrence_takes_it_from_the_envelope(event_type: str, payload: dict) -> None:
    document = json.loads(_elastic_bulk_body(_event_at(event_type, payload)).strip().split("\n")[1])
    assert document["@timestamp"] == _OCCURRED.isoformat()
    # The assertion that would have caught this on the day it shipped.
    assert document["@timestamp"] != _DRAINED.isoformat()
    # And the hints themselves never reach the index — they are transport, not data.
    assert ENVELOPE not in document


def test_the_envelope_instant_is_converted_not_forwarded() -> None:
    """`envelope()` stores epoch **seconds**; Elastic's default date mapping is
    `strict_date_optional_time||epoch_millis`. Forwarding the float would be read as
    milliseconds and file every document in January 1970 — silent, and it still indexes,
    which is worse than the skew this fixes. So the value must be an ISO string."""
    document = json.loads(_elastic_bulk_body(_event_at("run.failed", {"event": "run.failed"})).strip().split("\n")[1])
    stamped = document["@timestamp"]
    assert isinstance(stamped, str)
    assert datetime.fromisoformat(stamped).year == 2026
    assert stamped != _OCCURRED.timestamp()


def test_a_body_occurrence_still_wins_over_the_envelope() -> None:
    """The two families that DO carry `occurredAt` are unchanged by #218 — the body key
    is read first, and the envelope is consulted only when there is none."""
    event = _event_at("run.completed", {"event": "run.completed", "occurredAt": "2026-09-04T02:30:00+00:00"})
    document = json.loads(_elastic_bulk_body(event).strip().split("\n")[1])
    assert document["@timestamp"] == "2026-09-04T02:30:00+00:00"


# --- Auth header ------------------------------------------------------------------


def test_elastic_api_key_header() -> None:
    headers = _build_headers(_elastic_destination())
    assert headers["Authorization"] == "ApiKey aWQ6a2V5"


# --- Delivery: the wire request, and the 200-with-errors trap ---------------------


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_elastic_delivery_posts_ndjson_bulk() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"errors": False, "items": [{"create": {"status": 201}}]})

    async with _client(handler) as client:
        ok, error = await _attempt_delivery(client, _elastic_destination(), _event())

    assert (ok, error) == (True, None)
    request = seen[0]
    assert str(request.url) == f"https://cluster.es.example:9243/{ELASTIC_DEFAULT_INDEX}/_bulk"
    assert request.headers["Content-Type"] == "application/x-ndjson"
    assert request.headers["Authorization"] == "ApiKey aWQ6a2V5"
    action_line = request.content.decode().split("\n")[0]
    assert json.loads(action_line) == {"create": {}}


async def test_bulk_200_with_item_errors_is_a_delivery_failure() -> None:
    """The trap the issue names: HTTP 200, errors buried per item. Swallowing this
    would mark the delivery `delivered` while Elastic indexed nothing."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "errors": True,
                "items": [
                    {
                        "create": {
                            "status": 400,
                            "error": {"type": "mapper_parsing_exception", "reason": "failed to parse field"},
                        }
                    }
                ],
            },
        )

    async with _client(handler) as client:
        ok, error = await _attempt_delivery(client, _elastic_destination(), _event())

    assert ok is False
    assert error is not None
    assert "mapper_parsing_exception" in error
    assert "failed to parse field" in error
    assert "400" in error


async def test_bulk_200_with_unparseable_body_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>proxy says hi</html>")

    async with _client(handler) as client:
        ok, error = await _attempt_delivery(client, _elastic_destination(), _event())

    assert ok is False
    assert error is not None and "not JSON" in error


async def test_bulk_http_error_still_fails_like_any_destination() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    async with _client(handler) as client:
        ok, error = await _attempt_delivery(client, _elastic_destination(), _event())

    assert ok is False
    assert error is not None and error.startswith("HTTP 401")


# --- RunReveal: a preset over the generic-webhook wire, not a new format ----------


def test_runreveal_body_is_the_bare_payload() -> None:
    destination = Destination(name="rr", type="runreveal", url="https://api.runreveal.com/sources/hook/abc")
    assert _build_body(destination, dict(_PAYLOAD)) == _PAYLOAD


async def test_runreveal_delivery_is_bearer_json() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    destination = Destination(
        name="rr",
        type="runreveal",
        url="https://api.runreveal.com/sources/hook/abc",
        auth_type="bearer",
        auth_secret_encrypted="rr-token",
    )
    async with _client(handler) as client:
        ok, error = await _attempt_delivery(client, destination, _event())

    assert (ok, error) == (True, None)
    request = seen[0]
    assert str(request.url) == "https://api.runreveal.com/sources/hook/abc"
    assert request.headers["Authorization"] == "Bearer rr-token"
    assert request.headers["Content-Type"] == "application/json"
    assert json.loads(request.content) == _PAYLOAD


# --- Schema: the new types and the index rules ------------------------------------


def test_create_accepts_elastic_with_index() -> None:
    from app.schemas.destinations import DestinationCreate

    created = DestinationCreate(
        name="elastic",
        type="elastic",
        url="https://cluster.es.example:9243",
        auth_type="elastic_api_key",
        auth_secret="aWQ6a2V5",
        elastic_index="logs-custom.events-prod",
    )
    assert created.elastic_index == "logs-custom.events-prod"


def test_create_accepts_runreveal_with_bearer() -> None:
    from app.schemas.destinations import DestinationCreate

    created = DestinationCreate(
        name="rr",
        type="runreveal",
        url="https://api.runreveal.com/sources/hook/abc",
        auth_type="bearer",
        auth_secret="rr-token",
    )
    assert created.type == "runreveal"


@pytest.mark.parametrize("bad", ["Logs-Upper", "has space", "a/b", "-leading", ".", "wild*card"])
def test_invalid_elastic_index_is_rejected(bad: str) -> None:
    """Elastic's own naming rules, enforced as a 422 at configuration time rather
    than a per-item bulk rejection discovered later in the delivery log."""
    from app.schemas.destinations import DestinationUpdate

    with pytest.raises(ValidationError, match="elasticIndex"):
        DestinationUpdate(elastic_index=bad)


def test_update_can_clear_the_index_back_to_default() -> None:
    from app.schemas.destinations import DestinationUpdate

    updated = DestinationUpdate(elastic_index=None)
    assert updated.elastic_index is None
