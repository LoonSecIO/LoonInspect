"""Snowflake's public export contract: replay, boundaries and incomplete receipts (#848)."""

import json
from copy import deepcopy

import pytest

from app.core.wire import ENVELOPE
from app.snowflake_export import ExportBatch, account_for, batches, event_row
from tests.test_hec_fanout import payload as payload
from tests.test_hec_fanout import raw as raw
from tests.test_hec_fanout import run as run


def row(event_id="1", *, source_id="install-a", tenant_id="tenant-a", payload=None):
    payload = payload if payload is not None else {"event": "device.change", "deviceMeta": {"eventID": "shared-pull"}}
    return event_row(payload, source_id=source_id, tenant_id=tenant_id, event_id=event_id, event_type=payload["event"])


def test_real_inventory_stays_one_public_source_event(payload):
    stored = deepcopy(payload)
    stored[ENVELOPE] = {"time": 42, "source": "example.jamfcloud.com", "host": "fixture"}
    before = deepcopy(stored)
    export = row(payload=stored)
    value = json.loads(export.ndjson)
    assert value["PAYLOAD"] == {key: item for key, item in payload.items() if key != ENVELOPE}
    assert len(value["PAYLOAD"]["app"]) == 83
    assert value["OCCURRED_AT"] == payload["occurredAt"].replace("Z", "+00:00")
    assert ENVELOPE not in value["PAYLOAD"]
    assert "LOADED_AT" not in value
    assert stored == before
    assert export.ndjson.endswith(b"\n")


def test_replay_identity_survives_reencoding_and_distinguishes_sibling_changes():
    original = {"event": "device.change", "deviceMeta": {"eventID": "same-pull"}, "after": "27.2.1"}
    replay = dict(reversed(list(original.items())))
    assert row(payload=original) == row(payload=replay)
    assert len({row().key, row("2").key, row(source_id="install-b").key, row(tenant_id="tenant-b").key}) == 4
    assert row(payload={**original, "after": "27.2.2"}).key == row(payload=original).key


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"event": "device.change"}, None),
        ({"event": "device.change", ENVELOPE: {"time": 0}}, "1970-01-01T00:00:00+00:00"),
        ({"event": "device.change", "occurredAt": "2026-11-20T10:00:00-06:00"}, "2026-11-20T16:00:00+00:00"),
    ],
)
def test_observation_time_is_preserved_and_missing_time_stays_missing(payload, expected):
    assert json.loads(row(payload=payload).ndjson)["OCCURRED_AT"] == expected


@pytest.mark.parametrize("value", ["2026-11-20T10:00:00", "not-a-date", 123])
def test_invalid_occurrence_time_is_not_replaced_with_delivery_time(value):
    with pytest.raises(ValueError):
        row(payload={"event": "device.change", "occurredAt": value})


def test_rejects_missing_identity_mismatched_event_and_non_json_values():
    with pytest.raises(ValueError, match="require source"):
        row(source_id="")
    with pytest.raises(ValueError, match="must match"):
        event_row({"event": "device.change"}, source_id="a", tenant_id="b", event_id="c", event_type="device.inventory")
    with pytest.raises(ValueError):
        row(payload={"event": "device.change", "bad": float("nan")})


def test_batch_byte_ceiling_counts_utf8_and_newlines_without_splitting_rows():
    rows = [row(str(i), payload={"event": "device.change", "name": "Mac 🦆"}) for i in range(4)]
    ceiling = len(rows[0].ndjson) * 2
    grouped = list(batches(iter(rows), max_bytes=ceiling, max_rows=10))
    assert [len(batch.keys) for batch in grouped] == [2, 2]
    assert all(len(batch.ndjson) <= ceiling for batch in grouped)
    assert b"".join(batch.ndjson for batch in grouped) == b"".join(item.ndjson for item in rows)
    assert sum(len(batch.ndjson.splitlines()) for batch in grouped) == 4
    below_boundary = list(batches(rows, max_bytes=ceiling - 1, max_rows=10))
    assert [len(batch.keys) for batch in below_boundary] == [1, 1, 1, 1]


def test_row_limit_empty_stream_and_oversized_row():
    rows = [row(str(i)) for i in range(3)]
    assert [len(batch.keys) for batch in batches(rows, max_bytes=10000, max_rows=2)] == [2, 1]
    assert list(batches([], max_bytes=1, max_rows=1)) == []
    with pytest.raises(ValueError, match="retain the event"):
        list(batches(rows, max_bytes=len(rows[0].ndjson) - 1, max_rows=2))
    with pytest.raises(ValueError, match="positive"):
        list(batches([], max_bytes=0, max_rows=1))
    with pytest.raises(ValueError, match="repeated"):
        list(batches([rows[0], rows[0]], max_bytes=10000, max_rows=2))


def test_partial_rejection_and_ambiguous_ack_never_complete_delivery():
    rows = [row(str(i)) for i in range(3)]
    batch = next(batches(rows, max_bytes=10000, max_rows=3))
    one, two, three = batch.keys
    partial = account_for(batch, accepted=[one], rejected={two: "Invalid target column"})
    assert partial.accepted == (one,)
    assert partial.rejected == ((two, "Invalid target column"),)
    assert partial.unresolved == (three,)
    assert not partial.delivered
    ambiguous = account_for(batch)
    assert ambiguous.unresolved == batch.keys
    assert not ambiguous.delivered
    # Rebuild after a worker restart: no new keys, times, or bytes on the retry.
    retried = next(batches([row(str(i)) for i in range(3)], max_bytes=10000, max_rows=3))
    assert retried == batch
    assert account_for(retried, accepted=reversed(retried.keys)).delivered
    assert not account_for(batch, rejected=dict.fromkeys(batch.keys, "Rejected")).delivered


@pytest.mark.parametrize(
    ("accepted", "rejected"),
    [(["unknown"], {}), ([], {"unknown": "bad"}), (["a"], {"a": "bad"}), ([], {"a": ""})],
)
def test_invalid_receipt_cannot_resolve_a_batch(accepted, rejected):
    with pytest.raises(ValueError):
        account_for(ExportBatch(("a", "b"), b""), accepted=accepted, rejected=rejected)


@pytest.mark.parametrize("keys", [(), ("a", "a")])
def test_empty_or_ambiguous_batch_is_not_delivered(keys):
    with pytest.raises(ValueError):
        account_for(ExportBatch(keys, b""), accepted=keys)
