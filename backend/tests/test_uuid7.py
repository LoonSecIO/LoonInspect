"""uuid7() — the run id's generator after #225: RFC 9562 version 7, minted locally
because `uuid.uuid7()` is Python 3.14 and this repo runs 3.12 (`Dockerfile`,
`requires-python >=3.11`).

Pure and fast — no session, no RUN_DB_TESTS gate, in the same spirit test_jamf_client.py
and test_wire.py are: these are unit tests of a function, not of the run lifecycle that
uses it (that lives in test_runs.py, gated on a real Postgres).
"""

from __future__ import annotations

import uuid

import pytest

from app.core import uuid7 as uuid7_module
from app.core.uuid7 import uuid7


def test_every_id_parses_as_version_7_with_the_rfc_4122_variant() -> None:
    for _ in range(200):
        generated = uuid7()
        assert generated.version == 7
        assert generated.variant == uuid.RFC_4122
        # Same 36-character hyphenated shape uuid4() already produced — the reason #188
        # ruled UUIDv7 over ULID: nothing downstream that stores or displays a run id as
        # a string changes format.
        assert len(str(generated)) == 36


def test_ids_from_a_strictly_increasing_clock_sort_in_creation_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """The property #225 exists for: `eventstats max(jobID) by serialNumber` — the
    latest-state idiom on a fan-out sourcetype — needs string-sort order to agree with
    creation order.

    Pinned against a scripted clock rather than real wall-clock gaps: two calls landing
    in the same millisecond legitimately tie under RFC 9562's pure-random construction
    (see the next test), so a tight loop fast enough to hit that tie would make an
    unpinned version of this assertion flaky through no fault of the generator.
    """
    millis = iter(range(1_700_000_000_000, 1_700_000_000_000 + 2000))
    monkeypatch.setattr(uuid7_module, "_current_unix_ms", lambda: next(millis))

    generated = [str(uuid7()) for _ in range(2000)]

    assert generated == sorted(generated)
    assert len(set(generated)) == len(generated)  # distinct throughout, not just ordered


def test_two_ids_in_the_same_millisecond_are_unordered_but_still_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    """A busy tenant's webhook burst can mint two runs in the same millisecond. RFC 9562
    does not order them relative to each other under this construction — that is
    expected, not a defect — but they must still be two different jobIDs on the wire."""
    monkeypatch.setattr(uuid7_module, "_current_unix_ms", lambda: 1_700_000_000_000)

    first, second = uuid7(), uuid7()

    assert first != second
    assert first.version == second.version == 7
    assert (first.int >> 80) == (second.int >> 80) == 1_700_000_000_000


def test_the_leading_48_bits_are_exactly_the_clock_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pins the RFC 9562 layout directly — the timestamp occupies bits 127-80 — rather
    than inferring it from sort order alone, so a shift-arithmetic mistake that happened
    to preserve ordering on the test above would still fail here."""
    monkeypatch.setattr(uuid7_module, "_current_unix_ms", lambda: 1_700_000_000_123)

    generated = uuid7()

    assert (generated.int >> 80) == 1_700_000_000_123


def test_the_random_tail_does_not_repeat_across_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same millisecond, same version and variant nibbles — the only thing left to prove
    distinct per call is the random tail actually drawing fresh bytes each time."""
    monkeypatch.setattr(uuid7_module, "_current_unix_ms", lambda: 1_700_000_000_000)

    tails = {generated.int & 0x3FFFFFFFFFFFFFFF for generated in (uuid7() for _ in range(50))}

    assert len(tails) == 50  # an os.urandom(10) collision here would be a real defect


def test_a_timestamp_past_the_48_bit_field_is_masked_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    """Defensive, not load-bearing before the year 10889: `uuid7()` must not raise out of
    an ingest path over a clock value wider than the field, the same posture
    `instance_label`'s malformed-port handling takes elsewhere on this wire (app.core.wire)."""
    monkeypatch.setattr(uuid7_module, "_current_unix_ms", lambda: 0xFFFFFFFFFFFF + 1)

    generated = uuid7()  # must not raise

    assert (generated.int >> 80) == 0  # the overflow bit was masked away, not carried in
    assert generated.version == 7
