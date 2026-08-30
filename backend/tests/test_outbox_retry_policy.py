"""Characterization tests for the outbox's retry policy — the arithmetic half.

Characterization, not specification: every number below was read off
`app/core/outbox.py` as it stands, and the point is to notice when it moves. #81 is
about to change what the outbox carries (one fattened snapshot per device per sweep
rather than one event per changed device), and the retry budget is what decides how
long a destination that cannot keep up stays in the table. If a build session widens
the backoff, drops the cap, or spends the attempt budget differently, these fail and
say so in seconds.

The delivery bookkeeping that *uses* these numbers — which rows get attempted, what
becomes `failed` versus staying `pending` — is pinned against a real Postgres in
`test_outbox_passes_db.py`. Nothing here needs a database: `_next_backoff` is a pure
function of an attempt count and the clock.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.core.outbox import (
    _BASE_BACKOFF_SECONDS,
    _MAX_ATTEMPTS,
    _MAX_BACKOFF_EXPONENT,
    _MAX_BACKOFF_SECONDS,
    _next_backoff,
)


def _delay_seconds(attempt_count: int) -> float:
    """`_next_backoff` returns an absolute time, so the delay is read back off the
    clock. Called either side of the function so a slow machine cannot make the
    measured delay look shorter or longer than the constant it came from."""
    before = datetime.now(timezone.utc)
    when = _next_backoff(attempt_count)
    after = datetime.now(timezone.utc)
    assert when >= before, "a backoff must never be in the past"
    return (when - after).total_seconds()


@pytest.mark.parametrize(
    ("attempt_count", "seconds"),
    [
        # `_next_backoff` is called with the attempt count *after* the increment, so a
        # delivery's first failure asks for backoff(1) and waits a minute — the 30s
        # base is the value for an attempt count of zero, which the delivery pass never
        # actually reaches.
        (0, 30),
        (1, 60),
        (2, 120),
        (3, 240),
        (4, 480),
        (5, 960),
        (6, 1920),
        # 30 * 2**7 is 3840, over the hour ceiling: the doubling stops here.
        (7, 3600),
        (8, 3600),
        (9, 3600),
    ],
)
def test_backoff_doubles_from_a_minute_and_stops_at_an_hour(attempt_count: int, seconds: int) -> None:
    assert _delay_seconds(attempt_count) == pytest.approx(seconds, abs=2)


def test_a_wild_attempt_count_cannot_overflow_the_exponent() -> None:
    """`min(attempt_count, _MAX_BACKOFF_EXPONENT)` is a guard against `2**n` for a
    row whose attempt count was raised by something other than the delivery pass — a
    migration, a manual UPDATE, a future batch writer. It stays an hour, and it stays
    fast, rather than computing a number with a million digits."""
    assert _delay_seconds(10) == pytest.approx(_MAX_BACKOFF_SECONDS, abs=2)
    assert _delay_seconds(1_000_000) == pytest.approx(_MAX_BACKOFF_SECONDS, abs=2)
    assert _MAX_BACKOFF_EXPONENT == 10


def test_the_retry_budget_is_ten_attempts_over_about_four_hours() -> None:
    """The whole life of a delivery to a destination that never answers, as one
    number. Nine backoffs separate the ten attempts (the tenth failure dead-letters
    instead of scheduling an eleventh), which is 4h03m from first attempt to
    `failed` — for every delivery row of every event, in parallel.

    Worth holding next to #81's volume: at 40,000 devices per sweep that is 40,000
    delivery rows per destination each carrying this budget, not one.
    """
    assert _MAX_ATTEMPTS == 10
    assert _BASE_BACKOFF_SECONDS == 30
    assert _MAX_BACKOFF_SECONDS == 3600

    total = sum(round(_delay_seconds(attempt)) for attempt in range(1, _MAX_ATTEMPTS))
    assert total == pytest.approx(14_580, abs=20)
    assert total / 3600 == pytest.approx(4.05, abs=0.05)
