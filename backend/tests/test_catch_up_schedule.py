"""An outage coalesces missed occurrences into the most recent scheduled reading."""

from datetime import UTC, datetime

import pytest

from app.core.scheduling import Schedule, latest_due, next_due


def utc(value):
    return datetime.fromisoformat(value).replace(tzinfo=UTC)


@pytest.mark.parametrize(
    "schedule,first,now,expected,following",
    [
        (Schedule("daily", "UTC", 2), "2026-10-03T02:00", "2026-10-06T16:00", "2026-10-06T02:00", "2026-10-07T02:00"),
        (Schedule("daily", "UTC", 2), "2026-10-03T02:00", "2026-10-06T02:00", "2026-10-06T02:00", "2026-10-07T02:00"),
        (Schedule("weekly", "UTC", 2, weekday=0), "2026-09-21T02:00", "2026-10-06T16:00", "2026-10-05T02:00", "2026-10-12T02:00"),
        (
            Schedule("every_n_days", "UTC", 2, interval_n=3),
            "2026-09-30T02:00",
            "2026-10-07T16:00",
            "2026-10-06T02:00",
            "2026-10-09T02:00",
        ),
        (
            Schedule("daily", "America/New_York", 21),
            "2026-10-04T01:00",
            "2026-10-06T16:00",
            "2026-10-06T01:00",
            "2026-10-07T01:00",
        ),
        (Schedule("daily", "America/Chicago", 1), "2026-10-30T06:00", "2026-11-01T07:30", "2026-11-01T06:00", "2026-11-02T07:00"),
        (
            Schedule("daily", "America/Chicago", 2, 30),
            "2026-03-06T08:30",
            "2026-03-08T08:00",
            "2026-03-07T08:30",
            "2026-03-08T08:30",
        ),
        (
            Schedule("daily", "America/Chicago", 2, 30),
            "2026-03-06T08:30",
            "2026-03-08T08:30",
            "2026-03-08T08:30",
            "2026-03-09T07:30",
        ),
        (
            Schedule("hourly", "America/Chicago", at_minute=17),
            "2026-10-30T06:17",
            "2026-11-01T07:10",
            "2026-11-01T06:17",
            "2026-11-01T07:17",
        ),
        (
            Schedule("hourly", "America/Chicago", at_minute=17),
            "2026-10-30T06:17",
            "2026-11-01T07:45",
            "2026-11-01T07:17",
            "2026-11-01T08:17",
        ),
    ],
)
def test_most_recent_occurrence(schedule, first, now, expected, following):
    due = latest_due(schedule, utc(first), utc(now))
    assert due == utc(expected)
    assert next_due(schedule, utc(now), anchor=due) == utc(following)


def test_spring_gap_does_not_skip_an_occurrence_whose_utc_instant_is_still_ahead():
    schedule = Schedule("daily", "America/Chicago", 2, 30)
    assert next_due(schedule, utc("2026-03-08T08:00")) == utc("2026-03-08T08:30")


def test_n_day_schedule_edit_keeps_materialized_anchor_despite_manual_run():
    from app.mdm.collections import apply_schedule
    from app.models.schema import Collection

    row = Collection(
        kind="catalog",
        frequency="every_n_days",
        interval_n=3,
        timezone="UTC",
        at_hour=2,
        next_due_at=utc("2026-10-06T02:00"),
        last_run_at=utc("2026-10-07T01:00"),
    )
    apply_schedule(row, now=utc("2026-10-07T16:00"))
    assert row.next_due_at == utc("2026-10-09T02:00")
