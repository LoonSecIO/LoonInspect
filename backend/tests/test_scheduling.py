"""`app.core.scheduling` is the only interpreter of a collection's "when".

Pure and timezone-aware: every `next_due` answer is a UTC instant computed from the
row's own IANA zone, so the wall-clock part survives DST and an MSP can express two
2ams three hours apart. These tests pin the arithmetic, the validation a customer hits
on save, and the rate floor that makes a manual run reset the scheduled one.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from app.core.scheduling import (
    KIND_CATALOG,
    KIND_DEVICE_SWEEP,
    KIND_WEBHOOK,
    STALE_OCCURRENCES,
    Schedule,
    ScheduleError,
    cadence,
    next_due,
    stale_after,
    validate_schedule,
    within_rate_floor,
)

CHICAGO = "America/Chicago"


def _utc(*parts: int) -> datetime:
    return datetime(*parts, tzinfo=timezone.utc)


def _local(zone: str, *parts: int) -> datetime:
    return datetime(*parts, tzinfo=ZoneInfo(zone))


class TestNextDue:
    def test_daily_fires_at_the_wall_clock_time_in_its_zone(self) -> None:
        schedule = Schedule(frequency="daily", timezone=CHICAGO, at_hour=1, at_minute=0)
        # 00:30 Chicago (CDT, UTC-5) → next is 01:00 Chicago = 06:00 UTC the same day.
        assert next_due(schedule, _local(CHICAGO, 2026, 8, 22, 0, 30)) == _utc(2026, 8, 22, 6, 0)
        # 01:00 exactly is not "after", so tomorrow.
        assert next_due(schedule, _local(CHICAGO, 2026, 8, 22, 1, 0)) == _utc(2026, 8, 23, 6, 0)

    def test_daily_stays_at_local_time_across_dst(self) -> None:
        """The morning DST ends (2026-11-01 in Chicago), 01:00 local moves from 06:00 to
        07:00 UTC — the sweep stays at 01:00 on the admin's clock rather than drifting."""
        schedule = Schedule(frequency="daily", timezone=CHICAGO, at_hour=1, at_minute=0)
        before = next_due(schedule, _local(CHICAGO, 2026, 10, 31, 12, 0))  # fires Nov 1 01:00 CDT
        after = next_due(schedule, before + timedelta(minutes=1))  # fires Nov 2 01:00 CST
        assert before.astimezone(ZoneInfo(CHICAGO)).hour == 1
        assert after.astimezone(ZoneInfo(CHICAGO)).hour == 1
        assert after - before == timedelta(hours=25)

    def test_hourly_uses_the_minute_only(self) -> None:
        schedule = Schedule(frequency="hourly", timezone="UTC", at_minute=17)
        assert next_due(schedule, _utc(2026, 8, 22, 10, 5)) == _utc(2026, 8, 22, 10, 17)
        assert next_due(schedule, _utc(2026, 8, 22, 10, 17)) == _utc(2026, 8, 22, 11, 17)
        assert next_due(schedule, _utc(2026, 8, 22, 23, 40)) == _utc(2026, 8, 23, 0, 17)

    def test_weekly_lands_on_the_weekday(self) -> None:
        schedule = Schedule(frequency="weekly", timezone="UTC", at_hour=3, at_minute=0, weekday=6)  # Sunday
        # 2026-08-22 is a Saturday.
        assert next_due(schedule, _utc(2026, 8, 22, 12, 0)) == _utc(2026, 8, 23, 3, 0)
        assert next_due(schedule, _utc(2026, 8, 23, 3, 0)) == _utc(2026, 8, 30, 3, 0)

    def test_every_n_days_counts_from_the_anchor(self) -> None:
        schedule = Schedule(frequency="every_n_days", timezone="UTC", at_hour=2, at_minute=0, interval_n=3)
        anchor = _utc(2026, 8, 20, 2, 0)
        assert next_due(schedule, _utc(2026, 8, 21, 9, 0), anchor=anchor) == _utc(2026, 8, 23, 2, 0)
        assert next_due(schedule, _utc(2026, 8, 23, 2, 0), anchor=anchor) == _utc(2026, 8, 26, 2, 0)
        # Without an anchor the count starts now.
        assert next_due(schedule, _utc(2026, 8, 21, 9, 0)) == _utc(2026, 8, 24, 2, 0)

    def test_two_zones_two_two_ams(self) -> None:
        """The MSP case from docs/ingest-scheduling.md §3.3."""
        ny = Schedule(frequency="daily", timezone="America/New_York", at_hour=2, at_minute=0)
        la = Schedule(frequency="daily", timezone="America/Los_Angeles", at_hour=2, at_minute=0)
        after = _utc(2026, 8, 22, 0, 0)
        assert next_due(la, after) - next_due(ny, after) == timedelta(hours=3)

    def test_event_driven_has_no_due_time(self) -> None:
        assert next_due(Schedule(frequency=None, timezone=None), _utc(2026, 8, 22)) is None


class TestValidate:
    def test_webhook_is_event_driven(self) -> None:
        validate_schedule(KIND_WEBHOOK, Schedule(frequency=None, timezone=None))
        with pytest.raises(ScheduleError):
            validate_schedule(KIND_WEBHOOK, Schedule(frequency="daily", timezone="UTC"))

    def test_runnable_kinds_need_a_frequency_and_a_zone(self) -> None:
        with pytest.raises(ScheduleError):
            validate_schedule(KIND_DEVICE_SWEEP, Schedule(frequency=None, timezone=None))
        with pytest.raises(ScheduleError):
            validate_schedule(KIND_CATALOG, Schedule(frequency="hourly", timezone=None))
        with pytest.raises(ScheduleError):
            validate_schedule(KIND_CATALOG, Schedule(frequency="hourly", timezone="Mars/Olympus"))

    @pytest.mark.parametrize(
        "schedule",
        [
            Schedule(frequency="daily", timezone="UTC", at_hour=24),
            Schedule(frequency="daily", timezone="UTC", at_minute=60),
            Schedule(frequency="weekly", timezone="UTC", at_hour=1),  # no weekday
            Schedule(frequency="weekly", timezone="UTC", at_hour=1, weekday=7),
            Schedule(frequency="every_n_days", timezone="UTC", interval_n=1),  # that is daily
            Schedule(frequency="fortnightly", timezone="UTC"),
        ],
    )
    def test_rejects_unsaveable_schedules(self, schedule: Schedule) -> None:
        with pytest.raises(ScheduleError):
            validate_schedule(KIND_DEVICE_SWEEP, schedule)

    def test_accepts_the_defaults(self) -> None:
        validate_schedule(KIND_DEVICE_SWEEP, Schedule(frequency="daily", timezone=CHICAGO, at_hour=1, at_minute=0))
        validate_schedule(KIND_CATALOG, Schedule(frequency="hourly", timezone=CHICAGO, at_minute=18))


class TestRateFloor:
    def test_manual_run_resets_the_scheduled_one(self) -> None:
        """Run manually at 01:55 and the 02:00 sweep skips — otherwise the floor is not
        a floor (docs/ingest-scheduling.md §4.2)."""
        now = _utc(2026, 8, 22, 2, 0)
        assert within_rate_floor(KIND_DEVICE_SWEEP, _utc(2026, 8, 22, 1, 55), now) is True
        assert within_rate_floor(KIND_DEVICE_SWEEP, _utc(2026, 8, 22, 0, 55), now) is False

    def test_catalog_floor_is_fifteen_minutes(self) -> None:
        now = _utc(2026, 8, 22, 2, 0)
        assert within_rate_floor(KIND_CATALOG, _utc(2026, 8, 22, 1, 50), now) is True
        assert within_rate_floor(KIND_CATALOG, _utc(2026, 8, 22, 1, 40), now) is False

    def test_never_run_is_never_within_the_floor(self) -> None:
        assert within_rate_floor(KIND_DEVICE_SWEEP, None, _utc(2026, 8, 22)) is False
        assert within_rate_floor(KIND_WEBHOOK, _utc(2026, 8, 22), _utc(2026, 8, 22)) is False


class TestStaleAfter:
    """Kyle's 2026-09-04 ruling for #106, pinned as arithmetic.

    "Inventory STALE = no successful full sweep in twice the collection's own configured
    cadence." Every number below comes from doubling something the operator already
    chose. A fixed 24-hour cut was rejected as wrong at both ends, and these cases are
    the two ends.
    """

    @pytest.mark.parametrize(
        ("schedule", "expected"),
        [
            (Schedule(frequency="hourly", timezone="UTC", at_minute=0), timedelta(hours=2)),
            (Schedule(frequency="daily", timezone="UTC", at_hour=2), timedelta(hours=48)),
            (Schedule(frequency="weekly", timezone="UTC", at_hour=2, weekday=0), timedelta(hours=336)),
            (Schedule(frequency="every_n_days", timezone="UTC", at_hour=2, interval_n=3), timedelta(days=6)),
            (Schedule(frequency="every_n_days", timezone="UTC", at_hour=2, interval_n=20), timedelta(days=40)),
        ],
    )
    def test_is_twice_the_rows_own_cadence(self, schedule: Schedule, expected: timedelta) -> None:
        assert stale_after(schedule) == expected
        assert stale_after(schedule) == STALE_OCCURRENCES * cadence(schedule)

    def test_the_two_ends_a_fixed_cut_gets_wrong(self) -> None:
        """The argument for the ruling, as a test: one threshold cannot serve both."""
        hourly = Schedule(frequency="hourly", timezone="UTC", at_minute=0)
        weekly = Schedule(frequency="weekly", timezone="UTC", at_hour=2, weekday=0)
        # A fixed 24h cut would let an hourly collection sit dead for most of a day…
        assert stale_after(hourly) < timedelta(hours=24)
        # …and would call a weekly one stale while it was still six days from due.
        assert stale_after(weekly) > timedelta(hours=24)

    def test_event_driven_makes_no_staleness_claim(self) -> None:
        """A webhook collection that has not fired is waiting, not stale. None means the
        caller renders nothing — never a zero threshold, which would be "always stale"."""
        assert cadence(Schedule(frequency=None, timezone=None)) is None
        assert stale_after(Schedule(frequency=None, timezone=None)) is None

    def test_an_unrecognised_frequency_makes_no_claim_either(self) -> None:
        """A row written by a newer build. Silence beats a guessed default, which would
        become a wrong claim about whether a customer's inventory is current."""
        assert stale_after(Schedule(frequency="fortnightly", timezone="UTC")) is None

    def test_nothing_but_the_schedule_feeds_it(self) -> None:
        """The "no new setting" half of the ruling. `stale_after` takes exactly one
        argument — the row's own schedule — so there is nothing to tune per pod and no
        second input that could drift from what the operator configured."""
        import inspect

        assert list(inspect.signature(stale_after).parameters) == ["schedule"]
