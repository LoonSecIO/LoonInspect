"""Schedule arithmetic for collections — pure, timezone-aware, and the only place the
"when" of a collection is interpreted.

A schedule is time-of-day + IANA timezone + a coarse frequency (docs/ingest-scheduling.md
§3.3): not a cron expression, because a cron invites `* * * * *` pointed at a production
Jamf tenant and cannot say "event-driven, no cadence". Everything here returns UTC
instants; the row's own timezone is used for the wall-clock part, so an MSP with
customers in New York and Los Angeles can express two 2ams three hours apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

Frequency = Literal["hourly", "daily", "weekly", "every_n_days"]
FREQUENCIES: tuple[str, ...] = ("hourly", "daily", "weekly", "every_n_days")

KIND_DEVICE_SWEEP = "device_sweep"
KIND_CATALOG = "catalog"
KIND_WEBHOOK = "webhook"
KINDS: tuple[str, ...] = (KIND_DEVICE_SWEEP, KIND_CATALOG, KIND_WEBHOOK)
RUNNABLE_KINDS: tuple[str, ...] = (KIND_DEVICE_SWEEP, KIND_CATALOG)

# Rate floors per kind (docs/ingest-scheduling.md §4.2): "no full pull more than once
# an hour" is enforced at claim time as well as on save, because manual runs never pass
# through schedule validation. A floor enforced only at config time is a floor with a
# bypass button next to it.
RATE_FLOORS: dict[str, timedelta] = {
    KIND_DEVICE_SWEEP: timedelta(hours=1),
    KIND_CATALOG: timedelta(minutes=15),
}

# How long one occurrence of each frequency is. `every_n_days` computes its own from
# interval_n, so it is absent here rather than unrepresentable.
CADENCE: dict[str, timedelta] = {
    "hourly": timedelta(hours=1),
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
}

# Two missed occurrences is stale (#106, ruled 2026-09-04). One missed occurrence is a
# hiccup — a tick that lost a race, a Jamf that was restarting — and calling that stale
# would make the word mean nothing by the second week.
STALE_OCCURRENCES = 2


@dataclass(frozen=True, slots=True)
class Schedule:
    frequency: str | None
    timezone: str | None
    at_hour: int | None = None
    at_minute: int | None = None
    weekday: int | None = None  # 0 = Monday … 6 = Sunday, for weekly
    interval_n: int | None = None  # for every_n_days

    @property
    def is_event_driven(self) -> bool:
        return self.frequency is None


class ScheduleError(ValueError):
    """A schedule a customer cannot be allowed to save."""


def validate_schedule(kind: str, schedule: Schedule) -> None:
    if kind not in KINDS:
        raise ScheduleError(f"unknown collection kind {kind!r}")
    if schedule.frequency is None:
        if kind in RUNNABLE_KINDS:
            raise ScheduleError(f"a {kind} collection needs a frequency")
        return
    if kind == KIND_WEBHOOK:
        raise ScheduleError("a webhook collection is event-driven and carries no schedule")
    if schedule.frequency not in FREQUENCIES:
        raise ScheduleError(f"unknown frequency {schedule.frequency!r}")
    if not schedule.timezone:
        raise ScheduleError("a scheduled collection needs a timezone")
    try:
        ZoneInfo(schedule.timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ScheduleError(f"unknown timezone {schedule.timezone!r}") from exc
    minute = schedule.at_minute if schedule.at_minute is not None else 0
    if not 0 <= minute <= 59:
        raise ScheduleError("minute must be 0–59")
    if schedule.frequency != "hourly":
        hour = schedule.at_hour if schedule.at_hour is not None else 0
        if not 0 <= hour <= 23:
            raise ScheduleError("hour must be 0–23")
    if schedule.frequency == "weekly" and (schedule.weekday is None or not 0 <= schedule.weekday <= 6):
        raise ScheduleError("a weekly schedule needs a weekday (0 = Monday … 6 = Sunday)")
    if schedule.frequency == "every_n_days" and (schedule.interval_n is None or schedule.interval_n < 2):
        raise ScheduleError("every_n_days needs an interval of at least 2 (use daily for 1)")


def next_due(schedule: Schedule, after: datetime, anchor: datetime | None = None) -> datetime | None:
    """The first instant strictly after `after` at which the schedule fires, in UTC.

    `anchor` matters only for every_n_days, where "every 3 days" counts from the last
    run (or creation) rather than from an arbitrary epoch; without one the count starts
    at `after`. Wall-clock arithmetic is done in the schedule's zone, so a 02:00 daily
    sweep stays at 02:00 local across a DST change rather than drifting an hour.
    """
    if schedule.frequency is None:
        return None
    tz = ZoneInfo(schedule.timezone or "UTC")
    local = after.astimezone(tz)
    minute = schedule.at_minute or 0
    hour = schedule.at_hour or 0

    if schedule.frequency == "hourly":
        candidate = local.replace(minute=minute, second=0, microsecond=0)
        if candidate <= local:
            candidate = (candidate + timedelta(hours=1)).replace(minute=minute)
        return candidate.astimezone(timezone.utc)

    candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)

    if schedule.frequency == "daily":
        if candidate <= local:
            candidate = _same_wall_time(candidate + timedelta(days=1), hour, minute)
        return candidate.astimezone(timezone.utc)

    if schedule.frequency == "weekly":
        weekday = schedule.weekday or 0
        ahead = (weekday - candidate.weekday()) % 7
        candidate = _same_wall_time(candidate + timedelta(days=ahead), hour, minute)
        if candidate <= local:
            candidate = _same_wall_time(candidate + timedelta(days=7), hour, minute)
        return candidate.astimezone(timezone.utc)

    if schedule.frequency == "every_n_days":
        n = schedule.interval_n or 2
        start = (anchor or after).astimezone(tz).replace(hour=hour, minute=minute, second=0, microsecond=0)
        candidate = start
        while candidate <= local:
            candidate = _same_wall_time(candidate + timedelta(days=n), hour, minute)
        return candidate.astimezone(timezone.utc)

    raise ScheduleError(f"unknown frequency {schedule.frequency!r}")


def _same_wall_time(value: datetime, hour: int, minute: int) -> datetime:
    # timedelta arithmetic on an aware datetime is wall-clock arithmetic; re-pinning the
    # hour and minute keeps a daily 02:00 at 02:00 when the offset changed underneath.
    return value.replace(hour=hour, minute=minute, second=0, microsecond=0)


def cadence(schedule: Schedule) -> timedelta | None:
    """How long one occurrence of this schedule is, or None when it has none.

    None covers two cases that both mean "there is no cadence to reason about": an
    event-driven collection (a webhook fires when Jamf says so), and a frequency this
    build does not recognise — a row written by a newer version and read by an older
    one. Returning None rather than guessing a default is deliberate: everything
    downstream treats it as "no claim", and a wrong guess here would become a wrong
    claim about whether a customer's inventory is current.
    """
    if schedule.frequency is None:
        return None
    if schedule.frequency == "every_n_days":
        return timedelta(days=schedule.interval_n or 2)
    return CADENCE.get(schedule.frequency)


def stale_after(schedule: Schedule) -> timedelta | None:
    """How long a collection may go without a **successful** run before what it collected
    stops describing the fleet — twice its own cadence (#106, ruled 2026-09-04).

    Derived from the schedule the operator already configured, and from nothing else:
    there is no setting behind this and there is deliberately no way to tune it per pod.
    An hourly collection is stale after two hours and a weekly one after a fortnight,
    which is the whole argument — a fixed 24-hour cut was rejected because it is wrong at
    both ends, screaming about an hourly collection twenty-three hours after anyone could
    have acted and calling a weekly one stale while it is still on time.

    None means "makes no staleness claim", propagated from `cadence`. A caller must
    render nothing for None; a webhook collection that has never fired is not overdue,
    it is waiting.
    """
    occurrence = cadence(schedule)
    return None if occurrence is None else STALE_OCCURRENCES * occurrence


def within_rate_floor(kind: str, last_run_at: datetime | None, now: datetime) -> bool:
    """True when running again now would breach the kind's floor. A manual run at 01:55
    makes the 02:00 sweep skip — otherwise the floor is not a floor."""
    floor = RATE_FLOORS.get(kind)
    if floor is None or last_run_at is None:
        return False
    return now - last_run_at < floor
