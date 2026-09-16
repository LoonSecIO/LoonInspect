"""The interval query (#465): a fixture ledger reproducing the #219 spike's cases — device 4's
eight spans coalescing to one island, the zero-length device-time interval, the departed tail —
and the three prohibitions: never project to today, never drop a quiet device, never ask `runs`."""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

from app.baseline.intervals import DEPARTED, NOT_OBSERVED, OBSERVED, ledger_heartbeat, section_intervals  # noqa: E402

COMPUTER = "computer"
SECURITY, APPLICATIONS = "security", "applications"
SEC_A, SEC_B, SEC_C, APP = "v0:sec-locked", "v0:sec-open", "v0:sec-partial", "v0:app-steady"
BASE = datetime(2026, 3, 1, tzinfo=UTC)  # last March: months older than the 30-day run horizon
LAG = timedelta(hours=1)  # our clock trails the device's


def _at(day: float) -> datetime:
    return BASE + timedelta(days=day)


# (subject, day observed, security digest, applications digest). Device 4 is the spike's: eight
# weekly spans, `applications` churning on every one, `security` never moving.
LEDGER = (
    *(("4", day, SEC_A, f"v0:app-{n}") for n, day in enumerate(range(0, 50, 7))),
    ("5", 30, SEC_B, APP),  # first seen inside the window, so a not-observed head before it
    ("5", 50, SEC_C, APP),
    ("6", 0, SEC_A, APP),  # three single-observation spans: the naive-duration trap
    ("6", 9, SEC_B, APP),
    ("6", 20, SEC_A, APP),
    ("7", 0, SEC_C, APP),  # two spans, one security digest, then a departure in the tail
    ("7", 5, SEC_C, "v0:app-late"),
    ("8", 2, SEC_A, APP),  # quiet since before the window opened, and still in the report
    ("10", 0, SEC_A, APP),  # came back under a new id, so its departure row is keyed to this one
)
DEPARTURES = (("7", None, 12, None), ("10b", "10", 20, 30))  # subject, prior id, departed, returned
AS_OF = _at(60)  # named, so every boundary below lands on a whole day
HEARTBEAT = _at(50) + LAG


@pytest_asyncio.fixture(loop_scope="session")
async def ledger(db):
    """The connection and its spans; spans and departures cascade on the connection's delete."""
    from app.models.schema import MdmConnection, ObservationSpan, SubjectDeparture

    row = MdmConnection(name=f"intervals {uuidlib.uuid4().hex[:8]}", provider="jamf", base_url="https://ledger.test")
    db.add(row)
    await db.commit()
    connection_id = row.id
    newest = {subject: day for subject, day, _, _ in LEDGER}
    for subject, day, security, applications in LEDGER:
        db.add(
            ObservationSpan(
                mdm_connection_id=connection_id,
                subject_kind=COMPUTER,
                subject_id=subject,
                contract_version="v0",
                aperture_digest="v0:aperture",
                head_digest=f"v0:head-{uuidlib.uuid4().hex[:12]}",
                section_digests={SECURITY: security, APPLICATIONS: applications},
                first_observed_at=_at(day),
                last_observed_at=_at(day),
                first_collected_at=_at(day) + LAG,
                last_collected_at=_at(day) + LAG,
                observation_count=1,
                last_trigger="sweep",
                is_current=newest[subject] == day,
            )
        )
    for subject, prior, departed, returned in DEPARTURES:
        db.add(
            SubjectDeparture(
                mdm_connection_id=connection_id,
                subject_kind=COMPUTER,
                subject_id=subject,
                prior_jamf_pro_id=prior,
                departed_at=_at(departed),
                returned_at=None if returned is None else _at(returned),
            )
        )
    await db.commit()
    try:
        yield row
    finally:
        await db.rollback()
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


async def _read(db, ledger, section: str = SECURITY, window_from: datetime = BASE, as_of: datetime | None = AS_OF):
    return await section_intervals(db, connection_id=ledger.id, section=section, window_from=window_from, as_of=as_of)


def _subject(result, subject_id: str):
    return next(s for s in result.subjects if s.subject_id == subject_id)


def _days(result, subject_id: str) -> list[tuple[str, int, int]]:
    """(state, the day it opened, the day it closed), in whole days off BASE."""
    return [(i.state, (i.starts_at - BASE).days, (i.ends_at - BASE).days) for i in _subject(result, subject_id).intervals]


def _held(result, subject_id: str) -> list:
    return [i for i in _subject(result, subject_id).intervals if i.state == OBSERVED]


async def test_eight_spans_sharing_a_security_digest_are_one_island(db, ledger) -> None:
    """Printing spans as rows would print one unchanged security stretch eight times."""
    security = await _read(db, ledger)
    (held,) = _held(security, "4")
    assert (held.digest, held.observation_count) == (SEC_A, 8)
    assert (held.starts_at, held.ends_at) == (_at(0), _at(49))
    assert held.longest_gap == timedelta(days=7)  # the widest stretch it was assumed, not seen
    assert (held.first_collected_at, held.last_collected_at) == (_at(0) + LAG, _at(49) + LAG)
    assert len(_held(await _read(db, ledger, APPLICATIONS), "4")) == 8  # the same spans, per section


async def test_single_observation_spans_still_have_length(db, ledger) -> None:
    """`observation_count` is 1 on every span here, so `last_observed_at - first_observed_at` is zero
    on every one. An interval runs to the NEXT observation — nine days, then eleven — and only the
    last, with nothing after it to run to, is a real zero."""
    held = _held(await _read(db, ledger), "6")
    assert [i.observation_count for i in held] == [1, 1, 1]
    assert [i.duration for i in held] == [timedelta(days=9), timedelta(days=11), timedelta(0)]
    assert [i.digest for i in held] == [SEC_A, SEC_B, SEC_A]


async def test_the_head_and_the_tail_are_not_observed_and_no_device_is_dropped(db, ledger) -> None:
    """Device 5 was first seen inside the window; device 8 was last seen eight days before it
    opened and has said nothing since. Dropping 8 is the one dishonest move available here."""
    security = await _read(db, ledger, window_from=_at(10))
    assert _days(security, "5")[:2] == [(NOT_OBSERVED, 10, 30), (OBSERVED, 30, 50)]  # carried to the next, not to today
    assert _days(security, "8") == [(NOT_OBSERVED, 10, 60)]
    for subject in security.subjects:
        assert subject.intervals[0].starts_at == _at(10)
        assert subject.intervals[-1].ends_at == AS_OF
        assert all(a.ends_at == b.starts_at for a, b in zip(subject.intervals, subject.intervals[1:], strict=False))
        for i in subject.intervals:  # both clocks on an observed interval, neither on a gap
            assert all((t is not None) is (i.state == OBSERVED) for t in (i.first_collected_at, i.last_collected_at))


async def test_a_departure_relabels_the_tail_and_a_return_bounds_it(db, ledger) -> None:
    security = await _read(db, ledger)
    # Two spans, one digest, one interval; a week quiet; then the census found it gone.
    assert _days(security, "7") == [(OBSERVED, 0, 5), (NOT_OBSERVED, 5, 12), (DEPARTED, 12, 60)]
    # Back under a new id, so the departed stretch is bounded and the rest is unobserved again.
    assert _days(security, "10") == [(OBSERVED, 0, 0), (NOT_OBSERVED, 0, 20), (DEPARTED, 20, 30), (NOT_OBSERVED, 30, 60)]
    assert all(i.digest is None for s in security.subjects for i in s.intervals if i.state != OBSERVED)


async def test_the_clock_is_the_ledgers_and_history_outlives_the_runs(db, ledger) -> None:
    """`as_of` is `max(observation_spans.last_collected_at)`, never a run. Runs purge at 30 days
    and this ledger is months older than that, with no run row behind it at all."""
    from app.core.config import settings
    from app.models.schema import Run

    assert datetime.now(UTC) - timedelta(days=settings.run_retention_days) > HEARTBEAT
    runs = await db.execute(select(func.count()).select_from(Run).where(Run.mdm_connection_id == ledger.id))
    assert runs.scalar_one() == 0
    assert await ledger_heartbeat(db, connection_id=ledger.id) == HEARTBEAT

    security = await _read(db, ledger, as_of=None)
    assert security.as_of == HEARTBEAT
    assert {s.subject_id for s in security.subjects} == {"4", "5", "6", "7", "8", "10"}
    assert all(i.ends_at <= HEARTBEAT for s in security.subjects for i in s.intervals)
