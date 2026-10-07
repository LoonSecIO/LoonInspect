"""The run mutex under real concurrency: racers in one process and in two, against a real Postgres.

tests/test_runs.py pins the mutex one acquisition at a time, so `uq_run_active_lock` is exercised
but never contested: every loser there meets a row that has already committed. Here the losers'
INSERTs in a clean race wait directly on the winner's uncommitted transaction
(tests/runs_race.py tags each participant and checks its active INSERT), from separate
sessions in one event loop and from two OS processes, and the
assertions are what run-now and the tick rely on: one run per (connection, lock class), every
loser handed the winner's jobID instead of an exception, every session usable afterwards — the
savepoint's job — and a retry that ends. One race starts over a dead holder, so the reclaim at
the top of every acquisition is raced as well.

Each lock is raced by the tick's trigger against run-now's, and every race also carries other
lock classes, a second connection and two webhooks, and runs over history, so these indexes fail
here: tenant only (#31's first sketch), connection without class, class without connection,
trigger in the key, sweeps exempted, no webhook exemption, no `running` predicate, no index. One
that adds `comparison` is caught separately by test_acquisition_boundaries_db.py, which
moves history from baseline to delta between a comparison read and its INSERT.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select, update

from app.core import runs
from app.core.config import settings
from app.core.runs import (
    LOCK_CATALOG,
    LOCK_DEVICE_REFRESH,
    LOCK_DEVICE_SWEEP,
    LOCK_RE_EMIT,
    LOCK_WEBHOOK,
    RUN_FAILED_EVENT,
    STATUS_FAILED,
    STATUS_RUNNING,
    TRIGGER_MANUAL,
    TRIGGER_SWEEP,
    acquire,
    finish,
)
from app.models.schema import EventOutbox, MdmConnection, Run
from tests.runs_race import HOLD_SECONDS, Outcome, race, racer

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

BACKEND = Path(__file__).resolve().parents[1]


@pytest_asyncio.fixture(loop_scope="session")
async def pair(db):
    """Two connections: the one every race contends for, and a sibling whose lock is its own."""
    tag = uuid.uuid4().hex[:8]
    rows = [MdmConnection(name=f"runs race {tag} {i}", provider="jamf", base_url="https://race.jamfcloud.com") for i in (0, 1)]
    db.add_all(rows)
    await db.commit()
    ids = [row.id for row in rows]
    try:
        yield ids
    finally:
        # Runs and their log lines go with the connections by cascade; the closing events do not.
        await db.rollback()
        await db.execute(delete(EventOutbox).where(EventOutbox.payload["connectionID"].astext.in_([str(i) for i in ids])))
        await db.execute(delete(MdmConnection).where(MdmConnection.id.in_(ids)))
        await db.commit()


def _field(a: int, b: int) -> list[tuple[int, str]]:
    """Who races: four for one device sweep, and a pair each for what must not contend with it."""
    pairs = [(a, LOCK_CATALOG), (a, LOCK_RE_EMIT), (a, LOCK_DEVICE_REFRESH), (b, LOCK_DEVICE_SWEEP), (a, LOCK_WEBHOOK)]
    return [(a, LOCK_DEVICE_SWEEP)] * 4 + [entry for entry in pairs for _ in range(2)]


def _verdict(outcomes: list[Outcome]) -> dict[tuple[int, str], str]:
    """Nobody raised, was left unusable or retried; every webhook started; each locked (connection,
    class) started exactly one run, whose jobID every other racer for it was handed. Its winners."""
    assert [o.error for o in outcomes if o.error] == []
    assert [o.inserts for o in outcomes] == [1] * len(outcomes)
    locked = [o for o in outcomes if o.lock_class != LOCK_WEBHOOK]
    winners = {(o.connection_id, o.lock_class): o.job_id for o in locked if o.started}
    assert sorted(winners) == sorted({(o.connection_id, o.lock_class) for o in locked})
    assert sum(o.started for o in locked) == len(winners), "a lock was started twice"
    losers = [o for o in locked if not o.started]
    assert [o.job_id for o in losers] == [winners[(o.connection_id, o.lock_class)] for o in losers]
    hooks = [o for o in outcomes if o.lock_class == LOCK_WEBHOOK]
    assert all(o.started for o in hooks) and len({o.job_id for o in hooks}) == len(hooks)
    return winners


async def _release(db, outcomes: list[Outcome]) -> None:
    """The database agrees with the racers — the runs they started are the only live ones on their
    connections — and finishing those frees each lock for whatever races next."""
    connections = {o.connection_id for o in outcomes}
    live = set(await db.scalars(select(Run.id).where(Run.mdm_connection_id.in_(connections), Run.status == STATUS_RUNNING)))
    assert {str(run_id) for run_id in live} == {o.job_id for o in outcomes if o.started}
    for run_id in live:
        assert await finish(db, await db.get(Run, run_id), ok=True)


async def test_racers_in_one_process_start_one_run_per_lock(db, pair) -> None:
    """Fourteen sessions acquire at once in one event loop, first over a sweep whose process
    died — so they race its reclaim too, and exactly one of them may fail it — then over the
    history the first round left, where the sessions that lost, their INSERT rolled back to the
    savepoint, race for fresh runs after all first-round winners have finished. The dead-holder
    round proves a tagged lock-wait chain, including reclaim waiters; the clean second round
    proves that each intended rival is blocked directly on the winning INSERT transaction."""
    dead = await acquire(db, await db.get(MdmConnection, pair[0]), trigger=TRIGGER_SWEEP)
    silent = datetime.now(UTC) - timedelta(seconds=settings.run_stale_after_seconds + 60)
    await db.execute(update(Run).where(Run.id == dead.run.id).values(heartbeat_at=silent))
    await db.commit()

    field = _field(*pair)
    sessions = [racer() for _ in field]
    try:
        entries = [(s, await s.get(MdmConnection, cid), lock) for s, (cid, lock) in zip(sessions, field, strict=True)]
        first = await race(entries, Counter(field), allow_reclaim_waiters=True)
        winners = _verdict(first)
        assert await db.scalar(select(Run.status).where(Run.id == dead.run.id)) == STATUS_FAILED
        alarms = select(func.count()).select_from(EventOutbox).where(EventOutbox.event_type == RUN_FAILED_EVENT)
        assert await db.scalar(alarms.where(EventOutbox.payload["jobID"].astext == str(dead.run.id))) == 1
        await _release(db, first)

        again = [i for i, o in enumerate(first) if not o.started or o.lock_class == LOCK_WEBHOOK]
        second = await race([entries[i] for i in again], Counter(field[i] for i in again))
        rewinners = _verdict(second)
        assert rewinners.keys() == winners.keys() and set(rewinners.values()).isdisjoint(winners.values())
        await _release(db, second)
    finally:
        for session in sessions:
            await session.close()


async def _half(field: list[tuple[int, str]], process: int) -> list[Outcome]:
    """One OS process's share of the race: `python -m tests.runs_race`, which prints its outcomes."""
    argument = json.dumps({"racers": field, "process": process, "processes": 2})
    pipes = {"stdout": asyncio.subprocess.PIPE, "stderr": asyncio.subprocess.PIPE}
    child = await asyncio.create_subprocess_exec(sys.executable, "-m", "tests.runs_race", argument, cwd=BACKEND, **pipes)
    try:
        out, err = await asyncio.wait_for(child.communicate(), timeout=120)
    finally:
        if child.returncode is None:
            child.kill()
            await child.wait()
    assert child.returncode == 0, err.decode()[-4000:]
    return [Outcome(**outcome) for outcome in json.loads(out.decode().splitlines()[-1])]


async def test_racers_in_two_processes_start_one_run_per_lock(db, pair) -> None:
    """The same field split across two OS processes — each takes half of every group, one starting
    its turns as the tick and the other as run-now — over a finished run per lock, so a winner in
    either process holds against rivals in both."""
    field = _field(*pair)
    for cid, lock in dict.fromkeys(entry for entry in field if entry[1] != LOCK_WEBHOOK):
        history = await acquire(db, await db.get(MdmConnection, cid), trigger=TRIGGER_MANUAL, lock_class=lock)
        assert history.started and await finish(db, history.run, ok=True)

    async with asyncio.TaskGroup() as group:  # one half failing cancels the other, which kills its child
        halves = [group.create_task(_half(field, process)) for process in (0, 1)]
    outcomes = [outcome for half in halves for outcome in half.result()]
    _verdict(outcomes)
    await _release(db, outcomes)


async def test_a_holder_that_finishes_inside_the_window_costs_one_retry(db, pair, monkeypatch) -> None:
    """The bounded retry, forced: the INSERT loses to a holder that finishes before the follow-up
    read can find it. acquire retries on the same session, and the retry is the last attempt —
    nothing is left to collide with — so one more INSERT, one read in all, and a run of its own."""
    holder = await acquire(db, await db.get(MdmConnection, pair[0]), trigger=TRIGGER_SWEEP)
    real_read, reads = runs.active_run, []

    async def holder_finishes_first(session, connection_id, lock_class):
        reads.append(lock_class)
        if len(reads) == 1:
            assert await finish(db, holder.run, ok=True)
        return await real_read(session, connection_id, lock_class)

    monkeypatch.setattr(runs, "active_run", holder_finishes_first)
    async with asyncio.timeout(HOLD_SECONDS), racer() as session:
        retried = await acquire(session, await session.get(MdmConnection, pair[0]), trigger=TRIGGER_MANUAL)
        assert retried.started and retried.run.id != holder.run.id
        assert (len(reads), session.info["inserts"]) == (1, 2)
    await _release(db, [Outcome(pair[0], LOCK_DEVICE_SWEEP, started=True, job_id=str(retried.run.id))])


async def test_a_retry_that_meets_a_new_holder_joins_it(db, pair, monkeypatch) -> None:
    """The same window, and the lock changes hands inside it: the tick's sweep takes it just before
    the retry's INSERT. The retry is a race like the first attempt and ends like one — on the new
    holder's jobID, not with another retry and not with an exception."""
    first = await acquire(db, await db.get(MdmConnection, pair[0]), trigger=TRIGGER_MANUAL)
    real_read, real_comparison, reads, second = runs.active_run, runs._comparison_for, [], []

    async with asyncio.timeout(HOLD_SECONDS), racer() as session, racer() as rival:

        async def first_finishes(s, connection_id, lock_class):
            if s is session and not reads:
                assert await finish(db, first.run, ok=True)
            reads.append(s)
            return await real_read(s, connection_id, lock_class)

        async def second_arrives(s, connection_id, lock_class):
            if s is session and reads and not second:  # the retry, about to INSERT
                second.append(await acquire(rival, await rival.get(MdmConnection, pair[0]), trigger=TRIGGER_SWEEP))
            return await real_comparison(s, connection_id, lock_class)

        monkeypatch.setattr(runs, "active_run", first_finishes)
        monkeypatch.setattr(runs, "_comparison_for", second_arrives)
        joined = await acquire(session, await session.get(MdmConnection, pair[0]), trigger=TRIGGER_MANUAL)
        assert second[0].started and not joined.started and joined.run.id == second[0].run.id
        assert (len(reads), session.info["inserts"]) == (2, 2)
    await _release(db, [Outcome(pair[0], LOCK_DEVICE_SWEEP, started=True, job_id=str(second[0].run.id))])


async def test_a_lock_that_changes_hands_twice_costs_at_most_one_retry(db, pair, monkeypatch) -> None:
    """acquire's comment says "one retry, not a loop". Here the holder finishes inside the first
    window and a new one arrives and finishes inside the second, so a second retry is the loop
    it rules out. Exhaustion must raise AcquisitionBusy after exactly two attempts."""
    holders = [(db, (await acquire(db, await db.get(MdmConnection, pair[0]), trigger=TRIGGER_SWEEP)).run)]
    real_read, real_comparison = runs.active_run, runs._comparison_for

    async with asyncio.timeout(HOLD_SECONDS), racer() as session, racer() as rival:

        async def holder_finishes(s, connection_id, lock_class):
            if s is session:
                assert await finish(*holders[-1], ok=True)
            return await real_read(s, connection_id, lock_class)

        async def next_holder_arrives(s, connection_id, lock_class):
            if s is session and session.info["inserts"] == 1:  # the retry, about to INSERT
                arrived = await acquire(rival, await rival.get(MdmConnection, pair[0]), trigger=TRIGGER_SWEEP)
                holders.append((rival, arrived.run))
            return await real_comparison(s, connection_id, lock_class)

        monkeypatch.setattr(runs, "active_run", holder_finishes)
        monkeypatch.setattr(runs, "_comparison_for", next_holder_arrives)
        with pytest.raises(runs.AcquisitionBusy):
            await acquire(session, await session.get(MdmConnection, pair[0]), trigger=TRIGGER_MANUAL)
        assert session.info["inserts"] <= 2, f"{session.info['inserts']} INSERTs for one acquisition"
