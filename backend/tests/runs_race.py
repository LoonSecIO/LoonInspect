"""Racers for the run mutex: one session per acquisition, and the hold that makes them collide.

`tests/test_runs_race_db.py` drives these in-process, and runs this file as a script for its
two-process test — `python -m tests.runs_race '<json>'` from backend/, against the suite's own
DATABASE_URL — whose last line on stdout is its outcomes, as JSON.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core import database
from app.core.runs import LOCK_WEBHOOK, TRIGGER_MANUAL, TRIGGER_SWEEP, TRIGGER_WEBHOOK, acquire
from app.core.tenancy import OPERATIONAL_TENANT_ID
from app.models.schema import MdmConnection, Run

# How long a winning INSERT waits for its rivals to queue behind it. Generous because it also
# absorbs the second process's start-up; spent in full only by an index that lets rivals through.
HOLD_SECONDS = 30

# Only tagged participants for this connection and class count. Clean races require
# an active INSERT waiting directly on the winner. The dead-holder round also allows
# reclaim wait chains. Clear the activity snapshot each poll so it reflects new waits.
_QUEUED = text(
    "WITH RECURSIVE queued(pid) AS ("
    " SELECT pid FROM pg_locks WHERE NOT granted AND :pid = ANY(pg_blocking_pids(pid))"
    " UNION SELECT l.pid FROM pg_locks l JOIN queued q ON q.pid = ANY(pg_blocking_pids(l.pid)) WHERE NOT l.granted"
    ") SELECT count(*) FROM queued q JOIN pg_stat_activity a ON a.pid = q.pid"
    " WHERE a.application_name = :tag AND (:reclaim OR"
    " (a.query LIKE 'INSERT INTO runs %' AND :pid = ANY(pg_blocking_pids(a.pid))))"
)


class RacingSession(AsyncSession):
    """A session whose winning INSERT holds, uncommitted, until `info["rivals"]` others queue behind it.

    Without the hold a gather races only when the scheduler happens to interleave the INSERTs: a
    fast winner commits first and every loser meets a committed row, the sequential case
    tests/test_runs.py already covers. With it, the losers' INSERTs are in flight against the
    winner's uncommitted index entry and Postgres alone decides who wins. In the explicitly
    marked dead-holder round, behind it also counts a racer queued through another one:
    a racer that waited out a concurrent reclaim keeps the
    reclaimed row locked until its transaction ends, and whoever queued on that row cannot reach
    an INSERT before then. `info["inserts"]` counts the INSERTs attempted, so a retry shows.
    """

    async def flush(self, objects=None) -> None:
        inserting = any(isinstance(obj, Run) for obj in self.new)
        self.info["inserts"] += inserting
        if inserting and "tag" in self.info:
            # Reclaim may have committed since race() assigned the transaction's
            # tag. Restore it before INSERT so rivals remain identifiable.
            await self.execute(text("SELECT set_config('application_name', :tag, true)"), {"tag": self.info["tag"]})
        await super().flush(objects)
        if inserting and self.info["rivals"]:
            pid = await self.scalar(text("SELECT pg_backend_pid()"))
            deadline = asyncio.get_running_loop().time() + HOLD_SECONDS
            while True:
                await self.execute(text("SELECT pg_stat_clear_snapshot()"))
                queued = await self.scalar(_QUEUED, {"pid": pid, "tag": self.info["tag"], "reclaim": self.info["reclaim"]})
                if queued >= self.info["rivals"]:
                    break
                if asyncio.get_running_loop().time() > deadline:
                    raise AssertionError(f"{queued} of {self.info['rivals']} rivals queued behind the winning INSERT")
                await asyncio.sleep(0.01)


_racers = async_sessionmaker(database.engine, class_=RacingSession, expire_on_commit=False)


def racer() -> RacingSession:
    """A racing session bound to the operational tenant, the way `session_for_tenant` binds one."""
    return _racers(info={"tenant_id": str(OPERATIONAL_TENANT_ID), "rivals": 0, "inserts": 0})


@dataclass
class Outcome:
    """One racer's acquisition: what it was handed, how many INSERTs it took, and what went wrong."""

    connection_id: int
    lock_class: str
    started: bool | None = None
    job_id: str | None = None
    inserts: int = 0
    error: str | None = None


async def race(
    entries: list[tuple[RacingSession, MdmConnection, str]], field: Counter, turn: int = 0, *, allow_reclaim_waiters: bool = False
) -> list[Outcome]:
    """Acquire once per (session, connection, lock class), all at once, each session on its own.

    `field` counts every racer for each (connection id, lock class), across both processes when
    there are two, so a winner knows how many rivals to hold for; a webhook holds for none, since
    the index exempts webhooks. A lock's racers take turns as the tick (`sweep`) and a person
    clicking (`manual`), the pair Acquisition's docstring names; `turn=1` starts on `manual`, so
    two processes race each other across triggers too. Bounded, so a race that wedges fails.
    """
    turns: Counter = Counter()
    for session, connection, lock_class in entries:
        key, locked = (connection.id, lock_class), lock_class != LOCK_WEBHOOK
        turns[key] += 1
        trigger = (TRIGGER_MANUAL, TRIGGER_SWEEP)[(turn + turns[key]) % 2] if locked else TRIGGER_WEBHOOK
        tag = f"loon-race:{connection.id}:{lock_class}"
        session.info.update(
            inserts=0, rivals=field[key] - 1 if locked else 0, trigger=trigger, tag=tag, reclaim=allow_reclaim_waiters
        )
        await session.execute(text("SELECT set_config('application_name', :tag, true)"), {"tag": tag})
    async with asyncio.timeout(3 * HOLD_SECONDS):
        return list(await asyncio.gather(*(_acquire(*entry) for entry in entries)))


async def _acquire(session: RacingSession, connection: MdmConnection, lock_class: str) -> Outcome:
    """One racer: acquire, then prove the session can carry on — and end its transaction at once,
    as a caller does; a loser still holding a row its reclaim re-checked would stall the rest."""
    outcome = Outcome(connection.id, lock_class)
    try:
        result = await acquire(session, connection, trigger=session.info["trigger"], lock_class=lock_class)
        outcome.started, outcome.job_id = result.started, str(result.run.id)
        outcome.error = await _unusable(session, connection)
    except Exception as exc:
        outcome.error = repr(exc)
        await session.rollback()
    outcome.inserts = session.info["inserts"]
    return outcome


async def _unusable(session: RacingSession, connection: MdmConnection) -> str | None:
    """Why this session cannot carry on after its acquisition, or None — the savepoint's whole job.

    A caller goes on with the same session: the tick acquires its next due collection on it. So
    no savepoint left open, no losing Run still pending for the next flush, the caller's instance
    still loaded (an expired attribute raises under asyncio), and a statement and a commit that
    land — a COMMIT alone would not tell, since Postgres answers an aborted one with ROLLBACK.
    """
    expired = sorted(inspect(connection).expired_attributes)
    if session.in_nested_transaction() or session.new or expired:
        return f"left dirty: savepoint={session.in_nested_transaction()} pending={list(session.new)} expired={expired}"
    await session.execute(text("SELECT 1"))
    await session.commit()
    return None


async def _main(racers: list[list], process: int, processes: int) -> list[dict]:
    """One OS process's share of a race: every `processes`-th racer, starting at `process`."""
    mine = racers[process::processes]
    sessions = [racer() for _ in mine]
    try:
        entries = [(s, await s.get(MdmConnection, cid), lock) for s, (cid, lock) in zip(sessions, mine, strict=True)]
        return [asdict(outcome) for outcome in await race(entries, Counter(map(tuple, racers)), turn=process)]
    finally:
        for session in sessions:
            await session.close()
        await database.engine.dispose()


if __name__ == "__main__":
    print(json.dumps(asyncio.run(_main(**json.loads(sys.argv[1])))))
