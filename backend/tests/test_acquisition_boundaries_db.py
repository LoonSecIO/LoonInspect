# ruff: noqa: F811 — imported fixtures are injected by pytest.
"""Comparison changes and repeatable snapshots do not widen or wedge the run mutex."""

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core import runs
from app.models.schema import MdmConnection, Run
from tests.runs_race import racer
from tests.test_runs_race_db import pair, pytestmark  # noqa: F401

pytestmark = pytestmark


async def test_baseline_to_delta_handoff_does_not_create_two_holders(db, pair, monkeypatch):
    first = await runs.acquire(db, await db.get(MdmConnection, pair[0]), trigger="manual")
    real_comparison = runs._comparison_for
    arrived = []
    async with racer() as loser, racer() as rival:

        async def comparison(session, connection_id, lock_class):
            value = await real_comparison(session, connection_id, lock_class)
            if session is loser and not arrived:
                assert value == "baseline"
                await runs.finish(db, first.run, ok=True)
                arrived.append(await runs.acquire(rival, await rival.get(MdmConnection, pair[0]), trigger="sweep"))
                assert arrived[0].run.comparison == "delta"
            return value

        monkeypatch.setattr(runs, "_comparison_for", comparison)
        result = await runs.acquire(loser, await loser.get(MdmConnection, pair[0]), trigger="manual")
        assert not result.started and result.run.id == arrived[0].run.id
        await loser.commit()
        await runs.finish(rival, arrived[0].run, ok=True)


async def test_repeatable_read_cannot_retry_forever_when_holder_is_invisible(db, pair):
    async with racer() as session:
        await session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
        connection = await session.get(MdmConnection, pair[0])
        holder = await runs.acquire(db, await db.get(MdmConnection, pair[0]), trigger="sweep")
        with pytest.raises(runs.AcquisitionBusy):
            await runs.acquire(session, connection, trigger="manual")
        assert session.info["inserts"] == 2
        await session.rollback()
        await runs.finish(db, holder.run, ok=True)


async def test_unrelated_constraint_failure_is_not_a_mutex_retry(db, pair):
    async with racer() as session:
        with pytest.raises(IntegrityError):
            await runs.acquire(session, await session.get(MdmConnection, pair[0]), trigger="manual", collection_id=-1)
        assert session.info["inserts"] == 1
        await session.rollback()


async def test_a_conflict_preserves_unrelated_pending_work(db, pair):
    holder = await runs.acquire(db, await db.get(MdmConnection, pair[0]), trigger="sweep")
    async with racer() as session:
        connection = await session.get(MdmConnection, pair[0])
        connection.name = "edited while acquiring"
        joined = await runs.acquire(session, connection, trigger="manual")
        assert not joined.started and joined.run.id == holder.run.id
        await session.commit()
    assert await db.scalar(select(MdmConnection.name).where(MdmConnection.id == pair[0])) == "edited while acquiring"
    assert await db.scalar(select(Run.status).where(Run.id == holder.run.id)) == "running"
    await runs.finish(db, holder.run, ok=True)
