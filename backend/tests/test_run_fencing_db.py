# ruff: noqa: F811 — imported fixtures are injected by pytest.
"""Runs beat during long reads and cannot commit observations after their reclaim."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, update

from app.core import runs
from app.core.database import session_for_tenant
from app.core.tenancy import OPERATIONAL_TENANT_ID
from app.mdm.service import ingest_computer
from app.models.schema import Device, MdmConnection, ObservationSpan, Run, RunLogLine
from tests.test_webhook_runs_db import connection, pytestmark  # noqa: F401

pytestmark = pytestmark


@pytest.mark.parametrize("lock_class", [runs.LOCK_DEVICE_SWEEP, runs.LOCK_CATALOG])
async def test_a_live_run_beats_while_no_device_loop_is_running(db, connection, monkeypatch, lock_class):
    now = [datetime.now(UTC)]
    monkeypatch.setattr(runs, "_utcnow", lambda: now[0])
    monkeypatch.setattr(runs, "_HEARTBEAT_INTERVAL_SECONDS", 0.01)
    acquired = await runs.acquire(db, connection, trigger=runs.TRIGGER_SWEEP, lock_class=lock_class)
    connection_id, job_id = connection.id, acquired.run.id
    async with runs.entered(acquired.run):
        now[0] += timedelta(seconds=301)
        async with asyncio.timeout(2):
            while True:
                async with session_for_tenant(OPERATIONAL_TENANT_ID) as check:
                    heartbeat = await check.scalar(select(Run.heartbeat_at).where(Run.id == job_id))
                if heartbeat == now[0]:
                    break
                await asyncio.sleep(0.01)
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as other:
            holder = await runs.acquire(
                other, await other.get(MdmConnection, connection_id), trigger=runs.TRIGGER_MANUAL, lock_class=lock_class
            )
            assert not holder.started and holder.run.id == job_id
    now[0] += timedelta(seconds=301)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as other:
        replacement = await runs.acquire(
            other, await other.get(MdmConnection, connection_id), trigger=runs.TRIGGER_MANUAL, lock_class=lock_class
        )
        assert replacement.started and replacement.run.id != job_id
        await runs.finish(other, replacement.run, ok=True)


async def test_reclaimed_worker_rolls_back_its_device_and_ledger(db, connection, jamf):
    acquired = await runs.acquire(db, connection, trigger=runs.TRIGGER_SWEEP)
    connection_id, job_id = connection.id, acquired.run.id
    async with runs.entered(acquired.run):
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as other:
            await other.execute(
                update(Run).where(Run.id == job_id).values(heartbeat_at=datetime.now(UTC) - timedelta(seconds=301))
            )
            await other.commit()
            replacement = await runs.acquire(other, await other.get(MdmConnection, connection_id), trigger=runs.TRIGGER_MANUAL)
            assert replacement.started
            await runs.finish(other, replacement.run, ok=True)
        with pytest.raises(runs.RunReclaimed, match="observations"):
            await ingest_computer(db, connection, jamf.real, aperture_digest="a" * 64, trigger="sweep")
        await db.rollback()
    for model in (Device, ObservationSpan):
        assert await db.scalar(select(func.count()).select_from(model).where(model.mdm_connection_id == connection_id)) == 0
    original = await db.get(Run, job_id, populate_existing=True)
    assert original.status == "failed" and "reclaimed:" in original.error


async def test_stalled_worker_stops_beating_and_can_be_reclaimed(db, connection, monkeypatch, caplog):
    from app.core.config import settings

    monkeypatch.setattr(runs, "_HEARTBEAT_INTERVAL_SECONDS", 0.01)
    acquired = await runs.acquire(db, connection, trigger=runs.TRIGGER_SWEEP)
    job_id, cid = acquired.run.id, connection.id
    async with runs.entered(acquired.run) as context:
        context.last_progress -= settings.run_stale_after_seconds + 1
        await asyncio.sleep(0.05)
        assert "Run progress stopped" in caplog.text
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as other:
            await other.execute(
                update(Run)
                .where(Run.id == job_id)
                .values(heartbeat_at=datetime.now(UTC) - timedelta(seconds=settings.run_stale_after_seconds + 1))
            )
            await other.commit()
            replacement = await runs.acquire(other, await other.get(MdmConnection, cid), trigger=runs.TRIGGER_MANUAL)
            assert replacement.started and replacement.run.id != job_id
            await runs.finish(other, replacement.run, ok=True)


async def test_outer_cancellation_during_keeper_shutdown_propagates(db, connection, monkeypatch):
    stopping = asyncio.Event()

    async def slow_keeper(tenant_id, context):
        try:
            await asyncio.Event().wait()
        finally:
            stopping.set()
            await asyncio.sleep(1)

    monkeypatch.setattr(runs, "_keep_alive", slow_keeper)
    acquired = await runs.acquire(db, connection, trigger=runs.TRIGGER_SWEEP)
    after = []

    async def worker():
        async with runs.entered(acquired.run):
            await asyncio.sleep(0)
        after.append("continued")

    task = asyncio.create_task(worker())
    await asyncio.wait_for(stopping.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert after == []
    await runs.finish(db, acquired.run, ok=True)


async def _backdate(job_id):
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as other:
        await other.execute(update(Run).where(Run.id == job_id).values(heartbeat_at=datetime.now(UTC) - timedelta(seconds=301)))
        await other.commit()


async def test_reclaim_waits_on_the_fence_share_lock_then_refuses_the_next_commit(db, connection):
    """A holds the fence's share lock with a pending write; B's reclaim must wait for A's commit,
    then A's next fenced commit and A's finish are refused and B's run is untouched."""
    acquired = await runs.acquire(db, connection, trigger=runs.TRIGGER_SWEEP)
    cid, job_id = connection.id, acquired.run.id
    await _backdate(job_id)
    held = await db.scalar(select(Run.id).where(Run.id == job_id, Run.status == runs.STATUS_RUNNING).with_for_update(read=True))
    assert held == job_id
    db.add(RunLogLine(run_id=job_id, ts=datetime.now(UTC), level="info", message="fence regression: pending under share lock"))
    await db.flush()

    async def rival():
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as other:
            result = await runs.acquire(other, await other.get(MdmConnection, cid), trigger=runs.TRIGGER_MANUAL)
            return result.started, result.run.id

    task = asyncio.create_task(rival())
    await asyncio.sleep(1.0)
    assert not task.done(), "the reclaim did not wait on the share lock"
    await db.commit()
    started, new_id = await asyncio.wait_for(task, 15)
    assert started and new_id != job_id
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as check:
        assert await check.scalar(select(Run.status).where(Run.id == job_id)) == runs.STATUS_FAILED
        durable = await check.scalar(
            select(RunLogLine.id).where(RunLogLine.message == "fence regression: pending under share lock")
        )
        assert durable is not None
    async with runs.entered(acquired.run):
        runs.fence_write(db)
        db.add(RunLogLine(run_id=job_id, ts=datetime.now(UTC), level="info", message="fence regression: after reclaim"))
        with pytest.raises(runs.RunReclaimed):
            await db.commit()
        await db.rollback()
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as check:
        assert await check.scalar(select(RunLogLine.id).where(RunLogLine.message == "fence regression: after reclaim")) is None
    reloaded = await db.get(Run, job_id)
    assert await runs.finish(db, reloaded, ok=True) is False
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as other:
        b = await other.get(Run, new_id)
        assert b.status == runs.STATUS_RUNNING
        assert await runs.finish(other, b, ok=True)


async def test_finish_can_close_an_armed_fenced_transaction(db, connection):
    """A terminal update must not refuse its own fenced pending write."""
    acquired = await runs.acquire(db, connection, trigger=runs.TRIGGER_SWEEP)
    job_id = acquired.run.id
    async with runs.entered(acquired.run):
        runs.fence_write(db)
        db.add(
            RunLogLine(run_id=job_id, ts=datetime.now(UTC), level="info", message="fence regression: fenced work before finish")
        )
        assert await runs.finish(db, acquired.run, ok=True)
    reloaded = await db.get(Run, job_id, populate_existing=True)
    assert reloaded.status == runs.STATUS_SUCCEEDED
    assert (
        await db.scalar(
            select(RunLogLine.id).where(
                RunLogLine.run_id == job_id, RunLogLine.message == "fence regression: fenced work before finish"
            )
        )
        is not None
    )


async def test_nested_run_context_updates_the_keepers_progress_clock(db, connection):
    acquired = await runs.acquire(db, connection, trigger=runs.TRIGGER_SWEEP)
    async with runs.entered(acquired.run) as outer:
        outer.last_progress = 0
        async with runs.entered(acquired.run) as inner:
            assert inner is outer
            await runs.beat(db, acquired.run)
            assert outer.last_progress > 0
    await runs.finish(db, acquired.run, ok=True)
