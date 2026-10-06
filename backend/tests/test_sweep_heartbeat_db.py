"""The device sweep's heartbeat and progress lines at fleet scale, on a simulated clock.

`app.core.runs.beat` writes `heartbeat_at` at most once per `_HEARTBEAT_INTERVAL_SECONDS`, and
`app.mdm.service._stream_jamf_fleet` calls it once per device, beside a run-log line every
`_PROGRESS_EVERY` devices. Both exist for the forty-minute pull (docs/runs.md §2 and §5). The FakeJamf
fleet finishes inside one interval, so the rest of the suite reaches the throttle's early return and,
with a heartbeat aged by hand, the fence's refusal; none of it is built to write one. Here the scheduled
path (`run_one_collection`) runs against the real `acquire`, `beat`, reclaim and run log, with three
stand-ins: the device stream is a stub of 40,000 records, ingest is a stub that spends simulated
seconds and commits as the real one does, and the run module's clock is the test's. The forty
minutes take about a second. The reads before the first device beat too (#757): the third test
charges every Jamf read simulated seconds, so that phase alone runs past the stale window.

`LOON_BENCH_DEVICES=<n>` runs the same test at another fleet size, and `-s` prints what the heartbeat
cost. Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import time
import uuid as uuidlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy import delete, event, select

from tests.jamf_fake import HOST

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

# The design target, over forty simulated minutes — eight times `run_stale_after_seconds`, so a
# sweep its heartbeat failed to keep alive would be reclaimed several times over.
_FLEET = int(os.environ.get("LOON_BENCH_DEVICES") or 40_000)
_SWEEP = timedelta(minutes=40)
# Rival acquisitions per sweep, evenly spaced: another process's run-now, tick or webhook, each of
# which runs the tenant-wide reclaim before it asks for a lock.
_RIVALS = 40
# Every run-log line that is not a progress line is a milestone (started, aperture, catalogs,
# census, finished, posture), and how many there are does not depend on the fleet.
_MILESTONES_AT_MOST = 15


@dataclass
class _Beat:
    device: int  # the device the loop had just ingested; 0 before the first
    statements: int
    commits: int
    wrote: datetime | None  # the heartbeat this call committed; None when the throttle returned early
    seconds: float


@dataclass
class _Rival:
    device: int  # it acquired just before this device reached the loop
    at: datetime
    started: bool  # True: its acquire reclaimed the sweep's run and took the lock
    holder: uuidlib.UUID
    heartbeat: datetime  # the holder's heartbeat_at, as committed when the rival read it


@dataclass
class _Harness:
    connection_id: int
    # Two hours back, so a rival's reclaim, which is tenant-wide, judges this test's run and never a
    # row an earlier test in the session left running on the real clock.
    now: datetime = field(default_factory=lambda: datetime.now(UTC) - timedelta(hours=2))
    fleet: int = 0
    step: timedelta = timedelta(0)
    device: int = 0
    read: timedelta = timedelta(0)  # what one Jamf read costs; FakeJamf answers in no time
    next_rival: datetime | None = None  # the next rival due during the reads, when they cost time
    lock_class: str = "device_sweep"
    beating: bool = True
    statements: int = 0
    commits: int = 0
    beats: list[_Beat] = field(default_factory=list)
    rivals: list[_Rival] = field(default_factory=list)

    def size(self, fleet: int) -> None:
        self.fleet, self.step = fleet, _SWEEP / fleet


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    """A Jamf connection of its own. Its runs, run log and collections go with it by cascade, and
    the stub ingest writes no device, so the sync state is the only other row to clear."""
    from app.models.schema import MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"sweep heartbeat {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
    )
    db.add(row)
    await db.commit()
    connection_id = row.id
    try:
        yield row
    finally:
        await db.rollback()
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


@pytest.fixture
def harness(monkeypatch, jamf, connection):
    """The three stand-ins, the rivals, and a count of every statement and commit the engine sends.
    FakeJamf (`jamf`) still answers everything before the device loop: aperture, org units, catalog,
    each read costing `read` on the clock."""
    from app.core import runs
    from app.core.database import engine, session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.mdm import service
    from app.mdm.jamf.client import JamfClient
    from app.models.schema import MdmConnection

    h = _Harness(connection.id)
    real_beat = runs.beat
    real_get = JamfClient._get

    async def rival(device: int) -> None:
        if h.rivals and h.rivals[-1].started:
            return  # the lock has changed hands; there is nothing left for a rival to find out
        # Its own session, as another process's would be: it sees only what the sweep committed.
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as other:
            connection_ = await other.get(MdmConnection, h.connection_id)
            got = await runs.acquire(other, connection_, trigger=runs.TRIGGER_SWEEP, lock_class=h.lock_class)
            h.rivals.append(_Rival(device, h.now, got.started, got.run.id, got.run.heartbeat_at))

    async def devices(_client, _http, _sections, **_):
        rivals_at = {h.fleet * index // _RIVALS for index in range(1, _RIVALS + 1)}
        for device in range(1, h.fleet + 1):
            h.device = device
            if device in rivals_at:
                await rival(device)
            yield {"id": str(device), "udid": f"HEARTBEAT-{device}", "hardware": {"serialNumber": f"HB{device:07d}"}}

    async def get(self, client, path, **kwargs):
        response = await real_get(self, client, path, **kwargs)
        h.now += h.read
        if h.next_rival and h.now >= h.next_rival:
            # Moved before the await, so another read in the same wave does not send a second rival.
            h.next_rival += timedelta(minutes=1)
            await rival(h.device)
        return response

    async def ingest(db_, _connection, _raw, **_):
        h.now += h.step  # the whole of one device's cost, in simulated seconds
        await db_.commit()  # and its boundary: the real ingest commits every device (process_sync)
        return SimpleNamespace(outcome="unchanged")

    async def beat(db_, run) -> None:
        statements, commits, before = h.statements, h.commits, run.heartbeat_at
        started = time.perf_counter()
        if h.beating:
            await real_beat(db_, run)
        wrote = run.heartbeat_at if run.heartbeat_at != before else None
        h.beats.append(_Beat(h.device, h.statements - statements, h.commits - commits, wrote, time.perf_counter() - started))

    def count_statement(*_) -> None:
        h.statements += 1

    def count_commit(*_) -> None:
        h.commits += 1

    monkeypatch.setattr(runs, "_utcnow", lambda: h.now)
    monkeypatch.setattr(JamfClient, "iter_computers", devices)
    monkeypatch.setattr(JamfClient, "_get", get)
    monkeypatch.setattr(service, "ingest_computer", ingest)
    monkeypatch.setattr(service, "beat", beat)
    event.listen(engine.sync_engine, "before_cursor_execute", count_statement)
    event.listen(engine.sync_engine, "commit", count_commit)
    try:
        yield h
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", count_statement)
        event.remove(engine.sync_engine, "commit", count_commit)


async def _sweep_collection(db, connection, kind="device_sweep"):
    from app.mdm.collections import ensure_default_collections, list_collections

    await ensure_default_collections(db, connection)
    await db.commit()
    return next(row for row in await list_collections(db, connection.id) if row.kind == kind)


async def test_a_forty_minute_sweep_beats_on_cadence_and_is_never_reclaimed(db, connection, harness) -> None:
    """The scheduled path end to end: rivals every minute of a forty-minute sweep all join it, the
    heartbeat they read is never one interval old, it advanced on the throttle's cadence, a write
    is one small transaction and every other call is free, and the run log grows by one line per
    `_PROGRESS_EVERY` devices on top of a fixed handful of milestones."""
    from app.core.runs import _HEARTBEAT_INTERVAL_SECONDS, TRIGGER_SWEEP
    from app.mdm.collections import run_one_collection
    from app.mdm.service import _PROGRESS_EVERY
    from app.models.schema import Run, RunLogLine

    harness.size(_FLEET)
    sweep = await _sweep_collection(db, connection)
    started = time.perf_counter()
    result = await run_one_collection(db, sweep, trigger=TRIGGER_SWEEP)
    wall = time.perf_counter() - started
    assert result.ok and result.device_count == _FLEET, result

    # One run, and it succeeded: no rival ever started a second.
    run = (await db.execute(select(Run).where(Run.mdm_connection_id == harness.connection_id))).scalars().one()
    await db.refresh(run)
    assert run.status == "succeeded", run.error
    # And it lasted the forty simulated minutes: the clock moved only as the devices did.
    assert harness.now - run.started_at == harness.step * _FLEET

    # Every rival joined. Each landed after one device's beat and before the next device's, which
    # is as old as the heartbeat gets — under one interval, against a reclaim that needs 300 s.
    interval = timedelta(seconds=_HEARTBEAT_INTERVAL_SECONDS)
    assert len(harness.rivals) == _RIVALS
    assert {(rival.started, rival.holder) for rival in harness.rivals} == {(False, run.id)}
    assert max(rival.at - rival.heartbeat for rival in harness.rivals) < interval

    # The cadence. beat() runs on every device and writes on the first device at or past each
    # interval, so the committed heartbeat steps by exactly that many devices' worth of time. The
    # reads before the first device beat as well (#757), and here the throttle turns them all away.
    every = -(-interval // harness.step)
    written = [beat.wrote for beat in harness.beats if beat.wrote]
    assert [beat.device for beat in harness.beats if beat.device] == list(range(1, _FLEET + 1))
    assert len(written) == _FLEET // every
    stamps = [run.started_at, *written]
    assert {later - earlier for earlier, later in pairwise(stamps)} == {every * harness.step}

    # The cost. A write is a transaction of its own: the tenant binding every transaction opens with
    # (app.core.database), the fenced UPDATE, its COMMIT. A call the throttle turns away sends nothing.
    writes = [beat for beat in harness.beats if beat.wrote]
    skips = [beat for beat in harness.beats if not beat.wrote]
    assert {(beat.statements, beat.commits) for beat in writes} == {(2, 1)}
    assert {(beat.statements, beat.commits) for beat in skips} == {(0, 0)}

    # Progress lines at exactly the multiples, and nothing else in the log that grows with the fleet.
    lines = (await db.execute(select(RunLogLine).where(RunLogLine.run_id == run.id))).scalars().all()
    progress = sorted(line.fields["deviceCount"] for line in lines if line.message == "devices processed")
    assert progress == list(range(_PROGRESS_EVERY, _FLEET + 1, _PROGRESS_EVERY))
    assert len(lines) - len(progress) <= _MILESTONES_AT_MOST, sorted(line.message for line in lines)

    print(
        f"\n[heartbeat] devices={_FLEET} simulated={harness.now - run.started_at} wall={wall:.1f}s "
        f"beat_calls={len(harness.beats)} writes={len(writes)} "
        f"statements_per_device={sum(beat.statements for beat in harness.beats) / _FLEET:.4f} "
        f"commits_per_device={sum(beat.commits for beat in harness.beats) / _FLEET:.4f} "
        f"write_ms={1000 * sum(beat.seconds for beat in writes) / len(writes):.2f} "
        f"early_return_us={1e6 * sum(beat.seconds for beat in skips) / max(len(skips), 1):.2f} "
        f"run_log_rows={len(lines)} progress_lines={len(progress)}"
    )


async def test_the_same_rivals_reclaim_a_sweep_that_stops_beating(db, connection, harness) -> None:
    """The control, so the test above cannot pass for the wrong reason: the same sweep with its
    heartbeat silenced is reclaimed by the first rival past `run_stale_after_seconds`, the sweep's
    own finish is then refused, and its collection reads failed."""
    from app.core.config import settings
    from app.core.runs import TRIGGER_SWEEP, finish
    from app.mdm.collections import run_one_collection
    from app.models.schema import Run

    harness.size(1_000)
    harness.beating = False
    sweep = await _sweep_collection(db, connection)
    await run_one_collection(db, sweep, trigger=TRIGGER_SWEEP)

    run = await db.get(Run, harness.rivals[0].holder)
    await db.refresh(run)
    assert run.status == "failed" and "no heartbeat" in (run.error or ""), run.error

    # Every rival joined until the first one past the stale window, and that one took the lock.
    stale = timedelta(seconds=settings.run_stale_after_seconds)
    *joined, took = harness.rivals
    assert took.started and not any(rival.started for rival in joined)
    assert {rival.holder for rival in joined} == {run.id}
    assert joined[-1].at - run.started_at <= stale < took.at - run.started_at

    await db.refresh(sweep)
    assert sweep.last_run_status == "failed"
    # The rival's run holds the lock now; close it so nothing is left running.
    assert await finish(db, await db.get(Run, took.holder), ok=True)


@pytest.mark.parametrize("kind", ["device_sweep", "catalog"])
async def test_a_catalog_read_past_the_stale_window_is_not_reclaimed(db, connection, jamf, harness, kind) -> None:
    """The gap #757 found, asserted closed: nothing beat before the first device, so a sweep reading a
    large or throttled tenant's catalog past the stale window was reclaimed and failed at its first
    device, and a catalog run beat only at its end. Here 150 smart groups at five simulated seconds a
    read, one at a time as under throttling, run past twice the window, with a rival every simulated
    minute, mid-wave. Every rival joins, and the run succeeds."""
    from app.core.config import settings
    from app.core.runs import _HEARTBEAT_INTERVAL_SECONDS, TRIGGER_SWEEP
    from app.mdm.collections import LOCK_CLASS_FOR_KIND, run_one_collection
    from app.mdm.jamf.client import _CONCURRENCY
    from app.models.schema import Run

    jamf.smart_groups = [{"id": str(n), "name": f"heartbeat group {n}", "siteId": "-1"} for n in range(1, 151)]
    harness.size(100)
    harness.lock_class, harness.read = LOCK_CLASS_FOR_KIND[kind], timedelta(seconds=5)
    harness.next_rival = harness.now + timedelta(minutes=1)
    collection = await _sweep_collection(db, connection, kind)
    result = await run_one_collection(db, collection, trigger=TRIGGER_SWEEP)

    query = select(Run).where(Run.mdm_connection_id == harness.connection_id).order_by(Run.started_at)
    run, *others = (await db.execute(query)).scalars().all()
    await db.refresh(run)
    assert run.status == "succeeded" and not others, run.error
    assert result.ok and result.device_count == (harness.fleet if kind == "device_sweep" else 0), result
    await db.refresh(collection)
    assert collection.last_run_status == "ok"

    # The reads before the first device outlasted the stale window twice over, every rival during
    # them joined, and the heartbeat each one read was at most one interval and one wave of reads old.
    reading = [rival for rival in harness.rivals if rival.device == 0]
    assert reading[-1].at - run.started_at > 2 * timedelta(seconds=settings.run_stale_after_seconds)
    assert {(rival.started, rival.holder) for rival in harness.rivals} == {(False, run.id)}
    wave = _CONCURRENCY * harness.read
    assert max(rival.at - rival.heartbeat for rival in reading) <= timedelta(seconds=_HEARTBEAT_INTERVAL_SECONDS) + wave
