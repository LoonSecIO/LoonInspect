"""Collections (#27) against a real Postgres and the fake Jamf tenant.

What a collection *is* — the what and the when carried by one row — and what the tick
does with it: defaults that exist as rows, a claim that is atomic, a narrowed sweep
whose scope reaches Jamf as `section=` and `filter=` and is recorded in the aperture,
the rate floor that makes a manual run reset the scheduled one, and the webhook path
scoped by its own collection.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenant_ready() -> None:
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, unscoped_session

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)


@pytest_asyncio.fixture(loop_scope="session")
async def db(tenant_ready):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


@pytest.fixture
def jamf(monkeypatch: pytest.MonkeyPatch) -> FakeJamf:
    from app.mdm.jamf.client import JamfClient

    fake = FakeJamf()

    @asynccontextmanager
    async def _mock_http(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as client:
            yield client

    monkeypatch.setattr(JamfClient, "http", _mock_http)
    return fake


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    """A Jamf connection with credentials; removed with everything under it afterwards
    (collections cascade in the database)."""
    from app.models.schema import (
        AppCatalogEntry,
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
    )

    row = MdmConnection(
        name=f"collections jamf {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
        capability_webhooks=True,
    )
    db.add(row)
    await db.commit()
    connection_id = row.id
    try:
        yield row
    finally:
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        # Keyed by tenant rather than by connection, so it outlives the cascade above and
        # would otherwise leave this suite's sweeps visible to test_catalog_db on the
        # next run against the same local database.
        await db.execute(delete(AppCatalogEntry))
        await db.commit()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _fresh(db, row):
    await db.refresh(row)
    return row


async def test_defaults_are_real_rows_and_idempotent(db, connection) -> None:
    from app.core.config import settings
    from app.mdm.collections import ensure_default_collections, list_collections
    from app.mdm.jamf.contract import V0_SECTIONS

    added = await ensure_default_collections(db, connection)
    await db.commit()
    assert sorted(row.kind for row in added) == ["catalog", "device_sweep", "webhook"]

    rows = {row.kind: row for row in await list_collections(db, connection.id)}
    sweep, catalog, webhook = rows["device_sweep"], rows["catalog"], rows["webhook"]
    assert sweep.sections == list(V0_SECTIONS) and sweep.selector is None
    assert (sweep.frequency, sweep.at_hour, sweep.at_minute, sweep.timezone) == (
        "daily", settings.sync_hour, settings.sync_minute, settings.sync_timezone
    )
    assert sweep.next_due_at is not None and sweep.next_due_at > _now()
    assert catalog.frequency == "hourly" and catalog.sections == [] and catalog.next_due_at is not None
    assert webhook.frequency is None and webhook.next_due_at is None and webhook.sections == list(V0_SECTIONS)

    assert await ensure_default_collections(db, connection) == []


async def test_run_connection_runs_the_sweeps_and_records_outcomes(db, connection, jamf: FakeJamf) -> None:
    from app.mdm.collections import list_collections
    from app.mdm.service import sync_connection

    result = await sync_connection(db, connection)
    assert result.ok and result.device_count == 2
    assert result.observations == {"new": 2, "group_new": 1}

    rows = {row.kind: await _fresh(db, row) for row in await list_collections(db, connection.id)}
    sweep, catalog = rows["device_sweep"], rows["catalog"]
    assert sweep.last_run_status == "ok" and sweep.last_run_at is not None
    assert sweep.last_run_summary["deviceCount"] == 2 and sweep.last_run_summary["trigger"] == "sweep"
    # Catalog collections keep their own cadence; the sweep's trailing refresh covered it.
    assert catalog.last_run_at is None


async def test_a_narrowed_sweep_reaches_jamf_and_the_aperture(db, connection, jamf: FakeJamf) -> None:
    from app.mdm.collections import apply_schedule, run_collection
    from app.models.schema import Collection, ObservationAperture, ObservationSpan

    narrowed = Collection(
        mdm_connection_id=connection.id,
        name="Managed, general + apps",
        kind="device_sweep",
        enabled=True,
        sections=["general", "applications"],
        selector="general.remoteManagement.managed==true",
        quarantined_extension_attributes=["9"],
        frequency="daily",
        at_hour=2,
        at_minute=30,
        timezone="UTC",
    )
    apply_schedule(narrowed)
    db.add(narrowed)
    await db.commit()

    result = await run_collection(db, narrowed, trigger="manual")
    assert result.ok and result.collection_id == narrowed.id

    # The selector was pushed into Jamf's query, not applied after the fetch, and only
    # the requested sections were asked for.
    assert jamf.filters and all(f == "general.remoteManagement.managed==true" for f in jamf.filters)
    assert jamf.sections and all(s == "GENERAL,APPLICATIONS" for s in jamf.sections)

    aperture = (
        await db.execute(
            select(ObservationAperture)
            .where(ObservationAperture.mdm_connection_id == connection.id)
            .order_by(ObservationAperture.id.desc())
            .limit(1)
        )
    ).scalar_one()
    assert aperture.document["sections"] == ["applications", "general"]
    assert aperture.document["quarantinedExtensionAttributes"] == ["9"]

    span = (
        await db.execute(
            select(ObservationSpan).where(
                ObservationSpan.mdm_connection_id == connection.id,
                ObservationSpan.subject_kind == "computer",
                ObservationSpan.is_current.is_(True),
            ).limit(1)
        )
    ).scalars().first()
    assert span is not None and set(span.section_digests) == {"general", "applications"}


async def test_claim_is_atomic_and_advances_next_due(db, connection) -> None:
    from app.mdm.collections import apply_schedule, claim_due
    from app.models.schema import Collection

    row = Collection(
        mdm_connection_id=connection.id, name="due now", kind="catalog", enabled=True, sections=[],
        frequency="hourly", at_minute=0, timezone="UTC",
    )
    apply_schedule(row)
    row.next_due_at = _now() - timedelta(minutes=1)
    db.add(row)
    await db.commit()

    # Other collections in this tenant may be due at the same moment (the tenancy
    # sweep's defaults, on a shared local database); only this row's claim is asserted.
    now = _now()
    first = await claim_due(db, now)
    # claim_due hands back (collection, due_at): the occurrence being served, captured
    # before the UPDATE advances next_due_at past it. That value becomes the run's
    # window, so a sweep the tick reaches late still stamps its events at the hour the
    # customer configured (#31).
    assert row.id in [c.id for c, _ in first]
    due_at = next(due for c, due in first if c.id == row.id)
    assert due_at < now
    second = await claim_due(db, now)
    assert row.id not in [c.id for c, _ in second]
    await db.refresh(row)
    assert row.last_claimed_at is not None and row.next_due_at is not None and row.next_due_at > now


async def test_claim_leaves_a_busy_connection_for_the_next_tick(db, connection) -> None:
    """Busy is a live run row, not a status string.

    The tick asks the run table because the run row *is* the lock now (#31). Skipping a
    busy connection at claim time rather than letting acquisition reject it is the point:
    claiming advances next_due_at, so losing the race afterwards would push the next
    sweep a whole occurrence out instead of retrying next minute.
    """
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_MANUAL, acquire, finish
    from app.mdm.collections import apply_schedule, claim_due
    from app.models.schema import Collection

    sweep = Collection(
        mdm_connection_id=connection.id, name="sweep due", kind="device_sweep", enabled=True,
        sections=["general"], frequency="daily", at_hour=1, at_minute=0, timezone="UTC",
    )
    catalog = Collection(
        mdm_connection_id=connection.id, name="catalog due", kind="catalog", enabled=True, sections=[],
        frequency="hourly", at_minute=0, timezone="UTC",
    )
    for row in (sweep, catalog):
        apply_schedule(row)
        row.next_due_at = _now() - timedelta(minutes=1)
        db.add(row)
    await db.commit()

    held = await acquire(db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_DEVICE_SWEEP)
    assert held.started

    mine = {c.kind for c, _ in await claim_due(db, _now()) if c.mdm_connection_id == connection.id}
    # The catalog is a different lock class and runs regardless — a fifteen-minute
    # definitions refresh has no reason to wait behind a forty-minute device sweep.
    assert mine == {"catalog"}
    await db.refresh(sweep)
    assert sweep.next_due_at < _now()

    await finish(db, held.run, ok=True)
    mine = {c.kind for c, _ in await claim_due(db, _now()) if c.mdm_connection_id == connection.id}
    assert mine == {"device_sweep"}


async def test_tick_skips_a_collection_inside_its_rate_floor(db, connection, jamf: FakeJamf) -> None:
    from app.mdm.collections import apply_schedule, tick_tenant
    from app.models.schema import Collection

    row = Collection(
        mdm_connection_id=connection.id, name="just ran", kind="device_sweep", enabled=True,
        sections=["general"], frequency="daily", at_hour=1, at_minute=0, timezone="UTC",
    )
    apply_schedule(row)
    row.next_due_at = _now() - timedelta(minutes=1)
    row.last_run_at = _now() - timedelta(minutes=5)  # a manual run five minutes ago
    db.add(row)
    await db.commit()

    results = await tick_tenant(db, _now())
    assert not any(r.collection_id == row.id for r in results)
    await db.refresh(row)
    assert row.last_run_status == "skipped"
    assert not any(path.startswith("GET /api/v4/computers-inventory") for path in jamf.requests)


async def test_a_sweep_that_asks_for_eas_reads_the_sections_they_are_displayed_under(db, connection, jamf: FakeJamf) -> None:
    """#197's aperture rule at run time. A row written straight to the table — as a row
    saved before the rule was — still fetches the five carriers, records them in the
    aperture, and lands the purchasing-displayed EA in the current-state rows with the
    section it came from."""
    from app.mdm.collections import apply_schedule, run_collection
    from app.models.schema import Collection, Device, DeviceExtensionAttribute, ObservationAperture

    narrowed = Collection(
        mdm_connection_id=connection.id,
        name="Apps + EAs",
        kind="device_sweep",
        enabled=True,
        sections=["applications", "extension_attributes"],
        quarantined_extension_attributes=[],
        frequency="daily",
        at_hour=2,
        at_minute=30,
        timezone="UTC",
    )
    apply_schedule(narrowed)
    db.add(narrowed)
    await db.commit()

    result = await run_collection(db, narrowed, trigger="manual")
    assert result.ok and result.collection_id == narrowed.id

    closed = "GENERAL,HARDWARE,OPERATING_SYSTEM,USER_AND_LOCATION,PURCHASING,APPLICATIONS,EXTENSION_ATTRIBUTES"
    assert jamf.sections and all(s == closed for s in jamf.sections)
    aperture = (
        await db.execute(
            select(ObservationAperture)
            .where(ObservationAperture.mdm_connection_id == connection.id)
            .order_by(ObservationAperture.id.desc())
            .limit(1)
        )
    ).scalar_one()
    assert aperture.document["sections"] == sorted(
        ["applications", "extension_attributes", "general", "hardware", "operating_system", "user_and_location", "purchasing"]
    )

    synthetic = (
        await db.execute(
            select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == jamf.synthetic["id"])
        )
    ).scalar_one()
    rows = (
        await db.execute(select(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id == synthetic.id))
    ).scalars().all()
    assert {(row.definition_id, row.source) for row in rows} == {
        ("5", "extensionAttributes"),
        ("27", "extensionAttributes"),
        ("12", "general"),
        ("9", "hardware"),
        ("22", "operatingSystem"),
        ("18", "userAndLocation"),
        ("31", "purchasing"),
    }
    cost_center = next(row for row in rows if row.definition_id == "31")
    assert cost_center.name == "Cost Center" and cost_center.values == ["CC-4410"] and cost_center.enabled is True
    departments = next(row for row in rows if row.definition_id == "27")
    assert departments.values == ["Research", "Engineering"]


async def test_webhook_path_is_scoped_by_its_collection(db, connection, jamf: FakeJamf) -> None:
    from app.mdm.collections import ensure_default_collections, list_collections
    from app.mdm.service import ingest_webhook
    from app.models.schema import ObservationAperture

    await ensure_default_collections(db, connection)
    await db.commit()
    webhook = next(row for row in await list_collections(db, connection.id) if row.kind == "webhook")
    webhook.sections = ["general", "security"]
    await db.commit()

    payload = {"webhook": {"webhookEvent": "ComputerInventoryCompleted"}, "event": {"jssID": jamf.real["id"]}}
    result = await ingest_webhook(db, connection, payload)
    assert result is not None and result.outcome == "new"

    aperture = (
        await db.execute(
            select(ObservationAperture)
            .where(ObservationAperture.mdm_connection_id == connection.id)
            .order_by(ObservationAperture.id.desc())
            .limit(1)
        )
    ).scalar_one()
    assert aperture.document["sections"] == ["general", "security"]


# --- last_success_at: the mark that survives a failure (#106) --------------------------
#
# `last_run_at` is the attempt's *start* and is written on every outcome, so it answers
# "when did we last try", not "when was this data last current". The staleness check on
# "/" asks the second question, and these four tests are the four ways the first answer
# would have been wrong.


@pytest_asyncio.fixture(loop_scope="session")
async def sweep(db, connection):
    """One enabled device sweep of its own, so a failure injected below lands on a row
    no other test in this module is asserting about."""
    from app.mdm.collections import apply_schedule
    from app.models.schema import Collection

    row = Collection(
        mdm_connection_id=connection.id,
        name=f"success mark {uuidlib.uuid4().hex[:8]}",
        kind="device_sweep",
        enabled=True,
        sections=["general"],
        frequency="daily",
        at_hour=3,
        at_minute=0,
        timezone="UTC",
    )
    apply_schedule(row)
    db.add(row)
    await db.commit()
    return row


async def test_a_successful_sweep_marks_the_attempt_and_the_success_together(db, sweep, jamf: FakeJamf) -> None:
    from app.mdm.collections import run_collection

    assert sweep.last_success_at is None  # never run

    assert (await run_collection(db, sweep, trigger="manual")).ok
    await db.refresh(sweep)

    assert sweep.last_run_status == "ok"
    # Both are the attempt's start, so on a success they agree. That they can be read
    # off the same instant is exactly why the second column looks redundant — the next
    # test is why it is not.
    assert sweep.last_success_at == sweep.last_run_at


async def test_a_failed_sweep_moves_the_attempt_and_leaves_the_success_standing(
    db, sweep, jamf: FakeJamf, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole reason the column exists.

    Before it, one failed sweep overwrote `last_run_at` and the pod lost every record of
    when its inventory was last current — so a freshness check reading that column would
    call a fleet fresh at the exact moment it stopped being collected.
    """
    from app.mdm import collections as collections_module
    from app.mdm.collections import run_collection
    from app.mdm.service import ConnectionSyncResult

    assert (await run_collection(db, sweep, trigger="manual")).ok
    await db.refresh(sweep)
    succeeded_at = sweep.last_success_at
    assert succeeded_at is not None

    async def _refused(_db, connection, **kwargs) -> ConnectionSyncResult:
        return ConnectionSyncResult(connection_id=connection.id, ok=False, error="Jamf refused the inventory read")

    monkeypatch.setattr(collections_module, "run_jamf", _refused)
    assert not (await run_collection(db, sweep, trigger="sweep")).ok
    await db.refresh(sweep)

    assert sweep.last_run_status == "failed"
    assert sweep.last_run_at > succeeded_at  # the attempt moved…
    assert sweep.last_success_at == succeeded_at  # …and the success did not


async def test_a_reclaimed_finish_does_not_leave_a_success_mark_behind(
    db, sweep, jamf: FakeJamf, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `closed is False` downgrade: the work finished, but the reclaim owns the
    verdict. The row's cached outcome is forced to failed, and its success mark has to
    be forced back with it — otherwise the collection claims a success the run history
    says never happened."""
    from app.mdm import collections as collections_module
    from app.mdm.collections import run_collection

    real_finish = collections_module.finish

    async def _finished_but_reclaimed(*args, **kwargs) -> bool:
        await real_finish(*args, **kwargs)
        return False

    monkeypatch.setattr(collections_module, "finish", _finished_but_reclaimed)
    await run_collection(db, sweep, trigger="manual")
    await db.refresh(sweep)

    assert sweep.last_run_status == "failed"
    assert sweep.last_success_at is None  # not the instant the sweep actually ran


async def test_a_reclaim_mid_flight_leaves_an_earlier_success_alone(
    db, sweep, jamf: FakeJamf, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Restored, never cleared. A run reclaimed mid-flight did not succeed, but an
    earlier real success is still a true statement about when this data was current."""
    from app.core.runs import RunReclaimed
    from app.mdm import collections as collections_module
    from app.mdm.collections import run_collection

    assert (await run_collection(db, sweep, trigger="manual")).ok
    await db.refresh(sweep)
    succeeded_at = sweep.last_success_at
    assert succeeded_at is not None

    async def _reclaimed(*args, **kwargs):
        raise RunReclaimed("reclaimed mid-flight")

    monkeypatch.setattr(collections_module, "run_jamf", _reclaimed)
    assert not (await run_collection(db, sweep, trigger="sweep")).ok
    await db.refresh(sweep)

    assert sweep.last_run_status == "failed"
    assert sweep.last_success_at == succeeded_at


# --- The process dies: the reclaim is the collection's fifth writer -------------------
#
# Every test above drives an outcome through a live `run_collection` frame, which is
# exactly why this defect survived them. `last_run_status` had four writers and all four
# sat inside that frame; when the frame's process goes — a deploy, an OOM kill, a node
# eviction at 03:12 — the reclaim fails the RUN and, before this, left the COLLECTION
# reading `ok`. Everything that judges a collection's health reads the collection, so the
# morning after a killed 3,000-Mac sweep #106's panel printed a dated all-clear over it.


async def _kill_the_process(db, run_id) -> None:
    """Stop the heartbeat and nothing else. To the database this is still a perfectly
    good running run, which is the whole difficulty: nobody is left to say otherwise."""
    from sqlalchemy import update as sa_update

    from app.core.config import settings
    from app.models.schema import Run

    stale = _now() - timedelta(seconds=settings.run_stale_after_seconds + 60)
    await db.execute(sa_update(Run).where(Run.id == run_id).values(heartbeat_at=stale))
    await db.commit()


async def test_a_reclaim_marks_the_collection_the_dead_run_was_serving(
    db, connection, sweep, jamf: FakeJamf
) -> None:
    """The sweep that was killed at 03:12 does not still read `ok` at 08:00."""
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, acquire
    from app.mdm.collections import run_collection

    # Yesterday's sweep succeeded, so the row carries the reassuring cache this defect
    # was hiding behind.
    assert (await run_collection(db, sweep, trigger="sweep")).ok
    await db.refresh(sweep)
    assert sweep.last_run_status == "ok"
    succeeded_at = sweep.last_success_at
    assert succeeded_at is not None

    # Tonight's sweep takes the lock for this collection and its process is killed
    # mid-flight. No `run_collection` frame ever finishes; nothing writes the row.
    dead = await acquire(
        db,
        connection,
        trigger=TRIGGER_SWEEP,
        lock_class=LOCK_DEVICE_SWEEP,
        collection_id=sweep.id,
    )
    assert dead.started
    started_at = dead.run.started_at
    await _kill_the_process(db, dead.run.id)

    # Morning. Any acquisition anywhere in the tenant runs the reclaim.
    revived = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert revived.started and revived.run.id != dead.run.id

    await db.refresh(sweep)
    assert sweep.last_run_status == "failed"
    assert sweep.last_run_at == started_at
    assert "heartbeat" in sweep.last_run_summary["error"]
    assert sweep.last_run_summary["jobId"] == str(dead.run.id)
    # The success mark is a separate claim, and an earlier real success is still true.
    # Clearing it would make a collection with a year of history read as
    # never-succeeded, which #106 turns into a louder and wronger row.
    assert sweep.last_success_at == succeeded_at


async def test_a_reclaim_leaves_a_collection_that_recorded_its_own_outcome_alone(
    db, connection, sweep, jamf: FakeJamf
) -> None:
    """The freshness guard, which is what keeps the fix from lying in the other direction.

    Run-now hands ONE run to every enabled sweep on a connection, so a process that dies
    inside the fourth must not restamp the three that finished under the same jobID.
    `collections.last_run_at` is the attempt's start and is therefore always later than
    the start of the run the attempt happens inside — a row at or after the dead run's
    `started_at` has already recorded its own outcome for this run and knows more than
    the reclaim does.
    """
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_MANUAL, acquire
    from app.mdm.collections import run_collection

    held = await acquire(
        db,
        connection,
        trigger=TRIGGER_MANUAL,
        lock_class=LOCK_DEVICE_SWEEP,
        collection_id=sweep.id,
    )
    assert held.started
    # The collection completes inside the handed-in run…
    assert (await run_collection(db, sweep, trigger="manual", run=held.run)).ok
    await db.refresh(sweep)
    succeeded_at = sweep.last_success_at
    assert sweep.last_run_status == "ok" and succeeded_at is not None

    # …and only then does the process die, before anything closes the run.
    await _kill_the_process(db, held.run.id)
    revived = await acquire(db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_DEVICE_SWEEP)
    assert revived.started

    await db.refresh(sweep)
    assert sweep.last_run_status == "ok"
    assert sweep.last_success_at == succeeded_at


async def test_a_reclaimed_webhook_run_marks_no_collection(db, connection, sweep) -> None:
    """Webhook runs carry no `collection_id`, and that is what keeps a reclaim off the
    webhook collection — by construction, not by a branch that could be edited out."""
    from app.core.runs import LOCK_DEVICE_SWEEP, LOCK_WEBHOOK, TRIGGER_WEBHOOK, acquire

    before = sweep.last_run_status
    hook = await acquire(db, connection, trigger=TRIGGER_WEBHOOK, lock_class=LOCK_WEBHOOK)
    assert hook.started and hook.run.collection_id is None
    await _kill_the_process(db, hook.run.id)

    revived = await acquire(db, connection, trigger=TRIGGER_WEBHOOK, lock_class=LOCK_DEVICE_SWEEP)
    assert revived.started
    await db.refresh(sweep)
    assert sweep.last_run_status == before


async def test_a_mark_that_cannot_be_written_still_frees_the_lock(
    db, connection, sweep, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mark may be dropped. It may never take the verdicts — or the mutex — with it.

    The stamp above rides in the verdicts' transaction on purpose, so that a collection's
    cached outcome and its run's verdict cannot disagree. Bare in that transaction it also
    inherited the power to abort it: an UPDATE that raised propagated out of
    `_reclaim_stale` and out of `acquire` with the verdicts uncommitted, so every run the
    reclaim had just failed stayed `running` and the lock it exists to free stayed held —
    on every connection in the tenant, since every acquisition runs the reclaim. That is a
    strictly worse failure than the blind panel the stamp was added to fix: a panel reads
    one morning wrong, a wedged mutex never syncs again.

    So the mark sits in a savepoint. Here it half-writes and then hits a statement the
    database rejects — not a bare `raise`, which a plain `try/except` would swallow just
    as well, but the real thing: an aborted transaction, which nothing short of a
    savepoint gets back. Three things must survive it, and do: the verdict is committed
    and durable, the lock is free, and the session the caller is still holding is usable
    (`acquire` reads `connection.id` on the line after the reclaim returns). What is lost
    is the stamp itself, half-write included — the collection reads `ok` beside a run
    reading `failed`, which is exactly the original defect, now narrowed to the case where
    the UPDATE genuinely cannot be performed. That loss is asserted rather than merely
    tolerated, so nobody re-fixes it by wedging the lock again.

    Two things this test does NOT see, named here so its green is not read as more than it
    is. It substitutes a stand-in for the mark, so no real `update(Collection)` runs and
    nothing is ever synchronised into the session; and it reads every collection back
    through `db.refresh`, which un-expires the instance before the assertion looks at it.
    Both were how a savepoint rollback could expire the caller's `Collection` and orphan
    the lock this test watches being freed, with this test green throughout.
    `test_a_failed_mark_does_not_orphan_the_lock_it_just_freed`, below, is the one that
    can see it.
    """
    from sqlalchemy import text
    from sqlalchemy import update as sa_update

    from app.core import runs as runs_module
    from app.core.database import session_for_tenant
    from app.core.runs import LOCK_DEVICE_SWEEP, STATUS_FAILED, STATUS_RUNNING, TRIGGER_SWEEP, acquire
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Collection, Run

    sweep.last_run_at = None
    sweep.last_run_status = "ok"
    await db.commit()

    dead = await acquire(
        db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP, collection_id=sweep.id
    )
    assert dead.started
    await _kill_the_process(db, dead.run.id)

    async def _boom(session, rows, *, error: str) -> None:
        await session.execute(
            sa_update(Collection).where(Collection.id == sweep.id).values(last_run_status="failed")
        )
        await session.execute(text("SELECT 1 / 0"))

    monkeypatch.setattr(runs_module, "_mark_collections_reclaimed", _boom)

    # The lock is free: this acquisition both survives the raise and takes the mutex.
    revived = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert revived.started and revived.run.id != dead.run.id

    # Committed, not merely pending in the session that did it. A second session is the
    # only witness that can tell those two apart.
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as witness:
        verdict = (await witness.execute(select(Run).where(Run.id == dead.run.id))).scalar_one()
        assert verdict.status == STATUS_FAILED
        assert "heartbeat" in (verdict.error or "")
        assert verdict.finished_at is not None
        still_held = (
            await witness.execute(
                select(Run.id).where(
                    Run.mdm_connection_id == connection.id,
                    Run.lock_class == LOCK_DEVICE_SWEEP,
                    Run.status == STATUS_RUNNING,
                )
            )
        ).scalars().all()
        assert still_held == [revived.run.id]

    # The disclosed cost of that guarantee, in the same breath as the guarantee — and the
    # half-written `failed` above went back with the savepoint rather than committing as
    # a stamp no complete mark ever stood behind.
    await db.refresh(sweep)
    assert sweep.last_run_status == "ok"


async def test_a_failed_mark_does_not_orphan_the_lock_it_just_freed(
    db, connection, sweep, jamf: FakeJamf, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dropped mark costs the stamp. It must not cost the caller its session.

    The test above proves the savepoint frees the lock. It cannot prove the caller can
    still *use* it, and that is not a small gap. It reads every collection back through
    `db.refresh`, which un-expires the instance before the assertion looks at it, and it
    substitutes a stand-in for the mark, so no real `update(Collection)` ever runs.
    `run_collection` — the scheduled tick's caller, the unattended path this whole
    mechanism exists for — does neither: it holds the `Collection` the tick handed it
    across `acquire()` and reads `collection.id` straight off it on the next line.

    `update(Collection)` is an ORM-enabled UPDATE. Left to synchronise, SQLAlchemy
    matches the in-session `Collection` instances against the WHERE clause, writes the
    new values onto them, and registers them as altered on the innermost transaction —
    which here is the savepoint. Rolling that savepoint back runs
    `_restore_snapshot(dirty_only=True)`, and that EXPIRES every instance so registered.
    The caller's `collection` is one of them, and under asyncio touching an expired
    attribute raises `MissingGreenlet` rather than lazily reloading. `acquire()` has
    already committed a new `running` run by the time the caller gets there, so the raise
    lands on the far side of the mutex: the lock the reclaim just freed is taken and
    immediately abandoned, held until the next `run_stale_after_seconds` reclaim comes
    round. Strictly worse than the blind panel the savepoint was chosen to pay for, and
    the second time this mark has reached out and wedged the thing it rides beside.

    Two collection-bearing stale runs in one batch are the trigger, and they are the
    ordinary shape rather than a contrived one: a pod dies holding `device_sweep` and
    `catalog` on the same connection, and the reclaim marks both. One mark lands, the
    next statement cannot be written, and the savepoint takes the landed one back along
    with the instance it had synchronised.
    """
    from sqlalchemy import text

    from app.core import runs as runs_module
    from app.core.database import session_for_tenant
    from app.core.runs import (
        LOCK_CATALOG,
        LOCK_DEVICE_SWEEP,
        STATUS_RUNNING,
        TRIGGER_SWEEP,
        acquire,
    )
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.mdm.collections import apply_schedule, run_collection
    from app.models.schema import Collection, Run

    catalog = Collection(
        mdm_connection_id=connection.id,
        name=f"groups {uuidlib.uuid4().hex[:8]}",
        kind="catalog",
        enabled=True,
        sections=[],
        frequency="hourly",
        at_minute=11,
        timezone="UTC",
    )
    apply_schedule(catalog)
    db.add(catalog)
    sweep.last_run_at = None
    sweep.last_run_status = "ok"
    await db.commit()

    # 03:12. The pod is holding both locks on this connection, and then it is not.
    dead_sweep = await acquire(
        db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP, collection_id=sweep.id
    )
    dead_catalog = await acquire(
        db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_CATALOG, collection_id=catalog.id
    )
    assert dead_sweep.started and dead_catalog.started
    await _kill_the_process(db, dead_sweep.run.id)
    await _kill_the_process(db, dead_catalog.run.id)

    real_mark = runs_module._mark_collections_reclaimed

    async def _one_mark_lands_then_the_batch_cannot_go_on(session, rows, *, error: str) -> None:
        # The real function, on one real row — the sweep's, so the mark that lands is
        # deterministically the one the caller below is holding. In the field the order
        # is the reclaim's and either row can be first; pinning it here is what lets the
        # assertion name an instance instead of a coin toss.
        ordered = sorted(rows, key=lambda row: row.collection_id != sweep.id)
        assert len(ordered) >= 2 and all(row.collection_id is not None for row in ordered)
        await real_mark(session, ordered[:1], error=error)
        # And then the batch meets something the database refuses — a statement timeout,
        # a deadlock with the in-frame writer this stands in for. An aborted transaction
        # is the real failure, not a bare `raise`, and only the savepoint gets it back.
        await session.execute(text("SELECT 1 / 0"))

    monkeypatch.setattr(runs_module, "_mark_collections_reclaimed", _one_mark_lands_then_the_batch_cannot_go_on)

    # 03:15. The tick reaches this collection and runs it, which is where the reclaim
    # happens. Whatever the mark managed to do, this call is the customer's sweep.
    raised: Exception | None = None
    result = None
    try:
        result = await run_collection(db, sweep, trigger="sweep")
    except Exception as exc:
        raised = exc

    # Asserted from a second session, and asserted first: whether the caller came back
    # with a result matters less than whether it left the mutex behind it.
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as witness:
        orphaned = (
            await witness.execute(
                select(Run.id, Run.lock_class).where(
                    Run.mdm_connection_id == connection.id,
                    Run.status == STATUS_RUNNING,
                )
            )
        ).all()

    assert orphaned == [], (
        f"the acquisition took the freed lock and walked away from it: {orphaned} left running, "
        f"because run_collection raised {type(raised).__name__ if raised is not None else 'nothing'}: {raised}"
    )
    assert raised is None, f"run_collection raised {type(raised).__name__}: {raised}"
    assert result is not None and result.ok

    # And the sweep that did run recorded its own outcome over the dropped stamp, which
    # is the whole reason the stamp is allowed to be dropped.
    await db.refresh(sweep)
    assert sweep.last_run_status == "ok" and sweep.last_run_at is not None


async def test_a_reclaimed_collection_that_then_succeeds_reads_ok(
    db, connection, sweep, jamf: FakeJamf
) -> None:
    """The mark is a stand-in for a run nobody closed. The next real run outranks it.

    03:12, the pod dies. 03:15, the tick reaches the same collection: `acquire` reclaims
    the dead run and stamps `failed` on the row, and then the sweep it just acquired runs
    and succeeds. The row must read `ok` — the mark exists to stop a killed sweep printing
    a dated all-clear, not to hold an alarm over a collection that has since succeeded.

    This is the other end of the fix above, and the reason `synchronize_session=False`
    could not stand on its own. Both writes land on one `Collection` instance that
    `run_collection` is holding: the reclaim's, through the session and behind the
    instance's back, and the frame's own, through the instance. With the UPDATE no longer
    synchronising and nothing reading the row back, the instance keeps its pre-mark `ok`,
    so `collection.last_run_status = "ok"` at the end of a successful sweep is not a
    change the ORM has any reason to flush — and the column keeps the mark's `failed`
    until some later tick loads the row fresh. A daily sweep succeeding into a permanent
    red row on #106's panel is a worse lie than the one the mark was added to prevent,
    and neither the panel nor the run history would contradict it.

    Read back from a second session on purpose: the instance in this one is the thing
    under suspicion, so it cannot also be the witness.
    """
    from app.core.database import session_for_tenant
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, acquire
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.mdm.collections import run_collection
    from app.models.schema import Collection

    assert (await run_collection(db, sweep, trigger="sweep")).ok
    await db.refresh(sweep)
    assert sweep.last_run_status == "ok"

    dead = await acquire(
        db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP, collection_id=sweep.id
    )
    assert dead.started
    await _kill_the_process(db, dead.run.id)

    # One call: the reclaim that stamps `failed`, and the sweep that supersedes it.
    assert (await run_collection(db, sweep, trigger="sweep")).ok

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as witness:
        row = (await witness.execute(select(Collection).where(Collection.id == sweep.id))).scalar_one()
        assert row.last_run_status == "ok", (
            f"the row reads {row.last_run_status!r} after a successful sweep; the session that wrote it "
            f"holds {sweep.last_run_status!r}, which is how the write went missing"
        )
        assert row.last_run_summary["error"] is None


# --- A skip is not a result ------------------------------------------------------------


async def test_the_rate_floor_does_not_erase_a_failure(db, connection, jamf: FakeJamf) -> None:
    """`skipped` overwriting `failed` made the alarm self-clearing on a timer.

    A daily sweep that failed at 03:00 and was manually re-run at 03:20 is inside its
    rate floor at the next occurrence; the tick wrote `skipped`, and every surface that
    reads this column — #106's panel first — went quiet for a day. On an hourly
    collection it happened every alternate tick. The skip is this tick declining to
    produce a result, not a result that supersedes one.
    """
    from app.mdm.collections import apply_schedule, tick_tenant
    from app.models.schema import Collection

    row = Collection(
        mdm_connection_id=connection.id, name=f"failed then floored {uuidlib.uuid4().hex[:8]}",
        kind="device_sweep", enabled=True, sections=["general"],
        frequency="daily", at_hour=1, at_minute=0, timezone="UTC",
    )
    apply_schedule(row)
    row.next_due_at = _now() - timedelta(minutes=1)
    failed_at = _now() - timedelta(minutes=5)
    row.last_run_at = failed_at  # a run five minutes ago…
    row.last_run_status = "failed"  # …that failed
    row.last_run_summary = {"error": "jamf refused the token"}
    db.add(row)
    await db.commit()

    results = await tick_tenant(db, _now())
    assert not any(r.collection_id == row.id for r in results)

    await db.refresh(row)
    assert row.last_run_status == "failed"
    assert row.last_run_at == failed_at
    # And the reason with it: a summary replaced by "within rate floor" would leave the
    # status alarming with nothing on the collection saying what went wrong.
    assert row.last_run_summary["error"] == "jamf refused the token"
    assert not any(path.startswith("GET /api/v4/computers-inventory") for path in jamf.requests)


# --- GET /api/mdm/collections: the tenant-wide list (#106) -----------------------------

ADMIN = ("collections-admin@example.com", "collections-admin-password")
VIEWER = ("collections-viewer@example.com", "collections-viewer-password")
NEIGHBOUR_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000c0106")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts() -> None:
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, NEIGHBOUR_TENANT_ID) is None:
            db.add(
                Tenant(
                    id=NEIGHBOUR_TENANT_ID,
                    slug="collections-neighbour",
                    name="Collections Neighbour",
                    kind="operational",
                )
            )
            await db.commit()

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        for (email, password), role in ((ADMIN, "admin"), (VIEWER, "viewer")):
            # Get-or-create: CI starts from a clean database, a developer re-running
            # this locally does not.
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=role, password=password, roles=(role,))
        await db.commit()


async def _signed_in(email: str, password: str) -> httpx.AsyncClient:
    """https, because the session cookie is Secure — a plain-http client discards it
    silently and every request after the 200 login comes back 401."""
    from app.main import app

    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://collections.example.com"
    )
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return client


@pytest_asyncio.fixture(loop_scope="session")
async def api(accounts):
    client = await _signed_in(*ADMIN)
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def two_connections(db, accounts):
    """Two Jamf connections in this tenant, each with its own collections, plus one in a
    *different* tenant. The neighbour is the point: a query with no tenant predicate is
    only safe if RLS is doing the work, and without a neighbour row a leak would look
    identical to a correct answer."""
    from app.core.database import session_for_tenant
    from app.mdm.collections import apply_schedule
    from app.models.schema import Collection, MdmConnection

    made: list[int] = []
    for index in (1, 2):
        row = MdmConnection(
            name=f"tenant-wide jamf {index} {uuidlib.uuid4().hex[:8]}",
            provider="jamf",
            base_url=HOST,
            credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
        )
        db.add(row)
        await db.flush()
        made.append(row.id)
        for kind, frequency in (("device_sweep", "hourly"), ("webhook", None)):
            collection = Collection(
                mdm_connection_id=row.id,
                name=f"{kind} {index}",
                kind=kind,
                enabled=True,
                sections=["general"],
                frequency=frequency,
                at_minute=0 if frequency else None,
                timezone="UTC" if frequency else None,
            )
            apply_schedule(collection)
            db.add(collection)
    await db.commit()

    async with session_for_tenant(NEIGHBOUR_TENANT_ID) as neighbour_db:
        theirs = MdmConnection(
            name=f"neighbour jamf {uuidlib.uuid4().hex[:8]}",
            provider="jamf",
            base_url="https://neighbour.jamfcloud.com",
        )
        neighbour_db.add(theirs)
        await neighbour_db.flush()
        hidden = Collection(
            mdm_connection_id=theirs.id,
            name="neighbour sweep",
            kind="device_sweep",
            enabled=True,
            sections=["general"],
            frequency="daily",
            at_hour=4,
            at_minute=0,
            timezone="UTC",
        )
        apply_schedule(hidden)
        neighbour_db.add(hidden)
        await neighbour_db.commit()
        neighbour_connection_id = theirs.id

    try:
        yield {"mine": made, "theirs": neighbour_connection_id}
    finally:
        await db.rollback()
        await db.execute(delete(MdmConnection).where(MdmConnection.id.in_(made)))  # collections cascade
        await db.commit()
        async with session_for_tenant(NEIGHBOUR_TENANT_ID) as neighbour_db:
            await neighbour_db.execute(delete(MdmConnection).where(MdmConnection.id == neighbour_connection_id))
            await neighbour_db.commit()


async def test_the_tenant_wide_list_spans_every_connection(api, two_connections) -> None:
    """One request, not one per connection. The panel on "/" has no connection in hand
    and polls; an N+1 there is an N+1 forever."""
    response = await api.get("/api/mdm/collections")
    assert response.status_code == 200, response.text

    assert set(two_connections["mine"]) <= {row["mdmConnectionId"] for row in response.json()}


async def test_the_tenant_wide_list_stops_at_the_tenant_line(api, two_connections) -> None:
    """SECURITY: the query carries no tenant predicate, so this asserts RLS is what
    scopes it. The neighbour's collection exists and is schedulable — and is not here."""
    response = await api.get("/api/mdm/collections")
    assert response.status_code == 200, response.text
    rows = response.json()

    assert two_connections["theirs"] not in {row["mdmConnectionId"] for row in rows}
    assert "neighbour sweep" not in {row["name"] for row in rows}


async def test_the_tenant_wide_list_needs_connection_read(accounts, two_connections) -> None:
    """A viewer reads inventory, not configuration. The per-connection route is gated
    the same way, and the new one must not become the cheaper way in."""
    viewer = await _signed_in(*VIEWER)
    try:
        assert (await viewer.get("/api/mdm/collections")).status_code == 403
    finally:
        await viewer.aclose()


async def test_every_collection_says_when_it_last_succeeded_and_when_it_goes_stale(api, two_connections) -> None:
    """The two fields a freshness check reads, and the one row that refuses to make the
    claim: a webhook is event-driven, has no cadence to double, and is waiting rather
    than late."""
    response = await api.get("/api/mdm/collections")
    assert response.status_code == 200, response.text
    rows = {(row["mdmConnectionId"], row["kind"]): row for row in response.json()}

    sweep = rows[(two_connections["mine"][0], "device_sweep")]
    assert sweep["lastSuccessAt"] is None  # never run, and says so rather than guessing
    assert sweep["staleAfterSeconds"] == 2 * 3600  # hourly, doubled — Kyle's ruling

    webhook = rows[(two_connections["mine"][0], "webhook")]
    assert webhook["staleAfterSeconds"] is None


async def test_the_tenant_wide_list_is_a_projection_not_the_configuration_row(db, api, two_connections) -> None:
    """SECURITY-ADJACENT: reach and cadence, not a boundary break.

    This route is polled every sixty seconds by the front page, by everyone holding
    `connection:read`. The per-connection route may answer with the whole configuration
    row because someone is editing it; this one may not, because nothing renders it.
    `selector` is the case that makes it concrete — it is the operator's RSQL, and
    narrowing a sweep by user means it routinely reads `username=="jdoe"`.

    Asserted as an exact key set rather than "selector is absent", so a field added to
    `CollectionOut` later cannot arrive here unnoticed — which is the whole reason
    `CollectionSummaryOut` is a separate model instead of a subclass.
    """
    from app.models.schema import Collection

    narrowed = (
        await db.execute(
            select(Collection).where(
                Collection.mdm_connection_id == two_connections["mine"][0],
                Collection.kind == "device_sweep",
            )
        )
    ).scalar_one()
    narrowed.selector = 'username=="jdoe"'
    await db.commit()

    response = await api.get("/api/mdm/collections")
    assert response.status_code == 200, response.text
    rows = response.json()
    assert rows, "the fixture made collections; an empty list would pass every assertion below"

    for row in rows:
        assert set(row) == {
            "id",
            "mdmConnectionId",
            "name",
            "kind",
            "enabled",
            "nextDueAt",
            "lastRunAt",
            "lastRunStatus",
            "lastSuccessAt",
            "staleAfterSeconds",
            "createdAt",
        }

    # And the per-connection route still carries it, so this is a narrowing of one
    # answer rather than a field that quietly left the product.
    editor = await api.get(f"/api/mdm/connections/{two_connections['mine'][0]}/collections")
    assert editor.status_code == 200, editor.text
    assert 'username=="jdoe"' in {row["selector"] for row in editor.json()}
