# ruff: noqa: E501 — assertion lines read better unwrapped in this end-to-end test.
"""The posture snapshot recorder against a real Postgres: a capture fired by the close of
a full sweep (success and failure alike), and the writing rules the table's readers rely
on — every active key lands, the run id is stamped, and an empty queue writes no
`outbox.oldest_pending_age_s` row rather than a lying zero.

Assertions on countable keys are deltas between a baseline capture and one taken after
seeding a known fleet, so the suite is honest against a lived-in local database as well as
CI's fresh one — it counts what it created, not what it found. Gated on RUN_DB_TESTS.
"""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

_TITLE_IDS = ("LOONT1", "LOONT2", "LOONT3", "LOONT4")


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


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash() -> str:
    return uuidlib.uuid4().hex


def _key67() -> str:
    return "v1:" + uuidlib.uuid4().hex + uuidlib.uuid4().hex


@pytest_asyncio.fixture(loop_scope="session")
async def fleet(db):
    """Two connections — one active, one not — and the cleanup for everything a test
    seeds around them through `_seed_fleet`. Seeding is a separate call rather than part
    of this fixture so a test can take its baseline capture *before* the fleet exists."""
    from app.models.schema import (
        Account,
        AccountRole,
        ApiToken,
        AppCatalogEntry,
        Destination,
        Device,
        DeviceExtensionAttribute,
        EventOutbox,
        InstalledApp,
        JamfPatchTitle,
        MdmConnection,
        MdmSyncState,
        OutboxDelivery,
        PostureSnapshot,
        Run,
    )

    suffix = uuidlib.uuid4().hex[:8]
    active = MdmConnection(name=f"posture jamf {suffix}", provider="jamf", base_url="https://posture.invalid", is_active=True)
    inactive = MdmConnection(name=f"posture inactive {suffix}", provider="jamf", base_url="https://posture-off.invalid", is_active=False)
    db.add_all([active, inactive])
    await db.commit()

    # Captured before yield: the rollback in cleanup expires ORM state, and touching an
    # expired attribute under asyncio raises instead of lazily refreshing.
    connection_ids = [active.id, inactive.id]
    ns = SimpleNamespace(connection=active, suffix=suffix, version_hashes=[], destination_id=None, account_ids=[])
    try:
        yield ns
    finally:
        await db.rollback()
        run_ids = (await db.execute(select(Run.id).where(Run.mdm_connection_id.in_(connection_ids)))).scalars().all()
        await db.execute(delete(PostureSnapshot).where(PostureSnapshot.full_sweep_run_id.in_(run_ids)))
        # Events this suite caused: the seeded posture.test rows and the run.completed
        # events the finishes under test emitted. Deliveries first, then the events.
        seeded_events = select(EventOutbox.id).where(EventOutbox.event_type == "posture.test")
        completed_events = select(EventOutbox.id).where(
            EventOutbox.event_type == "run.completed",
            EventOutbox.payload["jobID"].astext.in_([str(run_id) for run_id in run_ids]),
        )
        for event_ids in (seeded_events, completed_events):
            await db.execute(delete(OutboxDelivery).where(OutboxDelivery.outbox_event_id.in_(event_ids)))
            await db.execute(delete(EventOutbox).where(EventOutbox.id.in_(event_ids)))
        if ns.destination_id is not None:
            await db.execute(delete(OutboxDelivery).where(OutboxDelivery.destination_id == ns.destination_id))
            await db.execute(delete(Destination).where(Destination.id == ns.destination_id))
        await db.execute(delete(ApiToken).where(ApiToken.account_id.in_(ns.account_ids)))
        await db.execute(delete(AccountRole).where(AccountRole.account_id.in_(ns.account_ids)))
        await db.execute(delete(Account).where(Account.id.in_(ns.account_ids)))
        await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_(ns.version_hashes)))  # matches cascade
        await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id.in_(_TITLE_IDS)))
        device_ids = select(Device.id).where(Device.mdm_connection_id.in_(connection_ids))
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id.in_(connection_ids)))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id.in_(connection_ids)))
        # Runs, run_log, and device_changes go with the connections by cascade.
        await db.execute(delete(MdmConnection).where(MdmConnection.id.in_(connection_ids)))
        await db.commit()


async def _seed_fleet(db, ns) -> None:
    """A fleet with a known posture, plus the operator surface around it.

    Three devices on the active connection (one healthy, one with a 200h-old check-in,
    one that has never checked in and is unmanaged) and one on the inactive connection
    that must count nowhere; three catalog entries (behind/latest/unmatched) installed
    across the devices; three Jamf Patch titles — one laggard 20 days behind, one on latest,
    one carrying a build Jamf never listed; four device changes
    straddling the notable cut and the 24h window; four alerts straddling the open/closed
    split, the 24h window and the active-connection cut; a failed run in the window and a
    succeeded sweep outside it; an outbox holding one pending, one delivered, and one
    dead-lettered event; one extra active admin, one disabled account, one live token,
    one revoked token.
    """
    from app.models.schema import (
        Account,
        AccountRole,
        Alert,
        ApiToken,
        AppCatalogEntry,
        AppCatalogTitleMatch,
        Destination,
        Device,
        DeviceChange,
        EventOutbox,
        InstalledApp,
        JamfPatchTitle,
        MdmConnection,
        OutboxDelivery,
        Run,
    )

    now = _now()
    suffix = ns.suffix
    active = ns.connection
    inactive_id = (
        await db.execute(select(MdmConnection.id).where(MdmConnection.name == f"posture inactive {suffix}"))
    ).scalar_one()

    def device(connection_id, external_id, *, check_in, inventory, managed):
        return Device(
            mdm_connection_id=connection_id, mdm_provider="jamf", external_id=external_id,
            serial_number=f"POSTURE{external_id}", hostname=f"posture-{external_id}",
            last_check_in=check_in, last_inventory_at=inventory, managed=managed,
        )

    d1 = device(active.id, f"{suffix}-1", check_in=now - timedelta(hours=1), inventory=now - timedelta(hours=1), managed=True)
    d2 = device(active.id, f"{suffix}-2", check_in=now - timedelta(hours=200), inventory=now - timedelta(hours=1), managed=True)
    d3 = device(active.id, f"{suffix}-3", check_in=None, inventory=None, managed=False)
    d9 = device(inactive_id, f"{suffix}-9", check_in=None, inventory=None, managed=False)
    db.add_all([d1, d2, d3, d9])
    await db.commit()

    def entry(name, app_hash, *, title_ids, is_latest, latest_version):
        return AppCatalogEntry(
            name=name, bundle_id=f"io.loonsec.{name}", version="1.0", app_hash=app_hash, version_hash=_hash(),
            key_title=_key67(), key_full=_key67(), first_seen_at=now, last_seen_at=now,
            jamf_title_ids=title_ids, is_latest=is_latest, latest_version=latest_version,
        )

    e1 = entry(f"behind-{suffix}", _hash(), title_ids=["LOONT1"], is_latest=False, latest_version="2.0")
    e2 = entry(f"latest-{suffix}", _hash(), title_ids=["LOONT2"], is_latest=True, latest_version="3.0")
    e3 = entry(f"unmatched-{suffix}", _hash(), title_ids=None, is_latest=None, latest_version=None)
    # AHEAD: installed newer than anything Jamf lists — Chrome and Safari are in this state on
    # a real fleet more or less permanently, because they auto-update faster than the catalog
    # publishes. `is_latest` is false (the matcher's own answer: ahead is neither compliant nor
    # patch-available) and `latest_version` is present, which is what makes it visible to
    # `catalog.installed_not_latest`. Added 2026-09-04: the fixture covered behind, latest and
    # unknown, and its four pairs happened to sum to `pairs_total`, so two keys that count an
    # ahead device as a laggard had nothing to fail against.
    e4 = entry(f"ahead-{suffix}", _hash(), title_ids=["LOONT4"], is_latest=False, latest_version="0.9")
    db.add_all([e1, e2, e3, e4])
    await db.commit()
    ns.version_hashes = [e1.version_hash, e2.version_hash, e3.version_hash, e4.version_hash]

    def install(dev, cat_entry):
        return InstalledApp(
            device_id=dev.id, name=cat_entry.name, bundle_id=cat_entry.bundle_id, version=cat_entry.version,
            app_hash=cat_entry.app_hash, version_hash=cat_entry.version_hash, key_title=cat_entry.key_title, key_full=cat_entry.key_full,
        )

    db.add_all([install(d1, e1), install(d1, e2), install(d2, e2), install(d1, e4)])

    for title_id in _TITLE_IDS:
        await db.merge(JamfPatchTitle(id=title_id, name=f"Posture Title {title_id}", current_version="9.9", last_modified="", patches=[], requirements=[]))
    # Committed before the matches reference them: the titles are global rows outside
    # tenancy, and the FK check needs them on disk first.
    await db.commit()
    db.add_all([
        AppCatalogTitleMatch(app_catalog_id=e1.id, title_id="LOONT1", basis="requirements", state="behind", version_known=True, on_latest=False, installed_version="1.0", latest_version="2.0", first_newer_released_at=now - timedelta(days=20), releases_missed=3),
        AppCatalogTitleMatch(app_catalog_id=e2.id, title_id="LOONT2", basis="requirements", state="latest", version_known=True, on_latest=True, installed_version="1.0", latest_version="3.0", releases_missed=0),
        # The same 20-day-old date on an unlisted build: counted under its own key, never as a laggard.
        AppCatalogTitleMatch(app_catalog_id=e1.id, title_id="LOONT3", basis="requirements", state="unknown", version_known=False, on_latest=False, installed_version="1.0", latest_version="4.0", first_newer_released_at=now - timedelta(days=20), releases_missed=5),
        # Ahead of the catalog: not on latest, but nothing is missing. No `first_newer_released_at`
        # and no releases missed, because there is no newer version to have missed.
        AppCatalogTitleMatch(app_catalog_id=e4.id, title_id="LOONT4", basis="requirements", state="ahead", version_known=False, on_latest=False, installed_version="1.0", latest_version="0.9", releases_missed=0),
    ])

    # Alerts (#101): the derived latch, seeded across every population edge the two keys
    # have to respect — an open one, one that opened and closed inside the window (which
    # `opened_24h` must still count, and `open` must not), one wholly outside the window,
    # and one on the inactive connection's device, which counts nowhere.
    def alert(dev, entry, *, opened, closed=None):
        return Alert(
            kind="new_app", level="high", device_id=dev.id, app_hash=entry.app_hash,
            app_name=entry.name, bundle_id=entry.bundle_id, opened_at=opened, closed_at=closed,
        )

    db.add_all([
        alert(d1, e1, opened=now - timedelta(hours=2)),
        alert(d2, e2, opened=now - timedelta(hours=3), closed=now - timedelta(hours=1)),
        alert(d3, e3, opened=now - timedelta(hours=30), closed=now - timedelta(hours=29)),
        alert(d9, e1, opened=now - timedelta(hours=2)),
    ])

    def change(level, observed):
        return DeviceChange(
            mdm_connection_id=active.id, subject_kind="computer", subject_id=f"{suffix}-1",
            observed_at=observed, collected_at=observed, trigger="sweep",
            section="security", field="firewallEnabled", change="changed", level=level, policy_version="v0",
        )

    db.add_all([
        change("high", now - timedelta(hours=1)),
        change("normal", now - timedelta(hours=2)),
        change("low", now - timedelta(hours=1)),          # below the notable cut
        change("high", now - timedelta(hours=30)),        # outside the 24h window
    ])

    db.add_all([
        Run(
            id=uuidlib.uuid4(), mdm_connection_id=active.id, trigger="manual", comparison="delta", lock_class="device_sweep",
            status="failed", window_start=now - timedelta(minutes=40), started_at=now - timedelta(minutes=40),
            finished_at=now - timedelta(minutes=30), heartbeat_at=now - timedelta(minutes=30), error="seeded failure",
        ),
        Run(
            id=uuidlib.uuid4(), mdm_connection_id=active.id, trigger="sweep", comparison="delta", lock_class="device_sweep",
            status="succeeded", window_start=now - timedelta(hours=31), started_at=now - timedelta(hours=31),
            finished_at=now - timedelta(hours=30), heartbeat_at=now - timedelta(hours=30),
        ),
    ])

    destination = Destination(name=f"posture sink {suffix}", type="generic_webhook", url="https://posture-sink.invalid", enabled=False)
    db.add(destination)
    await db.commit()
    ns.destination_id = destination.id

    ev_pending = EventOutbox(event_type="posture.test", payload={"seed": suffix}, fanned_out=False, created_at=now - timedelta(hours=1))
    ev_delivered = EventOutbox(event_type="posture.test", payload={"seed": suffix}, fanned_out=True, created_at=now - timedelta(hours=2))
    ev_dead = EventOutbox(event_type="posture.test", payload={"seed": suffix}, fanned_out=True, created_at=now - timedelta(hours=2))
    db.add_all([ev_pending, ev_delivered, ev_dead])
    await db.commit()
    db.add_all([
        OutboxDelivery(outbox_event_id=ev_delivered.id, destination_id=destination.id, status="delivered", attempt_count=1, last_attempted_at=now - timedelta(hours=1), delivered_at=now - timedelta(hours=1)),
        OutboxDelivery(outbox_event_id=ev_dead.id, destination_id=destination.id, status="failed", attempt_count=10, last_attempted_at=now - timedelta(hours=1), last_error="seeded dead letter"),
    ])

    admin = Account(email=f"posture-admin-{suffix}@example.com", display_name="Posture Admin")
    disabled = Account(email=f"posture-disabled-{suffix}@example.com", display_name="Posture Disabled", status="disabled")
    db.add_all([admin, disabled])
    await db.commit()
    ns.account_ids = [admin.id, disabled.id]
    db.add(AccountRole(account_id=admin.id, role="admin", source="manual"))
    db.add_all([
        ApiToken(id=uuidlib.uuid4().hex[:32], account_id=admin.id, name="posture live", token_hash=uuidlib.uuid4().hex + uuidlib.uuid4().hex),
        ApiToken(id=uuidlib.uuid4().hex[:32], account_id=admin.id, name="posture revoked", token_hash=uuidlib.uuid4().hex + uuidlib.uuid4().hex, revoked_at=now),
    ])
    await db.commit()


async def _capture(db, run_id) -> dict[str, float]:
    from app.models.schema import PostureSnapshot

    rows = (await db.execute(select(PostureSnapshot).where(PostureSnapshot.full_sweep_run_id == run_id))).scalars().all()
    return {row.metric_key: float(row.value) for row in rows}


async def test_a_closed_full_sweep_captures_every_active_key(db, fleet) -> None:
    """The whole pipeline: finish() on a device-sweep run fires the recorder, and the
    deltas between a capture taken before the fleet existed and one taken after match
    Definitions v1 exactly — including the populations each key must ignore (inactive
    connections, the low level, the 24h window, disabled accounts, revoked tokens)."""
    from app.core.posture import ACTIVE_KEYS
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, acquire, finish
    from app.models.schema import PostureSnapshot

    baseline_acq = await acquire(db, fleet.connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert baseline_acq.started
    assert await finish(db, baseline_acq.run, ok=True)
    baseline = await _capture(db, baseline_acq.run.id)
    # This run's own run.completed event is pending at capture time, so the oldest-age
    # key is present and the baseline always carries the full vocabulary.
    assert set(baseline) == set(ACTIVE_KEYS)

    await _seed_fleet(db, fleet)

    acq = await acquire(db, fleet.connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert acq.started
    assert await finish(db, acq.run, ok=True, device_count=3, devices_processed=3)
    captured = await _capture(db, acq.run.id)

    assert set(captured) == set(ACTIVE_KEYS)
    rows = (await db.execute(select(PostureSnapshot).where(PostureSnapshot.full_sweep_run_id == acq.run.id))).scalars().all()
    assert len(rows) == len(ACTIVE_KEYS)  # one row per metric per capture
    assert all(row.captured_at is not None and row.captured_at.tzinfo is not None for row in rows)

    def delta(key: str) -> float:
        return captured[key] - baseline[key]

    # Devices: rows on active connections only; NULLs are the worst staleness.
    assert delta("devices.total") == 3  # d9 sits on an inactive connection and counts nowhere
    assert delta("devices.stale_checkin_7d") == 2  # the 200h check-in and the never-checked-in NULL
    assert delta("devices.unmanaged") == 1
    assert delta("devices.stale_inventory_7d") == 1  # only the NULL; the others inventoried an hour ago

    # Catalog: CatalogSummaryOut's semantics at the entry grain.
    assert delta("catalog.entries") == 4
    assert delta("catalog.installed") == 3  # the unmatched entry is on no device
    assert delta("catalog.matched") == 3
    assert delta("catalog.unmatched") == 1
    # NOT-LATEST INCLUDES AHEAD. The behind entry and the ahead one both read `is_latest = false`
    # with a `latest_version` present, so a build NEWER than anything Jamf lists is counted here
    # beside one that is genuinely behind. Pinned as the current definition, flagged 2026-09-04:
    # the key reads as "how many builds need updating" and answers "how many builds are not the
    # catalog's current one", which are different questions on any fleet running Chrome.
    assert delta("catalog.installed_not_latest") == 2  # entries, not device pairs
    assert delta("apps.distinct") == 3

    # Patch pairs: (d1,T1) behind by 20 days, (d1,T2) latest, (d2,T2) latest, (d1,T3) an
    # unlisted build, (d1,T4) ahead of the catalog. Only the behind pair crosses 14 days — the
    # unknown pair carries the same date and lands under its own key, never here (#68).
    assert delta("patch.pairs_total") == 5
    assert delta("patch.pairs_on_latest") == 2
    assert delta("patch.pairs_laggard_over_14d") == 1
    assert delta("patch.pairs_behind_under_14d") == 0
    assert delta("patch.pairs_unknown_build") == 1
    assert delta("patch.pairs_ahead") == 1
    # THE FIVE STATE KEYS PARTITION `pairs_total` (#314). Asserted as an identity rather than
    # as five numbers that happen to add up, because that is exactly how the gap hid: the old
    # fixture had four pairs in three buckets and summed by luck, so nothing failed when an
    # `ahead` pair and a `behind`-inside-the-cut pair belonged to no bucket at all.
    assert (
        delta("patch.pairs_on_latest")
        + delta("patch.pairs_behind_under_14d")
        + delta("patch.pairs_laggard_over_14d")
        + delta("patch.pairs_unknown_build")
        + delta("patch.pairs_ahead")
    ) == delta("patch.pairs_total")
    # AN AHEAD DEVICE IS NOT A LAGGARD (#314, Kyle 2026-09-04). T1 alone: T2 is on latest, T3's
    # build cannot be placed and stays in its own key, and T4 is running something NEWER than
    # Jamf publishes. Before the correction this read 3 — the key was `devices_on_latest <
    # device_count`, which seated both T3 and T4 in a number called "laggards". On the reference
    # tenant it read 11 against 10 laggard pairs and the extra title was Google Chrome; ahead is
    # not rare, so the tenant patching fastest scored worst.
    assert delta("patch.titles_with_laggards") == 1

    # Changes: high + normal inside 24h; the low row and the 30h-old high row do not count.
    assert delta("changes.notable_24h") == 2

    # Alerts: one open latch on an active connection — the one on the inactive
    # connection's device counts nowhere, same population rule as devices.*. Two opened in
    # the window, and the second of them has already closed: `opened_24h` counts it
    # anyway, which is exactly why closed rows are purged on a clock rather than deleted
    # at close (docs/alerts.md §6).
    assert delta("alerts.open") == 1
    assert delta("alerts.opened_24h") == 2

    # Runs: this sweep joins the succeeded count; the seeded failure joins failed_24h;
    # the 30h-old success is outside the window. (The baseline run is in both captures.)
    assert delta("runs.sweeps_succeeded_24h") == 1
    assert delta("runs.failed_24h") == 1
    assert 0 <= captured["runs.full_sweep_duration_s"] < 600

    # Outbox: the seeded pending event plus this run's own run.completed enqueued at
    # close; the dead-lettered delivery entered failed inside the window.
    assert delta("outbox.pending") == 2
    assert delta("outbox.failed_24h") == 1
    assert captured["outbox.oldest_pending_age_s"] >= 3500  # the seeded pending event is an hour old

    # Operator surface: the disabled account and the revoked token contribute nothing.
    assert delta("accounts.total") == 1
    assert delta("accounts.admins") == 1
    assert delta("tokens.active") == 1


async def test_a_failed_night_still_writes_the_stamped_rows(db, fleet) -> None:
    """Founder-ruled: a failed sweep's database state is real, so the capture happens
    anyway — and the failed run id on every row is what makes the staleness visible."""
    from app.core.posture import ACTIVE_KEYS
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, acquire, finish
    from app.models.schema import PostureSnapshot, Run

    acq = await acquire(db, fleet.connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert acq.started
    assert await finish(db, acq.run, ok=False, error="jamf said no")

    run = (await db.execute(select(Run).where(Run.id == acq.run.id))).scalar_one()
    assert run.status == "failed"

    captured = await _capture(db, acq.run.id)
    assert set(captured) == set(ACTIVE_KEYS)
    assert captured["runs.full_sweep_duration_s"] >= 0
    rows = (await db.execute(select(PostureSnapshot).where(PostureSnapshot.full_sweep_run_id == acq.run.id))).scalars().all()
    assert all(row.full_sweep_run_id == acq.run.id for row in rows)


async def test_an_empty_queue_writes_no_oldest_pending_row(db, fleet) -> None:
    """Absent means "no pending existed", never zero. This one empties the tenant's
    outbox to prove it (destructive to a lived-in local queue, by design), then records
    directly against a run row with a known 120s duration — which also pins
    runs.full_sweep_duration_s to the definition's exact arithmetic."""
    from app.core.posture import ACTIVE_KEYS, record_full_sweep_snapshot
    from app.models.schema import EventOutbox, OutboxDelivery, Run

    await db.execute(delete(OutboxDelivery))
    await db.execute(delete(EventOutbox))
    await db.commit()

    now = _now()
    run = Run(
        id=uuidlib.uuid4(), mdm_connection_id=fleet.connection.id, trigger="sweep", comparison="delta",
        lock_class="device_sweep", status="succeeded", window_start=now - timedelta(seconds=120),
        started_at=now - timedelta(seconds=120), finished_at=now, heartbeat_at=now,
    )
    db.add(run)
    await db.commit()

    written = await record_full_sweep_snapshot(db, run_id=run.id)
    captured = await _capture(db, run.id)

    assert "outbox.oldest_pending_age_s" not in captured
    assert captured["outbox.pending"] == 0  # zero is written as 0; only "did not apply" is absent
    assert written == len(ACTIVE_KEYS) - 1 == len(captured)
    assert captured["runs.full_sweep_duration_s"] == 120.0


async def test_every_captured_row_names_the_population_it_counted(db, fleet) -> None:
    """#230: the population is on the row, not inferred from the era it was written in.
    v0 reads computers only, so a capture stamps `macos` on every key it writes."""
    from app.core.posture import CAPTURE_PLATFORM, record_full_sweep_snapshot
    from app.models.schema import PostureSnapshot, Run

    now = _now()
    run = Run(
        id=uuidlib.uuid4(), mdm_connection_id=fleet.connection.id, trigger="sweep", comparison="delta",
        lock_class="device_sweep", status="succeeded", window_start=now - timedelta(seconds=60),
        started_at=now - timedelta(seconds=60), finished_at=now, heartbeat_at=now,
    )
    db.add(run)
    await db.commit()

    written = await record_full_sweep_snapshot(db, run_id=run.id)
    rows = (await db.execute(select(PostureSnapshot).where(PostureSnapshot.full_sweep_run_id == run.id))).scalars().all()

    assert written == len(rows) > 0
    assert CAPTURE_PLATFORM == "macos"
    assert {row.platform for row in rows} == {"macos"}


async def test_one_row_per_key_per_capture_per_population(db, fleet) -> None:
    """uq_posture_snapshot_capture (#230): the invariant every reader of the tape already
    assumes, finally declared. A `macos` row and an `all` roll-up row for one key at one
    instant are two legitimate rows — the constraint does not and must not stop them.
    What it stops is the second row for the *same* population, which is what would make
    a correctly-filtered read double. It lands now because today the table satisfies it
    trivially; once v5 writes several populations per capture, adding it needs a cleanup
    pass first."""
    from sqlalchemy.exc import IntegrityError

    from app.core.posture import CAPTURE_PLATFORM, PLATFORM_ROLLUP, record_full_sweep_snapshot
    from app.models.schema import PostureSnapshot, Run

    now = _now()
    run = Run(
        id=uuidlib.uuid4(), mdm_connection_id=fleet.connection.id, trigger="sweep", comparison="delta",
        lock_class="device_sweep", status="succeeded", window_start=now - timedelta(seconds=60),
        started_at=now - timedelta(seconds=60), finished_at=now, heartbeat_at=now,
    )
    db.add(run)
    await db.commit()

    await record_full_sweep_snapshot(db, run_id=run.id)
    row = (
        await db.execute(select(PostureSnapshot).where(PostureSnapshot.full_sweep_run_id == run.id))
    ).scalars().first()
    assert row is not None
    key, value, captured_at = row.metric_key, row.value, row.captured_at

    # A different population at the same instant is a different row, and permitted.
    db.add(PostureSnapshot(
        metric_key=key, platform=PLATFORM_ROLLUP, value=value,
        captured_at=captured_at, full_sweep_run_id=run.id,
    ))
    await db.commit()

    # The same (tenant, key, platform, capture) is not.
    db.add(PostureSnapshot(
        metric_key=key, platform=CAPTURE_PLATFORM, value=value,
        captured_at=captured_at, full_sweep_run_id=run.id,
    ))
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()
