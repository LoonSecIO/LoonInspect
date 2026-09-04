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
