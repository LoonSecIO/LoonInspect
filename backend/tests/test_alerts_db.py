"""The NEW-app latch against a real Postgres and the fake Jamf tenant (#101).

Drives real sweeps and webhook ingests, so what is under test is the whole path
`process_sync` takes: the delta, the ON CONFLICT open, the close-in-place, the aperture
guard, the cascade, and retention. `tests/test_alerts.py` covers the decision itself with
no session; this file exists for everything the decision cannot see — the index that
stops a racing duplicate, and the fact that a closed row stays a row.

The endpoint is here too, over HTTP and signed in as a **Viewer**, because that is the
persona the latch is for: the read-only account whose whole job is noticing that a
managed Mac grew software nobody deployed. Its population rule (devices on *active*
connections) is the same rule the posture keys count over, and a divergence between them
would be two numbers for one question on the same screen. Gated on RUN_DB_TESTS.
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
from sqlalchemy import delete, select, update

from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

VIEWER = ("viewer@alerts.example.com", "alerts-viewer-password")
# Only here to mint the narrowed tokens the guard test needs. No role grants one of
# `device:read` / `app:read` without the other — `_INVENTORY_READ` hands over both as a
# block — so the only principal that can hold exactly one is a scoped API token, and
# minting one takes `token:create`, which Viewer does not have.
ADMIN = ("admin@alerts.example.com", "alerts-admin-password")

# The install under test: a network scanner nobody deployed, appearing on a managed Mac.
# Deliberately *not* Wireshark, which is the usual fixture for this story — the reference
# record already ships Wireshark, so appending it is a no-op the contract's own entry
# identity dedupes away, and every assertion below would then pass for the wrong reason.
NMAP = {
    "name": "Nmap.app",
    "path": "/Applications/Nmap.app",
    "version": "7.95",
    "macAppStore": False,
    "sizeMegabytes": 26,
    "bundleId": "org.insecure.nmap",
    "updateAvailable": False,
    "externalVersionId": "0",
    "cfBundleShortVersionString": "7.95",
    "cfBundleVersion": "7.95",
}


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenant_ready() -> None:
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        if (await db.execute(select(Account).where(Account.email == VIEWER[0]))).scalars().first() is None:
            await create_account(db, email=VIEWER[0], display_name="alerts viewer", password=VIEWER[1], roles=("viewer",))
            await db.commit()
        if (await db.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first() is None:
            await create_account(db, email=ADMIN[0], display_name="alerts admin", password=ADMIN[1], roles=("admin",))
            await db.commit()


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
    from app.models.schema import (
        Alert,
        AppCatalogEntry,
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
    )

    row = MdmConnection(
        name=f"alerts jamf {uuidlib.uuid4().hex[:8]}",
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
        # The tenant app catalog goes back out too, not just the device rows. Every sweep
        # in this file writes an `app_catalog` entry per distinct build the reference
        # record carries, the suite shares one database, and files that run after this one
        # assert on a catalog that has not seen those builds. Leaving them behind makes a
        # later file fail for a reason that has nothing to do with it.
        catalog_hashes = set(
            (await db.execute(select(InstalledApp.version_hash).where(InstalledApp.device_id.in_(device_ids))))
            .scalars()
            .all()
        )
        # Explicit rather than left to the cascade, so a failure in this suite cannot
        # leave rows behind for the next run's counts to fold in.
        await db.execute(delete(Alert).where(Alert.device_id.in_(device_ids)))
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        if catalog_hashes:
            await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_(catalog_hashes)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def viewer(tenant_ready):
    """Signed in as the least-privileged role. https, because the session cookie is
    Secure and a plain-http client silently discards it."""
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://alerts.example.com") as client:
        response = await client.post("/api/auth/login", json={"email": VIEWER[0], "password": VIEWER[1]})
        assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
        client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
        yield client


@pytest_asyncio.fixture(loop_scope="session")
async def admin(tenant_ready):
    """Signed in as admin, and used for one thing only: minting the scoped tokens below
    through the product's own endpoint, so the principals under test are configurations an
    operator can actually reach rather than rows constructed to make a point."""
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://alerts.example.com") as client:
        response = await client.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
        client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
        yield client


@pytest_asyncio.fixture(loop_scope="session")
async def scoped(admin):
    """A factory for `httpx` clients bearing an API token narrowed to exactly the given
    scopes. Token scopes are an intersection with the owner's set (`scoped_permissions`),
    so an admin-owned token scoped to one permission holds precisely that one."""
    from app.main import app

    opened: list[httpx.AsyncClient] = []

    async def _client(*scopes: str) -> httpx.AsyncClient:
        response = await admin.post(
            "/api/auth/tokens",
            json={"name": f"alerts-guard {'+'.join(scopes) or 'none'}", "scopes": list(scopes)},
        )
        assert response.status_code == 201, response.text
        # No CSRF header: bearer auth is exempt.
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://alerts.example.com",
            headers={"Authorization": f"Bearer {response.json()['token']}"},
        )
        opened.append(client)
        return client

    try:
        yield _client
    finally:
        for client in opened:
            await client.aclose()


def _at(jamf: FakeJamf, minute: int) -> None:
    """Move the Mac mini's report date forward. The ledger's monotonic guard drops an
    observation that is not newer than the one it already holds, so every pass in this
    file has to advance the clock or it never reaches `process_sync` at all."""
    jamf.real["general"]["reportDate"] = f"2026-08-23T09:{minute:02d}:00.000Z"


def _install(jamf: FakeJamf) -> None:
    jamf.real["applications"].append(dict(NMAP))


def _uninstall(jamf: FakeJamf) -> None:
    jamf.real["applications"] = [a for a in jamf.real["applications"] if a["bundleId"] != NMAP["bundleId"]]


def _as_a_new_session_would(db) -> None:
    """Forget the device rows this session has already loaded.

    Every sweep and every webhook gets its own session in production; this suite shares
    one so the assertions can read rows back on the same connection. That difference is
    not cosmetic here: SQLAlchemy does not prune a loaded collection on delete (see
    `process_sync`'s own note about it), and `expire_on_commit` is False, so a `Device`
    carried across passes still remembers an app the *previous* pass uninstalled. The
    latch would then compare this read against a previous inventory that never existed —
    a bug in the test, invisible in the assertion, and one that quietly made a reinstall
    look like a no-op. Dropping the instances makes the next pass load them fresh.
    """
    from app.models.schema import Device

    session = db.sync_session
    # Devices only: expunge cascades along the relationship, so the app rows go with
    # their device and expunging them by hand afterwards raises "not present".
    for instance in [row for row in session.identity_map.values() if isinstance(row, Device)]:
        if instance in session:
            session.expunge(instance)


async def _webhook(db, connection, jamf: FakeJamf):
    from app.mdm.service import ingest_webhook

    _as_a_new_session_would(db)
    return await ingest_webhook(
        db,
        connection,
        {"webhook": {"webhookEvent": "ComputerInventoryCompleted"}, "event": {"jssID": jamf.real["id"]}},
    )


async def _alerts(db, connection_id: int):
    from app.models.schema import Alert, Device

    return (
        await db.execute(
            select(Alert)
            .join(Device, Device.id == Alert.device_id)
            .where(Device.mdm_connection_id == connection_id)
            .order_by(Alert.id)
        )
    ).scalars().all()


async def test_the_latch_opens_stays_open_and_closes_itself(db, connection, jamf: FakeJamf) -> None:
    """The whole life of one latch across four passes — the ruling, executed.

    Pass 1 is the baseline and opens nothing, which is the property that keeps a 40k
    fleet's first sweep from writing millions of rows there is no dismiss to dig out of.
    Pass 2 installs Nmap and opens exactly one. Pass 3 changes nothing and must
    still show exactly one — the partial unique index plus ON CONFLICT DO NOTHING, not an
    accident of ordering. Pass 4 removes it, and the row closes *in place*:
    `alerts.opened_24h` counts rows that have since closed, so a delete here would
    silently redefine that key.
    """
    from app.mdm.service import sync_connection

    first = await sync_connection(db, connection)
    assert first.ok
    assert await _alerts(db, connection.id) == [], "a device's first inventory is a baseline, not 83 installs"

    _at(jamf, 1)
    _install(jamf)
    assert (await _webhook(db, connection, jamf)).outcome == "changed"

    opened = await _alerts(db, connection.id)
    assert len(opened) == 1
    (row,) = opened
    assert row.kind == "new_app" and row.level == "high"
    assert row.app_name == "Nmap.app" and row.bundle_id == "org.insecure.nmap"
    assert row.closed_at is None and row.closed_run_id is None
    # The pull's own run, stamped so a latch can be walked back to the sweep that noticed
    # it even after the run row is purged at 30 days.
    assert row.opened_run_id is not None
    opened_at, opened_run_id, alert_id = row.opened_at, row.opened_run_id, row.id

    # Pass 3: still installed. The latch is a fact about the fleet, not an event, so it
    # neither duplicates nor re-stamps.
    _at(jamf, 2)
    await _webhook(db, connection, jamf)
    still = await _alerts(db, connection.id)
    assert len(still) == 1 and still[0].id == alert_id
    assert still[0].opened_at == opened_at and still[0].opened_run_id == opened_run_id
    assert still[0].closed_at is None

    # Pass 4: uninstalled. Closed by the same code path that opened it — which is why
    # there is no dismiss anywhere in the product and none is needed.
    _at(jamf, 3)
    _uninstall(jamf)
    await _webhook(db, connection, jamf)
    closed = await _alerts(db, connection.id)
    assert len(closed) == 1 and closed[0].id == alert_id, "a closed latch stays a row"
    assert closed[0].closed_at is not None
    assert closed[0].closed_run_id is not None and closed[0].closed_run_id != opened_run_id


async def test_a_reinstall_after_a_close_opens_a_second_row(db, connection, jamf: FakeJamf) -> None:
    """Accepted churn, no cooldown (2026-08-29). The partial unique index is on
    `closed_at IS NULL` precisely so the second open is legal rather than a violation."""
    from app.mdm.service import sync_connection

    await sync_connection(db, connection)
    for minute, act in ((6, _install), (7, _uninstall), (8, _install)):
        _at(jamf, minute)
        act(jamf)
        await _webhook(db, connection, jamf)

    rows = await _alerts(db, connection.id)
    assert len(rows) == 2
    assert rows[0].closed_at is not None and rows[1].closed_at is None


async def test_a_version_bump_opens_nothing(db, connection, jamf: FakeJamf) -> None:
    """The silent-new-version ruling end to end. Slack updating rewrites the device's
    whole `version_hash` set — the inventory delta reports a removal and an addition —
    and the latch, keyed on `app_hash`, sees nothing move."""
    from app.mdm.service import sync_connection
    from app.models.schema import InstalledApp

    await sync_connection(db, connection)
    assert await _alerts(db, connection.id) == []

    _at(jamf, 5)
    slack = next(a for a in jamf.real["applications"] if a["bundleId"] == "com.tinyspeck.slackmacgap")
    slack["version"] = slack["cfBundleShortVersionString"] = "4.51.0"
    slack["cfBundleVersion"] = "451000000"
    await _webhook(db, connection, jamf)

    installed = (
        await db.execute(select(InstalledApp.version).where(InstalledApp.bundle_id == "com.tinyspeck.slackmacgap"))
    ).scalars().all()
    assert "4.51.0" in installed, "the update really landed"
    assert await _alerts(db, connection.id) == [], "a version bump is not a new app"


async def test_a_read_outside_the_aperture_opens_and_closes_nothing(db, connection, jamf: FakeJamf) -> None:
    """`device.apps is None` observed neither presence nor absence, so it may do neither.

    The sharp half is the close: the record here no longer carries Nmap at all, and
    a latch that closed on that would be closing on an absence nobody looked for.
    """
    from app.mdm.service import ingest_computer, sync_connection

    await sync_connection(db, connection)
    _at(jamf, 10)
    _install(jamf)
    await _webhook(db, connection, jamf)
    (opened,) = await _alerts(db, connection.id)
    assert opened.closed_at is None

    _at(jamf, 11)
    _uninstall(jamf)
    await ingest_computer(
        db,
        connection,
        jamf.real,
        aperture_digest="v1:" + "0" * 64,
        trigger="webhook",
        sections=["general", "hardware", "operating_system"],
    )

    rows = await _alerts(db, connection.id)
    assert len(rows) == 1 and rows[0].closed_at is None, "a section that was not read cannot close a latch"


async def test_an_open_latch_cannot_be_opened_twice(db, connection, jamf: FakeJamf) -> None:
    """The concurrency guard, exercised directly rather than by racing two sessions.

    Webhook runs never take the sweep lock, so two ingests of one device really can both
    decide an app is new. `uq_alerts_open` is the only thing that stops two identical
    open rows, and the writer has to go through ON CONFLICT — an ORM `db.add()` would
    bypass the inference and raise on flush instead.
    """
    from app.alerts.service import sync_new_app_latches
    from app.mdm.service import sync_connection
    from app.models.schema import Device, InstalledApp

    await sync_connection(db, connection)
    device = (
        await db.execute(
            select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == jamf.real["id"])
        )
    ).scalar_one()
    rows = (await db.execute(select(InstalledApp).where(InstalledApp.device_id == device.id))).scalars().all()
    subject = rows[0]
    previous = {row.app_hash for row in rows if row.app_hash != subject.app_hash}

    for _ in range(3):
        delta = await sync_new_app_latches(
            db,
            device_id=device.id,
            previous_app_hashes=previous,
            current_rows=rows,
            device_is_new=False,
            run_id=None,
        )
        assert delta.to_open == frozenset({subject.app_hash}), "each pass really does decide it is new"
    await db.commit()

    assert len(await _alerts(db, connection.id)) == 1


async def test_deleting_a_device_takes_its_latches_with_it(db, connection, jamf: FakeJamf) -> None:
    """CASCADE, not SET NULL: a device that is gone has no fleet state left to assert,
    and an alert about a Mac nobody can name is not evidence of anything."""
    from app.mdm.service import sync_connection
    from app.models.schema import Alert, Device, DeviceExtensionAttribute, InstalledApp

    await sync_connection(db, connection)
    _at(jamf, 20)
    _install(jamf)
    await _webhook(db, connection, jamf)
    assert len(await _alerts(db, connection.id)) == 1

    device_id = (
        await db.execute(
            select(Device.id).where(Device.mdm_connection_id == connection.id, Device.external_id == jamf.real["id"])
        )
    ).scalar_one()
    await db.execute(delete(InstalledApp).where(InstalledApp.device_id == device_id))
    await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id == device_id))
    await db.execute(delete(Device).where(Device.id == device_id))
    await db.commit()

    assert (await db.execute(select(Alert).where(Alert.device_id == device_id))).scalars().all() == []


async def test_closed_latches_age_out_and_open_ones_never_do(db, connection, jamf: FakeJamf) -> None:
    """Retention. Closed rows cannot be deleted at close — that would redefine
    `alerts.opened_24h` — so they age out here, and an open latch is never eligible
    however long it has been true."""
    from app.alerts.service import purge_closed_alerts
    from app.mdm.service import sync_connection
    from app.models.schema import Alert

    await sync_connection(db, connection)
    _at(jamf, 30)
    _install(jamf)
    await _webhook(db, connection, jamf)
    (row,) = await _alerts(db, connection.id)

    ancient = datetime.now(timezone.utc) - timedelta(days=400)
    await db.execute(update(Alert).where(Alert.id == row.id).values(opened_at=ancient))
    await db.commit()
    assert await purge_closed_alerts(db, 30) == 0, "an open latch is never purged, however old"
    assert len(await _alerts(db, connection.id)) == 1

    await db.execute(update(Alert).where(Alert.id == row.id).values(closed_at=ancient))
    await db.commit()
    assert await purge_closed_alerts(db, 30) == 1
    assert await _alerts(db, connection.id) == []


async def test_a_viewer_can_read_the_open_latches(db, connection, jamf: FakeJamf, viewer) -> None:
    """The read surface, over HTTP and as the least-privileged role.

    Viewer holds `device:read` and nothing else, and it is exactly the persona this latch
    serves — so the endpoint sitting behind `device:read` rather than a permission of its
    own is a decision worth a test rather than a comment. The active-connection scoping is
    the same population rule the posture keys count over.
    """
    from app.mdm.service import sync_connection

    await sync_connection(db, connection)
    _at(jamf, 40)
    _install(jamf)
    await _webhook(db, connection, jamf)

    async def nmaps(query: str = "") -> list[dict]:
        response = await viewer.get(f"/api/alerts?pageSize=200&{query}")
        assert response.status_code == 200, response.text
        return [item for item in response.json()["items"] if item["appName"] == "Nmap.app"]

    (item,) = await nmaps()
    assert item["kind"] == "new_app" and item["level"] == "high" and item["closedAt"] is None
    assert item["bundleId"] == "org.insecure.nmap" and item["deviceLabel"]
    assert item["openedAt"]

    # Closed rows are a different list, not a filtered absence.
    assert await nmaps("open=false") == []
    # An unknown kind is named rather than answered with an empty list, which would read
    # as "nothing is wrong" (#150).
    assert (await viewer.get("/api/alerts?kind=not_a_kind")).status_code == 422

    # A connection an operator switched off is not a fleet they are being asked to look at.
    connection.is_active = False
    await db.commit()
    assert await nmaps() == []
    connection.is_active = True
    await db.commit()


async def test_the_guard_names_both_identities_the_row_discloses(scoped) -> None:
    """`GET /api/alerts` requires **both** `device:read` and `app:read` (Kyle,
    2026-09-04), because an `AlertOut` hands over two identities at once: a named Mac
    (`deviceId`, `deviceLabel`) and an application (`appHash`, `appName`, `bundleId`).

    Driven with API tokens rather than roles, because no role can express the failing
    case: `_INVENTORY_READ` grants the pair as a block, so a principal holding one and
    not the other only exists as a scoped token. That is exactly the split the ruling is
    made *for* — "the application team sees the catalog but not the fleet" — and this is
    the day it would otherwise have leaked `deviceLabel` to an app-scoped caller.

    The 200 case is asserted beside the two 403s so a guard that simply refused everyone
    could not pass this test. It asserts the status only: the rows themselves belong to
    the viewer test above, which proves the same endpoint answers the least-privileged
    *role*, unchanged by this ruling.
    """
    fleet_only = await scoped("device:read")
    apps_only = await scoped("app:read")
    both = await scoped("device:read", "app:read")

    assert (await fleet_only.get("/api/alerts")).status_code == 403
    assert (await apps_only.get("/api/alerts")).status_code == 403
    assert (await both.get("/api/alerts")).status_code == 200
