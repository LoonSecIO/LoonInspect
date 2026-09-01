"""Deleting a connection: what goes with it, what refuses, and what the body says (#185).

`DELETE /api/mdm/connections/{id}` had no test at all, and two defects behind that:

1. It 500'd on any connection that had ever *started* a sync. `mdm_sync_state`'s
   foreign key carried no ON DELETE and no ORM relationship, so the parent delete hit a
   raw ForeignKeyViolation — and `set_sync_status` writes that row before the first page
   is fetched, so "has ever started a sync" is nearly every real connection. This is the
   first destructive action a cold operator takes after misconfiguring something.
2. Underneath it, the ORM's default nullify on `MdmConnection.devices` would have
   orphaned the fleet rather than removing it: device rows alive forever, attached to no
   connection, still listed by `/api/devices` but outside every `devices.*` posture key.

The ruling implemented and pinned here: **the connection owns its fleet, and the delete
takes it.** These tests exist to make that ruling expensive to reverse by accident.

The client deliberately runs with `raise_app_exceptions=False`. Every other suite lets an
unhandled exception escape the app, which is the better default — but part of this finding
is about what a *failing* delete puts in the response body, and that body only exists when
the transport builds the 500 the way uvicorn does. A regression that reintroduces the
crash therefore shows up here as a status code and a body to assert on, not as a traceback.

Gated on RUN_DB_TESTS like the other database-backed suites: row-level security is one of
the properties under test and SQLite has no opinion about it.
"""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"
    ),
    # One loop for the module, for the same reason test_tenancy_sweep gives: the engine's
    # pooled connections belong to whichever loop first used them.
    pytest.mark.asyncio(loop_scope="session"),
]

TENANT2_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000d1")
ADMIN = ("admin@delete.example.com", "delete-connection-password")

# Anything in a response body that would mean the database spoke to the client directly.
# Table and constraint names are schema, and schema handed to an unauthenticated-adjacent
# caller is a map for the next request.
_DATABASE_INTERNALS = (
    "mdm_sync_state",
    "mdm_connections",
    "installed_apps",
    "device_extension_attributes",
    "ForeignKeyViolation",
    "IntegrityError",
    "psycopg",
    "asyncpg",
    "sqlalchemy",
    "violates foreign key",
    "constraint",
    "DETAIL:",
    "SELECT",
    "DELETE FROM",
    "UPDATE ",
)


def _assert_no_database_internals(response: httpx.Response) -> None:
    body = response.text
    for needle in _DATABASE_INTERNALS:
        assert needle not in body, f"{needle!r} leaked into a {response.status_code} body: {body!r}"


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def seeded():
    """Migrated schema, the operational tenant plus a second one, and an admin who can
    actually sign in.

    Get-or-create, so a developer re-running this locally debugs the route rather than a
    unique constraint left behind by the previous run.
    """
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, TENANT2_ID) is None:
            db.add(
                Tenant(id=TENANT2_ID, slug="delete-second", name="Delete Second", kind="operational")
            )
            await db.commit()

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        account = (
            await db.execute(select(Account).where(Account.email == ADMIN[0]))
        ).scalars().first()
        if account is None:
            await create_account(
                db, email=ADMIN[0], display_name="delete admin", password=ADMIN[1], roles=("admin",)
            )
            await db.commit()
    return {"tenant_id": OPERATIONAL_TENANT_ID}


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def client(seeded):
    from app.main import app

    # https, not http: the session cookie is Secure, and a plain-http client discards it
    # silently — login returns 200 and everything after it 401s.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="https://delete.example.com") as c:
        response = await c.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
        c.headers["X-CSRF-Token"] = c.cookies.get("loon_csrf", "")
        yield c


@pytest_asyncio.fixture(loop_scope="session")
async def db(seeded):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    """One connection per test, torn down by hand in the order the route uses.

    Deliberately not `DELETE FROM mdm_connections` alone: that is the very statement the
    finding is about, and a teardown that cannot run is a teardown that hides the bug.
    """
    from app.models.schema import (
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
    )

    row = MdmConnection(
        name=f"delete-target-{uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url="https://delete.jamfcloud.com",
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
        await db.execute(
            delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids))
        )
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


async def _sync_once(db, connection) -> None:
    """Everything a connection that has synced carries: the sync-state row that made the
    delete 500, one device with an app and an extension attribute, its default
    collections, a finished run, and an observation span."""
    from app.mdm.collections import ensure_default_collections
    from app.models.schema import (
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmSyncState,
        ObservationSpan,
        Run,
    )

    now = datetime.now(timezone.utc)
    db.add(MdmSyncState(mdm_connection_id=connection.id, provider="jamf", status="idle"))
    await ensure_default_collections(db, connection)

    device = Device(
        mdm_connection_id=connection.id,
        mdm_provider="jamf",
        external_id=f"ext-{uuidlib.uuid4().hex[:8]}",
        serial_number="C02DELETE01",
        hostname="delete-me.example",
    )
    db.add(device)
    await db.flush()
    db.add(
        InstalledApp(
            device_id=device.id,
            name="Wireshark",
            bundle_id="org.wireshark.Wireshark",
            version="3.6.0",
            app_hash="a" * 32,
            version_hash="b" * 32,
            key_title="v1:" + "c" * 64,
            key_full="v1:" + "d" * 64,
        )
    )
    db.add(DeviceExtensionAttribute(device_id=device.id, key="Asset Tag", value="LOON-1"))
    db.add(
        Run(
            id=uuidlib.uuid4(),
            mdm_connection_id=connection.id,
            trigger="manual",
            comparison="baseline",
            lock_class="device_sweep",
            status="succeeded",
            window_start=now,
            window_end=now,
            started_at=now,
            finished_at=now,
            heartbeat_at=now,
        )
    )
    db.add(
        ObservationSpan(
            mdm_connection_id=connection.id,
            subject_kind="device",
            subject_id=device.external_id,
            contract_version="v1",
            aperture_digest="v1:" + "e" * 64,
            head_digest="v1:" + "f" * 64,
            section_digests={"identity": "v1:" + "0" * 64},
            first_observed_at=now,
            last_observed_at=now,
            first_collected_at=now,
            last_collected_at=now,
            last_trigger="manual",
        )
    )
    await db.commit()


async def _count(db, model, where) -> int:
    return (await db.execute(select(func.count()).select_from(model).where(where))).scalar_one()


# --- The two deletes ------------------------------------------------------------------


async def test_delete_of_a_never_synced_connection_still_succeeds(client, db, connection) -> None:
    """The path that already worked, pinned before the one that did not is changed."""
    from app.models.schema import MdmConnection

    # Read the id before expiring: an expired instance reloads on attribute access, and
    # under asyncio that lazy load raises MissingGreenlet rather than refreshing — the
    # same trap test_sad_paths.py was written about.
    connection_id = connection.id
    response = await client.delete(f"/api/mdm/connections/{connection_id}")
    assert response.status_code == 204, response.text

    db.expire_all()
    assert await db.get(MdmConnection, connection_id) is None


async def test_delete_of_a_synced_connection_takes_its_fleet(client, db, connection) -> None:
    """The 500. A connection with a sync-state row deleted cleanly, and nothing it owned
    is left behind pointing at an id that no longer exists.

    The enumeration is the assertion: sync state, devices, the apps and extension
    attributes hanging off them, collections, runs, spans. `event_outbox` is checked in
    the opposite direction — already-emitted events survive, because the wire is a record
    of what was reported and a delete must not rewrite what a SIEM already indexed.
    """
    from app.models.schema import (
        Collection,
        Device,
        DeviceExtensionAttribute,
        EventOutbox,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
        ObservationSpan,
        Run,
    )

    await _sync_once(db, connection)
    connection_id = connection.id
    device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
    assert await _count(db, Device, Device.mdm_connection_id == connection_id) == 1
    assert await _count(db, InstalledApp, InstalledApp.device_id.in_(device_ids)) == 1
    outbox_before = await _count(db, EventOutbox, EventOutbox.id > 0)

    response = await client.delete(f"/api/mdm/connections/{connection_id}")
    assert response.status_code == 204, response.text

    db.expire_all()
    assert await db.get(MdmConnection, connection_id) is None
    assert await _count(db, MdmSyncState, MdmSyncState.mdm_connection_id == connection_id) == 0
    assert await _count(db, Device, Device.mdm_connection_id == connection_id) == 0
    assert await _count(db, Collection, Collection.mdm_connection_id == connection_id) == 0
    assert await _count(db, Run, Run.mdm_connection_id == connection_id) == 0
    assert await _count(db, ObservationSpan, ObservationSpan.mdm_connection_id == connection_id) == 0

    # The children of the devices, found by device id rather than by connection: the
    # nullify this replaces would have left every one of these reachable and correct
    # while the fleet itself belonged to nothing.
    assert await _count(db, InstalledApp, InstalledApp.device_id.in_(device_ids)) == 0
    assert (
        await _count(db, DeviceExtensionAttribute, DeviceExtensionAttribute.device_id.in_(device_ids))
        == 0
    )

    assert await _count(db, EventOutbox, EventOutbox.id > 0) == outbox_before


async def test_no_device_survives_the_delete_without_a_connection(client, db, connection) -> None:
    """The orphan #185 actually describes, stated as its own property.

    Distinct from the count above: that one asks whether *this* connection's devices are
    gone, and a nullify would satisfy it — `mdm_connection_id = X` matches nothing once
    the column is NULL. This asks the question the nullify fails: is there any device row
    at all with no connection?
    """
    from app.models.schema import Device

    await _sync_once(db, connection)
    assert (await client.delete(f"/api/mdm/connections/{connection.id}")).status_code == 204

    db.expire_all()
    assert await _count(db, Device, Device.mdm_connection_id.is_(None)) == 0


# --- Information disclosure ------------------------------------------------------------


async def test_delete_never_puts_database_internals_in_the_response_body(
    client, db, connection
) -> None:
    """SECURITY. A raw database error reaching the client is a free schema disclosure —
    table names, constraint names, and the shape of the SQL that failed.

    The review that found this expected the crash to be leaking exactly that. Measured, it
    was not: the app registers no exception handler and is not in debug, so Starlette
    answered `text/plain: Internal Server Error` and the constraint name went only to the
    server log. The disclosure was in the log, not the body — which is a smaller finding
    than it looked, and worth saying plainly.

    The property is still worth pinning, because the distance between here and a leak is
    one handler: this very router already echoes `str(exc)` into a detail once, in
    `_validate_credentials`. A generic `except IntegrityError as exc: detail=str(exc)`
    added to this route — the obvious lazy fix for the 500 — would fail this test.

    Asserted on every answer the route can give: the 404 for an id that is not there, the
    409 refusal, and the 204.
    """
    from app.core.runs import TRIGGER_MANUAL, acquire

    await _sync_once(db, connection)

    missing = await client.delete("/api/mdm/connections/999999999")
    assert missing.status_code == 404
    _assert_no_database_internals(missing)

    await acquire(db, connection, trigger=TRIGGER_MANUAL)
    await db.commit()
    refused = await client.delete(f"/api/mdm/connections/{connection.id}")
    assert refused.status_code == 409
    _assert_no_database_internals(refused)

    from app.models.schema import Run

    await db.execute(delete(Run).where(Run.mdm_connection_id == connection.id))
    await db.commit()

    ok = await client.delete(f"/api/mdm/connections/{connection.id}")
    assert ok.status_code == 204
    _assert_no_database_internals(ok)


# --- The run in flight -----------------------------------------------------------------


async def test_delete_is_refused_while_a_sweep_is_running(client, db, connection) -> None:
    """A live sweep is writing devices and spans under this connection; deleting the run
    row out from under it is the expired-instance sad path (#125) in a new place.

    The message is asserted, not just the status: a 409 whose body says "conflict" tells a
    cold operator nothing. It has to name the job and the next step.
    """
    from app.core.runs import TRIGGER_MANUAL, acquire
    from app.models.schema import MdmConnection

    await _sync_once(db, connection)
    connection_id = connection.id
    acquisition = await acquire(db, connection, trigger=TRIGGER_MANUAL)
    run_id = acquisition.run.id
    await db.commit()

    response = await client.delete(f"/api/mdm/connections/{connection_id}")
    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert str(run_id) in detail, detail
    assert "Wait for it to finish" in detail, detail
    assert "/api/runs/" in detail, detail

    db.expire_all()
    assert await db.get(MdmConnection, connection_id) is not None, "a refused delete must not delete"


async def test_a_dead_run_does_not_make_a_connection_undeletable(client, db, connection) -> None:
    """The guard is gated on the heartbeat, not on `status == 'running'`.

    A collector process that dies leaves its run `running` until the next *acquisition*
    reclaims it — and the only way to reach an acquisition is to start another sync. A
    status-only guard would therefore answer "start a sync before you can delete this",
    which is not an instruction anyone should have to follow, on a connection whose
    credentials are the thing they are trying to get rid of.
    """
    from app.core.config import settings
    from app.core.runs import TRIGGER_MANUAL, acquire
    from app.models.schema import MdmConnection, Run

    await _sync_once(db, connection)
    connection_id = connection.id
    acquisition = await acquire(db, connection, trigger=TRIGGER_MANUAL)
    run_id = acquisition.run.id
    await db.commit()

    dead = datetime.now(timezone.utc) - timedelta(seconds=settings.run_stale_after_seconds + 60)
    run = await db.get(Run, run_id)
    run.heartbeat_at = dead
    await db.commit()

    response = await client.delete(f"/api/mdm/connections/{connection_id}")
    assert response.status_code == 204, response.text

    db.expire_all()
    assert await db.get(MdmConnection, connection_id) is None


# --- Tenancy ---------------------------------------------------------------------------
#
# The cross-tenant *id* case is already covered, systematically, by
# test_tenancy_sweep.test_foreign_connection_reads_and_writes_404: another tenant's
# connection id answers 404 to DELETE and the row is untouched. Not duplicated here. What
# is new in this change is a set of bulk DELETE statements, and this is the test for those.


async def test_the_cascade_cannot_reach_another_tenants_rows(client, db, connection) -> None:
    """SECURITY. The new deletes are `WHERE mdm_connection_id = X` with no tenant column
    in the predicate — exactly like their neighbour in `delete_destination` — because
    row-level security supplies it. This proves that is true rather than assumed.

    The probe is the one row that would make the predicate lie: a device belonging to the
    *second* tenant that carries the first tenant's connection id. Nothing in the sync
    path can write that row (a device is always written on the connection's own session),
    so it is planted here on purpose. If RLS ever stopped applying to these statements,
    one tenant's delete would silently destroy another's fleet.

    The delete is then expected to fail rather than succeed, and that is the correct
    direction: the foreign key still guards the parent row, so a device the statement was
    not allowed to see keeps the connection alive. Fail-closed, and with nothing about the
    database in the body.
    """
    from app.core.database import session_for_tenant
    from app.models.schema import Device, MdmConnection

    connection_id = connection.id
    await _sync_once(db, connection)

    async with session_for_tenant(TENANT2_ID) as other:
        planted = Device(
            mdm_connection_id=connection_id,
            mdm_provider="jamf",
            external_id=f"tenant2-{uuidlib.uuid4().hex[:8]}",
            serial_number="C02TENANT02",
            hostname="not-yours.example",
        )
        other.add(planted)
        await other.commit()
        planted_id = planted.id

    try:
        response = await client.delete(f"/api/mdm/connections/{connection_id}")
        assert response.status_code != 204, "a delete that cannot see a child must not report success"
        _assert_no_database_internals(response)

        async with session_for_tenant(TENANT2_ID) as other:
            survivor = await other.get(Device, planted_id)
            assert survivor is not None, "the delete reached across the tenant boundary"
            assert survivor.hostname == "not-yours.example"
            assert survivor.mdm_connection_id == connection_id

        db.expire_all()
        assert await db.get(MdmConnection, connection_id) is not None
    finally:
        async with session_for_tenant(TENANT2_ID) as other:
            await other.execute(delete(Device).where(Device.id == planted_id))
            await other.commit()
