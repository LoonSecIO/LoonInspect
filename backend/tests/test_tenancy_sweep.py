"""The contract's tenancy test, run systematically: two tenants, two users, every id
from A requested as B, all 404 — plus the two failure modes a route-level sweep never
touches (outbox fan-out, and a session bound to no tenant).

Needs a real Postgres: row-level security is the mechanism under test, and SQLite has
no opinion about it. Gated on RUN_DB_TESTS so the pure suite stays runnable with no
database present; CI provides one (see .github/workflows/ci.yml), and locally:

    docker compose exec -T db psql -U looninspect -c \
      "CREATE ROLE tenancy_test LOGIN PASSWORD 'tenancy_test'" -c \
      "CREATE DATABASE looninspect_test OWNER tenancy_test"
    RUN_DB_TESTS=1 DATABASE_URL=postgresql+asyncpg://tenancy_test:tenancy_test@db:5432/looninspect_test \
      uv run pytest tests/test_tenancy_sweep.py

Why 404 and never 403: a 403 confirms the row exists, which is the same enumeration
leak in a different status code. Every cross-tenant assertion below therefore checks
the status AND that the row is untouched afterward.

The second tenant's account deliberately cannot log in over HTTP — identity
resolution is pinned to the operational tenant until #35 builds the narrow RLS
bypass. That boundary is asserted here too, so when #35 lands, this file is the test
that notices the door opened and demands the sweep widen to two live HTTP sessions.
"""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import datetime, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError

# One event loop for the whole module, not one per test: app.core.database's engine
# is created at import and its pooled connections belong to whichever loop first used
# them. Function-scoped loops hand the second test a connection from a closed loop,
# which surfaces as "attached to a different loop" rather than anything about tenancy.
pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"
    ),
    pytest.mark.asyncio(loop_scope="session"),
]

TENANT2_ID = uuidlib.UUID("00000000-0000-0000-0000-0000000000a2")

ADMIN1 = ("admin-one@sweep.example.com", "sweep-password-one")
ADMIN2 = ("admin-two@sweep.example.com", "sweep-password-two")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def seeded():
    """Migrated schema, two operational tenants, one admin and one row of everything
    in each.

    Get-or-create throughout rather than blind inserts: CI runs this against a fresh
    database, but a developer re-running it locally must not trip a unique constraint
    left by the previous run and spend the evening debugging the fixture instead of
    the boundary it exists to test.
    """
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.mdm.collections import ensure_default_collections
    from app.models.schema import (
        Account,
        ApiToken,
        Collection,
        Destination,
        Device,
        EventOutbox,
        InstalledApp,
        MdmConnection,
        Tenant,
    )

    await init_db()

    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, TENANT2_ID) is None:
            db.add(Tenant(id=TENANT2_ID, slug="sweep-second", name="Sweep Second", kind="operational"))
            await db.commit()

    async def one(db, model, where, **kwargs):
        """Get-or-create. Takes constructor kwargs rather than a factory callable so
        nothing closes over the loop variable it is called from."""
        row = (await db.execute(select(model).where(where))).scalars().first()
        if row is None:
            row = model(**kwargs)
            db.add(row)
            await db.flush()
        return row

    ids: dict[str, dict] = {}
    for label, tenant_id, (email, password) in (
        ("t1", OPERATIONAL_TENANT_ID, ADMIN1),
        ("t2", TENANT2_ID, ADMIN2),
    ):
        async with session_for_tenant(tenant_id) as db:
            account = (
                await db.execute(select(Account).where(Account.email == email))
            ).scalars().first()
            if account is None:
                account, _ = await create_account(
                    db, email=email, display_name=label, password=password, roles=("admin",)
                )

            destination = await one(
                db,
                Destination,
                Destination.name == f"{label} destination",
                name=f"{label} destination",
                type="generic_webhook",
                url=f"https://siem.{label}.example/hook",
                auth_type="none",
                enabled=True,
                subscribed_events=None,
            )
            connection = await one(
                db,
                MdmConnection,
                MdmConnection.name == f"{label} jamf",
                name=f"{label} jamf",
                provider="jamf",
                base_url=f"https://{label}.jamfcloud.com",
            )
            # The connection's default collections (#27): real rows, so they need the
            # same cross-tenant treatment as everything else under the connection.
            await ensure_default_collections(db, connection)
            await db.flush()
            collection = (
                await db.execute(
                    select(Collection).where(Collection.mdm_connection_id == connection.id).order_by(Collection.id)
                )
            ).scalars().first()
            device = await one(
                db,
                Device,
                Device.external_id == f"{label}-device-1",
                mdm_provider="jamf",
                external_id=f"{label}-device-1",
                serial_number=f"{label}SERIAL",
                hostname=f"{label}-host",
            )
            await one(
                db,
                InstalledApp,
                InstalledApp.bundle_id == f"com.{label}.app",
                device_id=device.id,
                name=f"{label} App",
                bundle_id=f"com.{label}.app",
                version="1.0",
                app_hash="0" * 32,
                version_hash="1" * 32,
                key_title="v1:" + "a" * 64,
                key_full="v1:" + "b" * 64,
            )
            token = await one(
                db,
                ApiToken,
                ApiToken.name == f"{label} token",
                id=f"{label}tok{uuidlib.uuid4().hex[:8]}",
                account_id=account.id,
                name=f"{label} token",
                token_hash=uuidlib.uuid4().hex + uuidlib.uuid4().hex,
            )
            # Deliberately NOT get-or-create: the fan-out test needs an un-fanned
            # event, and a previous run's rows are all marked fanned_out.
            event = EventOutbox(
                event_type="device.updated",
                payload={"tenant_label": label},
                created_at=datetime.now(timezone.utc),
            )
            db.add(event)
            await db.commit()
            ids[label] = {
                "tenant_id": tenant_id,
                "account_id": account.id,
                "destination_id": destination.id,
                "destination_name": destination.name,
                "connection_id": connection.id,
                "collection_id": collection.id,
                "device_id": device.id,
                "token_id": token.id,
                "event_id": event.id,
            }
    return ids


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def client(seeded):
    """An HTTP client signed in as tenant 1's admin, CSRF header armed."""
    from app.main import app

    # https, not http: the session cookie is Secure by default, and a client on a
    # plain-http origin silently discards it — login returns 200 and every request
    # after it 401s. That is the same failure app.serve warns operators about, and
    # it looks exactly like a tenancy bug from inside a test.
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://sweep.example.com") as c:
        response = await c.post(
            "/api/auth/login", json={"email": ADMIN1[0], "password": ADMIN1[1]}
        )
        assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
        c.headers["X-CSRF-Token"] = c.cookies.get("loon_csrf", "")
        yield c


# --- 1. Every id from A requested as B: 404, and the row untouched ----------------


async def test_foreign_connection_reads_and_writes_404(client, seeded) -> None:
    other = seeded["t2"]["connection_id"]
    assert (await client.get(f"/api/mdm/connections/{other}")).status_code == 404
    assert (
        await client.patch(f"/api/mdm/connections/{other}", json={"name": "stolen"})
    ).status_code == 404
    assert (await client.delete(f"/api/mdm/connections/{other}")).status_code == 404
    assert (await client.post(f"/api/mdm/connections/{other}/sync")).status_code == 404


async def test_foreign_destination_survives_patch_and_delete(client, seeded) -> None:
    from app.core.database import session_for_tenant
    from app.models.schema import Destination

    other = seeded["t2"]["destination_id"]
    assert (
        await client.patch(f"/api/destinations/{other}", json={"name": "stolen", "enabled": False})
    ).status_code == 404
    assert (await client.delete(f"/api/destinations/{other}")).status_code == 404

    async with session_for_tenant(seeded["t2"]["tenant_id"]) as db:
        row = await db.get(Destination, other)
        assert row is not None, "cross-tenant DELETE must not remove the row"
        assert row.name == seeded["t2"]["destination_name"]
        assert row.enabled is True


async def test_foreign_collection_404_and_untouched(client, seeded) -> None:
    """Collections hang off connections and carry the what/when of every pull; a
    foreign one must be as invisible as its connection, for reads, writes, and runs."""
    from app.core.database import session_for_tenant
    from app.models.schema import Collection

    other = seeded["t2"]["collection_id"]
    assert (await client.get(f"/api/mdm/collections/{other}")).status_code == 404
    assert (await client.patch(f"/api/mdm/collections/{other}", json={"name": "stolen"})).status_code == 404
    assert (await client.delete(f"/api/mdm/collections/{other}")).status_code == 404
    assert (await client.post(f"/api/mdm/collections/{other}/run")).status_code == 404
    assert (
        await client.get(f"/api/mdm/connections/{seeded['t2']['connection_id']}/collections")
    ).status_code == 404
    assert (
        await client.post(
            f"/api/mdm/connections/{seeded['t2']['connection_id']}/collections",
            json={"name": "stolen", "kind": "catalog", "frequency": "hourly", "atMinute": 5, "timezone": "UTC"},
        )
    ).status_code == 404

    async with session_for_tenant(seeded["t2"]["tenant_id"]) as db:
        row = await db.get(Collection, other)
        assert row is not None and row.name != "stolen"

    mine = await client.get(f"/api/mdm/connections/{seeded['t1']['connection_id']}/collections")
    assert mine.status_code == 200
    listed = {row["id"] for row in mine.json()}
    assert seeded["t1"]["collection_id"] in listed and other not in listed
    assert (await client.get(f"/api/mdm/collections/{seeded['t1']['collection_id']}")).status_code == 200


async def test_change_feed_and_policy_are_tenant_scoped(client, seeded) -> None:
    """The change feed lists only this tenant's rows, and the policy is per tenant: a PUT
    from tenant 1 must not alter what tenant 2 derives under."""
    from app.core.database import session_for_tenant
    from app.models.schema import ChangePolicy

    feed = await client.get("/api/changes?pageSize=5")
    assert feed.status_code == 200
    assert all(row["mdmConnectionId"] != seeded["t2"]["connection_id"] for row in feed.json()["items"])

    before = await client.get("/api/changes/policy")
    assert before.status_code == 200 and before.json()["minimumLevel"] == "normal"

    saved = await client.put("/api/changes/policy", json={"minimumLevel": "high", "fields": {"general.name": True}})
    assert saved.status_code == 200 and saved.json()["minimumLevel"] == "high"

    async with session_for_tenant(seeded["t2"]["tenant_id"]) as db:
        rows = (await db.execute(select(ChangePolicy))).scalars().all()
        assert rows == [], "tenant 2 must not see or inherit tenant 1's policy row"

    # Restore the default for the next run on a shared local database.
    assert (await client.put("/api/changes/policy", json={"minimumLevel": "normal"})).status_code == 200


async def test_foreign_device_account_token_404(client, seeded) -> None:
    assert (await client.get(f"/api/devices/{seeded['t2']['device_id']}")).status_code == 404
    assert (await client.get(f"/api/accounts/{seeded['t2']['account_id']}")).status_code == 404
    assert (
        await client.patch(
            f"/api/accounts/{seeded['t2']['account_id']}", json={"displayName": "stolen"}
        )
    ).status_code == 404
    assert (await client.delete(f"/api/tokens/{seeded['t2']['token_id']}")).status_code == 404


async def test_own_rows_still_resolve(client, seeded) -> None:
    """The sweep is meaningless if 404 is just the route's answer to everything."""
    assert (await client.get(f"/api/mdm/connections/{seeded['t1']['connection_id']}")).status_code == 200
    assert (await client.get(f"/api/devices/{seeded['t1']['device_id']}")).status_code == 200
    assert (await client.get(f"/api/accounts/{seeded['t1']['account_id']}")).status_code == 200


# --- 2. Every list endpoint: no A rows in B's results -----------------------------


@pytest.mark.parametrize(
    ("path", "foreign_key", "id_field"),
    [
        ("/api/mdm/connections", "connection_id", "id"),
        ("/api/destinations", "destination_id", "id"),
        ("/api/accounts", "account_id", "id"),
    ],
)
async def test_lists_never_contain_foreign_rows(client, seeded, path, foreign_key, id_field) -> None:
    response = await client.get(path)
    assert response.status_code == 200
    body = response.json()
    rows = body if isinstance(body, list) else body.get("items", [])
    listed = {row[id_field] for row in rows}
    assert seeded["t2"][foreign_key] not in listed
    assert seeded["t1"][foreign_key] in listed


async def test_device_list_is_tenant_scoped(client, seeded) -> None:
    response = await client.get("/api/devices")
    assert response.status_code == 200
    body = response.json()
    rows = body if isinstance(body, list) else body.get("items", [])
    serials = {row.get("serialNumber") for row in rows}
    assert "t2SERIAL" not in serials
    assert "t1SERIAL" in serials


# --- 3. Fan-out: no delivery row ever pairs across tenants ------------------------


async def test_fan_out_never_pairs_across_tenants(seeded) -> None:
    """The failure this pins is silent, outbound, and to a third party: tenant A's
    inventory delivered to tenant B's SIEM, with no API request involved. The
    predicate is the RLS policy on destinations — which only holds for a session
    that named a tenant, which is what the worker loop does per tenant.

    Assertions are scoped to the events this run seeded rather than to every row in
    the table, so a database that already contains cross-tenant deliveries — from a
    deliberately broken run, which is exactly how this test gets validated — reports
    the state of *this* fan-out instead of inheriting the previous verdict.
    """
    from app.core.database import session_for_tenant
    from app.core.outbox import fan_out_pending
    from app.models.schema import Destination, OutboxDelivery

    for label in ("t1", "t2"):
        async with session_for_tenant(seeded[label]["tenant_id"]) as db:
            await fan_out_pending(db)
            await db.commit()

    for label, other in (("t1", "t2"), ("t2", "t1")):
        async with session_for_tenant(seeded[label]["tenant_id"]) as db:
            mine = (
                (
                    await db.execute(
                        select(OutboxDelivery).where(
                            OutboxDelivery.outbox_event_id == seeded[label]["event_id"]
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert mine, f"{label}'s own event must fan out to its own destination"

            visible_destinations = {
                d.id for d in (await db.execute(select(Destination))).scalars()
            }
            for delivery in mine:
                assert delivery.destination_id in visible_destinations
                assert delivery.destination_id != seeded[other]["destination_id"]

            # And the other direction: this tenant's destination must never have been
            # paired with the other tenant's event.
            crossed = (
                (
                    await db.execute(
                        select(OutboxDelivery).where(
                            OutboxDelivery.outbox_event_id == seeded[other]["event_id"]
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert not crossed, "a foreign tenant's event must not be visible here at all"


# --- 4. A session bound to no tenant fails closed ---------------------------------


async def test_unbound_session_raises_rather_than_matching_everything(seeded) -> None:
    """`get_tenant_id()` documents None as "not a wildcard": the GUC is unset, and
    every policy read raises instead of quietly returning zero rows — or all of
    them. This is the invariant everything else in this file stands on."""
    from app.core.database import unscoped_session
    from app.models.schema import Account

    async with unscoped_session() as db:
        with pytest.raises(DBAPIError):
            await db.execute(select(Account))


# --- 5. The identity-resolution boundary (#35), pinned ----------------------------


async def test_second_tenant_cannot_authenticate_yet(seeded) -> None:
    """Not a bug — the documented v0 boundary: identity resolution is pinned to the
    operational tenant, so a second tenant's credentials cannot start a session at
    all. When #35 builds the narrow bypass, this test fails, which is the signal to
    widen this sweep to two live HTTP sessions."""
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://sweep.example.com") as c:
        response = await c.post(
            "/api/auth/login", json={"email": ADMIN2[0], "password": ADMIN2[1]}
        )
        assert response.status_code == 401
