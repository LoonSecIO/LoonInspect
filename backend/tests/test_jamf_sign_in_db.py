"""The Jamf Pro sign-in a connection keeps (#412), against a real Postgres.

The pure lane (test_jamf_sign_in.py) proves the holder; this proves the path an operator
walks: the mode is a column every existing connection comes up in the default of, the API
carries it, a real webhook through the receiver borrows the held sign-in, a settings change
retires it at once, and the sign-in tick starts and stops the Perpetual cache renewal.

Webhooks go through the real receiver on a bare FastAPI app over ASGITransport, as
test_sad_paths.py drives them, with FakeJamf patched in at `JamfClient.http` by the
shared `jamf` fixture — so every token request is counted.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError

from tests.jamf_fake import HOST

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

_SECRET = "sign-in-db-webhook-secret"
ADMIN = ("sign-in-admin@sign-in.example.com", "sign-in-admin-password")
TOKEN = "POST /api/oauth/token"


async def _make_connection(db, mode: str):
    from app.models.schema import MdmConnection

    row = MdmConnection(
        name=f"sign-in jamf {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
        capability_webhooks=True,
        webhook_secret_encrypted=_SECRET,
        token_cache_mode=mode,
    )
    db.add(row)
    await db.commit()
    return row


async def _drop_connection(db, connection_id: int) -> None:
    from app.mdm.jamf.sign_in import SIGN_INS
    from app.models.schema import AppCatalogEntry, Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    await db.rollback()
    row = await db.get(MdmConnection, connection_id)
    if row is not None:
        await SIGN_INS.forget(str(row.tenant_id), connection_id)
    device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
    await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
    await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
    await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
    await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
    await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
    # Keyed by tenant, not connection — see test_runs.py's fixture for why.
    await db.execute(delete(AppCatalogEntry))
    await db.commit()


def _webhook_transport(db) -> httpx.ASGITransport:
    from fastapi import FastAPI

    from app.api import webhooks
    from app.core.database import get_db

    api = FastAPI()
    api.include_router(webhooks.router)

    async def _test_session():
        yield db

    api.dependency_overrides[get_db] = _test_session
    return httpx.ASGITransport(app=api)


async def _webhook(db, connection_id: int, jamf_id: str) -> httpx.Response:
    payload = {"webhook": {"webhookEvent": "ComputerInventoryCompleted"}, "event": {"jssID": jamf_id}}
    async with httpx.AsyncClient(transport=_webhook_transport(db), base_url="http://sign-in") as client:
        return await client.post(f"/webhooks/jamf/{connection_id}", json=payload, headers={"X-API-Key": _SECRET})


@pytest.mark.parametrize(("mode", "tokens"), [("cache_and_hold", 1), ("perpetual", 1), ("no_cache", 2)])
async def test_two_webhooks_sign_in_as_their_connections_mode_says(db, jamf, mode: str, tokens: int) -> None:
    """The whole point, end to end through the receiver: two webhooks inside one token's
    lifetime cost one token request under either cache mode, and two under No cache —
    the behaviour every webhook had before #412."""
    from app.mdm.jamf import sign_in

    connection = await _make_connection(db, mode)
    connection_id = connection.id
    if mode == "perpetual":
        # The renewal is the tick's business (tested below); here it would only add its
        # own sign-in to the count, at a moment the test does not choose.
        started = sign_in.HeldSignIn.start_renewal
        sign_in.HeldSignIn.start_renewal = lambda self: None
    try:
        for _ in range(2):
            response = await _webhook(db, connection_id, jamf.real["id"])
            assert response.status_code == 200, response.text
            assert response.json()["status"] == "accepted"
        assert jamf.requests.count(TOKEN) == tokens
    finally:
        if mode == "perpetual":
            sign_in.HeldSignIn.start_renewal = started
        await _drop_connection(db, connection_id)


async def test_every_existing_connection_comes_up_in_cache_and_hold(db) -> None:
    """The migration's server default, read off the catalog rather than inferred from an
    ORM default: a row written by anything that never heard of the column is on."""
    default = (
        await db.execute(
            text(
                "SELECT column_default FROM information_schema.columns "
                "WHERE table_name = 'mdm_connections' AND column_name = 'token_cache_mode'"
            )
        )
    ).scalar_one()
    assert "cache_and_hold" in default


async def test_the_column_takes_only_the_three_modes(db) -> None:
    connection = await _make_connection(db, "cache_and_hold")
    connection_id = connection.id
    try:
        with pytest.raises(IntegrityError):
            await db.execute(
                text("UPDATE mdm_connections SET token_cache_mode = 'forever' WHERE id = :id"), {"id": connection_id}
            )
            await db.commit()
    finally:
        await _drop_connection(db, connection_id)


async def test_the_sign_in_tick_starts_and_stops_the_perpetual_renewal(db, jamf) -> None:
    """At startup and within a minute of a switch, Perpetual cache has a token before its
    first webhook; switched away, the renewal stops."""
    from app.main import sign_in_tick
    from app.mdm.jamf.sign_in import SIGN_INS
    from app.models.schema import MdmConnection

    connection = await _make_connection(db, "perpetual")
    connection_id, tenant_id = connection.id, str(connection.tenant_id)
    try:
        await sign_in_tick()
        held = SIGN_INS.get(tenant_id, connection_id)
        assert held is not None and held.renewing

        row = await db.get(MdmConnection, connection_id)
        row.token_cache_mode = "no_cache"
        await db.commit()
        await sign_in_tick()

        assert held.retired and not held.renewing
        assert SIGN_INS.get(tenant_id, connection_id) is None
    finally:
        await _drop_connection(db, connection_id)


async def test_the_tick_retires_a_deactivated_connections_sign_in(db, jamf) -> None:
    from app.main import sign_in_tick
    from app.mdm.factory import get_mdm_client
    from app.mdm.jamf.sign_in import SIGN_INS
    from app.models.schema import MdmConnection

    connection = await _make_connection(db, "cache_and_hold")
    connection_id, tenant_id = connection.id, str(connection.tenant_id)
    try:
        get_mdm_client(connection)  # a run held its sign-in
        held = SIGN_INS.get(tenant_id, connection_id)
        assert held is not None

        row = await db.get(MdmConnection, connection_id)
        row.is_active = False
        await db.commit()
        await sign_in_tick()

        assert held.retired
    finally:
        await _drop_connection(db, connection_id)


# --- through the API -------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def seeded() -> None:
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        existing = (await db.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first()
        if existing is None:
            await create_account(db, email=ADMIN[0], display_name="sign-in admin", password=ADMIN[1], roles=("admin",))
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == ADMIN[0]))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def client(seeded):
    """Signed in as the admin, CSRF armed; https because the session cookie is Secure."""
    from app.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://sign-in.example.com") as c:
        response = await c.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        assert response.status_code == 200, response.text
        c.headers["X-CSRF-Token"] = c.cookies.get("loon_csrf", "")
        yield c


async def _create(c: httpx.AsyncClient, **extra) -> dict:
    payload = {
        "name": f"sign-in api {uuidlib.uuid4().hex[:8]}",
        "provider": "jamf",
        "baseUrl": "https://sign-in-api.jamfcloud.com",
        "credentials": {"clientId": "sign-in-client", "clientSecret": "sign-in-client-secret"},
        **extra,
    }
    response = await c.post("/api/mdm/connections", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


async def test_the_api_carries_the_mode_and_defaults_it(client) -> None:
    created = await _create(client)
    try:
        assert created["tokenCacheMode"] == "cache_and_hold"

        response = await client.patch(f"/api/mdm/connections/{created['id']}", json={"tokenCacheMode": "perpetual"})
        assert response.status_code == 200, response.text
        assert response.json()["tokenCacheMode"] == "perpetual"

        listed = {row["id"]: row for row in (await client.get("/api/mdm/connections")).json()}
        assert listed[created["id"]]["tokenCacheMode"] == "perpetual"
    finally:
        await client.delete(f"/api/mdm/connections/{created['id']}")


async def test_the_api_refuses_a_mode_it_does_not_know(client) -> None:
    response = await client.post(
        "/api/mdm/connections",
        json={
            "name": f"sign-in bad {uuidlib.uuid4().hex[:8]}",
            "provider": "jamf",
            "baseUrl": "https://sign-in-api.jamfcloud.com",
            "credentials": {"clientId": "c", "clientSecret": "s"},
            "tokenCacheMode": "forever",
        },
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "change",
    [
        {"tokenCacheMode": "no_cache"},
        {"credentials": {"clientSecret": "rotated-sign-in-secret"}},
        {"userAgentOverride": "Acme"},
        {"isActive": False},
    ],
)
async def test_a_settings_change_retires_the_held_sign_in_at_once(client, change: dict) -> None:
    """Not at the next run: a Perpetual cache renewal would otherwise keep signing in with
    what the edit just replaced."""
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.mdm.jamf.sign_in import SIGN_INS, HeldSignIn

    created = await _create(client)
    key = (str(OPERATIONAL_TENANT_ID), created["id"])
    try:
        # Stand in for the held sign-in a run would have left behind.
        held = HeldSignIn(key, "stamp", "cache_and_hold", lambda h: None)
        SIGN_INS._held[key] = held

        response = await client.patch(f"/api/mdm/connections/{created['id']}", json=change)
        assert response.status_code == 200, response.text

        assert held.retired
        assert SIGN_INS.get(*key) is None
    finally:
        SIGN_INS._held.pop(key, None)
        await client.delete(f"/api/mdm/connections/{created['id']}")


async def test_a_rename_leaves_the_held_sign_in_alone(client) -> None:
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.mdm.jamf.sign_in import SIGN_INS, HeldSignIn

    created = await _create(client)
    key = (str(OPERATIONAL_TENANT_ID), created["id"])
    try:
        held = HeldSignIn(key, "stamp", "cache_and_hold", lambda h: None)
        SIGN_INS._held[key] = held

        response = await client.patch(
            f"/api/mdm/connections/{created['id']}", json={"name": f"renamed {uuidlib.uuid4().hex[:6]}"}
        )
        assert response.status_code == 200, response.text

        assert not held.retired
    finally:
        SIGN_INS._held.pop(key, None)
        await client.delete(f"/api/mdm/connections/{created['id']}")


async def test_deleting_the_connection_retires_its_sign_in(client) -> None:
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.mdm.jamf.sign_in import SIGN_INS, HeldSignIn

    created = await _create(client)
    key = (str(OPERATIONAL_TENANT_ID), created["id"])
    held = HeldSignIn(key, "stamp", "perpetual", lambda h: None)
    SIGN_INS._held[key] = held

    response = await client.delete(f"/api/mdm/connections/{created['id']}")
    assert response.status_code == 204, response.text

    assert held.retired
    assert SIGN_INS.get(*key) is None
