"""409 where 500 lived: the three check-then-insert paths of #134.

Each of these used to reach the database's unique constraint unguarded, so the second
of two requests — concurrent for the login counter and the account, merely sequential
for the connection, which checked nothing at all — died with an IntegrityError and a
500. The constraint is the right arbiter; the answer it produces has to be a 409 (or,
for the lockout counter, silence: a lost increment is fine on the login path, a 500 is
not).

The races are made deterministic rather than raced. For the account, the competing
request's insert is performed inside the real `create_account` call, after the route's
own duplicate check has already passed; for the login counter, the row exists and the
first lookup is made to miss it, which is exactly the window the race opens. A test that
merely fired two requests at once would pass whenever the interleaving happened not to
occur, which is the property a race test must not have.

Needs a real Postgres: every one of these is a constraint the database enforces.
"""

from __future__ import annotations

import asyncio
import os
import uuid as uuidlib
from datetime import UTC, datetime

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("races-admin@example.com", "races-admin-password")
DATABASE_WORDS = ("IntegrityError", "uq_", "duplicate key", "asyncpg", "sqlalchemy")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts() -> None:
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        email, password = ADMIN
        if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
            await create_account(db, email=email, display_name="admin", password=password, roles=("admin",))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def client(accounts):
    from app.main import app

    # raise_app_exceptions=False so a regression shows as the 500 it would be in
    # production, on the response, rather than as a traceback out of the transport.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    signed_in = httpx.AsyncClient(transport=transport, base_url="https://races.example.com")
    email, password = ADMIN
    response = await signed_in.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    signed_in.headers["X-CSRF-Token"] = signed_in.cookies.get("loon_csrf", "")
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def db(accounts):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


def _assert_no_database_internals(response: httpx.Response) -> None:
    """A 409 that quotes the constraint or the driver is a 500 with better manners."""
    for word in DATABASE_WORDS:
        assert word not in response.text, response.text


def _connection_payload(name: str) -> dict:
    return {
        "name": name,
        "provider": "jamf",
        "baseUrl": "https://races.jamfcloud.com",
        "credentials": {"clientId": "id", "clientSecret": "secret"},
    }


async def _delete_connection(client: httpx.AsyncClient, connection_id: int) -> None:
    assert (await client.delete(f"/api/mdm/connections/{connection_id}")).status_code == 204


# --- connections: nothing checked, so even a sequential duplicate was a 500 -------------


async def test_a_second_connection_with_the_same_name_is_a_409_not_a_500(client) -> None:
    name = f"races {uuidlib.uuid4().hex[:8]}"
    first = await client.post("/api/mdm/connections", json=_connection_payload(name))
    assert first.status_code == 201, first.text
    try:
        second = await client.post("/api/mdm/connections", json=_connection_payload(name))
        assert second.status_code == 409, second.text
        assert second.json()["detail"] == "A connection with that name already exists"
        _assert_no_database_internals(second)
    finally:
        await _delete_connection(client, first.json()["id"])


async def test_renaming_a_connection_onto_another_ones_name_is_a_409(client) -> None:
    """Same constraint, one route over: the rename used to be the other way to 500 it."""
    taken = f"races taken {uuidlib.uuid4().hex[:8]}"
    holder = await client.post("/api/mdm/connections", json=_connection_payload(taken))
    other = await client.post("/api/mdm/connections", json=_connection_payload(f"races other {uuidlib.uuid4().hex[:8]}"))
    assert holder.status_code == 201 and other.status_code == 201
    try:
        renamed = await client.patch(f"/api/mdm/connections/{other.json()['id']}", json={"name": taken})
        assert renamed.status_code == 409, renamed.text
        assert renamed.json()["detail"] == "A connection with that name already exists"
        _assert_no_database_internals(renamed)

        # The refusal left the row as it was, and still editable.
        kept = await client.get(f"/api/mdm/connections/{other.json()['id']}")
        assert kept.status_code == 200 and kept.json()["name"] == other.json()["name"]
    finally:
        await _delete_connection(client, holder.json()["id"])
        await _delete_connection(client, other.json()["id"])


# --- accounts: the check passes, then the insert loses ----------------------------------


async def test_an_account_that_loses_the_race_after_the_check_is_a_409(client, db, monkeypatch) -> None:
    """The route checks for the email and then inserts; a second request for the same
    address between those two statements met uq_account_tenant_email with a 500. The
    competing insert is made *inside* the real `create_account`, i.e. strictly after the
    route's check has passed and strictly before its own insert."""
    from app.api import accounts as accounts_module
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, AccountRole, AuthIdentity

    email = f"races-{uuidlib.uuid4().hex[:8]}@example.com"
    real_create_account = accounts_module.create_account

    async def other_request_wins_then_ours_inserts(session, **kwargs):
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as other:
            await real_create_account(
                other,
                email=kwargs["email"],
                display_name="the other request",
                password=kwargs["password"],
                roles=("viewer",),
            )
            await other.commit()
        return await real_create_account(session, **kwargs)

    monkeypatch.setattr(accounts_module, "create_account", other_request_wins_then_ours_inserts)
    try:
        response = await client.post(
            "/api/accounts",
            json={"email": email, "displayName": "Racer", "password": "races-correct-horse-battery-9", "roles": ["viewer"]},
        )
        assert response.status_code == 409, response.text
        assert response.json()["detail"] == "An account with that email already exists"
        _assert_no_database_internals(response)

        # Exactly one account came out of two attempts — the winner's.
        rows = (await db.execute(select(Account).where(Account.email == email))).scalars().all()
        assert [row.display_name for row in rows] == ["the other request"]
    finally:
        ids = (await db.execute(select(Account.id).where(Account.email == email))).scalars().all()
        await db.execute(delete(AccountRole).where(AccountRole.account_id.in_(ids)))
        await db.execute(delete(AuthIdentity).where(AuthIdentity.account_id.in_(ids)))
        await db.execute(delete(Account).where(Account.id.in_(ids)))
        await db.commit()


# --- the lockout counter: the loser adopts the winner's row -----------------------------


async def test_a_first_failure_that_loses_the_insert_race_adopts_the_winners_row(db, monkeypatch) -> None:
    """The window: `_get_attempt` finds no row, the other request's INSERT lands, ours
    used to raise against uq_login_attempt_identifier_ip. Now ON CONFLICT DO NOTHING
    swallows the insert and the read-after re-finds the winner's row, so the failure is
    still counted — on the row that exists."""
    from app.api import auth as auth_module
    from app.models.schema import LoginAttempt

    identifier = f"races-{uuidlib.uuid4().hex[:8]}@example.com"
    ip = "203.0.113.7"
    db.add(LoginAttempt(identifier=identifier, ip=ip, failure_count=1, last_failure_at=datetime.now(UTC)))
    await db.commit()

    real_get_attempt = auth_module._get_attempt
    lookups = 0

    async def misses_once(session, who, where):
        nonlocal lookups
        lookups += 1
        return None if lookups == 1 else await real_get_attempt(session, who, where)

    monkeypatch.setattr(auth_module, "_get_attempt", misses_once)
    try:
        await auth_module._record_failure(db, identifier, ip)  # used to raise IntegrityError

        rows = (await db.execute(select(LoginAttempt).where(LoginAttempt.identifier == identifier))).scalars().all()
        assert len(rows) == 1, "one row per (identifier, ip), whoever inserted it"
        assert rows[0].failure_count == 2
        assert lookups == 2, "the re-read after the insert is what adopts the winner's row"
    finally:
        await db.rollback()
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == identifier))
        await db.commit()


async def test_two_concurrent_first_failures_never_500(client, db) -> None:
    """The black-box half. This cannot prove the interleaving happened — see the module
    docstring — but with the fix no interleaving can 500, so it can never flake either.
    An address nobody holds, so no real account gathers failures."""
    from app.models.schema import LoginAttempt

    email = f"nobody-{uuidlib.uuid4().hex[:8]}@example.com"
    try:
        responses = await asyncio.gather(
            *(client.post("/api/auth/login", json={"email": email, "password": "not-it"}) for _ in range(2))
        )
        assert [r.status_code for r in responses] == [401, 401], [r.text for r in responses]
    finally:
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
        await db.commit()
