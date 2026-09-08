"""A credential minted in a second operational tenant resolves — the lookup #35 named as
the blocker for multi-tenancy, built as two unscoped index tables rather than a
row-level-security bypass (docs/auth-design.md §4.8).

Every request arrives bound to the identity-resolution scope, which is the operational
tenant. Before this the session row of a second tenant was invisible from there, so its
cookie was a 401 by construction. Now `resolve_session` and the bearer path read
`session_tenants` / `api_token_tenants` first, rebind the request to the tenant they
name, and only then read the tenant-scoped row. These tests are the two-live-sessions
sweep: a session and a token minted in the second tenant authenticate as that tenant's
account and see only that tenant's rows; a cookie nobody issued says nothing; the login
route writes the index row; and the hourly purge takes the index row with the session.

Needs a real Postgres with a second operational tenant of this file's own.
"""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, update

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

TENANT2_ID = uuidlib.UUID("00000000-0000-0000-0000-000000000035")
ADMIN1 = ("resolve-one@example.com", "resolve-password-one")
ADMIN2 = ("resolve-two@example.com", "resolve-password-two")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def seeded() -> None:
    """Both tenants, one admin in each, get-or-create."""
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt, Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, TENANT2_ID) is None:
            db.add(Tenant(id=TENANT2_ID, slug="resolve-second", name="Resolve Second", kind="operational"))
            await db.commit()

    for tenant_id, (email, password) in ((OPERATIONAL_TENANT_ID, ADMIN1), (TENANT2_ID, ADMIN2)):
        async with session_for_tenant(tenant_id) as db:
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name="resolve admin", password=password, roles=("admin",))
            await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
            await db.commit()


async def _mint_session(tenant_id: uuidlib.UUID, email: str) -> tuple[str, str]:
    """A session the way the switcher or a per-tenant login would mint one: through
    `create_session` under that tenant's scope. Returns the raw cookie and the CSRF token."""
    from app.core.auth import create_session
    from app.core.database import session_for_tenant
    from app.models.schema import Account

    async with session_for_tenant(tenant_id) as db:
        account = (await db.execute(select(Account).where(Account.email == email))).scalar_one()
        session, raw = await create_session(db, account, identity_id=None)
        csrf = session.csrf_token
        await db.commit()
    return raw, csrf


def _client(raw: str | None = None, csrf: str | None = None, bearer: str | None = None) -> httpx.AsyncClient:
    from app.main import app

    cookies = {"loon_session": raw, **({"loon_csrf": csrf} if csrf else {})} if raw else {}
    headers = {**({"X-CSRF-Token": csrf} if csrf else {}), **({"Authorization": f"Bearer {bearer}"} if bearer else {})}
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://resolve.example.com", cookies=cookies, headers=headers
    )


@pytest_asyncio.fixture(loop_scope="session")
async def tidy(seeded):
    """Every session and token this suite minted, gone afterwards; the index rows
    cascade with them, which is itself part of what is being pinned."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, ApiToken, UserSession

    yield
    for tenant_id, (email, _password) in ((OPERATIONAL_TENANT_ID, ADMIN1), (TENANT2_ID, ADMIN2)):
        async with session_for_tenant(tenant_id) as db:
            account_id = (await db.execute(select(Account.id).where(Account.email == email))).scalar_one()
            await db.execute(delete(ApiToken).where(ApiToken.account_id == account_id))
            await db.execute(delete(UserSession).where(UserSession.account_id == account_id))
            await db.commit()


# --- the two live sessions -----------------------------------------------------------------


async def test_a_session_minted_in_the_second_tenant_resolves_to_its_own_account(tidy) -> None:
    raw, _csrf = await _mint_session(TENANT2_ID, ADMIN2[0])
    async with _client(raw) as client:
        me = await client.get("/api/auth/me")
        assert me.status_code == 200, me.text
        assert me.json()["email"] == ADMIN2[0]
        status = await client.get("/api/auth/status")
        assert status.json()["authenticated"] is True


async def test_each_session_acts_in_its_own_tenant_and_sees_only_it(tidy) -> None:
    """The isolation the index must not loosen: rebinding to the credential's tenant is
    exactly as narrow as the old single scope was."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import MdmConnection

    names = {
        OPERATIONAL_TENANT_ID: f"resolve one {uuidlib.uuid4().hex[:6]}",
        TENANT2_ID: f"resolve two {uuidlib.uuid4().hex[:6]}",
    }
    for tenant_id, name in names.items():
        async with session_for_tenant(tenant_id) as db:
            db.add(MdmConnection(name=name, provider="jamf", base_url="https://resolve.jamfcloud.com"))
            await db.commit()
    try:
        raw1, _ = await _mint_session(OPERATIONAL_TENANT_ID, ADMIN1[0])
        raw2, _ = await _mint_session(TENANT2_ID, ADMIN2[0])
        async with _client(raw1) as one, _client(raw2) as two:
            seen_by_one = {row["name"] for row in (await one.get("/api/mdm/connections")).json()}
            seen_by_two = {row["name"] for row in (await two.get("/api/mdm/connections")).json()}
        assert names[OPERATIONAL_TENANT_ID] in seen_by_one and names[TENANT2_ID] not in seen_by_one
        assert names[TENANT2_ID] in seen_by_two and names[OPERATIONAL_TENANT_ID] not in seen_by_two
    finally:
        for tenant_id, name in names.items():
            async with session_for_tenant(tenant_id) as db:
                await db.execute(delete(MdmConnection).where(MdmConnection.name == name))
                await db.commit()


async def test_an_api_token_minted_in_the_second_tenant_authenticates_there(tidy) -> None:
    """The bearer path takes the same two reads: the secret's hash names the tenant,
    the token row is read where it lives."""
    raw, csrf = await _mint_session(TENANT2_ID, ADMIN2[0])
    async with _client(raw, csrf) as session_client:
        minted = await session_client.post("/api/auth/tokens", json={"name": "resolve probe"})
        assert minted.status_code == 201, minted.text
        secret = next(value for value in minted.json().values() if isinstance(value, str) and value.startswith("loon_pat_"))
    async with _client(bearer=secret) as api_client:
        me = await api_client.get("/api/auth/me")
        assert me.status_code == 200, me.text
        assert me.json()["email"] == ADMIN2[0]


async def test_logout_with_the_second_tenants_cookie_revokes_it(tidy) -> None:
    raw, _ = await _mint_session(TENANT2_ID, ADMIN2[0])
    async with _client(raw) as client:
        assert (await client.post("/api/auth/logout")).status_code == 204
        assert (await client.get("/api/auth/me")).status_code == 401


async def test_a_cookie_nobody_issued_is_a_401_that_says_nothing(tidy) -> None:
    """Failure to resolve is indistinguishable from any other bad credential: no index
    row means no tenant, means the same answer a revoked cookie gets."""
    async with _client("not-a-session-anyone-issued") as client:
        response = await client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


# --- the index is kept exact ---------------------------------------------------------------


async def test_the_login_route_writes_the_index_row(tidy) -> None:
    from app.core.database import session_for_tenant
    from app.core.security import hash_token
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import SessionTenant

    async with _client() as client:
        response = await client.post("/api/auth/login", json={"email": ADMIN1[0], "password": ADMIN1[1]})
        assert response.status_code == 200, response.text
        raw = client.cookies.get("loon_session")
    assert raw
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        row = await db.get(SessionTenant, hash_token(raw))
    assert row is not None and row.tenant_id == OPERATIONAL_TENANT_ID


async def test_the_hourly_purge_takes_the_index_row_with_the_session(tidy) -> None:
    from app.core.database import session_for_tenant
    from app.core.security import hash_token
    from app.main import hourly_session_cleanup
    from app.models.schema import SessionTenant, UserSession

    raw, _ = await _mint_session(TENANT2_ID, ADMIN2[0])
    token_hash = hash_token(raw)
    async with session_for_tenant(TENANT2_ID) as db:
        assert await db.get(SessionTenant, token_hash) is not None
        await db.execute(
            update(UserSession)
            .where(UserSession.token_hash == token_hash)
            .values(expires_at=datetime.now(timezone.utc) - timedelta(days=3))
        )
        await db.commit()

    await hourly_session_cleanup()

    async with session_for_tenant(TENANT2_ID) as db:
        assert (await db.execute(select(UserSession).where(UserSession.token_hash == token_hash))).scalar_one_or_none() is None
        assert await db.get(SessionTenant, token_hash) is None, "the cascade from the session row is what keeps the index exact"
    async with _client(raw) as client:
        assert (await client.get("/api/auth/me")).status_code == 401
