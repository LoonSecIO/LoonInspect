"""Who may learn which build this instance is running (#130).

#41 put the version in the unauthenticated `/api/auth/status` payload so the sign-in
page could show it, and said so knowingly. That trade was priced against a private
repo. Once the source is public a short sha resolves to a commit, so an exact build
read off the sign-in page is a list of the fixes this instance has not taken — which
is the very fact SYSTEM_READ exists to keep behind a login.

The ruling this suite holds: the build is for people who own the instance. Anonymous
callers get null; anyone signed in may read it, with no permission required, because
"what am I running?" is a question every bug reporter has to answer. The exception is
an unclaimed instance, which is already handing the next caller the first admin
account and so has nothing left to protect.

Needs a real Postgres like every session test; gated on RUN_DB_TESTS. See
test_tenancy_sweep.py for the local invocation pattern.
"""

from __future__ import annotations

import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

# One event loop for the whole module — the engine's pooled connections belong to
# whichever loop first used them.
pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"
    ),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("version-admin@build.example.com", "version-admin-password")
VIEWER = ("version-viewer@build.example.com", "version-viewer-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def seeded() -> uuidlib.UUID:
    """Migrated schema, bootstrapped tenants, and the two accounts this suite owns.

    Get-or-create, like every DB fixture here: a developer re-running against a
    persistent local database must not trip a unique constraint from the last run.
    """
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    await init_db()

    async with unscoped_session() as db:
        await bootstrap_tenants(db)

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        for (email, password), role, name in (
            (ADMIN, "admin", "version admin"),
            (VIEWER, "viewer", "version viewer"),
        ):
            existing = (
                (await db.execute(select(Account).where(Account.email == email))).scalars().first()
            )
            if existing is None:
                await create_account(
                    db, email=email, display_name=name, password=password, roles=(role,)
                )
            # A previous crashed run's failed logins would trip the lockout and turn
            # this suite red about rate limiting instead of about the version.
            await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
        await db.commit()

    return OPERATIONAL_TENANT_ID


def _client() -> httpx.AsyncClient:
    from app.main import app

    # https, not http: the cookies are Secure by default and a plain-http origin
    # silently discards them — login 200s and everything after it 401s.
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="https://build.example.com")


async def _login(c: httpx.AsyncClient, credentials: tuple[str, str]) -> None:
    email, password = credentials
    response = await c.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"


async def test_anonymous_status_withholds_the_build(seeded: uuidlib.UUID) -> None:
    """The regression #130 names: a stranger on the port must not be told the build."""
    async with _client() as c:
        response = await c.get("/api/auth/status")

    assert response.status_code == 200
    body = response.json()
    # Still answers the question it exists to answer — the SPA needs both of these to
    # choose a screen, and only the build is being withheld.
    assert body["setupRequired"] is False
    assert body["authenticated"] is False
    assert body["version"] is None


async def test_signed_in_status_carries_the_build(seeded: uuidlib.UUID) -> None:
    from app.core.version import get_app_version

    async with _client() as c:
        await _login(c, ADMIN)
        response = await c.get("/api/auth/status")

    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["version"] == get_app_version()


async def test_unclaimed_instance_still_states_the_build(seeded: uuidlib.UUID) -> None:
    """Nobody owns it yet, so there is nothing the build could betray — and the
    first-run operator has no signed-in surface to read it from."""
    from app.core.version import get_app_version

    async with _client() as c:
        # Patched rather than emptied: the account table is shared with every other
        # DB suite, and setup_required is exactly "account_count() == 0".
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("app.api.auth.account_count", _zero_accounts)
            response = await c.get("/api/auth/status")

    assert response.status_code == 200
    body = response.json()
    assert body["setupRequired"] is True
    assert body["version"] == get_app_version()


async def _zero_accounts(_db: object) -> int:
    return 0


async def test_system_version_needs_a_session(seeded: uuidlib.UUID) -> None:
    async with _client() as c:
        response = await c.get("/api/system/version")

    assert response.status_code == 401


async def test_a_narrow_api_token_can_still_read_the_build(seeded: uuidlib.UUID) -> None:
    """The scriptable half of the ruling, and the path the macOS client will take.

    A token scoped to device:read holds no SYSTEM_READ, and must still answer "what
    build is this?" — otherwise reporting a bug from a script means minting a token
    broad enough to also read behind-ness, which is the fact being protected.
    """
    from app.core.version import get_app_version

    async with _client() as c:
        await _login(c, ADMIN)
        created = await c.post(
            "/api/auth/tokens",
            headers={"X-CSRF-Token": c.cookies["loon_csrf"]},
            json={"name": "version probe", "scopes": ["device:read"], "expiresInDays": 1},
        )
        assert created.status_code == 201, f"{created.status_code} {created.text}"
        bearer = {"Authorization": f"Bearer {created.json()['token']}"}

    # A second client so the session cookie cannot be what authenticates these.
    async with _client() as c:
        version = await c.get("/api/system/version", headers=bearer)
        update_status = await c.get("/api/system/update-status", headers=bearer)

    assert version.status_code == 200
    assert version.json()["version"] == get_app_version()
    assert update_status.status_code == 403


async def test_system_version_needs_no_permission(seeded: uuidlib.UUID) -> None:
    """A viewer holds no SYSTEM_READ, and must still be able to say what it is running.

    The boundary the ruling draws: the running build is unprivileged among signed-in
    users, while behind-ness — the sensitive half — stays behind SYSTEM_READ. Both
    halves are asserted here so a later grant that blurs them fails loudly.
    """
    from app.core.version import get_app_version

    async with _client() as c:
        await _login(c, VIEWER)
        version = await c.get("/api/system/version")
        update_status = await c.get("/api/system/update-status")

    assert version.status_code == 200
    assert version.json()["version"] == get_app_version()
    assert update_status.status_code == 403
