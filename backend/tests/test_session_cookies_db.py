"""The sliding idle timeout, held at the cookie (#124).

The DB-side slide always worked: activity pushes `expires_at` forward, at most once
per `_SESSION_TOUCH_INTERVAL`. What #124 pinned is the browser's half — Max-Age was
stamped once at login and never again, so the browser dropped both auth cookies a
fixed hour after login while the server kept alive a session no browser could
present. The fix re-issues BOTH cookies whenever the DB slide advances; this suite
holds its four corners: a fresh re-issue past the touch interval, silence before it,
the 0=unlimited case untouched, and logout still clearing.

Needs a real Postgres for the same reason every session test does — sessions are
rows. Gated on RUN_DB_TESTS like the other DB suites; see test_tenancy_sweep.py for
the local invocation pattern.
"""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, update

# One event loop for the whole module — see test_tenancy_sweep.py for why: the
# engine's pooled connections belong to whichever loop first used them.
pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"
    ),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("cookie-admin@slide.example.com", "cookie-slide-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def seeded() -> uuidlib.UUID:
    """Migrated schema, bootstrapped tenants, and one admin this suite owns.

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
        account = (
            (await db.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first()
        )
        if account is None:
            await create_account(
                db, email=ADMIN[0], display_name="cookie admin", password=ADMIN[1], roles=("admin",)
            )
        # A previous crashed run's failed logins would trip the lockout and turn this
        # suite red about rate limiting instead of cookies.
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == ADMIN[0]))
        await db.commit()

    return OPERATIONAL_TENANT_ID


def _client() -> httpx.AsyncClient:
    from app.main import app

    # https, not http: the cookies are Secure by default and a plain-http origin
    # silently discards them — login 200s and everything after it 401s. Same trap
    # test_tenancy_sweep.py documents.
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="https://slide.example.com")


async def _login(c: httpx.AsyncClient) -> httpx.Response:
    response = await c.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    return response


async def _rewind(raw_token: str, tenant_id: uuidlib.UUID, seconds: int) -> None:
    """Backdate the session as if its last request were `seconds` ago.

    Moves both clocks the way real elapsed time would: `last_seen_at` back by
    `seconds`, and `expires_at` (when one exists) to what the last touch would have
    left it at — last_seen + lifetime. The suite cannot sleep through the real
    60-second touch interval, so it moves the timestamps instead.
    """
    from app.core.config import settings
    from app.core.database import session_for_tenant
    from app.core.security import hash_token
    from app.models.schema import UserSession

    now = datetime.now(timezone.utc)
    last_seen = now - timedelta(seconds=seconds)
    expires = (
        last_seen + timedelta(seconds=settings.session_lifetime_seconds)
        if settings.session_lifetime_seconds
        else None
    )
    async with session_for_tenant(tenant_id) as db:
        await db.execute(
            update(UserSession)
            .where(UserSession.token_hash == hash_token(raw_token))
            .values(last_seen_at=last_seen, expires_at=expires)
        )
        await db.commit()


async def _session_row(raw_token: str, tenant_id: uuidlib.UUID) -> tuple[datetime, datetime | None]:
    from app.core.auth import as_utc
    from app.core.database import session_for_tenant
    from app.core.security import hash_token
    from app.models.schema import UserSession

    async with session_for_tenant(tenant_id) as db:
        row = (
            (
                await db.execute(
                    select(UserSession).where(UserSession.token_hash == hash_token(raw_token))
                )
            )
            .scalars()
            .one()
        )
        return as_utc(row.last_seen_at), as_utc(row.expires_at)


def _cookies_named(response: httpx.Response, name: str) -> list[str]:
    return [v for v in response.headers.get_list("set-cookie") if v.startswith(f"{name}=")]


async def test_activity_past_touch_interval_reissues_both_cookies(seeded, monkeypatch) -> None:
    """The bug itself: a request after the DB slide advanced must hand the browser
    fresh Max-Age on BOTH cookies — the same token and CSRF secret, new clock."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "session_lifetime_seconds", 3600)

    async with _client() as c:
        await _login(c)
        raw, csrf = c.cookies["loon_session"], c.cookies["loon_csrf"]
        await _rewind(raw, seeded, seconds=120)
        _, expires_before = await _session_row(raw, seeded)

        response = await c.get("/api/auth/me")
        assert response.status_code == 200

        session_headers = _cookies_named(response, "loon_session")
        csrf_headers = _cookies_named(response, "loon_csrf")
        assert session_headers and csrf_headers, (
            f"both cookies must re-issue together, got {response.headers.get_list('set-cookie')}"
        )
        for header in (*session_headers, *csrf_headers):
            assert "max-age=3600" in header.lower(), header

        # A refresh of the existing session, not a new one: same values re-stamped.
        assert session_headers[0].split(";")[0] == f"loon_session={raw}"
        assert csrf_headers[0].split(";")[0] == f"loon_csrf={csrf}"

        # And the DB half of the slide still happened alongside the cookie half.
        _, expires_after = await _session_row(raw, seeded)
        assert expires_after is not None and expires_before is not None
        assert expires_after > expires_before
        assert abs(
            (expires_after - datetime.now(timezone.utc)).total_seconds() - 3600
        ) < 30


async def test_no_reissue_before_touch_interval(seeded, monkeypatch) -> None:
    """Inside the touch interval nothing slides, so nothing re-issues — the fix must
    not turn every response into Set-Cookie noise."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "session_lifetime_seconds", 3600)

    async with _client() as c:
        await _login(c)
        response = await c.get("/api/auth/me")
        assert response.status_code == 200
        assert "set-cookie" not in response.headers, response.headers.get_list("set-cookie")


async def test_unlimited_lifetime_stays_untouched(seeded, monkeypatch) -> None:
    """0 = unlimited, exactly as before #124: login cookies carry no Max-Age (browser-
    session cookies), expires_at stays NULL, and activity re-issues nothing — there is
    no clock to wind. The touch itself must still record activity."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "session_lifetime_seconds", 0)

    async with _client() as c:
        login_response = await _login(c)
        for header in login_response.headers.get_list("set-cookie"):
            assert "max-age" not in header.lower(), header
        raw = c.cookies["loon_session"]

        await _rewind(raw, seeded, seconds=120)
        response = await c.get("/api/auth/me")
        assert response.status_code == 200
        assert "set-cookie" not in response.headers, response.headers.get_list("set-cookie")

        last_seen, expires = await _session_row(raw, seeded)
        assert expires is None
        assert datetime.now(timezone.utc) - last_seen < timedelta(seconds=30)


async def test_logout_still_clears_both_cookies(seeded) -> None:
    async with _client() as c:
        await _login(c)
        response = await c.post("/api/auth/logout")
        assert response.status_code == 204

        cleared = {v.split("=", 1)[0] for v in response.headers.get_list("set-cookie")}
        assert {"loon_session", "loon_csrf"} <= cleared
        for header in response.headers.get_list("set-cookie"):
            assert "max-age=0" in header.lower(), header

        assert (await c.get("/api/auth/me")).status_code == 401
