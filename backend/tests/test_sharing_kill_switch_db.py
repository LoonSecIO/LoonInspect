"""COMMUNITY_SHARING=false: the kill switch, tested for the first time (#302).

Three suites covered consent, the wizard, the 413 shed, backoff, globs and the row shape,
and not one of them ever set `community_sharing = False`. The literal `skipped_env` was
written by `run_exchange` and read by nobody. These four tests pin the whole path:

* the API reports the override (`envDisabled`);
* a PUT while overridden is persisted — the route's docstring says so on purpose, and the
  page now lets an administrator make that choice;
* an overridden exchange writes one `skipped_env` row and dials nothing — the daily proof
  the page renders as its own sentence;
* an *off* tier under the override writes nothing at all, so "never" keeps meaning "no
  exchange has been recorded" (the trap the issue names).

Needs a real Postgres: the consent row and the share log are tenant-scoped rows.
"""

from __future__ import annotations

import os

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("kill-switch-admin@example.com", "kill-switch-admin-password")


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

    signed_in = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://kill-switch.example.com")
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


@pytest_asyncio.fixture(loop_scope="session")
async def restored(db):
    """The tier as this suite found it, put back afterwards, and this suite's own
    `skipped_env` rows removed — other suites share the tenant."""
    from app.core.sharing import get_or_create_settings
    from app.models.schema import ShareLog

    row = await get_or_create_settings(db)
    original = row.tier
    yield
    await db.rollback()
    row = await get_or_create_settings(db)
    row.tier = original
    await db.execute(delete(ShareLog).where(ShareLog.outcome == "skipped_env"))
    await db.commit()


@pytest.fixture
def overridden(monkeypatch):
    from app.core.config import settings as app_settings

    monkeypatch.setattr(app_settings, "community_sharing", False)


def _never_dials(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"an overridden exchange must not dial anything; it dialled {request.url}")


async def test_the_api_reports_the_override(client, monkeypatch) -> None:
    from app.core.config import settings as app_settings

    monkeypatch.setattr(app_settings, "community_sharing", True)
    assert (await client.get("/api/system/data-sharing")).json()["envDisabled"] is False
    monkeypatch.setattr(app_settings, "community_sharing", False)
    assert (await client.get("/api/system/data-sharing")).json()["envDisabled"] is True


async def test_a_tier_chosen_while_overridden_is_recorded_for_when_the_override_lifts(client, db, restored, overridden) -> None:
    from app.core.sharing import get_or_create_settings

    response = await client.put("/api/system/data-sharing", json={"tier": "keys"})
    assert response.status_code == 200, response.text
    assert response.json()["tier"] == "keys"
    assert response.json()["envDisabled"] is True

    await db.rollback()
    assert (await get_or_create_settings(db)).tier == "keys"
    assert (await client.get("/api/system/data-sharing")).json()["tier"] == "keys"


async def test_an_overridden_exchange_writes_one_skipped_row_and_dials_nothing(client, db, restored, overridden) -> None:
    from app.core.sharing import get_or_create_settings, run_exchange
    from app.models.schema import ShareLog

    row = await get_or_create_settings(db)
    row.tier = "keys"
    await db.commit()

    await run_exchange(db, transport=httpx.MockTransport(_never_dials))

    skipped = (await db.execute(select(ShareLog).where(ShareLog.outcome == "skipped_env"))).scalars().all()
    assert len(skipped) == 1
    assert skipped[0].tier == "keys"
    assert skipped[0].payload is None, "nothing was assembled, so nothing is logged as having left"
    assert skipped[0].reveals_shed is False

    # And the page's own read of it: the daily proof the override is biting.
    settings_out = (await client.get("/api/system/data-sharing")).json()
    assert settings_out["lastExchangeOutcome"] == "skipped_env"
    assert settings_out["lastExchangeAt"] is not None


async def test_an_off_tier_under_the_override_records_nothing_so_never_still_means_never(db, restored, overridden) -> None:
    from app.core.sharing import get_or_create_settings, run_exchange
    from app.models.schema import ShareLog

    row = await get_or_create_settings(db)
    row.tier = "off"
    await db.commit()
    before = len((await db.execute(select(ShareLog).where(ShareLog.tier != "ai"))).scalars().all())

    await run_exchange(db, transport=httpx.MockTransport(_never_dials))

    after = len((await db.execute(select(ShareLog).where(ShareLog.tier != "ai"))).scalars().all())
    assert after == before, "an off tier logs nothing — a skipped row would turn 'never' into 'skipped'"
