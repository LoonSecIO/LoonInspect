"""The daily exchange's sad paths against a real Postgres (INSPECT-0082, -0083).

`post_exchange` and the due-ness arithmetic are covered without a database in
test_sharing.py. What needs one is the property those tests cannot see: what the
share-log row ends up saying. A failed exchange must still land a row, because the
row is what consumes the day — an upstream answering 200 with a non-JSON body used
to raise past `db.add` entirely, so `exchange_due` said yes again on the next tick
and the once-a-day exchange became a crash loop. And a 413 day must land a row that
admits the reveals never left, because the payload column alone claims they did.
Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

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


async def _reset(db) -> None:
    """Clear this suite's exchange rows and put the tier back to the shipped
    default. Other suites share the tenant, so only what this suite touches is
    cleared — the AI rows (tier "ai") share the log and are left alone."""
    from app.models.schema import DataSharingSettings, ShareLog

    await db.rollback()
    await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
    row = (await db.execute(select(DataSharingSettings))).scalar_one_or_none()
    if row is not None:
        row.tier = "reveal"
        row.pending_reveal_keys = []
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def clean(db):
    await _reset(db)
    yield
    await _reset(db)


async def _exchange_rows(db) -> list:
    from app.models.schema import ShareLog

    return (await db.execute(select(ShareLog).where(ShareLog.tier != "ai"))).scalars().all()


async def test_a_200_that_is_not_json_is_logged_and_consumes_the_day(db, clean, monkeypatch) -> None:
    """The captive-portal shape: 200, text/html, undecodable. It must behave exactly
    like any other failed attempt — no exception out of run_exchange, one share-log
    row recording the failure, and a day that is now spent rather than retried on
    the scheduler's next tick."""
    from app.core import sharing
    from app.core.config import settings as app_settings
    from app.core.sharing import _due, _last_attempt_at, run_exchange

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(app_settings, "community_sharing", True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>Sign in to the guest network</html>")

    # Midnight as the jittered slot, so "due" is decided by the log alone and not by
    # where in the day the suite happens to run.
    now = datetime.now(timezone.utc)
    assert await _last_attempt_at(db) is None
    assert _due(now, None, minute_of_day=0) is True

    await run_exchange(db, transport=httpx.MockTransport(handler))

    (row,) = await _exchange_rows(db)
    assert row.outcome == "failed"
    assert row.error  # the decode error, recorded rather than swallowed
    assert row.payload is not None  # exactly what would have left, logged as always

    last = await _last_attempt_at(db)
    assert last is not None
    assert _due(datetime.now(timezone.utc), last, minute_of_day=0) is False
    # Nothing was shed on this run, and a failed row never claims one was.
    assert row.reveals_shed is False


async def test_a_413_day_records_that_the_reveals_never_left(db, clean, monkeypatch) -> None:
    """The row is the tenant's proof of "exactly what left the box". On a 413 the
    payload column is a superset of the body the server accepted — the reveals in it
    were shed and resent as [] — so the row has to carry the marker or it reads as an
    ordinary reveal day (INSPECT-0083)."""
    import json

    from app.core import sharing
    from app.core.config import settings as app_settings
    from app.core.sharing import run_exchange

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(app_settings, "community_sharing", True)

    reveals = [{"title": "v1:aa", "app_name": "Some Common Tool", "versions": []}]

    async def fake_reveals(_db, _row) -> list[dict]:
        # The fixture tenant has no pending reveal requests to answer, and the shed
        # path only exists for a body that has reveals to give up.
        return reveals

    monkeypatch.setattr(sharing, "build_reveals", fake_reveals)

    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        sent.append(body)
        if body["reveals"]:
            return httpx.Response(413)
        return httpx.Response(200, json={"contract": "v1"})

    await run_exchange(db, transport=httpx.MockTransport(handler))

    (row,) = await _exchange_rows(db)
    assert row.outcome == "sent"
    assert row.reveals_shed is True
    # Both halves of the auditor's question: what was offered, and what was accepted.
    assert row.payload["reveals"] == reveals
    assert [b["reveals"] for b in sent] == [reveals, []]


async def test_an_ordinary_day_leaves_the_marker_false(db, clean, monkeypatch) -> None:
    """The marker is only worth reading if it is quiet on every normal exchange."""
    from app.core import sharing
    from app.core.config import settings as app_settings
    from app.core.sharing import run_exchange

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(app_settings, "community_sharing", True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"contract": "v1"})

    await run_exchange(db, transport=httpx.MockTransport(handler))

    (row,) = await _exchange_rows(db)
    assert row.outcome == "sent"
    assert row.reveals_shed is False
