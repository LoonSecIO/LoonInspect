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
    """Clear this suite's exchange rows and put the tier back to "reveal".

    Not the shipped default any more — that is "off", so an unanswered install shares
    nothing (test_sharing_consent_db.py). This suite is about what a *consented*
    instance puts on the wire, so it sets the tier the consent would have set. Other
    suites share the tenant, so only what this suite touches is cleared — the AI rows
    (tier "ai") share the log and are left alone."""
    from app.core.sharing import get_or_create_settings
    from app.models.schema import ShareLog

    await db.rollback()
    await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
    # get-or-create rather than "update it if it happens to be there": with the default
    # at "off", a row this suite does not find is a row that would silently short-circuit
    # every exchange below into a no-op, and a suite about the wire would pass by never
    # reaching it.
    row = await get_or_create_settings(db)
    row.tier = "reveal"
    row.pending_reveal_keys = []
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def clean(db):
    await _reset(db)
    yield
    await _reset(db)


async def test_exclude_globs_cover_the_reveal_path(db, clean) -> None:
    """The operator's exclude list must gag the plaintext path, not just the hashes.

    Until INSPECT-0174 `_excluded` had one call site — build_exchange_request — so an
    excluded app vanished from the snapshot (and from the preview button, which is the
    trust feature) while its NAME still crossed the wire the moment the server asked
    about the title. The snapshot leaks a hash; this path leaks "Acme Payroll". Both
    apps below are pending reveals; only the unexcluded one may come back.
    """
    import uuid as uuidlib

    from app.core.sharing import build_reveals
    from app.models.schema import DataSharingSettings, Device, InstalledApp

    suffix = uuidlib.uuid4().hex[:8]
    device = Device(
        mdm_provider="jamf",
        external_id=f"reveal-{suffix}",
        serial_number=f"SER{suffix}",
        hostname=f"host-{suffix}",
    )
    db.add(device)
    await db.commit()

    secret_key = f"v1:secret{suffix}"[:67]
    public_key = f"v1:public{suffix}"[:67]

    def app(name, bundle_id, key):
        return InstalledApp(
            device_id=device.id, name=name, bundle_id=bundle_id, version="1.0",
            app_hash=uuidlib.uuid4().hex, version_hash=uuidlib.uuid4().hex,
            key_title=key, key_full=key,
        )

    db.add_all([
        app(f"Acme Payroll {suffix}", "com.acme.payroll", secret_key),
        app(f"Google Chrome {suffix}", "com.google.Chrome", public_key),
    ])
    await db.commit()

    row = (await db.execute(select(DataSharingSettings))).scalar_one()
    row.tier = "reveal"
    row.pending_reveal_keys = [secret_key, public_key]
    row.exclude_globs = ["com.acme.*"]
    await db.commit()

    try:
        reveals = await build_reveals(db, row)
    finally:
        row.exclude_globs = []
        row.pending_reveal_keys = []
        await db.commit()
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id == device.id))
        await db.execute(delete(Device).where(Device.id == device.id))
        await db.commit()

    titles = {entry["title"] for entry in reveals}
    assert public_key in titles, "an unexcluded pending title must still be revealed"
    assert secret_key not in titles, "an excluded bundle id leaked its title through the reveal path"
    # The name is the thing that must not travel; assert on it directly rather than
    # trusting that filtering the title was enough.
    names = {entry["app_name"] for entry in reveals}
    assert not any(name.startswith("Acme Payroll") for name in names), f"plaintext name leaked: {names}"


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
