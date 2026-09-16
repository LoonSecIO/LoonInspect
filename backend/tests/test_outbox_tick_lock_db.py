"""Two app processes, one delivery (#467).

`deliver_pending` claims nothing — it selects the deliveries that are due and POSTs them
— so two scheduler-enabled containers selected the same rows and sent every event to the
customer's SIEM twice: outbound, no API request involved, nothing in any log saying it
had happened. `docs/ingest-scheduling.md` §5 buys "identical behaviour on one process or
six" with the run row whose partial unique index *is* the mutex; this tick never had one.
It has a per-tenant `pg_try_advisory_lock` now, and a refusal in words when it cannot be
taken — a second process that silently does nothing is indistinguishable from a broken one.

Two connections rather than two containers: an advisory lock is held by a database
session, and `engine.connect()` twice is two of those in the sense two containers are.
The last test is the one worth keeping, and says why in its own docstring.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid as uuidlib
from collections.abc import Awaitable, Callable
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app import main
from app.core import outbox

# One event loop for the whole module, as every database-lane file carries: the engine's
# pooled connections belong to whichever loop first used them.
pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

# This file's own tenant, and a second one it never writes a row for — only takes the
# lock of, to show that a busy tenant is not a stopped product.
TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-000000000467")
OTHER_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-000000000468")

EVENT_TYPE = "device.change"
DOCS = Path(__file__).resolve().parents[2] / "docs"


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenant_ready() -> None:
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, unscoped_session
    from app.models.schema import Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, TENANT_ID) is None:
            db.add(Tenant(id=TENANT_ID, slug="outbox-tick-lock", name="Outbox tick lock", kind="operational"))
            await db.commit()


async def _clear(db) -> None:
    from app.models.schema import Destination, EventOutbox, OutboxDelivery

    await db.rollback()
    await db.execute(delete(OutboxDelivery))
    await db.execute(delete(EventOutbox))
    await db.execute(delete(Destination))
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def db(tenant_ready, monkeypatch: pytest.MonkeyPatch):
    """This tenant's session, and a tick narrowed to it: the loop sweeps every operational
    tenant, and the operational one carries rows other files left behind, so narrowing is
    what makes "one POST" a count rather than an estimate."""
    from app.core.database import session_for_tenant

    async def only_this_tenant() -> list[uuidlib.UUID]:
        return [TENANT_ID]

    monkeypatch.setattr(main, "operational_tenant_ids", only_this_tenant)
    async with session_for_tenant(TENANT_ID) as session:
        await _clear(session)
        try:
            yield session
        finally:
            await _clear(session)


def _mock_posts(monkeypatch: pytest.MonkeyPatch, during: Callable[[int], Awaitable[None]] | None = None) -> list[httpx.Request]:
    """Every delivery behind a MockTransport, and the list they land in. `during` is
    awaited while a POST is in flight — inside the tick, and so inside the lock."""
    seen: list[httpx.Request] = []

    async def _record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if during is not None:
            await during(len(seen))
        return httpx.Response(200, json={"ok": True})

    class _MockedClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(_record)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(outbox.httpx, "AsyncClient", _MockedClient)
    return seen


async def _queued(db, events: int = 1) -> None:
    """One enabled destination and `events` events waiting to be fanned out — what a tick
    finds after a sweep. Committed, so another session's tick sees it."""
    from app.models.schema import Destination

    db.add(Destination(name="siem", type="generic_webhook", url="https://siem.example/events", auth_type="none", enabled=True))
    for index in range(events):
        await outbox.enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "serial_number": f"LOONMINI0M{index}"})
    await db.commit()


async def _deliveries(db):
    from app.models.schema import OutboxDelivery

    await db.rollback()  # end this session's transaction, so it reads what the tick committed
    return (await db.execute(select(OutboxDelivery).order_by(OutboxDelivery.id))).scalars().all()


def _skips(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.getMessage().startswith("outbox tick skipped")]


async def test_two_ticks_at_once_deliver_the_event_once(
    db, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    seen = _mock_posts(monkeypatch, during=lambda _count: asyncio.sleep(0.05))
    await _queued(db)

    with caplog.at_level(logging.INFO, logger="app.main"):
        await asyncio.gather(main.outbox_worker_tick(), main.outbox_worker_tick())

    assert len(seen) == 1
    assert [(row.status, row.attempt_count) for row in await _deliveries(db)] == [("delivered", 1)]
    [skipped] = _skips(caplog)
    assert skipped.tenant_id == str(TENANT_ID)


async def test_the_refused_tick_touches_nothing_and_says_which_process_is_delivering(
    db, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from app.models.schema import EventOutbox

    seen = _mock_posts(monkeypatch)
    await _queued(db)

    async with outbox.outbox_tick_lock(TENANT_ID) as held:  # the other process, mid-tick
        assert held
        with pytest.raises(RuntimeError):
            async with outbox.outbox_tick_lock(OTHER_TENANT_ID) as elsewhere:
                assert elsewhere  # keyed per tenant: one slow SIEM is one tenant's problem
                raise RuntimeError("the tick this lock was wrapping died")
        async with outbox.outbox_tick_lock(OTHER_TENANT_ID) as after_a_death:
            assert after_a_death  # released on the exception path too, so nothing deadlocks
        with caplog.at_level(logging.INFO, logger="app.main"):
            await main.outbox_worker_tick()

    # Neither half ran: no POST, no delivery row, and the event still un-fanned — the
    # state it was already in rather than a new one to recover from.
    assert seen == []
    assert await _deliveries(db) == []
    assert [event.fanned_out for event in (await db.execute(select(EventOutbox))).scalars().all()] == [False]

    [skipped] = _skips(caplog)
    message = skipped.getMessage()
    assert "this tick did nothing" in message and "the next one tries again" in message
    assert "SCHEDULER_ENABLED" in message and "operations.md" in message
    # And the words an operator greps the container log for are in the step-through they
    # land on (docs/diagnosability.md rule 4).
    assert "outbox tick skipped" in (DOCS / "troubleshooting.md").read_text()

    # Released with the `async with` above — a finished tick locks nobody out — so the
    # next tick takes it and drains. Two ticks against one database, one delivery.
    await main.outbox_worker_tick()
    assert len(seen) == 1


async def test_the_lock_outlives_the_commit_inside_the_delivery_loop(db, monkeypatch: pytest.MonkeyPatch) -> None:
    """The trap, pinned: `deliver_pending` commits per delivery (#91), so a claim with
    transaction lifetime — `FOR UPDATE SKIP LOCKED` on its select, or
    `pg_try_advisory_xact_lock` here — would be released by the first one and hand the
    rest of the tick to a second process. Probed from inside the second POST, after the
    first delivery has committed."""
    probed: list[bool] = []

    async def probe(_count: int) -> None:
        async with outbox.outbox_tick_lock(TENANT_ID) as held:
            probed.append(held)

    seen = _mock_posts(monkeypatch, during=probe)
    await _queued(db, events=2)

    await main.outbox_worker_tick()

    assert len(seen) == 2
    assert probed == [False, False]  # the second is the one a row claim would have broken
    assert [row.status for row in await _deliveries(db)] == ["delivered", "delivered"]
