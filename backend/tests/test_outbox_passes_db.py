"""Characterization tests for the outbox's two hot passes and its retention sweep.

Characterization, not specification. Every assertion here was read off
`app/core/outbox.py` as it stands on main and describes what the code *does*, not
what it should do — including a few behaviours that are worth a second look and are
called out as such in the comments rather than quietly corrected. The value is the
alarm: #81 proposes moving the outbox from one event per *changed* device to one
fattened snapshot per device per sweep (~30KB each, at a design target of 40,000
devices), and before this file `fan_out_pending` and `deliver_pending` had two
referencing test files between them. Whatever #81's build sessions do to the volume
story, these say immediately what moved.

What is pinned, by section:

1. **Fan-out.** Which destinations get a delivery row (subscribed, catch-all, and
   the empty list the model documents as "all"), the defaults a new delivery row
   carries, and the one-way `fanned_out` flag — which is why fan-out is one-shot:
   an event is burned even when there is nothing to deliver it to, so a destination
   created (or re-enabled) afterwards never receives it.
2. **The shape of the passes.** Both read every matching row with every column,
   with no LIMIT — `fan_out_pending` drags the full JSONB payload out of the
   database purely to flip a boolean. Pinned by capturing the SQL, because it is the
   exact property #81 has to change and the one most likely to change by accident.
3. **Producer volume.** One connection sync of a two-device tenant: how many events
   the first sweep enqueues, and how many the second, unchanged sweep does. This is
   the number #81 rewrites.
4. **Delivery.** Success, failure, backoff, the ten-attempt dead-letter, and the
   disabled-destination path that leaves a delivery pending on purpose.
5. **Retention.** `purge_delivered_events` refusing to touch an event that still
   holds one pending delivery — and what that composes into when a destination is
   left disabled, which is the open storage question on #81.

Everything runs against a real Postgres in a tenant of this file's own
(`…-000000000154`), so RLS makes the counts exact rather than "whatever else the
suite left in the operational tenant". Gated on RUN_DB_TESTS; see
.github/workflows/ci.yml for the role setup.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

from tests.jamf_fake import HOST, FakeJamf

# One event loop for the whole module: app.core.database's engine is created at import
# and its pooled connections belong to whichever loop first used them.
pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

# This file's own tenant. The fan-out pass selects *every* un-fanned event the session
# can see and pairs it with *every* enabled destination it can see, so exact counts are
# only possible in a tenant nothing else writes to — the operational tenant carries a
# permanent catch-all destination from the tenancy sweep's fixture, which would fan out
# into every count below.
TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-000000000154")

EVENT_TYPE = "device.change"


# --- Fixtures ---------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenant_ready() -> None:
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, unscoped_session
    from app.models.schema import Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, TENANT_ID) is None:
            db.add(
                Tenant(
                    id=TENANT_ID,
                    slug="outbox-characterization",
                    name="Outbox characterization",
                    kind="operational",
                )
            )
            await db.commit()


async def _clear(db) -> None:
    """Empty this tenant's outbox tables. Run either side of every test so a local
    re-run starts from the same place CI does, and so a test that fails half way
    cannot make the next one lie."""
    from app.models.schema import Destination, EventOutbox, OutboxDelivery

    await db.rollback()
    await db.execute(delete(OutboxDelivery))
    await db.execute(delete(EventOutbox))
    await db.execute(delete(Destination))
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def db(tenant_ready):
    from app.core.database import session_for_tenant

    async with session_for_tenant(TENANT_ID) as session:
        await _clear(session)
        try:
            yield session
        finally:
            await _clear(session)


def _destination(name: str, **overrides):
    from app.models.schema import Destination

    values = {
        "name": name,
        "type": "generic_webhook",
        "url": f"https://siem.example/{name.replace(' ', '-')}",
        "auth_type": "none",
        "enabled": True,
        "subscribed_events": None,
    }
    values.update(overrides)
    return Destination(**values)


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True})


def _boom(request: httpx.Request) -> httpx.Response:
    return httpx.Response(500, text="destination is having a day")


def _mock_posts(monkeypatch: pytest.MonkeyPatch, handler=_ok) -> list[httpx.Request]:
    """Put every outbound delivery behind a MockTransport, and return the list the
    requests land in.

    `deliver_pending` opens its own `async with httpx.AsyncClient()`, so unlike
    `JamfClient.http` there is no injected seam — the class itself is the seam.
    Patched through the module object `app.core.outbox` reads it from, and restored
    by monkeypatch at teardown.
    """
    from app.core import outbox

    seen: list[httpx.Request] = []

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    class _MockedClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(_record)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(outbox.httpx, "AsyncClient", _MockedClient)
    return seen


async def _deliveries(db):
    from app.models.schema import OutboxDelivery

    return (await db.execute(select(OutboxDelivery).order_by(OutboxDelivery.id))).scalars().all()


async def _one_pending_delivery(db, **destination_overrides):
    """One enabled destination, one event, one fanned-out delivery row — the state
    every delivery test below starts from."""
    from app.core.outbox import enqueue_event, fan_out_pending

    destination = _destination("siem", **destination_overrides)
    db.add(destination)
    event = await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "serial_number": "LOONMINI0M4"})
    await db.commit()
    await fan_out_pending(db)
    (delivery,) = await _deliveries(db)
    return destination, event, delivery


# --- 1. Fan-out: who gets a row, and the one-way flag ------------------------------


async def test_fan_out_creates_one_pending_delivery_per_subscribed_destination(db) -> None:
    from app.core.outbox import enqueue_event, fan_out_pending

    subscribed = _destination("by name", subscribed_events=[EVENT_TYPE])
    catch_all = _destination("null list", subscribed_events=None)
    elsewhere = _destination("other type", subscribed_events=["run.completed"])
    db.add_all([subscribed, catch_all, elsewhere])
    event = await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE})
    await db.commit()

    # The return value is the count of delivery rows created, not of events fanned.
    assert await fan_out_pending(db) == 2

    deliveries = await _deliveries(db)
    assert {row.destination_id for row in deliveries} == {subscribed.id, catch_all.id}
    assert event.fanned_out is True

    # A brand-new delivery row is due immediately and carries no history: the first
    # delivery tick after fan-out attempts it, with no initial delay.
    row = deliveries[0]
    assert row.status == "pending"
    assert row.attempt_count == 0
    assert row.next_attempt_at <= datetime.now(timezone.utc)
    assert row.last_attempted_at is None
    assert row.last_error is None
    assert row.delivered_at is None
    assert row.outbox_event_id == event.id


async def test_fan_out_reads_an_empty_subscription_list_as_all_events(db) -> None:
    """`if subscribed and ...` — an empty list is falsy, so `[]` behaves exactly like
    the null "everything" default rather than like "nothing". The model's own comment
    says so ("Null/empty means all"), so this is documented intent, pinned because it
    is the kind of thing a rewrite reads as an empty allowlist."""
    from app.core.outbox import enqueue_event, fan_out_pending

    empty = _destination("empty list", subscribed_events=[])
    db.add(empty)
    await enqueue_event(db, "run.failed", {"event": "run.failed"})
    await db.commit()

    assert await fan_out_pending(db) == 1
    (delivery,) = await _deliveries(db)
    assert delivery.destination_id == empty.id


async def test_fan_out_skips_a_disabled_destination_and_burns_the_event_anyway(db) -> None:
    """Both halves are the behaviour on main. The event is marked fanned out even
    though the pass created nothing for it, so re-enabling the destination a minute
    later does not backfill: those events are gone as far as this destination is
    concerned. Worth questioning, not fixed here."""
    from app.core.outbox import enqueue_event, fan_out_pending

    disabled = _destination("switched off", enabled=False)
    db.add(disabled)
    event = await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE})
    await db.commit()

    assert await fan_out_pending(db) == 0
    assert await _deliveries(db) == []
    assert event.fanned_out is True

    disabled.enabled = True
    await db.commit()
    assert await fan_out_pending(db) == 0
    assert await _deliveries(db) == []


async def test_fan_out_is_one_shot_so_a_later_destination_never_sees_the_event(db) -> None:
    """The fresh-install case: events produced before any destination exists are
    burned by the first tick of the worker, and the destination configured that
    afternoon starts from empty. Worth questioning, not fixed here."""
    from app.core.outbox import enqueue_event, fan_out_pending

    event = await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE})
    await db.commit()

    assert await fan_out_pending(db) == 0
    assert event.fanned_out is True

    db.add(_destination("configured later"))
    await db.commit()

    # Nothing left to select: the flag, not the absence of deliveries, is what the
    # pass looks at.
    assert await fan_out_pending(db) == 0
    assert await _deliveries(db) == []


async def test_fan_out_drains_every_unfanned_event_in_a_single_pass(db) -> None:
    """No batch size, no LIMIT, no per-tick ceiling: one call handles the whole
    backlog and creates one row per event per destination in one transaction. Twelve
    events stands in for a sweep's worth; the property is that the number does not
    matter to the pass, which is precisely what #81's volume change leans on."""
    from app.core.outbox import enqueue_event, fan_out_pending

    db.add_all([_destination("first"), _destination("second")])
    for index in range(12):
        await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "index": index})
    await db.commit()

    assert await fan_out_pending(db) == 24
    assert len(await _deliveries(db)) == 24
    assert await fan_out_pending(db) == 0  # and the backlog is empty afterwards


# --- 2. The shape of the passes: every column, every row, no limit -----------------


def _capture_sql():
    """Record the SQL the passes actually send. The unbounded selects are the two
    things #81's review named as prerequisites, so they are pinned as statements
    rather than inferred from row counts."""
    from sqlalchemy import event as sa_event

    from app.core.database import engine

    statements: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany) -> None:
        statements.append(statement)

    sa_event.listen(engine.sync_engine, "before_cursor_execute", _record)
    return statements, lambda: sa_event.remove(engine.sync_engine, "before_cursor_execute", _record)


async def test_the_fan_out_pass_selects_the_whole_payload_just_to_flip_a_boolean(db) -> None:
    """`select(EventOutbox)` — every column of every un-fanned row, JSONB payload
    included, when the pass only reads `event_type` and writes `fanned_out`. At
    30KB a row and 40,000 rows that is the whole sweep pulled into the worker for
    nothing.
    Characterized deliberately: fixing it is #81's work, not this file's."""
    from app.core.outbox import enqueue_event, fan_out_pending

    db.add(_destination("siem"))
    await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "big": "x" * 1000})
    await db.commit()

    statements, stop = _capture_sql()
    try:
        await fan_out_pending(db)
    finally:
        stop()

    selects = [text for text in statements if "FROM event_outbox" in text and text.lstrip().startswith("SELECT")]
    assert selects, "the fan-out pass must have read the outbox"
    assert "event_outbox.payload" in selects[0]
    assert "LIMIT" not in selects[0].upper()


async def test_the_delivery_pass_loads_every_due_row_and_every_event_it_names(db) -> None:
    """Same shape on the delivery side: all due deliveries, then their events by id —
    both unbounded, both full rows, both resident in the worker at once."""
    from app.core.outbox import deliver_pending

    await _one_pending_delivery(db)

    statements, stop = _capture_sql()
    try:
        await deliver_pending(db)
    finally:
        stop()

    due = [text for text in statements if "FROM outbox_deliveries" in text and text.lstrip().startswith("SELECT")]
    events = [text for text in statements if "FROM event_outbox" in text and text.lstrip().startswith("SELECT")]
    assert due and "LIMIT" not in due[0].upper()
    assert events and "event_outbox.payload" in events[0]
    assert "LIMIT" not in events[0].upper()


# --- 3. Producer volume: what one connection sync enqueues today -------------------


@pytest.fixture
def jamf(monkeypatch: pytest.MonkeyPatch) -> FakeJamf:
    from app.mdm.jamf.client import JamfClient

    fake = FakeJamf()

    @asynccontextmanager
    async def _mock_http(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as client:
            yield client

    monkeypatch.setattr(JamfClient, "http", _mock_http)
    return fake


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    from app.models.schema import (
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
    )

    row = MdmConnection(
        name=f"outbox jamf {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
        capability_webhooks=True,
    )
    db.add(row)
    await db.commit()
    connection_id = row.id
    try:
        yield row
    finally:
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


async def test_a_sync_enqueues_one_event_per_changed_device_and_nothing_for_the_rest(
    db, connection, jamf: FakeJamf
) -> None:
    """The number #81 rewrites, written down before it changes.

    Today the producer is delta-shaped: a device whose app inventory did not move
    produces no event at all, so a quiet fleet costs an empty outbox. The proposed
    ruling makes it one snapshot per device per sweep — the same two-device tenant
    would produce 2 here *and* 2 on the second sweep, and a 40,000-device tenant
    40,000 of them every time.
    """
    from app.mdm.service import sync_connection
    from app.models.schema import EventOutbox

    async def _by_type() -> dict[str, int]:
        rows = await db.execute(
            select(EventOutbox.event_type, func.count()).group_by(EventOutbox.event_type)
        )
        return dict(rows.all())

    first = await sync_connection(db, connection)
    assert first.ok
    # Two computers in the fake tenant, both seen for the first time, both with apps —
    # and nothing else in the outbox but the sweep's own completion event.
    assert await _by_type() == {"device.inventory.changed": 2, "run.completed": 1}

    second = await sync_connection(db, connection)
    assert second.ok
    # The delta shape, in one line: the second sweep of an unchanged fleet adds its
    # run event and not one device event.
    assert await _by_type() == {"device.inventory.changed": 2, "run.completed": 2}


# --- 4. Delivery: success, failure, backoff, dead-letter, disabled ------------------


async def test_a_successful_post_is_stamped_delivered_exactly_once(db, monkeypatch) -> None:
    from app.core.outbox import deliver_pending

    seen = _mock_posts(monkeypatch)
    destination, _event, delivery = await _one_pending_delivery(db)

    await deliver_pending(db)

    assert delivery.status == "delivered"
    assert delivery.attempt_count == 1
    assert delivery.last_error is None
    # One clock for the whole pass: `now` is read once at the top of deliver_pending
    # and stamped on every row it touches, so these three are the same instant even
    # when the pass takes minutes.
    assert delivery.delivered_at == delivery.last_attempted_at
    assert destination.last_success_at == delivery.delivered_at
    assert destination.last_failure_at is None
    assert len(seen) == 1 and str(seen[0].url) == destination.url

    # `delivered` is terminal: the next tick does not re-POST it.
    await deliver_pending(db)
    assert len(seen) == 1
    assert delivery.attempt_count == 1


async def test_a_failed_post_stays_pending_and_waits_out_the_backoff(db, monkeypatch) -> None:
    """Failure is not `failed`. The row stays `pending` with a future
    `next_attempt_at`, which is what the retry budget is spent through — only
    exhausting it (or losing the destination row) writes `failed`."""
    from app.core.outbox import deliver_pending

    seen = _mock_posts(monkeypatch, _boom)
    destination, _event, delivery = await _one_pending_delivery(db)
    before = datetime.now(timezone.utc)

    await deliver_pending(db)

    assert delivery.status == "pending"
    assert delivery.attempt_count == 1
    assert delivery.delivered_at is None
    assert delivery.last_error is not None and delivery.last_error.startswith("HTTP 500")
    assert destination.last_failure_at == delivery.last_attempted_at
    assert destination.last_success_at is None
    # backoff(1), not backoff(0): the counter is incremented first, so the first
    # retry is a minute out rather than the 30s base.
    assert 55 <= (delivery.next_attempt_at - before).total_seconds() <= 75

    # And the backoff is real — a second tick inside that minute makes no request.
    await deliver_pending(db)
    assert len(seen) == 1
    assert delivery.attempt_count == 1


async def test_a_delivery_scheduled_for_later_is_not_even_read(db, monkeypatch) -> None:
    from app.core.outbox import deliver_pending

    seen = _mock_posts(monkeypatch)
    _destination_row, _event, delivery = await _one_pending_delivery(db)
    delivery.next_attempt_at = datetime.now(timezone.utc) + timedelta(hours=1)
    await db.commit()

    await deliver_pending(db)

    assert seen == []
    assert delivery.attempt_count == 0
    assert delivery.last_attempted_at is None
    assert delivery.status == "pending"


async def test_the_tenth_failure_dead_letters_and_schedules_nothing(db, monkeypatch) -> None:
    """`attempt_count >= _MAX_ATTEMPTS` writes `failed` and deliberately does not
    advance `next_attempt_at`, so a dead-lettered row keeps the stale schedule it
    died on. Harmless — `status` is what the pass filters on — but it means
    `next_attempt_at` on a failed row is not a time anything will happen."""
    from app.core.outbox import _MAX_ATTEMPTS, deliver_pending

    seen = _mock_posts(monkeypatch, _boom)
    _destination_row, _event, delivery = await _one_pending_delivery(db)
    stale = datetime.now(timezone.utc) - timedelta(hours=1)
    delivery.attempt_count = _MAX_ATTEMPTS - 1
    delivery.next_attempt_at = stale
    await db.commit()

    await deliver_pending(db)

    assert delivery.attempt_count == _MAX_ATTEMPTS
    assert delivery.status == "failed"
    assert delivery.next_attempt_at == stale
    assert delivery.delivered_at is None
    assert len(seen) == 1

    # `failed` is terminal too: nothing revives a dead-lettered row.
    await deliver_pending(db)
    assert len(seen) == 1


async def test_a_destination_disabled_after_fan_out_leaves_its_delivery_pending(db, monkeypatch) -> None:
    """The documented pause. A destination switched off between fan-out and delivery
    is skipped without touching the row at all — no attempt, no error, no backoff —
    so re-enabling it resumes the queue instead of dead-lettering work the operator
    never wanted attempted. The cost is that the row (and, per the retention section
    below, its event) stays in the table for as long as the destination is off."""
    from app.core.outbox import deliver_pending

    seen = _mock_posts(monkeypatch)
    destination, _event, delivery = await _one_pending_delivery(db)
    destination.enabled = False
    await db.commit()

    await deliver_pending(db)

    assert seen == []
    assert delivery.status == "pending"
    assert delivery.attempt_count == 0
    assert delivery.last_attempted_at is None
    assert delivery.last_error is None
    assert destination.last_failure_at is None
    # Still due, so every tick re-reads it for as long as it stays disabled.
    assert delivery.next_attempt_at <= datetime.now(timezone.utc)

    destination.enabled = True
    await db.commit()
    await deliver_pending(db)

    assert len(seen) == 1
    assert delivery.status == "delivered"


async def test_one_destination_failing_does_not_hold_up_the_other(db, monkeypatch) -> None:
    """Why the delivery row is per (event, destination): the same event delivered to
    a healthy and a broken destination gets two independent verdicts in one pass."""
    from app.core.outbox import deliver_pending, enqueue_event, fan_out_pending

    def _split(request: httpx.Request) -> httpx.Response:
        return _boom(request) if "broken" in str(request.url) else _ok(request)

    seen = _mock_posts(monkeypatch, _split)
    healthy = _destination("healthy")
    broken = _destination("broken")
    db.add_all([healthy, broken])
    await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE})
    await db.commit()
    await fan_out_pending(db)

    await deliver_pending(db)

    by_destination = {row.destination_id: row for row in await _deliveries(db)}
    assert by_destination[healthy.id].status == "delivered"
    assert by_destination[broken.id].status == "pending"
    assert by_destination[broken.id].attempt_count == 1
    assert len(seen) == 2


# --- 5. Retention: what a pending delivery keeps alive ------------------------------


async def _age_event(db, event, days: int) -> None:
    event.created_at = datetime.now(timezone.utc) - timedelta(days=days)
    await db.commit()


async def _counts(db) -> tuple[int, int]:
    from app.models.schema import EventOutbox, OutboxDelivery

    events = (await db.execute(select(func.count()).select_from(EventOutbox))).scalar_one()
    deliveries = (await db.execute(select(func.count()).select_from(OutboxDelivery))).scalar_one()
    return events, deliveries


async def test_purge_deletes_an_old_event_and_the_deliveries_that_finished(db, monkeypatch) -> None:
    from app.core.outbox import deliver_pending, purge_delivered_events

    _mock_posts(monkeypatch)
    _destination_row, event, _delivery = await _one_pending_delivery(db)
    await deliver_pending(db)
    await _age_event(db, event, days=10)

    assert await purge_delivered_events(db, 7) == 1
    assert await _counts(db) == (0, 0)


async def test_purge_leaves_an_event_younger_than_retention_alone(db, monkeypatch) -> None:
    from app.core.outbox import deliver_pending, purge_delivered_events

    _mock_posts(monkeypatch)
    _destination_row, _event, _delivery = await _one_pending_delivery(db)
    await deliver_pending(db)

    assert await purge_delivered_events(db, 7) == 0
    assert await _counts(db) == (1, 1)
    # The cutoff is `created_at < now - retention_days`, so a retention of zero days
    # means "everything already written", not "nothing".
    assert await purge_delivered_events(db, 0) == 1
    assert await _counts(db) == (0, 0)


async def test_one_pending_delivery_keeps_the_event_and_its_delivered_sibling(db, monkeypatch) -> None:
    """`purge_delivered_events` is all-or-nothing per event: one delivery still
    mid-retry protects the event *and* every already-delivered delivery row hanging
    off it, however old they are. Correct — the pending row still needs the payload —
    and the reason a single broken destination pins a whole sweep's storage."""
    from app.core.outbox import deliver_pending, enqueue_event, fan_out_pending, purge_delivered_events
    from app.models.schema import OutboxDelivery

    def _split(request: httpx.Request) -> httpx.Response:
        return _boom(request) if "broken" in str(request.url) else _ok(request)

    _mock_posts(monkeypatch, _split)
    healthy = _destination("healthy")
    broken = _destination("broken")
    db.add_all([healthy, broken])
    event = await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE})
    await db.commit()
    await fan_out_pending(db)
    await deliver_pending(db)
    await _age_event(db, event, days=365)

    assert await purge_delivered_events(db, 7) == 0
    assert await _counts(db) == (1, 2)

    # Once the last pending row reaches a terminal state, the whole event goes.
    await db.execute(
        OutboxDelivery.__table__.update()
        .where(OutboxDelivery.destination_id == broken.id)
        .values(status="failed")
    )
    await db.commit()
    assert await purge_delivered_events(db, 7) == 1
    assert await _counts(db) == (0, 0)


async def test_an_event_that_was_never_fanned_out_is_never_purged(db) -> None:
    """`fanned_out.is_(True)` is part of the candidate filter, so an event the worker
    never reached is kept for ever rather than dropped unsent. Protective as written;
    it also means a tenant whose worker never ran accumulates outbox rows that no
    retention setting will ever clear."""
    from app.core.outbox import enqueue_event, purge_delivered_events

    event = await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE})
    await db.commit()
    await _age_event(db, event, days=365)

    assert await purge_delivered_events(db, 7) == 0
    assert await _counts(db) == (1, 0)


async def test_a_disabled_destination_makes_its_events_immortal(db, monkeypatch) -> None:
    """The composition behind #81's open storage question, as one test.

    A disabled destination's deliveries stay `pending` for ever by design (section 4),
    and a pending delivery blocks the purge for ever by design (above). Together:
    switching a destination off freezes every event fanned out to it in the table,
    at any age, with no retention setting that clears it and nothing in the product
    that reports the growth. Today that is one event per changed device; under #81 it
    would be a 30KB snapshot per device per sweep.
    """
    from app.core.outbox import deliver_pending, purge_delivered_events

    seen = _mock_posts(monkeypatch)
    destination, event, delivery = await _one_pending_delivery(db)
    destination.enabled = False
    await db.commit()

    for _tick in range(3):
        await deliver_pending(db)
    assert seen == []
    assert delivery.status == "pending"

    await _age_event(db, event, days=365)
    assert await purge_delivered_events(db, 7) == 0
    assert await purge_delivered_events(db, 0) == 0
    assert await _counts(db) == (1, 1)
