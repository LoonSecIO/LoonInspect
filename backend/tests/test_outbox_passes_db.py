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
   carries, and the one-way `fanned_out` flag — set once the event has been
   *considered* against the enabled destinations. Considered-and-declined counts: a
   destination subscribed to other event types marks the event without producing a
   row. Nothing enabled at all does not count, and the event is held (#157).
2. **The shape of the passes.** Both read every column of every row they take, and
   both now stop at a per-tick ceiling with an ORDER BY that makes the remainder the
   next tick's head. `fan_out_pending` still drags the full JSONB payload out of the
   database purely to flip a boolean — narrowing the columns is #81's, and the
   assertion stays until it moves. Pinned by capturing the SQL, because a LIMIT with
   the wrong ORDER BY passes every behavioural test here while starving the back of
   the queue.
3. **Producer volume.** One connection sync of a two-device tenant: how many events
   the first sweep enqueues, and how many the second, unchanged sweep does. This is
   the number #81 rewrites.
4. **Delivery.** Success, failure, backoff, the ten-attempt dead-letter, and the
   disabled-destination path that leaves a delivery pending on purpose.
5. **Retention.** `purge_delivered_events` refusing to touch an event that still
   holds one pending delivery — and what that composes into when a destination is
   left disabled, which is the open storage question on #81. Held events carry no
   delivery row, so nothing shields them: they age out on the ordinary window (#157).
6. **The per-tick ceiling.** A backlog larger than `_TICK_LIMIT` drains across ticks
   losing nothing; a backlog smaller than it behaves exactly as it did before the
   ceiling existed; and — the one that would be worst to get wrong — a delivery the
   tick simply did not reach keeps its `attempt_count` and `next_attempt_at` untouched,
   so being deferred can never spend a healthy destination's retry budget.

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


async def test_fan_out_holds_the_event_when_the_only_destination_is_disabled(db) -> None:
    """A disabled destination is not an enabled destination, so the pass has nothing
    to consider and holds the event rather than burning it (#157). Re-enabling the
    destination a minute later therefore *does* backfill — the ordinary next pass
    picks the held event up, with no re-fan machinery involved.

    Scoped to the only-destination case, deliberately: the guard is all-or-nothing
    across destinations, not per-destination. Add one *enabled* destination beside this
    disabled one and the enabled one takes the event, the flag is set, and re-enabling
    the second backfills nothing. Backfill is a property of holding, not of enabling."""
    from app.core.outbox import enqueue_event, fan_out_pending

    disabled = _destination("switched off", enabled=False)
    db.add(disabled)
    event = await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE})
    await db.commit()

    assert await fan_out_pending(db) == 0
    assert await _deliveries(db) == []
    assert event.fanned_out is False

    disabled.enabled = True
    await db.commit()
    assert await fan_out_pending(db) == 1
    (delivery,) = await _deliveries(db)
    assert delivery.destination_id == disabled.id
    assert event.fanned_out is True


async def test_fan_out_holds_events_produced_before_any_destination_exists(db) -> None:
    """The onboarding case #157 was filed for. The setup stepper orders connect →
    first sync → add a destination, and calls the last step optional, so a whole
    baseline sweep normally completes with nothing configured. Those events wait
    instead of being consumed by the first worker tick."""
    from app.core.outbox import enqueue_event, fan_out_pending

    event = await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE})
    await db.commit()

    assert await fan_out_pending(db) == 0
    assert event.fanned_out is False

    db.add(_destination("configured later"))
    await db.commit()

    # Still selectable, because the flag was never set: the destination added that
    # afternoon receives the morning's baseline.
    assert await fan_out_pending(db) == 1
    assert len(await _deliveries(db)) == 1
    assert event.fanned_out is True


async def test_fan_out_marks_an_event_no_destination_subscribes_to(db) -> None:
    """The line between "considered and declined" and "nothing to consider".

    A destination that exists but is subscribed to other event types produces no
    delivery row — and that event is still burned, because it *was* judged against the
    destinations that exist and legitimately not delivered. Only the empty-destination
    case holds. Getting this wrong would hold subscription-filtered events for ever and
    quietly redefine what `subscribed_events` means.
    """
    from app.core.outbox import enqueue_event, fan_out_pending

    db.add(_destination("runs only", subscribed_events=["run.completed"]))
    event = await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE})
    await db.commit()

    # Zero rows created, exactly as when no destination exists — and the flag is what
    # tells the two apart.
    assert await fan_out_pending(db) == 0
    assert await _deliveries(db) == []
    assert event.fanned_out is True

    # So it is not re-considered when a subscriber for its type arrives later.
    db.add(_destination("everything"))
    await db.commit()
    assert await fan_out_pending(db) == 0
    assert await _deliveries(db) == []


async def test_the_baseline_reaches_a_destination_added_after_the_first_sync(db, monkeypatch) -> None:
    """#157 end to end, through both passes: events enqueued with nothing configured,
    a Splunk destination added afterwards, and the next worker tick POSTing every one
    of them. This is the whole reason the hold exists — the first sweep is the largest
    and most interesting pull the pod will ever do."""
    from app.core.outbox import deliver_pending, enqueue_event, fan_out_pending

    seen = _mock_posts(monkeypatch)

    for index in range(5):
        await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "index": index})
    await db.commit()

    # The worker ticks all through the baseline sweep with no destination configured.
    for _tick in range(3):
        await fan_out_pending(db)
        await deliver_pending(db)
    assert seen == []
    assert await _counts(db) == (5, 0)

    destination = _destination("splunk, added that afternoon")
    db.add(destination)
    await db.commit()

    await fan_out_pending(db)
    await deliver_pending(db)

    assert len(seen) == 5
    deliveries = await _deliveries(db)
    assert len(deliveries) == 5
    assert {row.status for row in deliveries} == {"delivered"}
    assert {json.loads(request.content)["index"] for request in seen} == set(range(5))


async def test_fan_out_drains_a_backlog_under_the_ceiling_in_a_single_pass(db) -> None:
    """A backlog smaller than _TICK_LIMIT is handled exactly as it was before the
    ceiling landed: one call, one transaction, one row per event per destination, and
    an empty backlog afterwards. Twelve events stands in for a sweep's worth. The
    ceiling is not supposed to be observable below itself, and this is the assertion
    that says so."""
    from app.core.outbox import _TICK_LIMIT, enqueue_event, fan_out_pending

    assert _TICK_LIMIT > 12, "this test only means anything below the ceiling"
    db.add_all([_destination("first"), _destination("second")])
    for index in range(12):
        await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "index": index})
    await db.commit()

    assert await fan_out_pending(db) == 24
    assert len(await _deliveries(db)) == 24
    assert await fan_out_pending(db) == 0  # and the backlog is empty afterwards


# --- 2. The shape of the passes: every column, a bounded number of rows ------------


def _capture_sql():
    """Record the SQL the passes actually send. The per-tick ceiling and the order it
    applies to are pinned as statements rather than inferred from row counts: a LIMIT
    with the wrong ORDER BY still passes every behavioural test in this file while
    quietly starving the back of the queue."""
    from sqlalchemy import event as sa_event

    from app.core.database import engine

    statements: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany) -> None:
        statements.append(statement)

    sa_event.listen(engine.sync_engine, "before_cursor_execute", _record)
    return statements, lambda: sa_event.remove(engine.sync_engine, "before_cursor_execute", _record)


async def test_the_fan_out_pass_still_selects_the_whole_payload_but_only_a_tickful(db) -> None:
    """Two halves, one statement.

    Unchanged: `select(EventOutbox)` is still every column of every row it reads,
    JSONB payload included, when the pass only reads `event_type` and writes
    `fanned_out`. Narrowing the columns is #81's work, not this change's, and the
    assertion stays so the day it moves is visible.

    Changed: the row count is now capped, and ordered oldest-first by `id` so the
    remainder the next tick sees is the tail of this one rather than an arbitrary
    re-slice of the same set."""
    from app.core.outbox import _TICK_LIMIT, enqueue_event, fan_out_pending

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
    assert "ORDER BY event_outbox.id" in selects[0]
    assert "LIMIT" in selects[0].upper()
    assert _TICK_LIMIT == 1000


async def test_a_destination_less_pass_never_reads_the_held_backlog(db) -> None:
    """The other half of the select above, and the reason the #157 guard is ordered the
    way it is. Holding means the un-fanned set now grows for the whole retention window
    on a pod with nothing configured — the state the stepper calls optional — while the
    worker ticks every 30s. If the guard sat below the events select, each of those
    ticks would drag a thousand held payloads into the worker to conclude there was
    nothing to do — the whole window before the per-tick ceiling landed, which is better
    and still entirely wasted. So the cheap indexed question is asked first, and a
    destination-less tick touches `event_outbox` not at all."""
    from app.core.outbox import enqueue_event, fan_out_pending

    for index in range(3):
        await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "index": index, "big": "x" * 1000})
    await db.commit()

    statements, stop = _capture_sql()
    try:
        assert await fan_out_pending(db) == 0
    finally:
        stop()

    assert [text for text in statements if "FROM destinations" in text], "it must ask which destinations exist"
    assert [text for text in statements if "FROM event_outbox" in text] == []

    # And the hold itself still stands: nothing was consumed by the pass that declined
    # to read it.
    assert await _counts(db) == (3, 0)


async def test_the_delivery_pass_reads_a_bounded_due_set_oldest_first(db) -> None:
    """Same shape on the delivery side: due deliveries, then their events by id, both
    full rows and both resident in the worker at once — but now at most _TICK_LIMIT of
    them, so what is resident is bounded by the ceiling instead of by the fleet.

    The ORDER BY is the assertion that matters most here. `next_attempt_at` first,
    which is the queue's own due-time discipline and the column
    ix_outbox_deliveries_next_attempt_at covers; `id` only as the tiebreak that makes
    the order total. Ordering by id alone would put every retry ahead of every event
    produced since it first failed, which under a ceiling is starvation.

    The events select carries no LIMIT of its own and does not need one: it is driven
    by the ids of the already-capped due set, and `_in_batches` keeps it inside
    asyncpg's bind-parameter budget."""
    from app.core.outbox import deliver_pending

    await _one_pending_delivery(db)

    statements, stop = _capture_sql()
    try:
        await deliver_pending(db)
    finally:
        stop()

    due = [text for text in statements if "FROM outbox_deliveries" in text and text.lstrip().startswith("SELECT")]
    events = [text for text in statements if "FROM event_outbox" in text and text.lstrip().startswith("SELECT")]
    assert due and "LIMIT" in due[0].upper()
    assert "ORDER BY outbox_deliveries.next_attempt_at, outbox_deliveries.id" in due[0]
    assert events and "event_outbox.payload" in events[0]
    assert "event_outbox.id IN" in events[0]


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


async def test_a_held_event_ages_out_on_the_ordinary_retention_window(db) -> None:
    """The other half of #157's ruling. Holding un-fanned events (so a destination
    added later still receives them) would be unbounded growth on a pod that never
    adds one, because a held event has no delivery row for the still-pending guard to
    protect it with. Age is therefore the whole candidate test: seven days to
    configure a destination and collect the baseline, then the queue stops being a
    queue."""
    from app.core.outbox import enqueue_event, purge_delivered_events

    event = await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE})
    await db.commit()

    # Inside the window it is still waiting for a destination, not garbage.
    assert await purge_delivered_events(db, 7) == 0
    assert await _counts(db) == (1, 0)

    await _age_event(db, event, days=8)
    assert event.fanned_out is False
    assert await purge_delivered_events(db, 7) == 1
    assert await _counts(db) == (0, 0)


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


# --- 6. The per-tick ceiling: drain across ticks, and touch nothing else ------------
#
# Both passes take at most _TICK_LIMIT rows. These tests lower the ceiling rather than
# building a thousand-row backlog: the property under test is "the pass stops at the
# ceiling and the next one resumes", which is the same property at 3 as at 1,000, and a
# suite that spends a real sweep's worth of inserts to prove it is a suite nobody runs.


def _lower_the_ceiling(monkeypatch: pytest.MonkeyPatch, rows: int) -> None:
    """Both passes read `_TICK_LIMIT` off the module at call time, so this is the seam."""
    from app.core import outbox

    monkeypatch.setattr(outbox, "_TICK_LIMIT", rows)


async def test_a_fan_out_backlog_larger_than_the_ceiling_drains_across_ticks(db, monkeypatch) -> None:
    """Nothing is lost and nothing is fanned twice: seven events under a ceiling of
    three become 3 + 3 + 1 delivery rows over three ticks, in arrival order, and the
    fourth tick has nothing left to do."""
    from app.core.outbox import enqueue_event, fan_out_pending

    db.add(_destination("siem"))
    events = [await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "index": index}) for index in range(7)]
    await db.commit()
    arrival = [event.id for event in events]
    _lower_the_ceiling(monkeypatch, 3)

    assert await fan_out_pending(db) == 3
    # Oldest first, and the slice is a prefix of arrival order rather than any three
    # rows — which is the difference between a queue and a lottery.
    assert [row.outbox_event_id for row in await _deliveries(db)] == arrival[:3]

    assert await fan_out_pending(db) == 3
    assert [row.outbox_event_id for row in await _deliveries(db)] == arrival[:6]

    assert await fan_out_pending(db) == 1
    assert [row.outbox_event_id for row in await _deliveries(db)] == arrival

    assert await fan_out_pending(db) == 0
    assert await _counts(db) == (7, 7)


async def test_a_delivery_deferred_by_the_ceiling_keeps_its_whole_retry_budget(db, monkeypatch) -> None:
    """The one that would be worst to get wrong.

    A row the tick did not reach must be indistinguishable from a row the tick never
    saw: same attempt_count, same next_attempt_at, no last_attempted_at, no last_error.
    Treating a deferred delivery as a failed attempt would burn the ten-try budget of a
    destination that is answering 200 to everything it is actually asked, and
    dead-letter healthy events on a schedule — silently, since only the row records it.
    That is a strictly worse failure than the unbounded load the ceiling replaces, so it
    is pinned rather than reasoned about.
    """
    from app.core.outbox import deliver_pending, enqueue_event, fan_out_pending

    seen = _mock_posts(monkeypatch)
    db.add(_destination("siem"))
    for index in range(7):
        await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "index": index})
    await db.commit()
    await fan_out_pending(db)

    before = {row.id: (row.attempt_count, row.next_attempt_at) for row in await _deliveries(db)}
    _lower_the_ceiling(monkeypatch, 3)

    await deliver_pending(db)

    rows = await _deliveries(db)
    assert [row.status for row in rows] == ["delivered"] * 3 + ["pending"] * 4
    assert len(seen) == 3
    for row in rows[3:]:
        assert (row.attempt_count, row.next_attempt_at) == before[row.id]
        assert row.last_attempted_at is None
        assert row.last_error is None

    # And the budget really is intact: every one of the seven eventually lands on its
    # first attempt, not its second.
    await deliver_pending(db)
    await deliver_pending(db)
    rows = await _deliveries(db)
    assert {row.status for row in rows} == {"delivered"}
    assert {row.attempt_count for row in rows} == {1}
    assert {json.loads(request.content)["index"] for request in seen} == set(range(7))


async def test_the_ceiling_takes_the_most_overdue_delivery_not_the_oldest_row(db, monkeypatch) -> None:
    """`ORDER BY next_attempt_at`, not `ORDER BY id`, and the two disagree exactly when
    it matters. A row that has failed and backed off has an older id than everything
    produced while it waited; ordering by id would hand it the whole ceiling on every
    tick and the newer events would never be reached. Ordering by due time puts it back
    in line where the backoff placed it."""
    from app.core.outbox import deliver_pending, enqueue_event, fan_out_pending

    seen = _mock_posts(monkeypatch)
    db.add(_destination("siem"))
    for index in range(3):
        await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "index": index})
    await db.commit()
    await fan_out_pending(db)

    # Due-time order deliberately the reverse of id order.
    now = datetime.now(timezone.utc)
    overdue = [timedelta(seconds=1), timedelta(minutes=5), timedelta(hours=1)]
    for row, overdue_by in zip(await _deliveries(db), overdue, strict=True):
        row.next_attempt_at = now - overdue_by
    await db.commit()
    _lower_the_ceiling(monkeypatch, 1)

    await deliver_pending(db)
    assert [row.status for row in await _deliveries(db)] == ["pending", "pending", "delivered"]
    assert json.loads(seen[0].content)["index"] == 2

    await deliver_pending(db)
    assert [row.status for row in await _deliveries(db)] == ["pending", "delivered", "delivered"]
    assert json.loads(seen[1].content)["index"] == 1


async def test_a_delivery_backlog_under_the_ceiling_is_drained_in_one_tick(db, monkeypatch) -> None:
    """The no-change assertion. Below the ceiling the pass must behave exactly as it did
    before it had one: every due row attempted in a single tick, none held back."""
    from app.core.outbox import _TICK_LIMIT, deliver_pending, enqueue_event, fan_out_pending

    seen = _mock_posts(monkeypatch)
    db.add(_destination("siem"))
    for index in range(6):
        await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "index": index})
    await db.commit()
    await fan_out_pending(db)
    assert _TICK_LIMIT > 6, "this test only means anything below the ceiling"

    await deliver_pending(db)

    rows = await _deliveries(db)
    assert len(rows) == 6
    assert {row.status for row in rows} == {"delivered"}
    assert {row.attempt_count for row in rows} == {1}
    assert {json.loads(request.content)["index"] for request in seen} == set(range(6))
