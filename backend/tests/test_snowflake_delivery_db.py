"""Real Postgres persistence plus a synthetic Named Channel peer: crash and partial acceptance recovery."""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text

from app.core import snowflake_delivery as worker
from app.models.schema import Destination, EventOutbox, OutboxDelivery, SnowflakeBatch, SnowflakeSource
from tests.snowflake_fake import CONFIG, URL, FakeSnowflake, install, pem

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres"),
    pytest.mark.asyncio(loop_scope="session"),
]
TENANT = uuid.UUID("00000000-0000-0000-0000-000000000848")
OTHER_TENANT = uuid.UUID("00000000-0000-0000-0000-000000008848")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenants():
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, unscoped_session
    from app.models.schema import Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        for tenant in (TENANT, OTHER_TENANT):
            if await db.get(Tenant, tenant) is None:
                db.add(Tenant(id=tenant, slug=f"snowflake-{tenant}", name="Synthetic warehouse test", kind="operational"))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def db(tenants):
    from app.core.database import session_for_tenant

    async with session_for_tenant(TENANT) as session:
        for table in (SnowflakeBatch, OutboxDelivery, EventOutbox, Destination, SnowflakeSource):
            await session.execute(delete(table))
        await session.commit()
        try:
            yield session
        finally:
            await session.rollback()
            for table in (SnowflakeBatch, OutboxDelivery, EventOutbox, Destination, SnowflakeSource):
                await session.execute(delete(table))
            await session.commit()


@pytest.fixture(scope="module")
def secret():
    return pem()


@pytest.fixture
def fake(monkeypatch):
    peer = FakeSnowflake()
    install(monkeypatch, peer)
    return peer


async def destination(db, secret):
    row = Destination(
        name="Synthetic warehouse",
        type="snowflake",
        url=URL,
        auth_type="snowflake_jwt",
        auth_secret_encrypted=secret,
        snowflake_config=CONFIG,
        enabled=True,
    )
    db.add(row)
    await db.commit()
    return row


async def events(db, target, *payloads):
    ids = []
    for payload in payloads:
        event = EventOutbox(
            event_type="device.change",
            payload={"event": "device.change", "occurredAt": "2026-11-23T12:00:00Z", **payload},
            fanned_out=True,
        )
        db.add(event)
        await db.flush()
        delivery = OutboxDelivery(outbox_event_id=event.id, destination_id=target.id)
        db.add(delivery)
        await db.flush()
        ids.append(delivery.id)
    await db.commit()
    return ids


async def deliveries(db):
    return (await db.execute(select(OutboxDelivery).order_by(OutboxDelivery.id))).scalars().all()


async def test_committed_row_counts_and_durable_before_send(db, secret, fake):
    from app.core.database import session_for_tenant

    target = await destination(db, secret)
    await events(db, target, {"value": "27.2.1"}, {"value": "27.2.10"})

    async def evidence(request):
        async with session_for_tenant(TENANT) as other:
            batch = (await other.execute(select(SnowflakeBatch))).scalar_one()
            assert batch.body.encode() == request.content
            assert batch.baseline == {"inserted": 0, "rejected": 0, "offset": None}
            assert len(batch.delivery_ids) == 2

    fake.on_append = evidence
    await worker.deliver_destination(db, target)
    assert [row.status for row in await deliveries(db)] == ["delivered", "delivered"]
    assert len(fake.rows) == 2
    assert len({row["SOURCE_EVENT_KEY"] for row in fake.rows}) == 2
    assert (await db.execute(select(SnowflakeBatch))).scalar_one_or_none() is None
    stored = (
        await db.execute(text("SELECT auth_secret_encrypted FROM destinations WHERE id=:id"), {"id": target.id})
    ).scalar_one()
    assert secret not in stored and "PRIVATE KEY" not in stored


@pytest.mark.parametrize("accepted_before_timeout", [True, False])
async def test_restart_after_ambiguous_append_never_loses_event(db, secret, fake, accepted_before_timeout, caplog):
    from app.core.database import session_for_tenant

    target = await destination(db, secret)
    await events(db, target, {"value": "synthetic"})
    fake.lose_response = accepted_before_timeout
    fake.drop_request = not accepted_before_timeout
    await worker.deliver_destination(db, target)
    batch = (await db.execute(select(SnowflakeBatch))).scalar_one()
    saved = batch.body
    assert (await deliveries(db))[0].status == "pending"
    async with session_for_tenant(TENANT) as restarted:
        await worker.deliver_destination(restarted, await restarted.get(Destination, target.id))
    await db.rollback()
    assert (await deliveries(db))[0].status == "delivered"
    assert all(body.decode() == saved for _, body in fake.appends)
    assert len(fake.appends) == (1 if accepted_before_timeout else 2)
    assert len(fake.rows) == 1
    assert "SYNTHETIC_PRIVATE_UPSTREAM" not in caplog.text


async def test_mixed_batch_stays_unresolved_until_singleton_proof(db, secret, fake):
    target = await destination(db, secret)
    await events(db, target, {"value": "accepted"}, {"syntheticReject": True})
    await worker.deliver_destination(db, target)
    rows = await deliveries(db)
    assert all(row.status == "pending" and row.snowflake_single_row for row in rows)
    first_keys = [json.loads(line)["SOURCE_EVENT_KEY"] for line in fake.appends[0][1].splitlines()]
    await worker.deliver_destination(db, target)
    await worker.deliver_destination(db, target)
    assert [row.status for row in await deliveries(db)] == ["delivered", "failed"]
    assert [json.loads(body)["SOURCE_EVENT_KEY"] for _, body in fake.appends[1:]] == first_keys
    assert len(fake.rows) == 2 and len({row["SOURCE_EVENT_KEY"] for row in fake.rows}) == 1


async def test_uncommitted_rows_retained_without_resend_or_purge(db, secret, fake):
    from app.core.outbox import purge_delivered_events

    target = await destination(db, secret)
    await events(db, target, {"value": "pending"})
    event = (await db.execute(select(EventOutbox))).scalar_one()
    event.created_at = datetime.now(UTC) - timedelta(days=90)
    await db.commit()
    fake.delay = True
    await worker.deliver_destination(db, target)
    await worker.deliver_destination(db, target)  # Reopen refuses pending rows (409).
    assert len(fake.appends) == 1
    assert (await deliveries(db))[0].status == "pending"
    assert await purge_delivered_events(db, 7, 30) == 0
    fake.flush()
    await worker.deliver_destination(db, target)
    assert (await deliveries(db))[0].status == "delivered"
    assert len(fake.appends) == 1


async def test_checkpoint_without_matching_counts_is_not_delivery(db, secret, fake):
    target = await destination(db, secret)
    await events(db, target, {"value": "pending"})
    fake.delay = True
    await worker.deliver_destination(db, target)
    fake.pending.clear()
    state = next(iter(fake.channels.values()))
    state["last_committed_offset_token"] = str((await db.execute(select(SnowflakeBatch))).scalar_one().id)
    await worker.deliver_destination(db, target)
    row = (await deliveries(db))[0]
    assert row.status == "pending" and "row counts" in row.last_error
    assert len(fake.appends) == 1
    state["rows_inserted"] = 1
    await worker.deliver_destination(db, target)
    assert row.status == "delivered"


async def test_source_namespace_and_batches_are_tenant_isolated(db, secret, fake):
    from app.core.database import session_for_tenant

    target = await destination(db, secret)
    await events(db, target, {"value": "pending"})
    fake.delay = True
    await worker.deliver_destination(db, target)
    source = await worker.source_namespace(db)
    async with session_for_tenant(OTHER_TENANT) as other:
        assert (await other.execute(select(SnowflakeBatch))).scalars().all() == []
        other_source = await worker.source_namespace(other)
        await other.commit()
        assert other_source != source
    assert await worker.source_namespace(db) == source


async def test_byte_ceiling_and_sparse_batch_flush(db, secret, fake, monkeypatch):
    target = await destination(db, secret)
    monkeypatch.setattr(worker, "MAX_BATCH_BYTES", 1500)
    await events(db, target, {"value": "x" * 800}, {"value": "y" * 800}, {"value": "z" * 2000})
    await worker.deliver_destination(db, target)
    assert [row.status for row in await deliveries(db)] == ["delivered", "pending", "pending"]
    await worker.deliver_destination(db, target)
    assert [row.status for row in await deliveries(db)] == ["delivered", "delivered", "failed"]
    assert all(len(body) <= 1500 for _, body in fake.appends)


async def test_targeted_test_uses_durable_delivery_path(db, secret, fake):
    target = await destination(db, secret)
    ok, pending, detail, key = await worker.test_destination(db, target)
    assert ok and not pending and "committed" in detail
    assert fake.rows[0]["SOURCE_EVENT_KEY"] == key
    assert fake.rows[0]["PAYLOAD"]["event"] == "destination.test"
    event = (await db.execute(select(EventOutbox))).scalar_one()
    assert event.only_destination_id == target.id and event.fanned_out


async def test_new_event_after_restored_integer_sequence_gets_new_export_identity(db, secret, fake):
    target = await destination(db, secret)
    await events(db, target, {"value": "before-restore"})
    old = (await db.execute(select(EventOutbox))).scalar_one()
    old_id, old_export_id = old.id, old.export_event_id
    await worker.deliver_destination(db, target)
    first_key = fake.rows[0]["SOURCE_EVENT_KEY"]
    await db.execute(delete(OutboxDelivery))
    await db.delete(old)
    await db.commit()
    new = EventOutbox(
        id=old_id, event_type="device.change", payload={"event": "device.change", "value": "after-restore"}, fanned_out=True
    )
    db.add(new)
    await db.flush()
    db.add(OutboxDelivery(outbox_event_id=new.id, destination_id=target.id))
    await db.commit()
    assert new.export_event_id != old_export_id
    await worker.deliver_destination(db, target)
    assert fake.rows[1]["SOURCE_EVENT_KEY"] != first_key


async def test_api_rotation_preserves_target_and_secret_is_never_returned(db, secret, fake, monkeypatch):
    from fastapi import HTTPException

    from app.api import destinations as api
    from app.schemas.destinations import DestinationCreate, DestinationUpdate

    async def safe_destination(url):
        assert url == URL

    monkeypatch.setattr(api, "_refuse_blocked_destination", safe_destination)
    result = await api.create_destination(
        DestinationCreate(name="Warehouse", type="snowflake", url=URL, auth_secret=secret, snowflake_config=CONFIG), db
    )
    assert result.has_secret and secret not in result.model_dump_json()
    assert result.snowflake_config.pipe == "EVENTS_PIPE"
    replacement = pem()
    changed = await api.update_destination(result.id, DestinationUpdate(auth_secret=replacement), db)
    assert replacement not in changed.model_dump_json()
    stored = await db.get(Destination, result.id)
    assert stored.auth_secret_encrypted == replacement
    for update in [
        DestinationUpdate(snowflake_config={**CONFIG, "pipe": "OTHER_PIPE"}),
        DestinationUpdate(allow_insecure_http=True),
        DestinationUpdate(url="https://other-account.snowflakecomputing.com"),
    ]:
        with pytest.raises(HTTPException) as error:
            await api.update_destination(result.id, update, db)
        assert error.value.status_code == 422
    assert stored.snowflake_config == CONFIG
    assert stored.url == URL


async def test_expired_channel_replay_uses_same_source_keys(db, secret, fake):
    target = await destination(db, secret)
    await events(db, target, {"value": "first"})
    await worker.deliver_destination(db, target)
    await events(db, target, {"value": "second"})
    fake.lose_response = True
    await worker.deliver_destination(db, target)
    saved = fake.appends[-1][1]
    fake.channels.clear()  # Snowflake expiry after a long shutdown, with local batch retained.
    await worker.deliver_destination(db, target)
    assert fake.appends[-1][1] == saved
    assert all(row.status == "delivered" for row in await deliveries(db))
    assert len(fake.rows) == 3 and len({row["SOURCE_EVENT_KEY"] for row in fake.rows}) == 2


async def test_legacy_null_identity_is_persisted_once_and_shared_across_destinations(db, secret, fake):
    from sqlalchemy import update

    first = await destination(db, secret)
    second = await destination(db, secret)
    await events(db, first, {"value": "legacy"})
    event = (await db.execute(select(EventOutbox))).scalar_one()
    await db.execute(update(EventOutbox).where(EventOutbox.id == event.id).values(export_event_id=None))
    db.add(OutboxDelivery(destination_id=second.id, outbox_event_id=event.id))
    await db.commit()
    assert event.export_event_id is None
    fake.lose_response = True
    await worker.deliver_destination(db, first)
    identity = event.export_event_id
    assert identity is not None
    await db.refresh(event)
    assert event.export_event_id == identity
    await worker.deliver_destination(db, first)
    await worker.deliver_destination(db, second)
    assert len(fake.rows) == 2
    assert fake.rows[0]["SOURCE_EVENT_KEY"] == fake.rows[1]["SOURCE_EVENT_KEY"]
    assert all(row.status == "delivered" for row in await deliveries(db))


async def test_regular_outbox_drains_multiple_batches_without_exceeding_selected_rows(db, secret, fake, monkeypatch):
    from app.core import outbox

    target = await destination(db, secret)
    await events(db, target, *({"value": str(index)} for index in range(7)))
    monkeypatch.setattr(worker, "MAX_BATCH_ROWS", 2)
    monkeypatch.setattr(outbox, "_TICK_LIMIT", 5)
    await outbox.deliver_pending(db)
    rows = await deliveries(db)
    assert [row.status for row in rows] == ["delivered"] * 5 + ["pending"] * 2
    assert [len(body.splitlines()) for _, body in fake.appends] == [2, 2, 1]
    assert [row.attempt_count for row in rows[-2:]] == [0, 0]
    await outbox.deliver_pending(db)
    assert all(row.status == "delivered" for row in rows)


async def test_regular_outbox_stops_draining_at_unresolved_batch(db, secret, fake, monkeypatch):
    from app.core import outbox

    target = await destination(db, secret)
    await events(db, target, *({"value": str(index)} for index in range(5)))
    monkeypatch.setattr(worker, "MAX_BATCH_ROWS", 2)
    fake.delay = True
    await outbox.deliver_pending(db)
    assert len(fake.appends) == 1
    rows = await deliveries(db)
    assert all(row.status == "pending" for row in rows)
    assert [row.attempt_count for row in rows] == [1, 1, 0, 0, 0]
