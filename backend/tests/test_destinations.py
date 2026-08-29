"""Destination event subscriptions: every event type a producer actually enqueues must
be subscribable by name, or it only flows through the "all events" (null) path.

The pure tests pin the producer constants to KNOWN_EVENT_TYPES so a new producer whose
type is missing from the set fails here instead of silently rejecting subscribers. The
DB test proves the fan-out end: a destination subscribed to `device.change` gets a
delivery row for one, and a destination subscribed to something else does not.
"""

from __future__ import annotations

import os
import uuid as uuidlib

import pytest
import pytest_asyncio
from pydantic import ValidationError


def test_enqueued_event_types_are_known() -> None:
    from app.changes.derive import EVENT_TYPE
    from app.core.outbox import KNOWN_EVENT_TYPES
    from app.core.runs import RUN_COMPLETED_EVENT

    assert EVENT_TYPE in KNOWN_EVENT_TYPES
    assert RUN_COMPLETED_EVENT in KNOWN_EVENT_TYPES


def test_destination_can_subscribe_to_device_change() -> None:
    from app.schemas.destinations import DestinationCreate, DestinationUpdate

    created = DestinationCreate(name="siem", url="https://siem.example/hook", subscribed_events=["device.change"])
    assert created.subscribed_events == ["device.change"]
    updated = DestinationUpdate(subscribed_events=["device.change", "device.inventory.changed"])
    assert updated.subscribed_events is not None


def test_unknown_event_type_is_rejected() -> None:
    from app.schemas.destinations import DestinationCreate

    with pytest.raises(ValidationError, match=r"Unknown event type\(s\): device\.changed"):
        DestinationCreate(name="siem", url="https://siem.example/hook", subscribed_events=["device.changed"])


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


@pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1")
@pytest.mark.asyncio(loop_scope="session")
async def test_subscribed_destination_receives_device_change(db) -> None:
    from sqlalchemy import delete, select

    from app.changes.derive import EVENT_TYPE
    from app.core.outbox import enqueue_event, fan_out_pending
    from app.models.schema import Destination, EventOutbox, OutboxDelivery

    tag = uuidlib.uuid4().hex[:8]
    subscriber = Destination(
        name=f"changes siem {tag}", url="https://siem.example/hook", subscribed_events=[EVENT_TYPE]
    )
    bystander = Destination(
        name=f"inventory only {tag}", url="https://other.example/hook", subscribed_events=["device.inventory.changed"]
    )
    db.add_all([subscriber, bystander])
    event = await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "test": tag})
    await db.commit()
    # Plain ints: the rollback in the teardown expires the instances, and refreshing
    # them there would be sync IO inside an async session.
    subscriber_id, bystander_id, event_id = subscriber.id, bystander.id, event.id

    try:
        await fan_out_pending(db)

        deliveries = (
            await db.execute(select(OutboxDelivery).where(OutboxDelivery.outbox_event_id == event_id))
        ).scalars().all()
        destination_ids = {d.destination_id for d in deliveries}
        assert subscriber_id in destination_ids
        assert bystander_id not in destination_ids
    finally:
        await db.rollback()
        await db.execute(
            delete(OutboxDelivery).where(
                OutboxDelivery.destination_id.in_([subscriber_id, bystander_id])
                | (OutboxDelivery.outbox_event_id == event_id)
            )
        )
        await db.execute(delete(EventOutbox).where(EventOutbox.id == event_id))
        await db.execute(delete(Destination).where(Destination.id.in_([subscriber_id, bystander_id])))
        await db.commit()
