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
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from pydantic import ValidationError


def test_enqueued_event_types_are_known() -> None:
    from app.changes.derive import EVENT_TYPE
    from app.core.outbox import KNOWN_EVENT_TYPES
    from app.core.runs import RUN_COMPLETED_EVENT, RUN_FAILED_EVENT

    assert EVENT_TYPE in KNOWN_EVENT_TYPES
    assert RUN_COMPLETED_EVENT in KNOWN_EVENT_TYPES
    assert RUN_FAILED_EVENT in KNOWN_EVENT_TYPES


def test_destination_can_subscribe_to_device_change() -> None:
    from app.schemas.destinations import DestinationCreate, DestinationUpdate

    created = DestinationCreate(name="siem", url="https://siem.example/hook", subscribed_events=["device.change"])
    assert created.subscribed_events == ["device.change"]
    updated = DestinationUpdate(subscribed_events=["device.change", "device.inventory.changed"])
    assert updated.subscribed_events is not None


def test_destination_can_subscribe_to_run_failed() -> None:
    """#86's precedent, applied to #103: the type finish and the reclaim enqueue must
    be subscribable by the same name, or the alarm only flows through the null path."""
    from app.core.runs import RUN_FAILED_EVENT
    from app.schemas.destinations import DestinationCreate, DestinationUpdate

    created = DestinationCreate(name="pager", url="https://pager.example/hook", subscribed_events=[RUN_FAILED_EVENT])
    assert created.subscribed_events == [RUN_FAILED_EVENT]
    updated = DestinationUpdate(subscribed_events=[RUN_FAILED_EVENT, "run.completed"])
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


@pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1")
@pytest.mark.asyncio(loop_scope="session")
async def test_migration_appends_run_failed_to_explicit_subscription_lists(db) -> None:
    """The default-on ruling (#103), as data: a destination that spelled out a list
    before run.failed existed gets the type appended; a null list already means "all"
    and is left alone; a list that somehow already carries it collects no duplicate.

    Runs the migration's own UPDATE — imported from the revision file, not restated
    here, so this cannot drift from what `alembic upgrade` actually executes. The
    tenant-bound test session stands in for the migration's per-tenant set_config
    walk, which is the same dance two earlier data migrations already do.
    """
    import importlib.util

    from sqlalchemy import delete, select, text

    from app.models.schema import Destination

    path = os.path.join(
        os.path.dirname(__file__), "..", "migrations", "versions", "a9d4c7e1f3b8_run_failed_default_on.py"
    )
    spec = importlib.util.spec_from_file_location("migration_a9d4c7e1f3b8", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    tag = uuidlib.uuid4().hex[:8]
    explicit = Destination(
        name=f"pre-ruling siem {tag}", url="https://siem.example/hook", subscribed_events=["device.change"]
    )
    unfiltered = Destination(name=f"everything {tag}", url="https://all.example/hook", subscribed_events=None)
    already = Destination(
        name=f"hand-subscribed {tag}", url="https://pager.example/hook", subscribed_events=["run.failed"]
    )
    db.add_all([explicit, unfiltered, already])
    await db.commit()
    ids = {"explicit": explicit.id, "unfiltered": unfiltered.id, "already": already.id}

    try:
        await db.execute(text(migration.ADD_RUN_FAILED))
        await db.commit()

        # Columns, not entities: the raw UPDATE went around the ORM, and an entity
        # select would answer from the identity map's pre-migration state.
        subs = dict(
            (
                await db.execute(
                    select(Destination.id, Destination.subscribed_events).where(
                        Destination.id.in_(list(ids.values()))
                    )
                )
            ).all()
        )
        assert subs[ids["explicit"]] == ["device.change", "run.failed"]
        assert subs[ids["unfiltered"]] is None
        assert subs[ids["already"]] == ["run.failed"]

        # And the downgrade takes it back out without disturbing the rest of the list.
        await db.execute(text(migration.REMOVE_RUN_FAILED))
        await db.commit()
        removed = (
            await db.execute(select(Destination.subscribed_events).where(Destination.id == ids["explicit"]))
        ).scalar_one()
        assert removed == ["device.change"]
    finally:
        await db.rollback()
        await db.execute(delete(Destination).where(Destination.id.in_(list(ids.values()))))
        await db.commit()


# --- the type/authType coupling (the API path that used to 401 for ever) ------------


def test_splunk_hec_derives_its_auth_type_when_the_caller_omits_it() -> None:
    """The defect this closes: POST {"type": "splunk_hec", "authSecret": "..."} returned
    201 with authType "none", stored the token, and then 401ed on every delivery,
    because outbox.py only sends `Authorization: Splunk` when auth_type is splunk_hec.
    The coupling lived only in the frontend's FIXED_AUTH map."""
    from app.schemas.destinations import DestinationCreate

    created = DestinationCreate(
        name="splunk", type="splunk_hec", url="https://splunk.example:8088/services/collector",
        auth_secret="token",
    )
    assert created.auth_type == "splunk_hec"


def test_every_fixed_type_derives_its_own_auth_type() -> None:
    from app.schemas.destinations import DestinationCreate

    for destination_type, expected in (("elastic", "elastic_api_key"), ("runreveal", "bearer")):
        created = DestinationCreate(
            name=destination_type, type=destination_type,
            url="https://example.test/ingest", auth_secret="s",
        )
        assert created.auth_type == expected


def test_generic_webhook_still_defaults_to_none_and_lets_the_operator_choose() -> None:
    from app.schemas.destinations import DestinationCreate

    assert DestinationCreate(name="hook", url="https://example.test/hook").auth_type == "none"
    chosen = DestinationCreate(
        name="hook", type="generic_webhook", url="https://example.test/hook",
        auth_type="bearer", auth_secret="s",
    )
    assert chosen.auth_type == "bearer"


def test_contradicting_a_fixed_auth_type_is_refused_and_names_the_right_one() -> None:
    from app.schemas.destinations import DestinationCreate

    with pytest.raises(ValidationError) as exc:
        DestinationCreate(
            name="splunk", type="splunk_hec",
            url="https://splunk.example:8088/services/collector",
            auth_type="none", auth_secret="token",
        )
    assert "splunk_hec" in str(exc.value)


def test_a_splunk_destination_without_a_secret_is_refused() -> None:
    """Falls out of deriving the auth type: authSecret is required unless authType is
    "none", and a splunk_hec destination can no longer claim to be "none"."""
    from app.schemas.destinations import DestinationCreate

    with pytest.raises(ValidationError):
        DestinationCreate(
            name="splunk", type="splunk_hec",
            url="https://splunk.example:8088/services/collector",
        )


def test_an_unknown_type_is_refused_by_the_schema() -> None:
    from app.schemas.destinations import DestinationCreate

    with pytest.raises(ValidationError):
        DestinationCreate(name="x", type="datadog", url="https://example.test/x")


def test_the_openapi_schema_publishes_the_four_working_types() -> None:
    """A bare `str` published nothing, so an API-driven caller reading the spec could not
    learn that splunk_hec was a legal value at all."""
    from app.schemas.destinations import DestinationCreate

    schema = DestinationCreate.model_json_schema()
    published = schema["properties"]["type"]
    values = published.get("enum") or schema["$defs"][published["allOf"][0]["$ref"].rsplit("/", 1)[-1]]["enum"]
    assert set(values) == {"generic_webhook", "splunk_hec", "elastic", "runreveal"}
# --- delivery diagnosability --------------------------------------------------------


def test_the_test_event_type_is_not_subscribable() -> None:
    """It exists so the destination test button sends something identifiable rather than
    a fabricated device event that would land in a customer's index looking real. Being
    outside KNOWN_EVENT_TYPES is what stops a destination subscribing to it."""
    from app.core.outbox import KNOWN_EVENT_TYPES, TEST_EVENT_TYPE

    assert TEST_EVENT_TYPE not in KNOWN_EVENT_TYPES

    from app.schemas.destinations import DestinationCreate

    with pytest.raises(ValidationError):
        DestinationCreate(name="x", url="https://example.test/x", subscribed_events=[TEST_EVENT_TYPE])


def test_destination_out_defaults_its_health_fields() -> None:
    """A destination with no deliveries yet reports a clean bill rather than nulls the
    UI has to special-case."""
    from datetime import datetime, timezone

    from app.schemas.destinations import DestinationOut

    now = datetime.now(timezone.utc)
    out = DestinationOut(
        id=1, name="siem", type="generic_webhook", url="https://siem.example/hook",
        auth_type="none", auth_header_name=None, elastic_index=None, has_secret=False,
        enabled=True, subscribed_events=None, last_success_at=None, last_failure_at=None,
        created_at=now, updated_at=now,
    )
    assert out.last_error is None and out.pending_count == 0 and out.failed_count == 0


@pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1")
@pytest.mark.asyncio(loop_scope="session")
async def test_health_reports_the_last_error_and_the_queue_depth(db) -> None:
    """The defect this closes: outbox_deliveries.last_error held the exact upstream
    refusal and no API read it, so the symptom an operator experienced was "Splunk is
    empty and the app says everything is fine"."""
    from sqlalchemy import delete

    from app.api.destinations import _health
    from app.core.outbox import enqueue_event
    from app.models.schema import Destination, EventOutbox, OutboxDelivery

    tag = uuidlib.uuid4().hex[:8]
    destination = Destination(name=f"broken splunk {tag}", url="https://splunk.example/x")
    db.add(destination)
    event = await enqueue_event(db, "device.change", {"event": "device.change", "test": tag})
    await db.commit()
    destination_id, event_id = destination.id, event.id

    db.add_all([
        OutboxDelivery(
            outbox_event_id=event_id, destination_id=destination_id, status="pending",
            attempt_count=1, last_error='HTTP 403: {"text":"Invalid token","code":4}',
            last_attempted_at=datetime.now(timezone.utc),
        ),
    ])
    await db.commit()

    try:
        health = await _health(db, [destination_id])
        assert health[destination_id]["last_error"] == 'HTTP 403: {"text":"Invalid token","code":4}'
        assert health[destination_id]["pending_count"] == 1
        assert health[destination_id]["failed_count"] == 0
    finally:
        await db.execute(delete(OutboxDelivery).where(OutboxDelivery.destination_id == destination_id))
        await db.execute(delete(EventOutbox).where(EventOutbox.id == event_id))
        await db.execute(delete(Destination).where(Destination.id == destination_id))
        await db.commit()
