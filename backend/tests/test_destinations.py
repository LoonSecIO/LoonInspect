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
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from pydantic import ValidationError


def test_enqueued_event_types_are_known() -> None:
    from app.changes.derive import EVENT_TYPE
    from app.core.outbox import KNOWN_EVENT_TYPES
    from app.core.runs import RUN_COMPLETED_EVENT, RUN_FAILED_EVENT
    from app.schemas.payload import INVENTORY_EVENT_TYPE, InventoryChangedEvent, InventorySnapshotEvent

    assert EVENT_TYPE in KNOWN_EVENT_TYPES
    assert RUN_COMPLETED_EVENT in KNOWN_EVENT_TYPES
    assert RUN_FAILED_EVENT in KNOWN_EVENT_TYPES
    assert INVENTORY_EVENT_TYPE in KNOWN_EVENT_TYPES
    # The two inventory families are distinct subscribable types: the state and the delta.
    assert InventorySnapshotEvent.model_fields["event"].default == INVENTORY_EVENT_TYPE
    assert InventoryChangedEvent.model_fields["event"].default in KNOWN_EVENT_TYPES
    assert InventoryChangedEvent.model_fields["event"].default != INVENTORY_EVENT_TYPE


def test_destination_can_subscribe_to_the_snapshot_alone_or_the_delta_alone() -> None:
    """Volume is a subscription knob, not a wire change (#241): a destination subscribed
    only to the delta never receives a ~30 KB snapshot per device per pass, and one
    subscribed only to the snapshot gets the state without the deltas."""
    from app.schemas.destinations import DestinationCreate
    from app.schemas.payload import INVENTORY_EVENT_TYPE

    snapshot_only = DestinationCreate(name="state", url="https://siem.example/hook", subscribed_events=[INVENTORY_EVENT_TYPE])
    assert snapshot_only.subscribed_events == ["device.inventory"]
    delta_only = DestinationCreate(name="deltas", url="https://siem.example/hook", subscribed_events=["device.inventory.changed"])
    assert delta_only.subscribed_events == ["device.inventory.changed"]


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


# A tenant of this file's own for the fan-out test, in the shape the other fan-out
# files use (tests/test_outbox_passes_db.py, tests/test_hec_fanout_db.py).
FAN_OUT_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-000000000514")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def fan_out_tenant() -> None:
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, unscoped_session
    from app.models.schema import Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, FAN_OUT_TENANT_ID) is None:
            db.add(Tenant(id=FAN_OUT_TENANT_ID, slug="destination-fan-out", name="Destination fan-out", kind="operational"))
            await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def alone(fan_out_tenant):
    """A session on that tenant, its outbox tables empty either side.

    `fan_out_pending` is a whole-tenant sweep: every held event, to every enabled
    destination the session can see. Called on the operational tenant it therefore
    reaches destinations other files left behind — including the catch-all one in
    tests/test_backup_secrecy_db.py — and writes delivery rows against them that
    outlive this test. That is what used to make the suite single-use against a
    database (#514). Scoped to a tenant of its own, the only destinations in the sweep
    are the two this test creates and this fixture removes.

    The three deletes below carry no `WHERE`, and what bounds them to this tenant is
    the RLS policy, not the statement. That holds only because these tables are
    `FORCE ROW LEVEL SECURITY` and not merely `ENABLE`: `looninspect_app` owns them
    and runs the suite, and an owner is exempt from its own policies without FORCE.
    Checked against the live schema rather than assumed — `relrowsecurity` and
    `relforcerowsecurity` are both true for `destinations`, `event_outbox` and
    `outbox_deliveries` — and kept that way by
    tests/test_identity_resolution_db.py::test_the_index_tables_carry_no_row_level_security_and_nothing_else_does_not,
    which fails the moment a table with a `tenant_id` has one flag and not the other.
    """
    from sqlalchemy import delete

    from app.core.database import session_for_tenant
    from app.models.schema import Destination, EventOutbox, OutboxDelivery

    async def _clear(session) -> None:
        await session.rollback()
        await session.execute(delete(OutboxDelivery))
        await session.execute(delete(EventOutbox))
        await session.execute(delete(Destination))
        await session.commit()

    async with session_for_tenant(FAN_OUT_TENANT_ID) as session:
        await _clear(session)
        try:
            yield session
        finally:
            await _clear(session)


@pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1")
@pytest.mark.asyncio(loop_scope="session")
async def test_subscribed_destination_receives_device_change(alone) -> None:
    from sqlalchemy import select

    from app.changes.derive import EVENT_TYPE
    from app.core.outbox import enqueue_event, fan_out_pending
    from app.models.schema import Destination, OutboxDelivery

    # A session on a tenant holding nothing but the rows this test writes.
    db = alone
    tag = uuidlib.uuid4().hex[:8]
    subscriber = Destination(name=f"changes siem {tag}", url="https://siem.example/hook", subscribed_events=[EVENT_TYPE])
    bystander = Destination(
        name=f"inventory only {tag}", url="https://other.example/hook", subscribed_events=["device.inventory.changed"]
    )
    db.add_all([subscriber, bystander])
    await enqueue_event(db, EVENT_TYPE, {"event": EVENT_TYPE, "test": tag})
    await db.commit()
    subscriber_id, bystander_id = subscriber.id, bystander.id

    # Every row in the tenant, because every row in the tenant is this test's: the one
    # event, and the one destination subscribed to its type.
    assert await fan_out_pending(db) == 1

    delivered_to = {delivery.destination_id for delivery in (await db.execute(select(OutboxDelivery))).scalars()}
    assert delivered_to == {subscriber_id}, "the destination subscribed by name, and nothing else in the tenant"
    assert bystander_id not in delivered_to, "subscribed to another type, so no row"


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

    path = os.path.join(os.path.dirname(__file__), "..", "migrations", "versions", "a9d4c7e1f3b8_run_failed_default_on.py")
    spec = importlib.util.spec_from_file_location("migration_a9d4c7e1f3b8", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    tag = uuidlib.uuid4().hex[:8]
    explicit = Destination(name=f"pre-ruling siem {tag}", url="https://siem.example/hook", subscribed_events=["device.change"])
    unfiltered = Destination(name=f"everything {tag}", url="https://all.example/hook", subscribed_events=None)
    already = Destination(name=f"hand-subscribed {tag}", url="https://pager.example/hook", subscribed_events=["run.failed"])
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
                    select(Destination.id, Destination.subscribed_events).where(Destination.id.in_(list(ids.values())))
                )
            ).all()
        )
        assert subs[ids["explicit"]] == ["device.change", "run.failed"]
        assert subs[ids["unfiltered"]] is None
        assert subs[ids["already"]] == ["run.failed"]

        # And the downgrade takes it back out without disturbing the rest of the list.
        await db.execute(text(migration.REMOVE_RUN_FAILED))
        await db.commit()
        removed = (await db.execute(select(Destination.subscribed_events).where(Destination.id == ids["explicit"]))).scalar_one()
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
        name="splunk",
        type="splunk_hec",
        url="https://splunk.example:8088/services/collector",
        auth_secret="token",
    )
    assert created.auth_type == "splunk_hec"


def test_every_fixed_type_derives_its_own_auth_type() -> None:
    from app.schemas.destinations import DestinationCreate

    for destination_type, expected in (("elastic", "elastic_api_key"), ("runreveal", "bearer")):
        created = DestinationCreate(
            name=destination_type,
            type=destination_type,
            url="https://example.test/ingest",
            auth_secret="s",
        )
        assert created.auth_type == expected


def test_generic_webhook_still_defaults_to_none_and_lets_the_operator_choose() -> None:
    from app.schemas.destinations import DestinationCreate

    assert DestinationCreate(name="hook", url="https://example.test/hook").auth_type == "none"
    chosen = DestinationCreate(
        name="hook",
        type="generic_webhook",
        url="https://example.test/hook",
        auth_type="bearer",
        auth_secret="s",
    )
    assert chosen.auth_type == "bearer"


def test_contradicting_a_fixed_auth_type_is_refused_and_names_the_right_one() -> None:
    from app.schemas.destinations import DestinationCreate

    with pytest.raises(ValidationError) as exc:
        DestinationCreate(
            name="splunk",
            type="splunk_hec",
            url="https://splunk.example:8088/services/collector",
            auth_type="none",
            auth_secret="token",
        )
    assert "splunk_hec" in str(exc.value)


def test_a_splunk_destination_without_a_secret_is_refused() -> None:
    """Falls out of deriving the auth type: authSecret is required unless authType is
    "none", and a splunk_hec destination can no longer claim to be "none"."""
    from app.schemas.destinations import DestinationCreate

    with pytest.raises(ValidationError):
        DestinationCreate(
            name="splunk",
            type="splunk_hec",
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
    from datetime import datetime

    from app.schemas.destinations import DestinationOut

    now = datetime.now(UTC)
    out = DestinationOut(
        id=1,
        name="siem",
        type="generic_webhook",
        url="https://siem.example/hook",
        auth_type="none",
        auth_header_name=None,
        elastic_index=None,
        has_secret=False,
        enabled=True,
        subscribed_events=None,
        last_success_at=None,
        last_failure_at=None,
        created_at=now,
        updated_at=now,
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

    db.add_all(
        [
            OutboxDelivery(
                outbox_event_id=event_id,
                destination_id=destination_id,
                status="pending",
                attempt_count=1,
                last_error='HTTP 403: {"text":"Invalid token","code":4}',
                last_attempted_at=datetime.now(UTC),
            ),
        ]
    )
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


@pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1")
@pytest.mark.asyncio(loop_scope="session")
async def test_migration_appends_both_departure_types_to_explicit_subscription_lists(db) -> None:
    """#179's 4.8, as data. The pair is what makes this the `run.failed` treatment rather than
    `device.inventory`'s: a curated list receiving departures without returns would hold a
    fleet that only ever shrinks, so BOTH go in and BOTH come back out. Idempotent, so a row
    an admin already subscribed by hand collects no duplicate.

    Runs the migration's own UPDATEs, imported from the revision file, so this cannot drift
    from what `alembic upgrade` executes.
    """
    import importlib.util

    from sqlalchemy import delete, select, text

    from app.models.schema import Destination

    path = os.path.join(os.path.dirname(__file__), "..", "migrations", "versions", "bd51c7a9e402_departure_family_default_on.py")
    spec = importlib.util.spec_from_file_location("migration_bd51c7a9e402", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    tag = uuidlib.uuid4().hex[:8]
    explicit = Destination(name=f"curated siem {tag}", url="https://siem.example/hook", subscribed_events=["device.change"])
    unfiltered = Destination(name=f"everything {tag}", url="https://all.example/hook", subscribed_events=None)
    already = Destination(
        name=f"half-subscribed {tag}", url="https://pager.example/hook", subscribed_events=["subject.departure"]
    )
    db.add_all([explicit, unfiltered, already])
    await db.commit()
    ids = {"explicit": explicit.id, "unfiltered": unfiltered.id, "already": already.id}

    try:
        for statement in migration.ADD_DEPARTURE_TYPES:
            await db.execute(text(statement))
        await db.commit()

        # Columns, not entities: the raw UPDATE went around the ORM.
        subs = dict(
            (
                await db.execute(
                    select(Destination.id, Destination.subscribed_events).where(Destination.id.in_(list(ids.values())))
                )
            ).all()
        )
        assert subs[ids["explicit"]] == ["device.change", "subject.departure", "subject.returned"]
        # Null already means every event; narrowing it here would change what it means.
        assert subs[ids["unfiltered"]] is None
        # The half-subscribed row collects the missing half and no duplicate of the one it had.
        assert subs[ids["already"]] == ["subject.departure", "subject.returned"]

        for statement in migration.REMOVE_DEPARTURE_TYPES:
            await db.execute(text(statement))
        await db.commit()
        removed = (await db.execute(select(Destination.subscribed_events).where(Destination.id == ids["explicit"]))).scalar_one()
        assert removed == ["device.change"]
    finally:
        await db.rollback()
        await db.execute(delete(Destination).where(Destination.id.in_(list(ids.values()))))
        await db.commit()
