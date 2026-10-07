"""Webhook runs, end to end: the run a Jamf Pro webhook opens, the lock it never takes, and
what Jamf Pro is answered when the fetch behind it fails.

`ingest_webhook` (app.mdm.service) opens one run per allowlisted event, trigger and lock
class `webhook`, and the partial unique index `uq_run_active_lock` leaves that class out of
its predicate, so a webhook waits neither for a held device sweep nor for another webhook
(docs/ingest-scheduling.md §4.4). `test_runs.py::test_webhooks_are_lock_exempt` pins the
predicate at `acquire`; this file drives `POST /webhooks/jamf/{id}` through the whole
application with Jamf Pro answered by `tests.jamf_fake.FakeJamf`, so each request has a
database session of its own, as two deliveries from Jamf Pro do.

When the fetch fails the run closes `failed` first and the route answers after it, a 502
for an HTTP status or a transport error; the answer is synchronous with the fetch, so the
delivery stays open through retries unless its optional total budget expires. Malformed
token/detail replies answer 502; optional aperture failures record absence. Network waits
hold no aperture transaction, and reclaim stays inside the webhook tenant.

Gated on RUN_DB_TESTS like every session-backed suite.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid as uuidlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, update

from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

_SECRET = "webhook-runs-secret"
_EVENT = "ComputerInventoryCompleted"
_FETCH_FAILED = {"detail": "Inventory fetch from Jamf Pro failed"}
# Seconds a delivery may take before it counts as blocked; an unblocked one takes well under one.
_PATIENCE = 10


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    """Webhooks on and a secret set. Torn down as test_sad_paths.py's is: a webhook ingest
    writes the same rows, and runs, their log and the apertures go by cascade."""
    from app.models.schema import AppCatalogEntry, Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"webhook runs jamf {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
        capability_webhooks=True,
        webhook_secret_encrypted=_SECRET,
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
        # Keyed by tenant, not connection — see test_runs.py's fixture.
        await db.execute(delete(AppCatalogEntry))
        await db.commit()


async def _post(connection_id: int, jss_id: str) -> httpx.Response:
    """One delivery as Jamf Pro sends it, through the whole application. With
    `raise_app_exceptions=False` an unhandled error comes back as the 500 Jamf Pro gets, and
    a delivery that blocks fails its test after `_PATIENCE` rather than hanging it."""
    from app.main import app

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="https://loon.test") as client:
        delivery = client.post(
            f"/webhooks/jamf/{connection_id}",
            json={"webhook": {"webhookEvent": _EVENT}, "event": {"jssID": jss_id}},
            headers={"X-API-Key": _SECRET},
        )
        return await asyncio.wait_for(delivery, _PATIENCE)


async def _runs(db, connection_id: int) -> list:
    """The connection's runs, oldest first, read past this session's identity map: the
    route wrote them through sessions of its own."""
    from app.models.schema import Run

    query = select(Run).where(Run.mdm_connection_id == connection_id).order_by(Run.started_at, Run.id)
    return list((await db.execute(query.execution_options(populate_existing=True))).scalars())


async def _log(db, run_id) -> list:
    from app.models.schema import RunLogLine

    query = select(RunLogLine.level, RunLogLine.message, RunLogLine.fields).where(RunLogLine.run_id == run_id)
    return list((await db.execute(query.order_by(RunLogLine.id))).all())


async def _events(db, run_id) -> list[str]:
    """The event types stamped with this run's jobID, matched by payload: the shared local
    database accumulates events across tests."""
    from app.models.schema import EventOutbox

    query = select(EventOutbox.event_type).where(EventOutbox.payload["jobID"].astext == str(run_id))
    return list((await db.execute(query)).scalars())


def _jamf_answers(monkeypatch: pytest.MonkeyPatch, jamf: FakeJamf, answer, where: str = "/computers-inventory-detail/") -> None:
    """Jamf Pro answers each request to `where` (the computer-detail read unless named) with
    `answer(request)`, the rest as the fake does."""

    def handler(request: httpx.Request) -> httpx.Response:
        if where in request.url.path:
            return answer(request)
        return FakeJamf.handler(jamf, request)

    monkeypatch.setattr(jamf, "handler", handler)


def _gate(monkeypatch: pytest.MonkeyPatch, jamf: FakeJamf, holds) -> tuple[asyncio.Event, asyncio.Event]:
    """Hold the first Jamf request `holds` picks until `release` is set; `held` says it arrived."""
    held, release = asyncio.Event(), asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        if not held.is_set() and holds(request):
            held.set()
            await release.wait()
        return FakeJamf.handler(jamf, request)

    monkeypatch.setattr(jamf, "handler", handler)
    return held, release


async def test_a_webhook_opens_one_run_of_its_own_and_closes_it(db, connection, jamf: FakeJamf) -> None:
    """One delivery, one run: trigger and lock class `webhook`, no collection, the event's
    name as its actor, closed `succeeded` over one device, its log opening with `run
    started` and ending with `run finished`."""
    response = await _post(connection.id, jamf.real["id"])

    assert (response.status_code, response.json()) == (200, {"status": "accepted", "outcome": "new"})
    (run,) = await _runs(db, connection.id)
    assert (run.trigger, run.lock_class, run.collection_id, run.actor_label) == ("webhook", "webhook", None, _EVENT)
    assert (run.status, run.error, run.device_count, run.devices_processed, run.devices_failed) == ("succeeded", None, 1, 1, 0)
    started, *_, finished = await _log(db, run.id)
    assert [(line.level, line.message) for line in (started, finished)] == [("info", "run started"), ("info", "run finished")]
    assert (started.fields["trigger"], started.fields["lockClass"], finished.fields["deviceCount"]) == ("webhook", "webhook", 1)


async def test_a_held_sweep_neither_blocks_a_webhook_nor_is_touched_by_it(db, connection, jamf: FakeJamf) -> None:
    """A device sweep holding the connection does not hold a webhook up, and the webhook
    leaves the sweep's run as it found it: still running, nothing counted or logged on it,
    and no event stamped with its jobID — the Mac the webhook read is its own run's."""
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, acquire, finish

    def state(run) -> tuple:
        return (run.status, run.heartbeat_at, run.finished_at, run.device_count, run.devices_processed, run.error)

    held = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert held.started
    (sweep,) = await _runs(db, connection.id)
    before, logged = state(sweep), await _log(db, sweep.id)
    try:
        response = await _post(connection.id, jamf.real["id"])

        assert response.status_code == 200, response.text
        sweep, hook = await _runs(db, connection.id)
        assert sweep.id == held.run.id
        assert (hook.lock_class, hook.status, hook.device_count) == ("webhook", "succeeded", 1)
        assert state(sweep) == before
        assert await _log(db, sweep.id) == logged
        assert await _events(db, sweep.id) == []
        assert {"device.inventory", "run.completed"} <= set(await _events(db, hook.id))
    finally:
        await finish(db, held.run, ok=True)


async def test_webhooks_for_one_connection_run_side_by_side(db, connection, jamf: FakeJamf, monkeypatch) -> None:
    """The predicate claim, through the route. The first webhook is held inside its first
    aperture read with its run open while two more arrive together and run start to finish.
    Each gets a run of its own: were the webhook class inside the predicate, the later two
    would be handed the first one's run and close it for it. Held past the token request,
    which the connection's webhooks share under its held sign-in."""
    jamf.seed(1)
    first, second, third = (computer["id"] for computer in jamf.computers)
    held, release = _gate(monkeypatch, jamf, lambda request: request.url.path == "/api/v1/jamf-pro-version")
    waiting = asyncio.create_task(_post(connection.id, first))
    try:
        await asyncio.wait_for(held.wait(), _PATIENCE)
        overtaking = await asyncio.gather(_post(connection.id, second), _post(connection.id, third))
    finally:
        release.set()
        last = await waiting

    assert [response.status_code for response in (*overtaking, last)] == [200, 200, 200]
    runs = await _runs(db, connection.id)
    assert len({run.id for run in runs}) == 3
    assert {(run.lock_class, run.status, run.device_count) for run in runs} == {("webhook", "succeeded", 1)}
    # Opened first, closed last: the other two did not queue behind it.
    assert runs[0].finished_at == max(run.finished_at for run in runs)


async def test_a_second_webhook_does_not_wait_out_the_first_ones_jamf_read(db, connection, jamf: FakeJamf, monkeypatch) -> None:
    """Concurrent reads and malformed upstream replies have explicit outcomes."""
    first = jamf.real["id"]
    held, release = _gate(monkeypatch, jamf, lambda request: request.url.path.endswith(f"/computers-inventory-detail/{first}"))
    waiting = asyncio.create_task(_post(connection.id, first))
    await asyncio.wait_for(held.wait(), _PATIENCE)
    second = asyncio.create_task(_post(connection.id, jamf.synthetic["id"]))
    done, _ = await asyncio.wait({second}, timeout=3)
    release.set()
    await asyncio.gather(waiting, second)
    assert second in done, "the second webhook could not finish while the first one waited on Jamf Pro"


def _timeout(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("Jamf Pro did not answer in time", request=request)


def _refused(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused", request=request)


def _not_json(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="<html>Down for maintenance</html>", headers={"content-type": "text/html"})


@pytest.mark.parametrize(
    ("answer", "answered"),
    [
        pytest.param(_timeout, _FETCH_FAILED, id="read-timeout"),
        pytest.param(_refused, _FETCH_FAILED, id="connection-refused"),
        pytest.param(_not_json, _FETCH_FAILED, id="not-json"),
    ],
)
async def test_a_fetch_that_raises_still_closes_its_run_failed(
    db, connection, jamf: FakeJamf, monkeypatch, answer, answered
) -> None:
    """`ingest_webhook` finishes the run before it re-raises, whatever the fetch raised, so
    no `running` row waits for the reclaim, one run.failed goes out, and Jamf Pro is told the
    delivery failed. An HTTP-layer failure is told so by the route's 502."""
    _jamf_answers(monkeypatch, jamf, answer)

    response = await _post(connection.id, jamf.real["id"])

    assert response.status_code >= 500, response.text
    if answered is not None:
        assert (response.status_code, response.json()) == (502, answered)
    (run,) = await _runs(db, connection.id)
    assert (run.lock_class, run.status) == ("webhook", "failed")
    assert run.error and run.finished_at is not None
    lines = await _log(db, run.id)
    assert (lines[-1].level, lines[-1].message, lines[-1].fields["error"]) == ("error", "run failed", run.error)
    assert (await _events(db, run.id)).count("run.failed") == 1


async def test_a_throttled_detail_read_holds_the_answer_through_the_retry_ladder(
    db, connection, jamf: FakeJamf, monkeypatch
) -> None:
    """A configured ten-second window admits the full ladder; record waits without sleeping."""
    from app.core.config import settings
    from app.mdm.jamf.client import JamfClient

    monkeypatch.setattr(settings, "webhook_timeout_seconds", 10)
    waits: list[float] = []

    async def record(seconds: float) -> None:
        waits.append(seconds)

    monkeypatch.setattr(JamfClient, "_sleep", staticmethod(record))
    jamf.transient.extend([("/api/v4/computers-inventory-detail", 503, {})] * 4)

    response = await _post(connection.id, jamf.real["id"])

    assert (response.status_code, response.json()) == (502, _FETCH_FAILED)
    assert sum("computers-inventory-detail" in request for request in jamf.requests) == 4
    assert [int(wait) for wait in waits] == [1, 2, 4]
    (run,) = await _runs(db, connection.id)
    assert run.status == "failed" and "503" in run.error


@pytest.mark.parametrize(
    "where",
    [
        pytest.param("/api/oauth/token", id="sign-in"),
        pytest.param("/api/v1/jamf-pro-version", id="aperture-read"),
        pytest.param("/computers-inventory-detail/", id="detail-read"),
    ],
)
async def test_a_jamf_answer_that_is_not_json_is_answered_as_a_failed_fetch(
    connection, jamf: FakeJamf, monkeypatch, where
) -> None:
    """Concurrent reads and malformed upstream replies have explicit outcomes."""
    _jamf_answers(monkeypatch, jamf, _not_json, where)

    response = await _post(connection.id, jamf.real["id"])

    expected = 200 if where == "/api/v1/jamf-pro-version" else 502
    assert response.status_code == expected, response.text


async def test_the_reclaim_a_webhook_runs_stays_inside_its_tenant(db, connection, jamf: FakeJamf) -> None:
    """Every acquisition reclaims stale runs first, a webhook's included, and the webhook
    route is bound to the operational tenant. Row-level security keeps that reclaim there: a
    stale sweep on the webhook's own connection is failed, a stale sweep in a second tenant
    is left exactly as it was. Both sweeps go stale only once both are held, so the webhook's
    is the one acquisition that meets them stale."""
    from app.core.config import settings
    from app.core.database import session_for_tenant, unscoped_session
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, acquire
    from app.models.schema import MdmConnection, Run, Tenant

    stale = datetime.now(UTC) - timedelta(seconds=settings.run_stale_after_seconds + 60)
    tenant_id, elsewhere_id = uuidlib.uuid4(), None

    async def theirs_now(run_id) -> tuple:
        async with session_for_tenant(tenant_id) as other:
            return tuple((await other.execute(select(Run.status, Run.heartbeat_at).where(Run.id == run_id))).one())

    async with unscoped_session() as unscoped:
        unscoped.add(Tenant(id=tenant_id, slug=f"webhook-runs-{tenant_id.hex[:8]}", name="Webhook runs", kind="operational"))
        await unscoped.commit()
    try:
        async with session_for_tenant(tenant_id) as other:
            elsewhere = MdmConnection(name="second tenant's jamf", provider="jamf", base_url=HOST, is_active=False)
            other.add(elsewhere)
            await other.commit()
            elsewhere_id = elsewhere.id
            theirs = (await acquire(other, elsewhere, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)).run.id
        ours = (await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)).run.id
        async with session_for_tenant(tenant_id) as other:
            await other.execute(update(Run).where(Run.id == theirs).values(heartbeat_at=stale))
            await other.commit()
        await db.execute(update(Run).where(Run.id == ours).values(heartbeat_at=stale))
        await db.commit()
        assert await theirs_now(theirs) == ("running", stale)

        response = await _post(connection.id, jamf.real["id"])

        assert response.status_code == 200, response.text
        assert {run.id: run.status for run in await _runs(db, connection.id)}[ours] == "failed"
        assert await theirs_now(theirs) == ("running", stale)
    finally:
        async with session_for_tenant(tenant_id) as other:
            # Its run and run log go with it by cascade.
            await other.execute(delete(MdmConnection).where(MdmConnection.id == elsewhere_id))
            await other.commit()
        async with unscoped_session() as unscoped:
            await unscoped.execute(delete(Tenant).where(Tenant.id == tenant_id))
            await unscoped.commit()


@pytest.mark.parametrize(
    "field,value",
    [
        ("hardware", []),
        ("applications", "abc"),
        ("general.remoteManagement", []),
        ("general.reportDate", 12345),
        ("hardware.extensionAttributes", ["bad"]),
    ],
)
async def test_malformed_consumed_detail_has_an_operator_error(db, connection, jamf, monkeypatch, field, value):
    from copy import deepcopy

    from sqlalchemy import func

    from app.models.schema import Device

    record = deepcopy(jamf.real)
    target = record
    parts = field.split(".")
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value
    _jamf_answers(monkeypatch, jamf, lambda r: httpx.Response(200, json=record))
    assert (await _post(connection.id, jamf.real["id"])).status_code == 502
    (run,) = await _runs(db, connection.id)
    assert run.status == "failed" and "unexpected shape" in run.error and "Test connection" in run.error
    assert await db.scalar(select(func.count()).select_from(Device).where(Device.mdm_connection_id == connection.id)) == 0


async def test_invalid_token_diagnostic_reaches_the_run(db, connection, jamf, monkeypatch):
    _jamf_answers(monkeypatch, jamf, lambda r: httpx.Response(200, json=[]), where="/api/oauth/token")
    assert (await _post(connection.id, jamf.real["id"])).status_code == 502
    (run,) = await _runs(db, connection.id)
    assert "invalid token response from /api/oauth/token" in run.error


async def test_rejected_id_logs_metadata_without_its_value(db, connection, jamf, caplog):
    value = "rejected-id-value"
    assert (await _post(connection.id, value)).json() == {"status": "ignored"}
    diagnostic = next(r for r in caplog.records if "rejected computer id" in r.message)
    assert diagnostic.id_present and diagnostic.id_type == "str" and diagnostic.id_length == len(value)
    assert value not in caplog.text
    assert await _runs(db, connection.id) == []
