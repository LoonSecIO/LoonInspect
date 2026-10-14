# ruff: noqa: F811 — imported fixtures are injected by pytest.
"""A slow Jamf cannot occupy the database pool, and same-device writes stay ordered."""

import asyncio
from copy import deepcopy
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import func, select, text

from app.core.config import settings
from app.core.database import engine, session_for_tenant
from app.core.tenancy import OPERATIONAL_TENANT_ID
from app.mdm import service
from app.models.schema import Device, MdmConnection, ObservationSpan, Run
from tests.jamf_fake import FakeJamf
from tests.test_webhook_runs_db import _post, _runs, connection, pytestmark  # noqa: F401

pytestmark = pytestmark


async def test_a_burst_waiting_on_jamf_leaves_health_and_database_available(db, connection, jamf, monkeypatch):
    from app.api import webhooks
    from app.main import app

    jamf.seed(20)
    full, release = asyncio.Event(), asyncio.Event()
    arrived = 0

    async def handler(request):
        nonlocal arrived
        if "computers-inventory-detail" in request.url.path:
            arrived += 1
            if arrived == webhooks._MAX_ACTIVE_WEBHOOKS:
                full.set()
            await release.wait()
        return FakeJamf.handler(jamf, request)

    monkeypatch.setattr(jamf, "handler", handler)
    baseline = engine.pool.checkedout()
    tasks = [asyncio.create_task(_post(connection.id, raw["id"])) for raw in jamf.computers]
    try:
        await asyncio.wait_for(full.wait(), 5)
        await asyncio.sleep(0.1)
        assert engine.pool.checkedout() == baseline
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as observer:
            assert (
                await observer.scalar(
                    text(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                        "AND state = 'idle in transaction' AND pid <> pg_backend_pid()"
                    )
                )
                == 0
            )
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://loon.test") as client:
            assert (await asyncio.wait_for(client.get("/api/health"), 1)).status_code == 200
    finally:
        release.set()
        responses = await asyncio.gather(*tasks)
    assert sum(response.status_code == 200 for response in responses) == webhooks._MAX_ACTIVE_WEBHOOKS
    assert all(response.status_code in (200, 503) for response in responses)
    assert webhooks._ACTIVE_WEBHOOKS == 0
    rows = await _runs(db, connection.id)
    assert len(rows) == len({r.id for r in rows}) == webhooks._MAX_ACTIVE_WEBHOOKS
    assert {r.status for r in rows} == {"succeeded"}


@pytest.mark.parametrize("same_time", [False, True])
async def test_first_creation_is_serialized_and_an_older_read_cannot_win(db, connection, jamf, monkeypatch, same_time):
    newer, older = deepcopy(jamf.real), deepcopy(jamf.real)
    newer["general"]["reportDate"] = "2026-10-07T12:00:00Z"
    older["general"]["reportDate"] = newer["general"]["reportDate"] if same_time else "2026-10-06T12:00:00Z"
    current_write, release = asyncio.Event(), asyncio.Event()
    original = service.process_sync

    async def pause_first(session, device, conn, **kwargs):
        if not current_write.is_set():
            current_write.set()
            await release.wait()
        return await original(session, device, conn, **kwargs)

    monkeypatch.setattr(service, "process_sync", pause_first)
    connection_id = connection.id

    async def write(raw):
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
            conn = await session.get(MdmConnection, connection_id)
            return await service.ingest_computer(
                session, conn, raw, aperture_digest="a" * 64, trigger="sweep" if raw is newer else "webhook"
            )

    first = asyncio.create_task(write(newer))
    await asyncio.wait_for(current_write.wait(), 5)
    second = asyncio.create_task(write(older))
    try:
        await asyncio.sleep(0.05)
        assert not second.done()
    finally:
        release.set()
        results = await asyncio.gather(first, second)
    assert [result.outcome for result in results] == ["new", "repeat" if same_time else "stale"]
    devices = await db.scalar(select(func.count()).select_from(Device).where(Device.mdm_connection_id == connection_id))
    spans = await db.scalar(
        select(func.count())
        .select_from(ObservationSpan)
        .where(ObservationSpan.mdm_connection_id == connection_id, ObservationSpan.is_current.is_(True))
    )
    assert (devices, spans) == (1, 1)


@pytest.mark.parametrize("phase", ["read", "write", "after_commit"])
async def test_optional_deadline_closes_the_run_and_releases_capacity(db, connection, jamf, monkeypatch, phase):
    from app.api import webhooks

    monkeypatch.setattr(settings, "webhook_timeout_seconds", 0.2)
    arrived = asyncio.Event()

    async def handler(request):
        if phase == "read" and "computers-inventory-detail" in request.url.path:
            arrived.set()
            await asyncio.Event().wait()
        return FakeJamf.handler(jamf, request)

    monkeypatch.setattr(jamf, "handler", handler)
    if phase == "write":

        async def stalled_write(*args, **kwargs):
            arrived.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(service, "process_sync", stalled_write)
    elif phase == "after_commit":

        async def stalled_after_commit(*args, **kwargs):
            arrived.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(service, "_log_collapsed_departures", stalled_after_commit)
    response = await _post(connection.id, jamf.real["id"])
    assert arrived.is_set()
    assert response.status_code == (200 if phase == "after_commit" else 502)
    (run,) = await _runs(db, connection.id)
    if phase == "after_commit":
        assert run.status == "succeeded" and run.error is None and run.devices_processed == 1
    else:
        assert "time limit" in response.json()["detail"]
        assert run.status == "failed" and "interrupted" in run.error
    assert webhooks._ACTIVE_WEBHOOKS == 0
    assert await db.scalar(select(func.count()).select_from(Run).where(Run.status == "running", Run.id == run.id)) == 0
    for model in (Device, ObservationSpan):
        count = await db.scalar(select(func.count()).select_from(model).where(model.mdm_connection_id == connection.id))
        assert count == (1 if phase == "after_commit" else 0)


async def test_acquisition_contention_is_a_retryable_response(connection, jamf, monkeypatch):
    from app.core.runs import LOCK_WEBHOOK, AcquisitionBusy

    async def busy(*args, **kwargs):
        raise AcquisitionBusy(connection.id, LOCK_WEBHOOK)

    monkeypatch.setattr(service, "acquire", busy)
    response = await _post(connection.id, jamf.real["id"])
    assert response.status_code == 503 and response.headers["Retry-After"] == "1"
    assert jamf.requests == []


async def test_webhook_never_finishes_a_holder_it_did_not_start(db, connection, jamf, monkeypatch):
    from app.core import runs

    holder = await runs.acquire(db, connection, trigger="sweep")

    async def joined(*args, **kwargs):
        return runs.Acquisition(holder.run, started=False)

    monkeypatch.setattr(service, "acquire", joined)
    response = await _post(connection.id, jamf.real["id"])
    assert response.status_code == 503 and jamf.requests == []
    await db.refresh(holder.run)
    assert holder.run.status == "running"
    await runs.finish(db, holder.run, ok=True)


async def test_same_device_lock_wait_is_bounded_and_rolls_back_cleanly(connection):
    from app.mdm.concurrency import IngestBusy, lock_device

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as owner, session_for_tenant(OPERATIONAL_TENANT_ID) as waiter:
        await lock_device(owner, connection.id, "macos", "1")
        async with asyncio.timeout(7):
            with pytest.raises(IngestBusy, match="still being saved"):
                await lock_device(waiter, connection.id, "macos", "1")
        # The savepoint leaves the caller usable, and a distinct computer is free.
        await lock_device(waiter, connection.id, "macos", "2")
        await waiter.commit()


async def test_authentication_and_ignored_events_do_not_take_capacity(db, connection, jamf, monkeypatch):
    from app.api import webhooks
    from app.main import app
    from tests.test_webhook_runs_db import _SECRET

    monkeypatch.setattr(webhooks, "_ACTIVE_WEBHOOKS", webhooks._MAX_ACTIVE_WEBHOOKS)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://loon.test") as client:
        url = f"/webhooks/jamf/{connection.id}"
        body = {"webhook": {"webhookEvent": "ComputerCheckIn"}, "event": {"jssID": jamf.real["id"]}}
        assert (await client.post(url, json=body)).status_code == 401
        ignored = await client.post(url, json=body, headers={"X-API-Key": _SECRET})
        assert ignored.status_code == 200 and ignored.json() == {"status": "ignored"}
        assert (await _post(connection.id, jamf.real["id"])).status_code == 503
    assert await _runs(db, connection.id) == []
    assert jamf.requests == []
    assert webhooks._ACTIVE_WEBHOOKS == webhooks._MAX_ACTIVE_WEBHOOKS


async def test_body_read_is_bounded_even_without_processing_budget(connection, monkeypatch):
    from app.api import webhooks
    from app.main import app
    from tests.test_webhook_runs_db import _SECRET

    monkeypatch.setattr(settings, "webhook_timeout_seconds", 0)
    monkeypatch.setattr(webhooks, "_BODY_READ_TIMEOUT_SECONDS", 0.05)

    async def trickle():
        yield b'{"event":'
        await asyncio.Event().wait()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://loon.test") as client:
        async with asyncio.timeout(1):
            response = await client.post(f"/webhooks/jamf/{connection.id}", content=trickle(), headers={"X-API-Key": _SECRET})
    assert response.status_code == 408
    assert webhooks._ACTIVE_WEBHOOKS == 0


async def test_two_macs_can_first_report_the_same_build_together(db, connection, jamf, monkeypatch):
    reached = 0
    both = asyncio.Event()
    original = service.record_device_apps

    async def together(session, device, **kwargs):
        nonlocal reached
        reached += 1
        if reached == 2:
            both.set()
        await asyncio.wait_for(both.wait(), 3)
        return await original(session, device, **kwargs)

    # Different observation content lets both transactions reach the shared catalog.
    for i, raw in enumerate(jamf.computers):
        raw["applications"] = [{"name": "Shared first build", "bundleId": "test.shared.first", "version": "1", "path": f"/{i}"}]
    monkeypatch.setattr(service, "record_device_apps", together)
    responses = await asyncio.gather(*(_post(connection.id, raw["id"]) for raw in jamf.computers))
    assert [response.status_code for response in responses] == [200, 200]
    assert {run.status for run in await _runs(db, connection.id)} == {"succeeded"}


@pytest.mark.parametrize("sqlstate", ["23505", "40P01"])
async def test_shared_write_contention_is_retryable(db, connection, jamf, monkeypatch, sqlstate):
    from sqlalchemy.exc import DBAPIError

    async def conflict(*args, **kwargs):
        cause = Exception("database write contention")
        cause.sqlstate = sqlstate
        raise DBAPIError(None, None, cause)

    monkeypatch.setattr(service, "ingest_computer", conflict)
    response = await _post(connection.id, jamf.real["id"])
    assert response.status_code == 503 and response.headers["Retry-After"] == "1"
    (run,) = await _runs(db, connection.id)
    assert run.status == "failed" and "overlapped" in run.error


async def test_enrollment_followed_by_inventory_waits_for_the_first_write(db, connection, jamf, monkeypatch):
    first_write = asyncio.Event()
    release = asyncio.Event()
    original = service.process_sync
    original_raw = deepcopy(jamf.real)
    original_raw["general"]["reportDate"] = "2026-10-06T10:00:00Z"
    newer = deepcopy(original_raw)
    newer["general"]["reportDate"] = "2026-10-06T10:01:00Z"
    jamf.real = original_raw

    async def pause_first(*args, **kwargs):
        if not first_write.is_set():
            first_write.set()
            await release.wait()
        return await original(*args, **kwargs)

    monkeypatch.setattr(service, "process_sync", pause_first)
    first = asyncio.create_task(_post(connection.id, jamf.real["id"]))
    await asyncio.wait_for(first_write.wait(), 3)
    jamf.real = newer
    second = asyncio.create_task(_post(connection.id, jamf.real["id"]))
    try:
        await asyncio.sleep(1.1)
        assert not second.done()
    finally:
        release.set()
        responses = await asyncio.gather(first, second)
    assert [r.status_code for r in responses] == [200, 200]
    current = (
        (
            await db.execute(
                select(ObservationSpan).where(
                    ObservationSpan.mdm_connection_id == connection.id, ObservationSpan.is_current.is_(True)
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(current) == 1
    assert current[0].last_observed_at == datetime(2026, 10, 6, 10, 1, tzinfo=UTC)
    assert {r.status for r in await _runs(db, connection.id)} == {"succeeded"}


async def test_busy_delivery_records_no_failure_alarm(db, connection, jamf, monkeypatch):
    from app.mdm.concurrency import IngestBusy
    from tests.test_webhook_runs_db import _events

    async def busy(*args, **kwargs):
        raise IngestBusy("Another inventory read is still being saved for this Mac. Retry shortly.")

    monkeypatch.setattr(service, "ingest_computer", busy)
    assert (await _post(connection.id, jamf.real["id"])).status_code == 503
    (run,) = await _runs(db, connection.id)
    assert run.status == "failed"
    assert "run.failed" not in await _events(db, run.id)


async def test_deadline_during_run_started_log_closes_only_its_committed_row(db, connection, jamf, monkeypatch):
    from app.core import runs

    monkeypatch.setattr(settings, "webhook_timeout_seconds", 0.1)
    original = runs.log

    async def stalled(session, run, level, message, **fields):
        if message == "run started":
            await asyncio.Event().wait()
        await original(session, run, level, message, **fields)

    monkeypatch.setattr(runs, "log", stalled)
    assert (await _post(connection.id, jamf.real["id"])).status_code == 502
    (run,) = await _runs(db, connection.id)
    assert run.status == "failed" and "before any inventory was read" in run.error
    assert jamf.requests == []


async def test_slow_close_events_cannot_undo_the_terminal_verdict(db, connection, jamf, monkeypatch):
    from app.core import runs

    async def stalled(*args, **kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(runs, "_emit_after_release", stalled)
    assert (await _post(connection.id, jamf.real["id"])).status_code == 200
    (run,) = await _runs(db, connection.id)
    assert run.status == "succeeded" and run.devices_processed == 1


async def test_real_socket_sign_in_obeys_the_route_budget(db, connection, monkeypatch):
    from app.mdm.jamf.client import JamfClient

    connected, closed = asyncio.Event(), asyncio.Event()

    async def silent(reader, writer):
        try:
            await reader.read(4096)
            connected.set()
            await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()
            closed.set()

    server = await asyncio.start_server(silent, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    socket_client = JamfClient(f"http://127.0.0.1:{port}", "id", "secret")
    monkeypatch.setattr(service, "get_mdm_client", lambda conn: socket_client)
    monkeypatch.setattr(settings, "webhook_timeout_seconds", 0.2)
    try:
        async with server, asyncio.timeout(3):
            response = await _post(connection.id, "1")
            assert response.status_code == 502 and connected.is_set()
            await asyncio.wait_for(closed.wait(), 1)
        (run,) = await _runs(db, connection.id)
        assert run.status == "failed" and "before any inventory was read" in run.error
        assert socket_client._tokens.failure_message is None
    finally:
        server.close()
        await server.wait_closed()


async def test_device_refresh_holds_no_transaction_during_network_reads(db, connection, jamf, monkeypatch):
    from app.mdm.device_refresh import refresh_device
    from tests.test_webhook_runs_db import _gate

    cid = connection.id
    held, release = _gate(monkeypatch, jamf, lambda r: "computers-inventory-detail" in r.url.path)
    baseline = engine.pool.checkedout()

    async def refresh():
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
            return await refresh_device(session, await session.get(MdmConnection, cid), jamf.real["id"], actor_label="test")

    task = asyncio.create_task(refresh())
    try:
        await asyncio.wait_for(held.wait(), 3)
        assert engine.pool.checkedout() == baseline
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as observer:
            assert (
                await observer.scalar(
                    text(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                        "AND state = 'idle in transaction' AND pid <> pg_backend_pid()"
                    )
                )
                == 0
            )
    finally:
        release.set()
        await task
