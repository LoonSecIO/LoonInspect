"""The rollback sad paths (#125), against a real Postgres and a mocked Jamf Pro.

With expire_on_commit=False a ROLLBACK still expires every ORM instance in the
session, and under asyncio touching an expired attribute raises MissingGreenlet
instead of lazily refreshing. Three error branches had exactly that shape, and none
had a test:

1. `ingest_webhook`'s fetch-failure branch: finish()'s `Run.id` read blew up after
   the rollback, the route 500'd instead of its designed 502, and the run sat
   'running' until the reclaim. The defined behavior, pinned here for a 404 (a
   computer deleted between the webhook and the fetch) and for a 5xx: the run
   finishes `failed` with the error recorded, exactly one run.failed goes to the
   wire (#103), no run.completed (#92), and the route answers 502.
2. `run_jamf`'s generic except: set_sync_status and the log extras read the expired
   connection, so the sync status stayed stuck 'syncing' and collections_tick's
   blanket handler ate the crash. Pinned: the status reaches a terminal 'failed'
   and the failure is logged with the right connection id.
3. `run_jamf_catalog`'s generic except: same expired reads in the log extras and
   the result. Pinned the same way.

The route tests mount the webhook router on a bare FastAPI app and drive it through
httpx's ASGITransport rather than TestClient, so the app runs on this test's own
event loop — the shared AsyncSession must never cross loops.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import json
import logging
import os
import uuid as uuidlib
from contextlib import asynccontextmanager

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text

from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

_SECRET = "sad-path-webhook-secret"


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
        AppCatalogEntry,
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
    )

    row = MdmConnection(
        name=f"sad paths jamf {uuidlib.uuid4().hex[:8]}",
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
        # Keyed by tenant, not connection — see test_runs.py's fixture for why leaving
        # these behind fails test_catalog_db on the next local run.
        await db.execute(delete(AppCatalogEntry))
        await db.commit()


def _webhook_transport(db) -> httpx.ASGITransport:
    """The webhook router on a bare FastAPI app, the real ingest path behind it.

    ASGITransport keeps the app on this test's event loop; its default
    raise_app_exceptions=True means an unhandled MissingGreenlet surfaces as the
    test's own failure rather than an opaque 500."""
    from fastapi import FastAPI

    from app.api import webhooks
    from app.core.database import get_db

    api = FastAPI()
    api.include_router(webhooks.router)

    async def _test_session():
        yield db

    api.dependency_overrides[get_db] = _test_session
    return httpx.ASGITransport(app=api)


async def _webhook_run(db, connection_id):
    from app.models.schema import Run

    run = (
        await db.execute(
            select(Run).where(Run.mdm_connection_id == connection_id, Run.lock_class == "webhook")
        )
    ).scalars().one()
    await db.refresh(run)
    return run


async def _latest_run(db, connection_id):
    from app.models.schema import Run

    run = (
        await db.execute(
            select(Run).where(Run.mdm_connection_id == connection_id).order_by(Run.started_at.desc()).limit(1)
        )
    ).scalars().one()
    await db.refresh(run)
    return run


async def _events(db, event_type: str, run_id) -> list:
    """This run's events of one type, matched by payload rather than recency — the
    shared local database accumulates events across tests."""
    from app.models.schema import EventOutbox

    rows = (
        await db.execute(
            select(EventOutbox).where(EventOutbox.event_type == event_type).order_by(EventOutbox.id)
        )
    ).scalars().all()
    return [row for row in rows if row.payload.get("run_id") == str(run_id)]


async def _post_webhook(db, connection_id: int, payload: dict) -> httpx.Response:
    async with httpx.AsyncClient(transport=_webhook_transport(db), base_url="http://sad-paths") as client:
        return await client.post(f"/webhooks/jamf/{connection_id}", json=payload, headers={"X-API-Key": _SECRET})


async def test_webhook_fetch_404_fails_the_run_and_answers_502(db, jamf: FakeJamf, connection) -> None:
    """The defined behavior for a computer deleted between the webhook and the fetch:
    Jamf answers 404, the run finishes `failed` with the error recorded, exactly one
    run.failed reaches the wire (#103), and the route answers its designed 502 —
    not the MissingGreenlet 500 that left the run 'running' until the reclaim."""
    connection_id = connection.id
    payload = {
        "webhook": {"webhookEvent": "ComputerInventoryCompleted"},
        "event": {"jssID": "999999", "serialNumber": "GONE"},
    }

    response = await _post_webhook(db, connection_id, payload)

    assert response.status_code == 502
    assert response.json() == {"detail": "Inventory fetch from Jamf Pro failed"}
    assert "GET /api/v4/computers-inventory-detail/999999" in jamf.requests

    run = await _webhook_run(db, connection_id)
    assert run.status == "failed"
    assert run.error and "404" in run.error

    alarms = await _events(db, "run.failed", run.id)
    assert len(alarms) == 1
    assert alarms[0].payload["connection_id"] == connection_id
    assert alarms[0].payload["trigger"] == "webhook"
    assert alarms[0].payload["error"] and "404" in alarms[0].payload["error"]
    # The webhook lock class stays outside run.completed (#92) — failing is no exception.
    assert await _events(db, "run.completed", run.id) == []


async def test_webhook_fetch_5xx_fails_the_run_and_answers_502(db, jamf: FakeJamf, connection) -> None:
    """The upstream-down case: Jamf answers 500 on the detail fetch (500 is not in the
    client's transient-retry set, so it surfaces at once). Same verdict as the 404."""
    connection_id = connection.id
    jamf.transient.append(("/api/v4/computers-inventory-detail", 500, {}))
    payload = {
        "webhook": {"webhookEvent": "ComputerInventoryCompleted"},
        "event": {"jssID": jamf.real["id"], "serialNumber": "LOONMINI0M4"},
    }

    response = await _post_webhook(db, connection_id, payload)

    assert response.status_code == 502
    assert response.json() == {"detail": "Inventory fetch from Jamf Pro failed"}

    run = await _webhook_run(db, connection_id)
    assert run.status == "failed"
    assert run.error and "500" in run.error

    alarms = await _events(db, "run.failed", run.id)
    assert len(alarms) == 1
    assert alarms[0].payload["connection_id"] == connection_id
    assert alarms[0].payload["trigger"] == "webhook"
    assert await _events(db, "run.completed", run.id) == []


async def test_generic_sweep_failure_lands_a_terminal_sync_status(
    db, jamf: FakeJamf, connection, monkeypatch, caplog
) -> None:
    """run_jamf's generic except (#125): a mid-transaction failure outside the
    per-device isolation — forced the way test_sweep_failures forces one, so the
    handler's rollback is load-bearing. The sync status must reach 'failed' rather
    than stick at the 'syncing' run_collection published, the run must close
    `failed` with one run.failed, and the log line must carry the connection id."""
    from app.core.runs import TRIGGER_MANUAL
    from app.mdm import service
    from app.mdm.collections import ensure_default_collections, list_collections, run_collection
    from app.models.schema import MdmSyncState

    connection_id = connection.id

    async def poisoned_ensure_aperture(db_, **kwargs):
        # A genuine Postgres error mid-transaction: until the handler rolls back,
        # every subsequent statement on this session is InFailedSQLTransaction.
        await db_.execute(text("SELECT 1/0"))

    monkeypatch.setattr(service, "ensure_aperture", poisoned_ensure_aperture)
    await ensure_default_collections(db, connection)
    await db.commit()
    sweep = next(row for row in await list_collections(db, connection_id) if row.kind == "device_sweep")

    with caplog.at_level(logging.ERROR, logger="app.mdm.service"):
        result = await run_collection(db, sweep, trigger=TRIGGER_MANUAL)

    assert result.ok is False
    assert result.connection_id == connection_id
    assert result.error and "division by zero" in result.error

    state = (
        await db.execute(select(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
    ).scalar_one()
    await db.refresh(state)
    assert state.status == "failed"  # terminal — not the stuck 'syncing' of #125

    run = await _latest_run(db, connection_id)
    assert run.status == "failed"
    assert run.error and "division by zero" in run.error
    alarms = await _events(db, "run.failed", run.id)
    assert len(alarms) == 1
    assert alarms[0].payload["connection_id"] == connection_id

    records = [record for record in caplog.records if record.getMessage() == "jamf sweep failed"]
    assert len(records) == 1
    assert records[0].connection_id == connection_id

    await db.refresh(sweep)
    assert sweep.last_run_status == "failed"


async def test_generic_catalog_failure_is_logged_with_the_connection_id(
    db, jamf: FakeJamf, connection, monkeypatch, caplog
) -> None:
    """run_jamf_catalog's generic except (#125): the same expired-instance shape, in
    the branch with no sync status to publish — the log extras and the result are
    what read the connection, and both must carry its id after the rollback."""
    from app.core.runs import TRIGGER_MANUAL
    from app.mdm import service
    from app.mdm.collections import ensure_default_collections, list_collections, run_collection

    connection_id = connection.id

    async def poisoned_ensure_aperture(db_, **kwargs):
        await db_.execute(text("SELECT 1/0"))

    monkeypatch.setattr(service, "ensure_aperture", poisoned_ensure_aperture)
    await ensure_default_collections(db, connection)
    await db.commit()
    catalog = next(row for row in await list_collections(db, connection_id) if row.kind == "catalog")

    with caplog.at_level(logging.ERROR, logger="app.mdm.service"):
        result = await run_collection(db, catalog, trigger=TRIGGER_MANUAL)

    assert result.ok is False
    assert result.connection_id == connection_id
    assert result.error and "division by zero" in result.error

    run = await _latest_run(db, connection_id)
    assert run.lock_class == "catalog"
    assert run.status == "failed"
    assert run.error and "division by zero" in run.error
    alarms = await _events(db, "run.failed", run.id)
    assert len(alarms) == 1
    assert alarms[0].payload["connection_id"] == connection_id

    records = [record for record in caplog.records if record.getMessage() == "jamf catalog refresh failed"]
    assert len(records) == 1
    assert records[0].connection_id == connection_id

    await db.refresh(catalog)
    assert catalog.last_run_status == "failed"
