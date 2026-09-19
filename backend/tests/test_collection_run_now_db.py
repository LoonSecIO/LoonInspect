"""Run now on one collection, against a real Postgres (#582).

The run row is the mutex, and this endpoint takes it in the request like `POST
/connections/{id}/sync` does: a free lock answers `started: true` and the run it took,
which the background task then closes with the collection's own outcome; a held lock
answers `started: false` and the holder's id, queues nothing behind it, and starts no
second run. A webhook collection is still refused. Gated on RUN_DB_TESTS like the other
database-backed suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("run-now-admin@example.com", "run-now-admin-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def account(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    email, password = ADMIN
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
            await create_account(db, email=email, display_name="run-now admin", password=password, roles=("admin",))
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def admin(account):
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://run-now.example.com")
    email, password = ADMIN
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def collections(db):
    """A Jamf connection with the three default collections, removed with its fleet."""
    from app.core.scheduling import KIND_DEVICE_SWEEP, KIND_WEBHOOK
    from app.mdm.collections import ensure_default_collections
    from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    connection = MdmConnection(
        name=f"run-now jamf {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
        capability_webhooks=True,
    )
    db.add(connection)
    await db.commit()
    kinds = {row.kind: row.id for row in await ensure_default_collections(db, connection)}
    await db.commit()
    connection_id = connection.id
    try:
        yield connection, kinds[KIND_DEVICE_SWEEP], kinds[KIND_WEBHOOK]
    finally:
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


async def _runs_on(db, connection_id: int) -> int:
    from app.models.schema import Run

    return (await db.execute(select(func.count(Run.id)).where(Run.mdm_connection_id == connection_id))).scalar_one()


async def test_a_free_lock_starts_a_run_and_the_task_closes_it(admin, db, jamf: FakeJamf, collections) -> None:
    """The 202 names the run it took, and the run is closed by the time the request
    returns — the background task runs inside the ASGI transport. Closed *with the
    result*, not merely closed: a handed-in run is not finished by `run_one_collection`,
    and a bare `finish(ok=True)` would leave the fleet it swept off its own row."""
    from app.core.runs import LOCK_DEVICE_SWEEP, STATUS_SUCCEEDED, TRIGGER_MANUAL
    from app.models.schema import Collection, Run

    _, sweep_id, _ = collections
    accepted = await admin.post(f"/api/mdm/collections/{sweep_id}/run")
    assert accepted.status_code == 202, accepted.text
    body = accepted.json()
    assert (body["collectionId"], body["status"], body["started"]) == (sweep_id, "queued", True)

    run = await db.get(Run, uuidlib.UUID(body["jobId"]))
    assert run is not None
    await db.refresh(run)
    assert (run.collection_id, run.lock_class, run.trigger) == (sweep_id, LOCK_DEVICE_SWEEP, TRIGGER_MANUAL)
    assert run.status == STATUS_SUCCEEDED, f"the run was left {run.status}: the lock is held until the reclaim"
    assert run.device_count >= 2, "the fake tenant is two devices, and the close carries the sweep's counts"
    assert run.actor_label == ADMIN[0]

    collection = await db.get(Collection, sweep_id)
    assert collection is not None
    await db.refresh(collection)
    assert collection.last_run_status == "ok"
    assert collection.last_run_summary["jobId"] == body["jobId"]


async def test_a_held_lock_answers_with_the_holder_and_queues_nothing(admin, db, collections) -> None:
    """No `jamf` fixture here on purpose: a second run would have to reach Jamf, and
    there is nothing for it to reach."""
    from app.core.runs import LOCK_DEVICE_SWEEP, TRIGGER_SWEEP, acquire, finish

    connection, sweep_id, _ = collections
    holder = await acquire(db, connection, trigger=TRIGGER_SWEEP, lock_class=LOCK_DEVICE_SWEEP)
    assert holder.started
    before = await _runs_on(db, connection.id)
    try:
        accepted = await admin.post(f"/api/mdm/collections/{sweep_id}/run")
        assert accepted.status_code == 202, accepted.text
        body = accepted.json()
        assert body["started"] is False and body["status"] == "running"
        assert body["jobId"] == str(holder.run.id), "the answer names the run that holds the connection"
        assert await _runs_on(db, connection.id) == before, "nothing was started or queued behind the holder"
    finally:
        assert await finish(db, holder.run, ok=True)


async def test_a_webhook_collection_is_still_refused(admin, db, collections) -> None:
    connection, _, webhook_id = collections
    before = await _runs_on(db, connection.id)
    refused = await admin.post(f"/api/mdm/collections/{webhook_id}/run")
    assert refused.status_code == 409, refused.text
    assert "event-driven" in refused.json()["detail"]
    assert await _runs_on(db, connection.id) == before
