"""`POST /api/destinations/{id}/redrive` through the running route (#91): gated on
`destination:write`, 404 for a destination that is not there, and the counts the
Destinations page reads move from "gave up" to "queued" in one call.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import UTC

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("redrive-admin@example.com", "redrive-admin-password")
VIEWER = ("redrive-viewer@example.com", "redrive-viewer-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        for (email, password), role in ((ADMIN, "admin"), (VIEWER, "viewer")):
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=f"redrive {role}", password=password, roles=(role,))
            await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
        await db.commit()


async def _signed_in(credentials: tuple[str, str]) -> httpx.AsyncClient:
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://redrive.example.com")
    email, password = credentials
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return client


@pytest_asyncio.fixture(loop_scope="session")
async def admin(accounts):
    client = await _signed_in(ADMIN)
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def viewer(accounts):
    client = await _signed_in(VIEWER)
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def dead_letters(db, admin):
    """A destination with two deliveries that spent their budget, removed afterwards.

    The rows are written directly rather than through `fan_out_pending`: a fan-out pass
    takes every held event in the tenant with it — hundreds, after the suites that run
    before this one — and this destination would inherit all of them.
    """
    from datetime import datetime

    from app.core.outbox import enqueue_event
    from app.models.schema import Destination, EventOutbox, OutboxDelivery

    created = await admin.post(
        "/api/destinations",
        json={
            "name": f"redrive {uuidlib.uuid4().hex[:8]}",
            "type": "generic_webhook",
            "url": "https://siem.example/redrive",
            "authType": "none",
            "enabled": True,
        },
    )
    assert created.status_code == 201, created.text
    destination_id = created.json()["id"]
    event_ids = []
    now = datetime.now(UTC)
    for _ in range(2):
        event = await enqueue_event(db, "device.change", {"event": "device.change"})
        event.fanned_out = True
        await db.flush()
        event_ids.append(event.id)
        db.add(
            OutboxDelivery(
                outbox_event_id=event.id,
                destination_id=destination_id,
                status="failed",
                attempt_count=10,
                next_attempt_at=now,
                last_attempted_at=now,
                last_error="HTTP 503: gone for the night",
            )
        )
    await db.commit()
    try:
        yield destination_id
    finally:
        await db.rollback()
        await db.execute(delete(OutboxDelivery).where(OutboxDelivery.outbox_event_id.in_(event_ids)))
        await db.execute(delete(EventOutbox).where(EventOutbox.id.in_(event_ids)))
        await db.execute(delete(Destination).where(Destination.id == destination_id))
        await db.commit()


async def _row(admin: httpx.AsyncClient, destination_id: int) -> dict:
    listed = await admin.get("/api/destinations")
    assert listed.status_code == 200, listed.text
    return next(row for row in listed.json() if row["id"] == destination_id)


async def test_a_redrive_moves_what_gave_up_back_to_queued(admin, dead_letters: int) -> None:
    before = await _row(admin, dead_letters)
    assert (before["failedCount"], before["pendingCount"]) == (2, 0)
    assert before["lastError"] == "HTTP 503: gone for the night"

    response = await admin.post(f"/api/destinations/{dead_letters}/redrive")
    assert response.status_code == 200, response.text
    assert response.json() == {"redriven": 2}

    after = await _row(admin, dead_letters)
    assert (after["failedCount"], after["pendingCount"]) == (0, 2)
    # The diagnosis stays on the page until a delivery clears it: the rows are pending
    # *because* of that error.
    assert after["lastError"] == "HTTP 503: gone for the night"

    # Nothing left waiting: zero is an answer, not an error.
    again = await admin.post(f"/api/destinations/{dead_letters}/redrive")
    assert again.status_code == 200 and again.json() == {"redriven": 0}


async def test_a_redrive_needs_destination_write(viewer, dead_letters: int) -> None:
    response = await viewer.post(f"/api/destinations/{dead_letters}/redrive")
    assert response.status_code == 403, response.text


async def test_a_redrive_of_a_destination_that_is_not_there_is_a_404(admin) -> None:
    response = await admin.post("/api/destinations/987654321/redrive")
    assert response.status_code == 404, response.text
