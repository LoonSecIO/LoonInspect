"""The deadline a redrive is decided against, and delivery health as a window (#469), read
back through `GET /api/destinations`.

`failedCount` is a lifetime count a redrive zeroes, so "has this destination ever failed" and
"is it failing now" were one number; `failed24h` is the second, in the window the recorder
counts as `outbox.failed_24h`. `deadLetterOldestExpiresAt` is the instant the purge takes the
oldest dead letter's event with it, after which the gap in the trail is permanent (#91).

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import os
import uuid as uuidlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("expiry-admin@example.com", "expiry-admin-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def admin(tenant_ready):
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.main import app
    from app.models.schema import Account, LoginAttempt

    email, password = ADMIN
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
            await create_account(db, email=email, display_name="expiry admin", password=password, roles=("admin",))
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
        await db.commit()

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://expiry.example.com")
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    try:
        yield client
    finally:
        await client.aclose()


async def _destination(admin: httpx.AsyncClient) -> int:
    created = await admin.post(
        "/api/destinations",
        json={
            "name": f"expiry {uuidlib.uuid4().hex[:8]}",
            "type": "generic_webhook",
            "url": "https://siem.example/expiry",
            "authType": "none",
            "enabled": True,
        },
    )
    assert created.status_code == 201, created.text
    return int(created.json()["id"])


async def _dead_letter(db, destination_id: int, *, produced: datetime, attempted: datetime) -> int:
    """One delivery that spent its ten attempts, with its event aged by hand. Written directly
    rather than through `fan_out_pending`, which would take every held event in the tenant with
    it — the suites that run before this one leave hundreds."""
    from app.core.outbox import enqueue_event
    from app.models.schema import OutboxDelivery

    event = await enqueue_event(db, "device.change", {"event": "device.change"})
    event.fanned_out = True
    event.created_at = produced
    await db.flush()
    db.add(
        OutboxDelivery(
            outbox_event_id=event.id,
            destination_id=destination_id,
            status="failed",
            attempt_count=10,
            next_attempt_at=attempted,
            last_attempted_at=attempted,
            last_error="HTTP 503: gone for the night",
        )
    )
    return int(event.id)


async def _row(admin: httpx.AsyncClient, destination_id: int) -> dict:
    listed = await admin.get("/api/destinations")
    assert listed.status_code == 200, listed.text
    return next(row for row in listed.json() if row["id"] == destination_id)


async def _forget(db, destination_id: int, event_ids: list[int]) -> None:
    from app.models.schema import Destination, EventOutbox, OutboxDelivery

    await db.rollback()
    await db.execute(delete(OutboxDelivery).where(OutboxDelivery.outbox_event_id.in_(event_ids or [0])))
    await db.execute(delete(EventOutbox).where(EventOutbox.id.in_(event_ids or [0])))
    await db.execute(delete(Destination).where(Destination.id == destination_id))
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def two_ages(db, admin):
    """One destination holding two dead letters of different ages: one produced five days ago
    and last attempted forty hours ago, one produced yesterday and attempted two hours ago.
    Yields the destination and the instant the older was produced."""
    now = datetime.now(UTC)
    oldest_produced = now - timedelta(days=5)
    destination_id = await _destination(admin)
    event_ids = [
        await _dead_letter(db, destination_id, produced=oldest_produced, attempted=now - timedelta(hours=40)),
        await _dead_letter(db, destination_id, produced=now - timedelta(days=1), attempted=now - timedelta(hours=2)),
    ]
    await db.commit()
    try:
        yield destination_id, oldest_produced
    finally:
        await _forget(db, destination_id, event_ids)


@pytest_asyncio.fixture(loop_scope="session")
async def nothing_failed(db, admin):
    """A destination that has never dead-lettered anything."""
    destination_id = await _destination(admin)
    try:
        yield destination_id
    finally:
        await _forget(db, destination_id, [])


async def test_a_destination_with_no_dead_letters_has_no_deadline(admin, nothing_failed: int) -> None:
    row = await _row(admin, nothing_failed)
    assert (row["failedCount"], row["failed24h"]) == (0, 0)
    # Absent, not a date: nothing is waiting, so there is no moment a redrive stops being
    # possible, and the page says no sentence about one.
    assert row["deadLetterOldestExpiresAt"] is None


async def test_the_oldest_dead_letter_owns_the_deadline(admin, two_ages) -> None:
    from app.core.config import settings

    destination_id, oldest_produced = two_ages
    row = await _row(admin, destination_id)
    assert row["failedCount"] == 2
    # The oldest governs: its event is the first the purge stops protecting, and from then on
    # a redrive of the pair cannot reach all of it.
    expires = datetime.fromisoformat(row["deadLetterOldestExpiresAt"])
    assert expires == oldest_produced + timedelta(days=settings.dead_letter_retention_days)


async def test_failed24h_is_a_window_where_failed_count_is_a_lifetime(admin, two_ages) -> None:
    destination_id, _ = two_ages
    row = await _row(admin, destination_id)
    # The forty-hour-old attempt is outside the window and still in the lifetime count: a
    # destination that failed badly last week no longer reads the same as one failing now.
    assert (row["failedCount"], row["failed24h"]) == (2, 1)
