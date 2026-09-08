"""The destination routes as an SSRF sink, and the outbox as its driver (#131).

`tests/test_destination_egress.py` pins the rule; this pins that the two routes which
write `destinations.url` apply it, and that the delivery pass refuses a row whose
hostname resolves somewhere blocked — without dialling, and with the reason on the
delivery row the Destinations page reads.

Needs a real Postgres: the routes write through the tenant-scoped session, and the
delivery test is about the rows `deliver_pending` leaves behind. The delivery test
runs in a tenant of its own so the counts are exact.
"""

from __future__ import annotations

import asyncio
import os
import socket
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("destination-egress-admin@example.com", "destination-egress-admin-password")
METADATA_URL = "https://169.254.169.254/latest/meta-data/iam/security-credentials/"
# The delivery test's own tenant, so `deliver_pending` sees exactly the rows it made.
TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-000000000131")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts() -> None:
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, Tenant

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, TENANT_ID) is None:
            db.add(Tenant(id=TENANT_ID, slug="destination-egress", name="Destination egress", kind="operational"))
            await db.commit()

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        email, password = ADMIN
        if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
            await create_account(db, email=email, display_name="admin", password=password, roles=("admin",))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def client(accounts):
    from app.main import app

    signed_in = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://egress.example.com")
    email, password = ADMIN
    response = await signed_in.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    signed_in.headers["X-CSRF-Token"] = signed_in.cookies.get("loon_csrf", "")
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def resolver(monkeypatch: pytest.MonkeyPatch):
    """Point one hostname wherever a test needs it, leaving every other name alone — the
    database pool resolves its own host on this loop."""
    loop = asyncio.get_running_loop()
    real = loop.getaddrinfo
    answers: dict[str, str] = {}

    async def _getaddrinfo(host, port, **kwargs):
        if host in answers:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answers[host], 0))]
        return await real(host, port, **kwargs)

    monkeypatch.setattr(loop, "getaddrinfo", _getaddrinfo)
    yield answers


def _payload(**overrides) -> dict:
    payload = {"name": f"egress {uuidlib.uuid4().hex[:8]}", "type": "generic_webhook", "url": "https://siem.example.com/hook"}
    payload.update(overrides)
    return payload


async def _delete(client: httpx.AsyncClient, destination_id: int) -> None:
    assert (await client.delete(f"/api/destinations/{destination_id}")).status_code == 204


# --- the writes ------------------------------------------------------------------------


async def test_security_a_destination_cannot_be_created_at_the_metadata_address(client) -> None:
    response = await client.post("/api/destinations", json=_payload(url=METADATA_URL))
    assert response.status_code == 422, response.text
    assert "link-local" in response.text


async def test_plain_http_is_refused_with_the_setting_named(client) -> None:
    response = await client.post("/api/destinations", json=_payload(url="http://siem.example.com:8088/services/collector"))
    assert response.status_code == 422, response.text
    assert "ALLOW_INSECURE_DESTINATION_URL" in response.text


async def test_security_a_hostname_resolving_to_the_metadata_address_is_refused_at_the_write(client, resolver) -> None:
    resolver["metadata.attacker.example"] = "169.254.169.254"
    response = await client.post("/api/destinations", json=_payload(url="https://metadata.attacker.example/hook"))
    assert response.status_code == 422, response.text
    assert "169.254.169.254" in response.text and "link-local" in response.text


async def test_a_legitimate_destination_still_saves_and_cannot_be_moved_somewhere_blocked(client, resolver) -> None:
    resolver["metadata.attacker.example"] = "169.254.169.254"
    created = await client.post("/api/destinations", json=_payload(url="https://siem.corp.internal:8088/services/collector"))
    assert created.status_code == 201, created.text
    destination_id = created.json()["id"]
    try:
        for blocked in (METADATA_URL, "https://metadata.attacker.example/hook", "https://127.0.0.1:8088/x"):
            moved = await client.patch(f"/api/destinations/{destination_id}", json={"url": blocked})
            assert moved.status_code == 422, moved.text
        kept = next(row for row in (await client.get("/api/destinations")).json() if row["id"] == destination_id)
        assert kept["url"] == "https://siem.corp.internal:8088/services/collector"
    finally:
        await _delete(client, destination_id)


# --- the driver ----------------------------------------------------------------------


async def test_security_delivery_to_a_row_that_resolves_somewhere_blocked_is_refused_without_dialling(
    accounts, resolver, monkeypatch
) -> None:
    """A row inserted beneath the schema — as a row stored before the rule would be —
    with a hostname whose record now points at the metadata address. The tick must
    count a failed attempt with the reason, back the delivery off, and never open a
    connection."""
    from app.core import outbox
    from app.core.database import session_for_tenant
    from app.core.outbox import deliver_pending, enqueue_event, fan_out_pending
    from app.models.schema import Destination, EventOutbox, OutboxDelivery

    resolver["metadata.attacker.example"] = "169.254.169.254"
    dialled: list[httpx.Request] = []

    class _Recording(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(lambda request: (dialled.append(request), httpx.Response(200))[1])
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(outbox.httpx, "AsyncClient", _Recording)

    async with session_for_tenant(TENANT_ID) as db:
        destination = Destination(
            name="stored before the rule", type="generic_webhook", url="https://metadata.attacker.example/hook",
            auth_type="none", enabled=True,
        )
        db.add(destination)
        event = await enqueue_event(db, "device.change", {"event": "device.change", "probe": uuidlib.uuid4().hex})
        await db.commit()
        destination_id, event_id = destination.id, event.id
        try:
            await fan_out_pending(db)
            await deliver_pending(db)
            await db.rollback()

            delivery = (
                await db.execute(select(OutboxDelivery).where(OutboxDelivery.outbox_event_id == event_id))
            ).scalar_one()
            assert delivery.status == "pending" and delivery.attempt_count == 1
            assert delivery.last_error is not None and "169.254.169.254" in delivery.last_error
            assert "link-local" in delivery.last_error and delivery.last_error.startswith("url may not point at")
            assert delivery.next_attempt_at is not None
            assert (await db.get(Destination, destination_id)).last_failure_at is not None
            assert dialled == [], "a blocked destination must never be dialled"
        finally:
            await db.rollback()
            await db.execute(delete(OutboxDelivery).where(OutboxDelivery.destination_id == destination_id))
            await db.execute(delete(EventOutbox).where(EventOutbox.id == event_id))
            await db.execute(delete(Destination).where(Destination.id == destination_id))
            await db.commit()
