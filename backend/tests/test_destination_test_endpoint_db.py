"""POST /api/destinations/{id}/test: the status code is a field, not a number in a sentence.

Kyle asked for "status 200" on the test result (#305). On the failure path it was already
there, inside `detail` — "HTTP 403: …" — which made parsing it out tempting; on the
success path it was discarded before the response was built. Both are answered the same
way: `statusCode` is its own field on both paths, and it is null when no HTTP response
came back at all, which is a different diagnosis from any status code.

The outbound request is answered by a MockTransport installed in place of
`app.core.outbox.httpx.AsyncClient`, the same seam `test_hec_fanout` uses, so the whole
path from the route to the wire runs — including the response hook that reads the code.

Needs a real Postgres: the route resolves the destination through the tenant-scoped
session. Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("destination-test-admin@example.com", "destination-test-admin-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts() -> None:
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        email, password = ADMIN
        # Get-or-create, so a developer re-running this locally is not stopped by the
        # unique constraint the previous pass left behind.
        if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
            await create_account(db, email=email, display_name="admin", password=password, roles=("admin",))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def client(accounts):
    from app.main import app

    # https, not http: the session cookie is Secure and a plain-http origin drops it.
    signed_in = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://destinations.example.com")
    email, password = ADMIN
    response = await signed_in.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    signed_in.headers["X-CSRF-Token"] = signed_in.cookies.get("loon_csrf", "")
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def destination_id(accounts):
    """One generic webhook with no auth, deleted afterwards."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Destination

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        row = Destination(
            name=f"test-button {uuidlib.uuid4().hex[:8]}",
            type="generic_webhook",
            url="https://receiver.example/hook",
            auth_type="none",
        )
        db.add(row)
        await db.commit()
        row_id = row.id
    try:
        yield row_id
    finally:
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            await db.execute(delete(Destination).where(Destination.id == row_id))
            await db.commit()


def _answering(monkeypatch, handler) -> None:
    """Every `httpx.AsyncClient` the outbox opens answers through `handler`. The
    subclass forwards the keyword arguments, so the response hook the test button
    installs survives the swap."""
    from app.core import outbox

    class _Mocked(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(outbox.httpx, "AsyncClient", _Mocked)


async def test_a_delivered_test_reports_its_status_code_as_a_field(client, destination_id, monkeypatch) -> None:
    _answering(monkeypatch, lambda request: httpx.Response(200, json={"received": True}))

    response = await client.post(f"/api/destinations/{destination_id}/test")

    assert response.status_code == 200
    body = response.json()
    assert body == {"ok": True, "detail": "Delivered. The destination accepted a test event.", "statusCode": 200}


async def test_a_refused_test_reports_the_refusing_status_beside_the_detail(client, destination_id, monkeypatch) -> None:
    _answering(monkeypatch, lambda request: httpx.Response(403, json={"text": "Invalid token", "code": 4}))

    response = await client.post(f"/api/destinations/{destination_id}/test")

    assert response.status_code == 200, "the upstream verdict is the payload, never the status of this call"
    body = response.json()
    assert body["ok"] is False
    assert body["statusCode"] == 403
    # The sentence is still there for a reader; the number is no longer only inside it.
    assert body["detail"].startswith("HTTP 403: ")


async def test_no_response_at_all_is_a_null_status_not_a_made_up_one(client, destination_id, monkeypatch) -> None:
    def refuse_connection(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[Errno 61] Connection refused")

    _answering(monkeypatch, refuse_connection)

    response = await client.post(f"/api/destinations/{destination_id}/test")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["statusCode"] is None
    assert "Connection refused" in body["detail"]
