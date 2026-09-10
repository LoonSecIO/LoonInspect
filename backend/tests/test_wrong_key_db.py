"""A wrong ENCRYPTION_KEY through the running routes (#374): the request answers 503 with the
sentence, the Connections and Destinations lists both do, and the log carries the sentence
once per process with no traceback. Gated on RUN_DB_TESTS like the other suites."""

from __future__ import annotations

import logging
import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("wrong-key-admin@example.com", "wrong-key-admin-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        if (await db.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first() is None:
            await create_account(db, email=ADMIN[0], display_name="wrong-key admin", password=ADMIN[1], roles=("admin",))
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == ADMIN[0]))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def admin(accounts):
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://wrong-key.example.com")
    response = await client.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def written_under_this_key(db, admin):
    """A destination with a secret and a connection with credentials, both encrypted under
    the key this run holds; removed afterwards."""
    from app.models.schema import Destination, MdmConnection

    suffix = uuidlib.uuid4().hex[:8]
    created = await admin.post(
        "/api/destinations",
        json={
            "name": f"wrong-key {suffix}",
            "type": "generic_webhook",
            "url": "https://siem.example/wrong-key",
            "authType": "bearer",
            "authSecret": "a-token-nobody-reads-back",
            "enabled": False,
        },
    )
    assert created.status_code == 201, created.text
    destination_id = created.json()["id"]
    connection = MdmConnection(
        name=f"wrong-key jamf {suffix}",
        provider="jamf",
        base_url="https://wrong-key.example.com",
        is_active=False,
        credentials_encrypted='{"clientId": "c", "clientSecret": "s"}',
    )
    db.add(connection)
    await db.commit()
    connection_id = connection.id
    try:
        yield
    finally:
        await db.rollback()
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.execute(delete(Destination).where(Destination.id == destination_id))
        await db.commit()


async def test_a_wrong_key_answers_a_sentence_and_a_503_and_logs_it_once(
    admin, written_under_this_key, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import app.main as main_module
    from app.core.config import settings
    from app.core.crypto import STORED_VALUE_UNREADABLE

    # Sanity: readable under the right key.
    assert (await admin.get("/api/mdm/connections")).status_code == 200

    monkeypatch.setattr(settings, "encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(main_module, "_unreadable_reported", False)
    with caplog.at_level(logging.ERROR, logger="app.main"):
        connections = await admin.get("/api/mdm/connections")
        destinations = await admin.get("/api/destinations")

    assert connections.status_code == 503, connections.text
    assert connections.json() == {"detail": STORED_VALUE_UNREADABLE}
    assert destinations.status_code == 503 and destinations.json() == {"detail": STORED_VALUE_UNREADABLE}

    # Once per process, the sentence, and no traceback riding it.
    lines = [record for record in caplog.records if record.getMessage() == STORED_VALUE_UNREADABLE]
    assert len(lines) == 1 and lines[0].levelno == logging.ERROR and lines[0].exc_info is None

    # The service is up: health and sign-in are untouched by a credential nobody can read.
    assert (await admin.get("/api/health")).status_code == 200
    assert (await admin.get("/api/auth/me")).status_code == 200
