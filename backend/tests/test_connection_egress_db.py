"""The connection routes as an SSRF sink, and the test endpoint as a read primitive.

`base_url` was a bare string on every schema that writes it, and `POST /test` echoed
whatever came back: together that made "create a connection" a way to have the server
issue an authenticated request to any address it can reach and hand you the answer
(#131). `tests/test_base_url_egress.py` pins the rule itself; this pins that the three
routes which set or dial the column actually apply it, and that a refusal never dials.

Needs a real Postgres, like the other route suites: creating and moving a connection
writes rows through the tenant-scoped session.
"""

from __future__ import annotations

import asyncio
import json
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

STORED_URL = "https://egress-stored.jamfcloud.com"
STORED_SECRET = "egress-stored-client-secret"
METADATA_URL = "https://169.254.169.254/latest/meta-data/iam/security-credentials/"

ADMIN = ("egress-admin@example.com", "egress-admin-password")


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
        if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
            await create_account(db, email=email, display_name="admin", password=password, roles=("admin",))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def client(accounts):
    from app.main import app

    # https, not http: the session cookie is Secure, and a client on a plain-http
    # origin discards it silently.
    signed_in = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://egress.example.com"
    )
    email, password = ADMIN
    response = await signed_in.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    signed_in.headers["X-CSRF-Token"] = signed_in.cookies.get("loon_csrf", "")
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
    from app.models.schema import MdmConnection

    row = MdmConnection(
        name=f"egress {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=STORED_URL,
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
def attempts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every destination the endpoint was about to send a credential to."""
    from app.mdm.jamf.client import JamfClient

    recorded: list[str] = []

    async def _record(self: JamfClient) -> dict:
        recorded.append(self._base_url)
        return {"expires_in": 1799, "token_type": "Bearer"}

    monkeypatch.setattr(JamfClient, "test_connection", _record)
    return recorded


@pytest_asyncio.fixture(loop_scope="session")
async def resolver(monkeypatch: pytest.MonkeyPatch):
    """Point one hostname wherever a test needs it, leaving every other name alone.

    Scoped rather than blanket: the database connection pool resolves its own host on
    this loop, and a resolver that answered 169.254.169.254 for everything would take
    the session down with it.
    """
    loop = asyncio.get_running_loop()
    real = loop.getaddrinfo
    answers: dict[str, str] = {}

    async def _getaddrinfo(host, port, **kwargs):
        if host in answers:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answers[host], 0))]
        return await real(host, port, **kwargs)

    monkeypatch.setattr(loop, "getaddrinfo", _getaddrinfo)
    yield answers


def _create_payload(**overrides) -> dict:
    payload = {
        "name": f"egress {uuidlib.uuid4().hex[:8]}",
        "provider": "jamf",
        "baseUrl": STORED_URL,
        "credentials": {"clientId": "id", "clientSecret": "secret"},
    }
    payload.update(overrides)
    return payload


async def _delete(client, connection_id: int) -> None:
    assert (await client.delete(f"/api/mdm/connections/{connection_id}")).status_code == 204


# --- creating one ---------------------------------------------------------------------


async def test_security_a_connection_cannot_be_created_at_the_metadata_address(client, db) -> None:
    """SECURITY: the row is the steering wheel, so the refusal has to be at the write.

    Nothing needs to click anything afterwards — the nightly sweep asks no permission
    and will drive whatever the column says (see #208's guard). A 422 here is what keeps
    169.254.169.254 out of the sweep's hands.
    """
    from app.models.schema import MdmConnection

    response = await client.post("/api/mdm/connections", json=_create_payload(baseUrl=METADATA_URL))

    assert response.status_code == 422, response.text
    assert "link-local" in response.text
    stored = (
        await db.execute(select(MdmConnection).where(MdmConnection.base_url == METADATA_URL))
    ).scalars().all()
    assert stored == []


async def test_security_a_hostname_that_resolves_to_link_local_is_refused_at_create(
    client, resolver
) -> None:
    """SECURITY: proves the route runs the resolver pass, not just the literal check.

    The literal rule lives in the schema and is pinned in tests/test_base_url_egress.py;
    this is the half that needs an event loop, so it can only be reached through a
    route. A caller who owns a domain would otherwise walk straight past the literals.
    """
    resolver["metadata.attacker.example"] = "169.254.169.254"

    response = await client.post(
        "/api/mdm/connections", json=_create_payload(baseUrl="https://metadata.attacker.example")
    )

    assert response.status_code == 422, response.text
    assert "169.254.169.254" in response.text


@pytest.mark.parametrize(
    "base_url",
    [
        "https://acme.jamfcloud.example",  # Jamf Cloud shape
        "https://jamf.corp.internal:8443",  # on-premises, internal DNS
        "https://10.20.30.40:8443",  # on-premises, by RFC 1918 address
    ],
)
async def test_a_legitimate_jamf_pro_is_still_accepted(client, base_url: str) -> None:
    """The expensive failure mode. An operator whose Jamf Pro is on their own network
    must still be able to save it; a rule that refuses this has broken the product to
    prevent an attack its own admin need not mount."""
    response = await client.post("/api/mdm/connections", json=_create_payload(baseUrl=base_url))

    assert response.status_code == 201, response.text
    assert response.json()["baseUrl"] == base_url
    await _delete(client, response.json()["id"])


# --- moving one -----------------------------------------------------------------------


async def test_security_a_saved_connection_cannot_be_moved_to_a_blocked_address(
    client, connection, db
) -> None:
    """SECURITY: the same rule on PATCH, with #208's guard satisfied.

    The client secret is re-entered so the refusal under test is this one and not
    "re-enter the secret to move the URL" — two guards on the same field, and a test
    that cannot tell them apart proves nothing about either.
    """
    from app.models.schema import MdmConnection

    response = await client.patch(
        f"/api/mdm/connections/{connection.id}",
        json={"baseUrl": METADATA_URL, "credentials": {"clientSecret": STORED_SECRET}},
    )

    assert response.status_code == 422, response.text
    assert "link-local" in response.text
    await db.refresh(connection)
    assert (await db.get(MdmConnection, connection.id)).base_url == STORED_URL


# --- dialling one ---------------------------------------------------------------------


async def test_security_the_test_endpoint_refuses_a_blocked_destination_without_dialling_it(
    client, attempts
) -> None:
    """SECURITY: refused *before* the outbound request, not after reading the answer.

    `attempts` records the destination of every token exchange the endpoint was about to
    make. It must stay empty: an endpoint that dials first and judges afterwards has
    already made the request that was the whole point of refusing.
    """
    response = await client.post(
        "/api/mdm/connections/test",
        json={"provider": "jamf", "baseUrl": METADATA_URL, "clientId": "id", "clientSecret": "secret"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is False
    assert "link-local" in body["message"]
    assert body["detail"] is None
    assert attempts == []


async def test_the_test_endpoint_still_dials_a_legitimate_on_premises_jamf(client, attempts) -> None:
    """The other side of the refusal above: an internal Jamf Pro is still testable."""
    response = await client.post(
        "/api/mdm/connections/test",
        json={
            "provider": "jamf",
            "baseUrl": "https://jamf.corp.internal:8443",
            "clientId": "id",
            "clientSecret": "secret",
        },
    )

    assert response.json()["success"] is True, response.text
    assert attempts == ["https://jamf.corp.internal:8443"]


def _raise_upstream(monkeypatch: pytest.MonkeyPatch, body: str, content_type: str) -> None:
    from app.mdm.jamf.client import JamfClient

    async def _rejected(self: JamfClient) -> dict:
        request = httpx.Request("POST", f"{self._base_url}/api/oauth/token")
        response = httpx.Response(
            401, content=body.encode(), headers={"content-type": content_type}, request=request
        )
        raise httpx.HTTPStatusError("rejected", request=request, response=response)

    monkeypatch.setattr(JamfClient, "test_connection", _rejected)


async def test_security_an_upstream_body_reaches_the_caller_only_bounded(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SECURITY: `detail` is diagnostics, not a window.

    Whatever answers `{base_url}/api/oauth/token` is a server the caller named, so its
    body must not come back whole. A JSON refusal still does come back — that is what
    makes a wrong credential fixable — capped; anything that is not JSON comes back
    described rather than quoted.
    """
    from app.api.connections import _DETAIL_MAX_CHARS

    _raise_upstream(
        monkeypatch, json.dumps({"errors": ["x" * 4000], "tail": "CANARY-JSON"}), "application/json"
    )
    detail = (
        await client.post(
            "/api/mdm/connections/test",
            json={"provider": "jamf", "baseUrl": STORED_URL, "clientId": "id", "clientSecret": "s"},
        )
    ).json()["detail"]
    assert "CANARY-JSON" not in detail
    assert "truncated" in detail
    assert len(detail) < _DETAIL_MAX_CHARS + 100

    _raise_upstream(monkeypatch, "<html>CANARY-HTML-PAGE</html>", "text/html")
    detail = (
        await client.post(
            "/api/mdm/connections/test",
            json={"provider": "jamf", "baseUrl": STORED_URL, "clientId": "id", "clientSecret": "s"},
        )
    ).json()["detail"]
    assert "CANARY-HTML-PAGE" not in detail
    assert "text/html" in detail
