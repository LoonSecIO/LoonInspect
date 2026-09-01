"""PATCH /api/mdm/connections/{id}: where a stored Jamf secret is allowed to be *pointed*.

#200 pinned the stored secret to the stored URL on POST /test. It did not — and could
not, from inside that endpoint — stop the other half of #132: the URL itself is a
writable field, gated on CONNECTION_WRITE alone. Move the row to a listener you control
and the secret follows it, not because any endpoint hands it over but because every
consumer of the connection reads `base_url` off the row. `POST /{id}/sync` is the fast
way there; the nightly sweep asks no permission at all and arrives on its own.

These tests drive the whole mechanism rather than the guard alone: the sweep really
runs, its OAuth POST is recorded off the wire (URL and form body, so "the secret, and
where it went" is read from the bytes that would have left the process), and the
assertions are about which host saw `client_secret`.

The realistic principal is an API token scoped to `connection:write` + `device:sync`.
No built-in role short of admin holds CONNECTION_WRITE at all — `test_no_builtin_role_...`
pins that — but token scopes are an intersection, so an admin can mint exactly that
pair, and such a token is meant to be *safe* to hand to automation. It was not.

Needs a real Postgres: the rule is a comparison against a stored row read through the
tenant-scoped session, and the sync path opens its own. Gated on RUN_DB_TESTS like the
other database-backed suites.
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
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

STORED_URL = "https://saved.jamfcloud.com"
STORED_SECRET = "stored-client-secret-never-shown"
ATTACKER_URL = "https://listener.attacker.example"

ADMIN = ("connection-move-admin@example.com", "connection-move-admin-password")
ANALYST = ("connection-move-analyst@example.com", "connection-move-analyst-password")
AUDITOR = ("connection-move-auditor@example.com", "connection-move-auditor-password")


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
        for (email, password), role in ((ADMIN, "admin"), (ANALYST, "analyst"), (AUDITOR, "auditor")):
            # Get-or-create, as in test_connection_test_endpoint_db: CI starts from a
            # fresh database, a local re-run does not.
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=role, password=password, roles=(role,))
        await db.commit()


async def _signed_in(email: str, password: str) -> httpx.AsyncClient:
    """An HTTP client signed in as `email`, CSRF header armed.

    https, not http: the session cookie is Secure, and a client on a plain-http origin
    discards it silently — login returns 200 and every request after it 401s.
    """
    from app.main import app

    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://connections.example.com"
    )
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return client


@pytest_asyncio.fixture(loop_scope="session")
async def admin(accounts):
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
async def connection(admin, db):
    """One connection holding a secret nothing may read back, created through the API.

    Through the API and not by INSERT, because `create_connection` is what lays down
    the default collections — and without a device sweep to run, `POST /{id}/sync` would
    make no outbound request at all and the exfiltration test would pass vacuously.
    """
    response = await admin.post(
        "/api/mdm/connections",
        json={
            "name": f"connection-move {uuidlib.uuid4().hex[:8]}",
            "provider": "jamf",
            "baseUrl": STORED_URL,
            "credentials": {"clientId": "stored-client-id", "clientSecret": STORED_SECRET},
        },
    )
    assert response.status_code == 201, response.text
    connection_id = response.json()["id"]
    try:
        yield connection_id
    finally:
        await _remove(db, connection_id)


async def _remove(db, connection_id: int) -> None:
    """Teardown for a connection a sweep has touched.

    `mdm_sync_state` is one of the two plain (non-cascading) foreign keys into
    `mdm_connections` — see `delete_connection`'s docstring — and `POST /{id}/sync`
    writes that row before the first page is fetched, so deleting the connection alone
    fails on the constraint the moment a test has synced.
    """
    from app.models.schema import MdmConnection, MdmSyncState

    await db.rollback()
    await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
    await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def moving_token(admin) -> str:
    """The principal the finding is about: `connection:write` + `device:sync`, and
    deliberately not `connection:credential-read`. Minted through the product's own
    endpoint, so this is a configuration an operator can actually reach — not one
    constructed in the database to make a point."""
    response = await admin.post(
        "/api/auth/tokens",
        json={"name": "sync-automation", "scopes": ["connection:write", "device:sync"]},
    )
    assert response.status_code == 201, response.text
    return response.json()["token"]


@pytest_asyncio.fixture(loop_scope="session")
async def mover(moving_token):
    """A client authenticated as that token. No CSRF header: bearer auth is exempt."""
    from app.main import app

    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://connections.example.com",
        headers={"Authorization": f"Bearer {moving_token}"},
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def outbound(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    """Every HTTP request a sweep actually makes, recorded off the transport.

    Replaces JamfClient.http — the one client a run opens — with a MockTransport, so
    what is asserted is the request as httpx would have put it on the wire: the URL and
    the form body carrying `client_secret`. Reading the client's attributes instead
    would prove what the object held, not what left the process.

    The token exchange succeeds and everything after it 401s, which is the shortest
    path to a finished (failed) run: the sweep reports a connection-level failure
    rather than raising, so the request under test still returns its 202.
    """
    from app.mdm.jamf.client import JamfClient

    recorded: list[dict[str, str]] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        recorded.append({"url": str(request.url), "body": request.content.decode()})
        if request.url.path == "/api/oauth/token":
            return httpx.Response(200, json={"access_token": "fake-token", "expires_in": 1799})
        return httpx.Response(401, json={"errors": ["nope"]})

    @asynccontextmanager
    async def _mock_http(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
            yield client

    monkeypatch.setattr(JamfClient, "http", _mock_http)
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

    # Built first, then appended to: _build_audit_logger *replaces* the handler list.
    tenant_logger = _audit_logger(str(OPERATIONAL_TENANT_ID))
    handler = _Capture()
    tenant_logger.addHandler(handler)
    try:
        yield captured
    finally:
        tenant_logger.removeHandler(handler)


def _hosts_that_saw_the_secret(outbound: list[dict[str, str]], secret: str) -> set[str]:
    return {httpx.URL(call["url"]).host for call in outbound if secret in call["body"]}


# --- The exploit, closed --------------------------------------------------------------


async def test_the_stored_secret_cannot_be_moved_to_an_attacker_host_and_synced_out(
    mover, connection, outbound
) -> None:
    """SECURITY: `connection:write` + `device:sync` must not become a read path.

    This is #132's still-open half as a pair of requests. Before the fix the PATCH
    returned 200, the row pointed at the attacker's listener, and the sync's
    client-credentials POST delivered STORED_SECRET to it — a secret the product has no
    endpoint that returns, held by a token that was never granted
    `connection:credential-read`.

    Every assertion here is about the second request, not the first: the guard is only
    worth having if the credential provably never reaches the foreign host.
    """
    moved = await mover.patch(f"/api/mdm/connections/{connection}", json={"baseUrl": ATTACKER_URL})
    assert moved.status_code == 422, moved.text
    assert "re-entering" in moved.json()["detail"]

    synced = await mover.post(f"/api/mdm/connections/{connection}/sync")
    assert synced.status_code == 202, synced.text

    assert outbound, "the sweep made no outbound request; the test would pass vacuously"
    assert _hosts_that_saw_the_secret(outbound, STORED_SECRET) == {"saved.jamfcloud.com"}
    assert not [call for call in outbound if httpx.URL(call["url"]).host == "listener.attacker.example"]


async def test_a_partial_credential_update_does_not_smuggle_the_move_past_the_guard(
    mover, connection, outbound
) -> None:
    """SECURITY: the credential merge is the obvious way around a naive check.

    `update_connection` merges the incoming credentials over the stored ones, so a
    payload naming only `clientId` moves the URL while leaving the stored
    `client_secret` in place — the exfiltration again, one key wider. The rule is per
    secret *field*, not "some credential was supplied".
    """
    moved = await mover.patch(
        f"/api/mdm/connections/{connection}",
        json={"baseUrl": ATTACKER_URL, "credentials": {"clientId": "attacker-client-id"}},
    )
    assert moved.status_code == 422, moved.text

    await mover.post(f"/api/mdm/connections/{connection}/sync")
    assert _hosts_that_saw_the_secret(outbound, STORED_SECRET) == {"saved.jamfcloud.com"}


async def test_an_empty_secret_is_not_a_re_entered_one(mover, connection) -> None:
    """SECURITY: blank means "keep what is stored" everywhere else in this form's
    contract, so a blank secret alongside a new URL is the stored secret moving."""
    moved = await mover.patch(
        f"/api/mdm/connections/{connection}",
        json={"baseUrl": ATTACKER_URL, "credentials": {"clientSecret": ""}},
    )
    assert moved.status_code == 422, moved.text


async def test_the_refused_move_is_on_the_audit_record(mover, connection, audit_records) -> None:
    """A blocked attempt is evidence. Without a record the only trace of someone trying
    to walk a credential off the instance is a 422 in an access log."""
    await mover.patch(f"/api/mdm/connections/{connection}", json={"baseUrl": ATTACKER_URL})

    refusals = [
        record
        for record in audit_records
        if record["action"] == "connection.updated" and record["outcome"] == "refused"
    ]
    assert len(refusals) == 1, refusals
    assert refusals[0]["metadata"]["base_url"] == ATTACKER_URL
    assert refusals[0]["metadata"]["reason"] == "base_url_moved_without_credential"
    # Names the token and its owner, so the record answers "who" for a credential that
    # is not a person.
    assert "sync-automation" in refusals[0]["actor_label"]
    assert STORED_SECRET not in json.dumps(refusals[0])


# --- The boundary each built-in role sits on ------------------------------------------


async def test_no_builtin_role_short_of_admin_can_move_a_connection(accounts, connection) -> None:
    """SECURITY: the permission table asserted rather than described, then the 403 live.

    The finding was briefed as "does not require admin". Among *roles* it does: Analyst
    holds `device:sync` but not `connection:write`, Auditor holds neither, Viewer holds
    nothing beyond inventory. Admin is the only role that can move a connection at all —
    which is why the realistic principal is a scoped token (above), and why the fix is
    an invariant on the row rather than one more permission on the route.
    """
    from app.core.permissions import Permission, Role, permissions_for

    for role in (Role.viewer, Role.analyst, Role.auditor):
        assert Permission.CONNECTION_WRITE not in permissions_for([role.value]), role
    assert Permission.CONNECTION_WRITE in permissions_for([Role.admin.value])
    # And the pair the exploit needs really is separable from the credential tier —
    # the premise of the scoped token that carries it.
    assert Permission.CONNECTION_CREDENTIAL_READ not in permissions_for([Role.analyst.value])

    for credentials in (ANALYST, AUDITOR):
        client = await _signed_in(*credentials)
        try:
            refused = await client.patch(
                f"/api/mdm/connections/{connection}", json={"baseUrl": ATTACKER_URL}
            )
        finally:
            await client.aclose()
        assert refused.status_code == 403, f"{credentials[0]}: {refused.text}"


# --- The legitimate flows that must survive -------------------------------------------


async def test_an_admin_moves_a_connection_by_re_entering_the_secret(
    admin, db, connection, outbound
) -> None:
    """The Jamf tenant really did move, and the operator really does hold the secret.

    End to end: save the new URL with the secret typed in, then sync — and the sweep
    now authenticates at the new host with the value that was typed. This is also what
    proves the sink is real: the sync follows the row, which is why the row is what the
    guard defends.
    """
    moved = "https://relocated.jamfcloud.com"
    patched = await admin.patch(
        f"/api/mdm/connections/{connection}",
        json={"baseUrl": moved, "credentials": {"clientSecret": "retyped-by-the-admin"}},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["baseUrl"] == moved
    # The rotation metadata moves with it: the fingerprint is the new secret's.
    assert patched.json()["credentialsFingerprint"] == "ret"

    synced = await admin.post(f"/api/mdm/connections/{connection}/sync")
    assert synced.status_code == 202, synced.text
    assert _hosts_that_saw_the_secret(outbound, "retyped-by-the-admin") == {"relocated.jamfcloud.com"}
    assert _hosts_that_saw_the_secret(outbound, STORED_SECRET) == set()


async def test_an_edit_that_leaves_the_url_alone_does_not_demand_the_secret(admin, connection) -> None:
    """The common edit. ConnectionForm sends `baseUrl` on every save whether or not it
    changed, so a rule keyed on "the field was present" would demand the secret for a
    rename — and teach operators to retype credentials for no reason."""
    patched = await admin.patch(
        f"/api/mdm/connections/{connection}", json={"name": "renamed", "baseUrl": STORED_URL}
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["name"] == "renamed"


async def test_a_trailing_slash_is_not_a_move(admin, connection) -> None:
    """The one spelling difference JamfClient itself erases, matching the rule POST
    /test already uses."""
    patched = await admin.patch(
        f"/api/mdm/connections/{connection}", json={"baseUrl": f"{STORED_URL}/"}
    )
    assert patched.status_code == 200, patched.text


async def test_a_connection_with_no_stored_secret_moves_freely(admin, db) -> None:
    """Nothing to walk off: the rule is keyed on a secret being *there*, so a row with
    none is not held hostage by a guard protecting a credential it does not have.

    Inserted rather than posted: `create_connection` validates the credential schema, so
    the API cannot produce a secret-less Jamf row today. The column is nullable and
    `_credentials_dict` handles the empty case, so the state is reachable — an older
    row, a restore, a provider added later whose credentials are optional — and a guard
    that 422s forever on it would be a support call nobody can resolve.
    """
    from app.models.schema import MdmConnection

    row = MdmConnection(
        name=f"connection-move-empty {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=STORED_URL,
    )
    db.add(row)
    await db.commit()

    try:
        patched = await admin.patch(f"/api/mdm/connections/{row.id}", json={"baseUrl": ATTACKER_URL})
        assert patched.status_code == 200, patched.text
    finally:
        await _remove(db, row.id)
