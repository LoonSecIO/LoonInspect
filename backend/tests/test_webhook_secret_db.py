"""The webhook secret is write-only, and setting it through the API is what arms the
webhook endpoint.

test_webhook_auth.py already covers the decision function and the route in isolation —
header parsing, constant-time comparison, and the identical-401 enumeration guard —
with the connection handed in as a constructed object and the database stubbed out.
None of that exercises the path an operator actually walks: set the secret over HTTP,
have it survive `EncryptedString` into Postgres and back, and have Jamf's callback
accepted with it.

That round trip is what this file pins, together with the property the form in
`frontend/src/features/mdm/ConnectionForm.tsx` depends on: the value goes in and never
comes back out. The form can only be write-only if the API is, so `has_webhook_secret`
had better be the only trace of it in any response — a "set" indicator that could be
turned back into the secret would make the whole write-only posture theatre.

Needs a real Postgres like every session test; gated on RUN_DB_TESTS. See
test_tenancy_sweep.py for the local invocation pattern.
"""

from __future__ import annotations

import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

# One event loop for the whole module — the engine's pooled connections belong to
# whichever loop first used them.
pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"
    ),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("webhook-admin@secret.example.com", "webhook-admin-password")

# Distinctive enough that a substring search over a response body means something: a
# short value like "s3cret" could plausibly collide with base64 or a uuid and make the
# absence assertions pass for the wrong reason.
SECRET = "webhook-secret-zzq-original-4f1c9e"
ROTATED = "webhook-secret-zzq-rotated-8b7d2a"


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def seeded() -> uuidlib.UUID:
    """Migrated schema, bootstrapped tenants, and the admin this suite owns.

    Get-or-create, like every DB fixture here: a developer re-running against a
    persistent local database must not trip a unique constraint from the last run.
    """
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    await init_db()

    async with unscoped_session() as db:
        await bootstrap_tenants(db)

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        existing = (
            (await db.execute(select(Account).where(Account.email == ADMIN[0]))).scalars().first()
        )
        if existing is None:
            await create_account(
                db, email=ADMIN[0], display_name="webhook admin", password=ADMIN[1], roles=("admin",)
            )
        # A previous crashed run's failed logins would trip the lockout and turn this
        # suite red about rate limiting instead of about the secret.
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == ADMIN[0]))
        await db.commit()

    return OPERATIONAL_TENANT_ID


def _transport() -> httpx.ASGITransport:
    from app.main import app

    return httpx.ASGITransport(app=app)


@pytest_asyncio.fixture(loop_scope="session")
async def client(seeded):
    """An HTTP client signed in as the admin, CSRF header armed.

    https, not http: the session cookie is Secure by default and a plain-http origin
    silently discards it — login 200s and everything after it 401s.
    """
    async with httpx.AsyncClient(transport=_transport(), base_url="https://secret.example.com") as c:
        response = await c.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
        c.headers["X-CSRF-Token"] = c.cookies.get("loon_csrf", "")
        yield c


@pytest_asyncio.fixture(loop_scope="session")
async def jamf():
    """A client with no session and no CSRF token, the way Jamf Pro actually arrives.

    Reusing the signed-in client for the callbacks would let a session cookie stand in
    for the secret without the test noticing — precisely the confusion the webhook
    route's separate credential exists to avoid.
    """
    async with httpx.AsyncClient(transport=_transport(), base_url="https://secret.example.com") as c:
        yield c


async def _create(c: httpx.AsyncClient, name: str, **extra) -> httpx.Response:
    payload = {
        # Suffixed rather than fixed: (tenant_id, name) is unique, and these rows are
        # created through the API so there is no get-or-create to fall back on. A
        # developer re-running against a persistent local database would otherwise
        # spend the evening on a fixture's 500 rather than on the secret.
        "name": f"{name} {uuidlib.uuid4().hex[:8]}",
        "provider": "jamf",
        "baseUrl": "https://webhook-secret.jamfcloud.com",
        # Real credentials matter even though nothing calls Jamf here: ingest_webhook
        # builds the client before it looks at the event, so a credential-less
        # connection 500s on an *authenticated* callback and the 200s below would stop
        # meaning what they say.
        "credentials": {"clientId": "webhook-client", "clientSecret": "webhook-client-secret"},
        "capabilityWebhooks": True,
        **extra,
    }
    response = await c.post("/api/mdm/connections", json=payload)
    assert response.status_code == 201, f"create failed: {response.status_code} {response.text}"
    # The response, not its body: the leak sweep needs the raw text of a create as much
    # as of a read — the create is the one response that held the secret a moment
    # earlier, in the request that produced it.
    return response


# An event Jamf sends that LoonInspect deliberately does not react to (#76), so an
# accepted callback answers "ignored" without a single request to Jamf Pro. The claim
# under test is authentication; a fetch would only add a network dependency that can
# fail for reasons having nothing to do with the secret.
CALLBACK = {"webhook": {"webhookEvent": "ComputerCheckIn"}, "event": {"jssID": 1}}


async def test_the_secret_set_over_http_authenticates_a_real_callback(client, jamf) -> None:
    """The end-to-end claim the form now rests on: a secret typed into it arms the
    endpoint, and the wrong one is still refused."""
    created = (await _create(client, "arms the endpoint", webhookSecret=SECRET)).json()
    assert created["hasWebhookSecret"] is True

    accepted = await jamf.post(
        f"/webhooks/jamf/{created['id']}", json=CALLBACK, headers={"X-API-Key": SECRET}
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json() == {"status": "ignored"}

    refused = await jamf.post(
        f"/webhooks/jamf/{created['id']}", json=CALLBACK, headers={"X-API-Key": SECRET + "x"}
    )
    assert refused.status_code == 401


async def test_no_connection_read_path_returns_the_secret(client, seeded) -> None:
    """The property that makes a write-only form honest.

    Fails if anyone adds `webhook_secret` to `MdmConnectionOut`, or widens a read path
    to serialize the ORM row. `has_webhook_secret` may say *that* one is set; the value
    itself must never leave the database.
    """
    from app.core.database import session_for_tenant
    from app.models.schema import MdmConnection

    create_response = await _create(client, "never readable", webhookSecret=SECRET)
    created = create_response.json()

    # The absences below have to be absences in the *responses*, not a secret that was
    # quietly never stored — read the column first so the sweep cannot pass vacuously.
    async with session_for_tenant(seeded) as db:
        row = await db.get(MdmConnection, created["id"])
        assert row is not None and row.webhook_secret_encrypted == SECRET

    for label, response in (
        ("create", create_response),
        ("get one", await client.get(f"/api/mdm/connections/{created['id']}")),
        ("list", await client.get("/api/mdm/connections")),
        (
            "patch",
            await client.patch(
                f"/api/mdm/connections/{created['id']}",
                json={"name": f"renamed {uuidlib.uuid4().hex[:8]}"},
            ),
        ),
        ("status", await client.get("/api/mdm/status")),
    ):
        assert response.status_code in (200, 201), f"{label}: {response.status_code} {response.text}"
        assert SECRET not in response.text, f"{label} leaked the webhook secret"

    single = await client.get(f"/api/mdm/connections/{created['id']}")
    assert single.json()["hasWebhookSecret"] is True


async def test_rotation_takes_effect_and_retires_the_old_value(client, jamf) -> None:
    """Rotation is the only way back into a write-only field, so it has to work.

    It is also this build's answer to auth-design.md §4.7's open question: one column,
    no grace window — the old value stops working the moment the new one is saved, and
    the operator updates Jamf Pro to match.
    """
    created = (await _create(client, "rotates", webhookSecret=SECRET)).json()

    patched = await client.patch(
        f"/api/mdm/connections/{created['id']}", json={"webhookSecret": ROTATED}
    )
    assert patched.status_code == 200
    assert patched.json()["hasWebhookSecret"] is True
    assert ROTATED not in patched.text

    old = await jamf.post(
        f"/webhooks/jamf/{created['id']}", json=CALLBACK, headers={"X-API-Key": SECRET}
    )
    assert old.status_code == 401, "the retired secret still opens the endpoint"

    new = await jamf.post(
        f"/webhooks/jamf/{created['id']}", json=CALLBACK, headers={"X-API-Key": ROTATED}
    )
    assert new.status_code == 200, new.text


async def test_an_edit_that_omits_the_secret_keeps_it(client, jamf) -> None:
    """What the form's blank field means.

    The form cannot render the stored secret back, so it omits the key entirely unless
    someone is deliberately rotating. If a PATCH that never mentions `webhookSecret`
    cleared it, saving an unrelated name change would silently take the webhook
    endpoint down.
    """
    created = (await _create(client, "survives an unrelated edit", webhookSecret=SECRET)).json()

    renamed = await client.patch(
        f"/api/mdm/connections/{created['id']}",
        json={"name": f"survives an unrelated edit, edited {uuidlib.uuid4().hex[:8]}"},
    )
    assert renamed.status_code == 200
    assert renamed.json()["hasWebhookSecret"] is True

    still_works = await jamf.post(
        f"/webhooks/jamf/{created['id']}", json=CALLBACK, headers={"X-API-Key": SECRET}
    )
    assert still_works.status_code == 200, still_works.text


async def test_the_capability_without_a_secret_rejects_everything(client, jamf) -> None:
    """The state the form now refuses to create, asserted from the API side.

    The API still allows it — a connection is a resource, not a wizard, and a caller is
    entitled to set the capability in one request and the secret in the next. What it
    must never do is fail *open*: until a secret lands, the endpoint answers every
    caller with the same 401 it gives a wrong secret.
    """
    created = (await _create(client, "armed but unloaded")).json()
    assert created["hasWebhookSecret"] is False

    for headers in ({}, {"X-API-Key": SECRET}, {"Authorization": f"Bearer {SECRET}"}):
        response = await jamf.post(f"/webhooks/jamf/{created['id']}", json=CALLBACK, headers=headers)
        assert response.status_code == 401, f"{headers}: {response.status_code} {response.text}"
