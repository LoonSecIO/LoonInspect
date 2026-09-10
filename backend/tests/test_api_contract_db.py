"""The API's shape, answered by the running routes against a real Postgres (#137).

`test_api_contract.py` pins the contract as the OpenAPI document states it; this file
pins it as the routes actually answer — the echoed page, the retired parameter names
refused in words, the runs list in the shared envelope, and the one asymmetry PATCH
/api/mdm/connections now names instead of hiding: credentials rotate but never clear.

Gated on RUN_DB_TESTS like the other database-backed suites.
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

ADMIN = ("contract-admin@example.com", "contract-admin-password")
ENVELOPE = {"items", "total", "page", "pageSize"}


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account, LoginAttempt

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        email, password = ADMIN
        if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
            await create_account(db, email=email, display_name="contract admin", password=password, roles=("admin",))
        # A crashed previous run's failed logins would trip the lockout and turn this
        # suite red about rate limiting instead of about the contract.
        await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == email))
        await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def client(accounts):
    from app.main import app

    signed_in = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://contract.example.com")
    email, password = ADMIN
    response = await signed_in.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    signed_in.headers["X-CSRF-Token"] = signed_in.cookies.get("loon_csrf", "")
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def connection_id(client):
    """A connection created the way an operator creates one, removed afterwards."""
    created = await client.post(
        "/api/mdm/connections",
        json={
            "name": f"contract {uuidlib.uuid4().hex[:8]}",
            "provider": "jamf",
            "baseUrl": "https://contract.jamfcloud.com",
            "credentials": {"clientId": "id", "clientSecret": "first-secret"},
            "webhookSecret": "hook-secret",
        },
    )
    assert created.status_code == 201, created.text
    connection_id = created.json()["id"]
    try:
        yield connection_id
    finally:
        assert (await client.delete(f"/api/mdm/connections/{connection_id}")).status_code == 204


# --- one pagination idiom -----------------------------------------------------------


async def test_applications_page_by_page_and_page_size_and_echo_them(client) -> None:
    response = await client.get("/api/applications?page=2&pageSize=50&q=nothing-is-called-this")
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) >= ENVELOPE
    assert (body["page"], body["pageSize"], body["items"]) == (2, 50, [])
    assert isinstance(body["total"], int)


@pytest.mark.parametrize(
    ("query", "replacement"),
    [("limit=5", "pageSize"), ("offset=10", "page"), ("search=x", "q"), ("limit=5&offset=10", "pageSize")],
)
async def test_applications_refuses_the_retired_parameter_names_in_words(client, query: str, replacement: str) -> None:
    """FastAPI drops an unknown query parameter silently, so a client still sending
    `limit=50` would get page one of a hundred and never learn why."""
    response = await client.get(f"/api/applications?{query}")
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert "retired" in detail and replacement in detail, detail


async def test_the_catalog_and_the_jamf_patch_titles_echo_the_page(client) -> None:
    for path, page, page_size in (("/api/catalog", 1, 5), ("/api/jamf-patch/titles", 3, 7)):
        response = await client.get(f"{path}?page={page}&pageSize={page_size}")
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) >= ENVELOPE, sorted(body)
        assert (body["page"], body["pageSize"]) == (page, page_size)


async def test_runs_answer_in_the_shared_envelope(client) -> None:
    response = await client.get("/api/runs?pageSize=5")
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == ENVELOPE, sorted(body)
    assert (body["page"], body["pageSize"]) == (1, 5)
    assert len(body["items"]) <= 5 <= max(5, body["total"])


# --- the policy document, typed -------------------------------------------------------


async def test_the_policy_is_served_and_replaced_as_one_typed_document(client) -> None:
    before = await client.get("/api/changes/policy")
    assert before.status_code == 200, before.text
    document = before.json()
    expected = {"version", "minimumLevel", "sections", "entries", "knownGroups", "knownExtensionAttributes", "updatedAt"}
    assert expected <= set(document), sorted(document)
    replaced = await client.put(
        "/api/changes/policy",
        json={
            "minimumLevel": document["minimumLevel"],
            "fields": {},
            "entries": {},
            "systemAppsIndividually": False,
            "mutedGroups": [],
            "mutedExtensionAttributes": [],
        },
    )
    assert replaced.status_code == 200, replaced.text
    assert set(replaced.json()) == set(document)
    # A datetime, serialised the way every other stamp on this API is — not a string
    # hand-rolled by the route.
    assert replaced.json()["updatedAt"] is not None and "T" in replaced.json()["updatedAt"]


# --- the secret-clear asymmetry, named ------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"credentials": None},
        {"credentials": {"clientSecret": ""}},
        {"credentials": {"clientId": "id", "clientSecret": None}},
    ],
)
async def test_a_credential_cannot_be_cleared_by_patch(client, connection_id: int, payload: dict) -> None:
    response = await client.patch(f"/api/mdm/connections/{connection_id}", json=payload)
    assert response.status_code == 422, response.text
    assert "cannot be cleared" in response.json()["detail"], response.text
    still = await client.get(f"/api/mdm/connections/{connection_id}")
    assert set(still.json()["credentialFieldsSet"]) >= {"clientId", "clientSecret"}


async def test_a_credential_rotates_and_the_optional_secrets_clear_on_null(client, connection_id: int) -> None:
    rotated = await client.patch(f"/api/mdm/connections/{connection_id}", json={"credentials": {"clientSecret": "second-secret"}})
    assert rotated.status_code == 200, rotated.text
    assert set(rotated.json()["credentialFieldsSet"]) >= {"clientId", "clientSecret"}
    assert rotated.json()["hasWebhookSecret"] is True

    cleared = await client.patch(f"/api/mdm/connections/{connection_id}", json={"webhookSecret": None})
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["hasWebhookSecret"] is False
    # Clearing the optional secret left the credentials exactly where rotation put them.
    assert set(cleared.json()["credentialFieldsSet"]) >= {"clientId", "clientSecret"}


async def test_devices_narrow_to_the_carriers_of_one_app_and_one_build(client, db) -> None:
    """#299: `appHash` and `versionHash` on `GET /api/devices` are the record page's
    "→ Devices" links; together they name one build of one app."""
    from app.core.content_keys import app_full_key, app_title_key
    from app.models.schema import Device, InstalledApp

    suffix = uuidlib.uuid4().hex[:8]
    name, bundle = f"Carrier {suffix}", f"io.loonsec.carrier.{suffix}"
    app_hash, old_build, new_build = f"a{suffix}".ljust(32, "0"), f"b{suffix}".ljust(32, "0"), f"c{suffix}".ljust(32, "0")
    devices = [
        Device(
            mdm_provider="jamf",
            external_id=f"carrier-{suffix}-{i}",
            serial_number=f"CARRIER{suffix}{i}",
            hostname=f"carrier-{suffix}-{i}",
        )
        for i in range(2)
    ]
    db.add_all(devices)
    await db.flush()
    for device, version, version_hash in ((devices[0], "1.0", old_build), (devices[1], "2.0", new_build)):
        db.add(
            InstalledApp(
                device_id=device.id,
                name=name,
                bundle_id=bundle,
                version=version,
                short_version=None,
                app_hash=app_hash,
                version_hash=version_hash,
                key_title=app_title_key(name, bundle),
                key_full=app_full_key(name, bundle, version, None),
            )
        )
    await db.commit()
    ids = {device.id for device in devices}
    try:
        both = await client.get(f"/api/devices?appHash={app_hash}&pageSize=10")
        assert both.status_code == 200 and {item["id"] for item in both.json()["items"]} == ids
        one = await client.get(f"/api/devices?appHash={app_hash}&versionHash={new_build}&pageSize=10")
        assert [item["id"] for item in one.json()["items"]] == [devices[1].id]
        none = await client.get(f"/api/devices?versionHash={'d' + suffix:0<32}&pageSize=10")
        assert none.json()["total"] == 0
    finally:
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(ids)))
        await db.execute(delete(Device).where(Device.id.in_(ids)))
        await db.commit()
