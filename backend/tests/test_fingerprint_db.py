"""The fingerprint on the wire is the hash, on create and on rotation (#316).

Through the real routes rather than the helper, because the write sites are what leaked:
`create_connection` and `update_connection` both stored `secret[:3]`. Needs a real
Postgres, like the other route suites.
"""

from __future__ import annotations

import os
import uuid as uuidlib

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("fingerprint-admin@example.com", "fingerprint-admin-password")
FIRST_SECRET = "first-client-secret-minted-by-jamf"
SECOND_SECRET = "second-client-secret-after-rotation"


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

    signed_in = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://fingerprint.example.com")
    email, password = ADMIN
    response = await signed_in.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    signed_in.headers["X-CSRF-Token"] = signed_in.cookies.get("loon_csrf", "")
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


async def test_the_fingerprint_is_the_hash_on_create_and_on_rotation(client) -> None:
    from app.mdm.credentials import credential_fingerprint

    created = await client.post(
        "/api/mdm/connections",
        json={
            "name": f"fingerprint {uuidlib.uuid4().hex[:8]}",
            "provider": "jamf",
            "baseUrl": "https://fingerprint.jamfcloud.com",
            "credentials": {"clientId": "id", "clientSecret": FIRST_SECRET},
        },
    )
    assert created.status_code == 201, created.text
    connection_id = created.json()["id"]
    try:
        tag = created.json()["credentialsFingerprint"]
        assert tag == credential_fingerprint(FIRST_SECRET)
        assert tag != FIRST_SECRET[:3], "the defect this closes"
        assert len(tag) == 12

        rotated = await client.patch(
            f"/api/mdm/connections/{connection_id}", json={"credentials": {"clientSecret": SECOND_SECRET}}
        )
        assert rotated.status_code == 200, rotated.text
        assert rotated.json()["credentialsFingerprint"] == credential_fingerprint(SECOND_SECRET)
        assert rotated.json()["credentialsFingerprint"] != tag

        # A save that does not touch the secret leaves the tag alone.
        renamed = await client.patch(f"/api/mdm/connections/{connection_id}", json={"name": f"renamed {uuidlib.uuid4().hex[:6]}"})
        assert renamed.status_code == 200, renamed.text
        assert renamed.json()["credentialsFingerprint"] == credential_fingerprint(SECOND_SECRET)

        # And the listing every CONNECTION_READ role can call carries the hash, not the secret.
        listed = await client.get("/api/mdm/connections")
        assert listed.status_code == 200
        row = next(item for item in listed.json() if item["id"] == connection_id)
        assert row["credentialsFingerprint"] == credential_fingerprint(SECOND_SECRET)
        assert row["credentialsFingerprint"] != SECOND_SECRET[:3]
        assert SECOND_SECRET not in listed.text and FIRST_SECRET not in listed.text
    finally:
        assert (await client.delete(f"/api/mdm/connections/{connection_id}")).status_code == 204
