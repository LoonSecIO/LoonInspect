"""Rotating ENCRYPTION_KEY against a real Postgres (#144).

What is pinned: with the old key in ENCRYPTION_KEY_PREVIOUS and a new one in ENCRYPTION_KEY, one
pass rewrites every stored value still under the old key — in every encrypted column, in every
tenant — so that afterwards the rows read under the new key alone; a value under a third key is
counted and named by its column, never rewritten and never printed; and the rewritten value
still carries the `k1` envelope. The lane's other rows are rotated with everything else, so the
test rotates back to the lane key before it ends, which exercises the reverse direction too.
"""

from __future__ import annotations

import os
import uuid as uuidlib

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from sqlalchemy import delete, text

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

NEIGHBOUR_TENANT_ID = uuidlib.UUID("00000000-0000-0000-0000-000000000144")
SECRET = '{"clientId": "rotate", "clientSecret": "rotate-me"}'
THIRD_KEY = Fernet.generate_key()


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def neighbour(tenant_ready) -> None:
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import unscoped_session
    from app.models.schema import Tenant

    async with unscoped_session() as db:
        await bootstrap_tenants(db)
        if await db.get(Tenant, NEIGHBOUR_TENANT_ID) is None:
            db.add(Tenant(id=NEIGHBOUR_TENANT_ID, slug="rotation-neighbour", name="Rotation Neighbour", kind="operational"))
            await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def rows(neighbour):
    """Under the lane's key: a connection with credentials and a destination with a secret in the
    operational tenant, and a destination in the neighbour's. Under a third key nobody configures:
    a second connection, written as raw text so the type decorator cannot restamp it. All gone
    afterwards."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Destination, MdmConnection

    suffix = uuidlib.uuid4().hex[:8]
    ids: dict[str, int] = {}
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        mine = MdmConnection(name=f"rotate {suffix}", provider="jamf", base_url="https://rotate.example.com")
        mine.credentials_encrypted = SECRET
        other = MdmConnection(name=f"rotate third {suffix}", provider="jamf", base_url="https://rotate-third.example.com")
        hook = Destination(name=f"rotate hook {suffix}", type="generic_webhook", url="https://siem.example/rotate", enabled=False)
        hook.auth_type, hook.auth_secret_encrypted = "bearer", "a-token-under-the-lane-key"
        db.add_all([mine, other, hook])
        await db.flush()
        ids["mine"], ids["other"], ids["hook"] = mine.id, other.id, hook.id
        stranger = "k1:" + Fernet(THIRD_KEY).encrypt(SECRET.encode()).decode()
        restamp = text("UPDATE mdm_connections SET credentials_encrypted = :v WHERE id = :id")
        await db.execute(restamp, {"v": stranger, "id": other.id})
        await db.commit()
    async with session_for_tenant(NEIGHBOUR_TENANT_ID) as db:
        theirs = Destination(name=f"rotate theirs {suffix}", type="generic_webhook", url="https://siem.example/theirs")
        theirs.enabled = False
        theirs.auth_type, theirs.auth_secret_encrypted = "bearer", "a-token-in-the-neighbour-tenant"
        db.add(theirs)
        await db.commit()
        ids["theirs"] = theirs.id
    try:
        yield ids
    finally:
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            await db.execute(delete(MdmConnection).where(MdmConnection.id.in_([ids["mine"], ids["other"]])))
            await db.execute(delete(Destination).where(Destination.id == ids["hook"]))
            await db.commit()
        async with session_for_tenant(NEIGHBOUR_TENANT_ID) as db:
            await db.execute(delete(Destination).where(Destination.id == ids["theirs"]))
            await db.commit()


async def _raw(tenant_id, table: str, column: str, row_id: int) -> str:
    from app.core.database import session_for_tenant

    async with session_for_tenant(tenant_id) as db:
        return (await db.execute(text(f"SELECT {column} FROM {table} WHERE id = :id"), {"id": row_id})).scalar_one()


async def test_one_pass_moves_every_value_to_the_new_key_and_names_what_it_cannot(rows, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import settings
    from app.core.database import session_for_tenant
    from app.core.rekey import rekey_stored_values
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Destination, MdmConnection

    lane_key = settings.encryption_key
    new_key = Fernet.generate_key().decode()
    before = {}
    for name in ("mine", "other"):
        before[name] = await _raw(OPERATIONAL_TENANT_ID, "mdm_connections", "credentials_encrypted", rows[name])

    monkeypatch.setattr(settings, "encryption_key", new_key)
    monkeypatch.setattr(settings, "encryption_key_previous", lane_key)
    try:
        summary = await rekey_stored_values()

        # Everything under the lane key moved — the three rows here and whatever else the lane holds.
        assert summary.rewritten >= 3
        assert summary.unreadable == 1 and summary.unreadable_in == ["mdm_connections.credentials_encrypted"]
        assert not summary.complete

        # Rewritten: a different token, the same envelope, readable under the new key alone.
        after = await _raw(OPERATIONAL_TENANT_ID, "mdm_connections", "credentials_encrypted", rows["mine"])
        assert after != before["mine"] and after.startswith("k1:")
        monkeypatch.setattr(settings, "encryption_key_previous", None)
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
            assert (await db.get(MdmConnection, rows["mine"])).credentials_encrypted == SECRET
            assert (await db.get(Destination, rows["hook"])).auth_secret_encrypted == "a-token-under-the-lane-key"
        async with session_for_tenant(NEIGHBOUR_TENANT_ID) as db:
            assert (await db.get(Destination, rows["theirs"])).auth_secret_encrypted == "a-token-in-the-neighbour-tenant"

        # The value under the third key was left exactly as it was, not rewritten and not cleared.
        assert await _raw(OPERATIONAL_TENANT_ID, "mdm_connections", "credentials_encrypted", rows["other"]) == before["other"]

        # A second pass finds nothing left to do under the new key.
        monkeypatch.setattr(settings, "encryption_key_previous", lane_key)
        again = await rekey_stored_values()
        assert again.rewritten == 0 and again.current >= 3 and again.unreadable == 1
    finally:
        # Back to the lane key, so the rows the lane's other tests wrote are theirs again.
        monkeypatch.setattr(settings, "encryption_key", lane_key)
        monkeypatch.setattr(settings, "encryption_key_previous", new_key)
        back = await rekey_stored_values()
        monkeypatch.setattr(settings, "encryption_key_previous", None)
    assert back.rewritten >= 3 and back.unreadable == 1
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        assert (await db.get(MdmConnection, rows["mine"])).credentials_encrypted == SECRET
