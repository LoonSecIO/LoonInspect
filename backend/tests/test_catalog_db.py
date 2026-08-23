# ruff: noqa: E501 — assertion lines read better unwrapped in this end-to-end test.
"""The app catalog's lookup and list against a real Postgres: the index rebuilt from the catalog
slice, the local lookup by the hashes an installed app carries, and the tenant list with the
fleet on it after a sweep of the fake tenant. Gated on RUN_DB_TESTS."""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

FIXTURES = Path(__file__).parent / "fixtures" / "jamf"


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenant_ready() -> None:
    from app.core.bootstrap import bootstrap_tenants
    from app.core.database import init_db, unscoped_session

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)


@pytest_asyncio.fixture(loop_scope="session")
async def db(tenant_ready):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


@pytest.fixture
def jamf(monkeypatch: pytest.MonkeyPatch) -> FakeJamf:
    from app.mdm.jamf.client import JamfClient

    fake = FakeJamf()

    @asynccontextmanager
    async def _mock_http(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as client:
            yield client

    monkeypatch.setattr(JamfClient, "http", _mock_http)
    return fake


@pytest_asyncio.fixture(loop_scope="session")
async def indexed(db):
    from app.catalog.index import rebuild_index
    from app.mdm.patch.matching import reset_catalog_cache
    from app.models.schema import JamfPatchTitle

    records = json.loads((FIXTURES / "patch_titles_subset.json").read_text())
    for record in records:
        await db.merge(
            JamfPatchTitle(
                id=record["id"], name=record["name"], publisher=record.get("publisher"), app_name=record.get("appName"),
                bundle_id=record.get("bundleId"), current_version=record["currentVersion"], last_modified=record.get("lastModified") or "",
                patches=record["patches"], requirements=record["requirements"], extension_attributes=record.get("extensionAttributes") or [],
            )
        )
    await db.commit()
    reset_catalog_cache()
    rows = await rebuild_index(db)
    yield rows
    reset_catalog_cache()


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    from app.models.schema import AppCatalogEntry, Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"catalog jamf {uuidlib.uuid4().hex[:8]}", provider="jamf", base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}), capability_webhooks=True,
    )
    db.add(row)
    await db.commit()
    connection_id = row.id
    try:
        yield row
    finally:
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        hashes = select(InstalledApp.version_hash).where(InstalledApp.device_id.in_(device_ids))
        await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_(hashes)))
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


async def test_index_and_lookup(db, indexed) -> None:
    from app.api.catalog import _lookup
    from app.catalog.index import lookup_versions
    from app.core.hashing import compute_version_hash
    from app.models.schema import AppCatalogVersion

    assert indexed > 0
    xcode_hash = compute_version_hash("Xcode.app", "com.apple.dt.Xcode", "26.6")
    rows = await lookup_versions(db, version_hashes=[xcode_hash])
    assert [(r.title_id, r.version, r.is_latest) for r in rows] == [("0C3", "26.6", True)]
    # The versioned Wireshark titles carry no appName: reached by (bundle, version), not by hash.
    pairs = await lookup_versions(db, pairs=[("org.wireshark.Wireshark", "4.2.0")])
    assert {r.title_id for r in pairs} == {"5F6", "612"}
    assert (await db.execute(select(AppCatalogVersion).where(AppCatalogVersion.title_name == "Node.js 14"))).first() is None

    # The API's answer for a key the fleet has not shown: Jamf's side only.
    (answer,) = await _lookup(db, version_hashes=[xcode_hash], key_fulls=[], app_hashes=[])
    assert answer.tenant is None and answer.jamf_title_ids == ["0C3"] and answer.is_latest is True and answer.this_version_seen is True
    (miss,) = await _lookup(db, version_hashes=["0" * 32], key_fulls=[], app_hashes=[])
    assert miss.tenant is None and miss.jamf == [] and miss.this_version_seen is False


async def _forget_fixture_apps(db, jamf: FakeJamf) -> None:
    """Catalog rows outlive devices by design, and other suites sweep the same fixture device
    into the same tenant; start from rows this test creates itself."""
    from app.mdm.jamf.client import normalize_computer
    from app.mdm.service import apply_hashes
    from app.models.schema import AppCatalogEntry

    hashes = set()
    for raw in (jamf.real, jamf.synthetic):
        for app in normalize_computer(raw).apps:
            hashes.add(apply_hashes(app).version_hash)
    await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_(hashes)))
    await db.commit()


async def test_list_and_lookup_after_a_sweep(db, jamf: FakeJamf, connection, indexed) -> None:
    from app.api.catalog import _lookup, list_catalog
    from app.mdm.service import sync_connection
    from app.models.schema import Device, InstalledApp

    await _forget_fixture_apps(db, jamf)
    result = await sync_connection(db, connection)
    assert result.ok
    real = (await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == jamf.real["id"]))).scalar_one()
    xcode = (await db.execute(select(InstalledApp).where(InstalledApp.device_id == real.id, InstalledApp.name == "Xcode.app"))).scalar_one()

    listing = await list_catalog(db=db, q="Xcode", jamf="all", installed_only=True, page=1, page_size=50)
    (entry,) = [item for item in listing.items if item.version_hash == xcode.version_hash]
    assert entry.device_count >= 1 and entry.jamf_titles[0].name == "Apple Xcode" and entry.patch_state == "latest"
    assert entry.first_seen_at == entry.last_seen_at
    assert listing.summary.installed >= 1 and listing.summary.matched >= 1

    unmatched = await list_catalog(db=db, q=None, jamf="unmatched", installed_only=True, page=1, page_size=5000)
    assert unmatched.total >= 60  # the /System apps and the rest Jamf does not track
    assert all(item.jamf_title_ids is None for item in unmatched.items)

    (answer,) = await _lookup(db, version_hashes=[xcode.version_hash], key_fulls=[], app_hashes=[])
    assert answer.tenant is not None and answer.tenant.device_count >= 1
    assert answer.jamf_title_ids == ["0C3"] and answer.is_latest is True and answer.latest == "26.6"
    (by_app,) = await _lookup(db, version_hashes=[], key_fulls=[], app_hashes=[xcode.app_hash])
    assert by_app.tenant is not None and by_app.tenant.version == "26.6"
