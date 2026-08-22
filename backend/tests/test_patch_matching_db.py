# ruff: noqa: E501 — assertion lines read better unwrapped in this end-to-end test.
"""Jamf Patch matching through the real ingest path: the catalog slice in `jamf_patch_titles`,
a sweep of the fake tenant, then the match rows, the summary columns on `installed_apps`, and
the tenant-scoped counts the Jamf Patch page reads. Gated on RUN_DB_TESTS like the other
database-backed suites.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

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
async def catalog_rows(db):
    """The catalog slice, upserted into the global titles table (idempotent by id)."""
    from app.mdm.patch.matching import reset_catalog_cache
    from app.models.schema import JamfPatchTitle

    records = json.loads((FIXTURES / "patch_titles_subset.json").read_text())
    for record in records:
        await db.merge(
            JamfPatchTitle(
                id=record["id"],
                name=record["name"],
                publisher=record.get("publisher"),
                app_name=record.get("appName"),
                bundle_id=record.get("bundleId"),
                current_version=record["currentVersion"],
                last_modified=record.get("lastModified") or "",
                patches=record["patches"],
                requirements=record["requirements"],
                extension_attributes=record.get("extensionAttributes") or [],
            )
        )
    await db.commit()
    reset_catalog_cache()
    yield records
    reset_catalog_cache()


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"patch jamf {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url=HOST,
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
        capability_webhooks=True,
    )
    db.add(row)
    await db.commit()
    connection_id = row.id
    try:
        yield row
    finally:
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        # installed_app_patch_matches cascade from installed_apps in the database.
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


async def test_sweep_writes_matches_summaries_and_counts(db, jamf: FakeJamf, connection, catalog_rows) -> None:
    from app.api.jamf_patch import title_device_counts, title_version_counts
    from app.mdm.service import sync_connection
    from app.models.schema import Device, InstalledApp, InstalledAppPatchMatch

    result = await sync_connection(db, connection)
    assert result.ok and result.device_count == 2, result

    real = (await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == jamf.real["id"]))).scalar_one()
    apps = {row.name: row for row in (await db.execute(select(InstalledApp).where(InstalledApp.device_id == real.id))).scalars().all()}
    assert len(apps) == 83

    # The summary columns, from the rolling title.
    xcode = apps["Xcode.app"]
    assert xcode.jamf_title_ids == ["0C3"] and xcode.patch_state == "latest"
    assert xcode.is_compliant is True and xcode.patch_available is False and xcode.this_version_seen is True
    assert xcode.latest_version == "26.6" and xcode.latest_released_at is not None and xcode.last_patch_check_at is not None

    safari = apps["Safari.app"]
    assert safari.patch_state == "ahead" and safari.this_version_seen is False and safari.is_compliant is False and safari.patch_available is False

    camtasia = apps["Camtasia 2022.app"]
    assert camtasia.jamf_title_ids == ["608", "514"] and camtasia.patch_state == "latest"  # latest on its own line
    assert camtasia.is_compliant is True and camtasia.patch_available is False and camtasia.latest_version == "2022.6.10"
    slack = apps["Slack.app"]
    assert slack.patch_state == "behind" and slack.patch_available is True and slack.patch_available_since is not None

    unmatched = apps["Calculator.app"] if "Calculator.app" in apps else next(row for row in apps.values() if row.jamf_title_ids is None)
    assert unmatched.jamf_title_ids is None and unmatched.is_compliant is None and unmatched.patch_available is None
    assert unmatched.last_patch_check_at is not None  # evaluated, nothing found

    # The rows behind the summary: one per (app, title).
    match_rows = (await db.execute(select(InstalledAppPatchMatch).where(InstalledAppPatchMatch.installed_app_id.in_([row.id for row in apps.values()])))).scalars().all()
    by_app = {}
    for row in match_rows:
        by_app.setdefault(row.installed_app_id, []).append(row)
    assert len(match_rows) == 14 and len(by_app) == 12
    wireshark = {row.title_id: row for row in by_app[apps["Wireshark.app"].id]}
    assert set(wireshark) == {"5F6", "612"} and all(row.basis == "requirements" and row.state == "behind" for row in wireshark.values())
    assert next(iter(wireshark.values())).tenant_id == real.tenant_id  # stamped by the database from the session's tenant
    (pycharm,) = by_app[apps["PyCharm.app"].id]
    assert pycharm.title_id == "0EE" and pycharm.basis == "ea_assumed"  # the scoping attribute, resolved TRUE

    # What the Jamf Patch page reads, scoped by RLS to this tenant. The synthetic second
    # device may share some titles, so the real device's contribution is a lower bound.
    counts = await title_device_counts(db, ["0C3", "5F6", "612", "240"])
    assert counts["0C3"][0] >= 1 and counts["0C3"][1] >= 1  # Xcode: a device, on latest
    assert counts["5F6"][0] >= 1 and counts["5F6"][1] == 0  # Wireshark 4.2: nobody on 4.2.14
    assert counts["240"][1] == 0  # Safari ahead is not "on latest"
    versions = await title_version_counts(db, "5F6")
    assert versions.get("4.2.0", 0) >= 1

    # A second sweep replaces the rows rather than duplicating them.
    await sync_connection(db, connection)
    again = (await db.execute(select(func.count()).select_from(InstalledAppPatchMatch).where(InstalledAppPatchMatch.installed_app_id.in_([row.id for row in apps.values()])))).scalar_one()
    assert again == 14
