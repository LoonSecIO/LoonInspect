# ruff: noqa: E501 — assertion lines read better unwrapped in this end-to-end test.
"""Jamf Patch matching through the real ingest path, now via the tenant app catalog (#67): the
catalog slice in `jamf_patch_titles`, a sweep of the fake tenant, then the catalog rows with
first/last seen, the title matches per row, the copies on `installed_apps`, and the tenant-scoped
counts the Jamf Patch page reads. Gated on RUN_DB_TESTS like the other database-backed suites.
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
    from app.models.schema import (
        AppCatalogEntry,
        Device,
        DeviceExtensionAttribute,
        InstalledApp,
        MdmConnection,
        MdmSyncState,
    )

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
        hashes = select(InstalledApp.version_hash).where(InstalledApp.device_id.in_(device_ids))
        # Catalog rows outlive devices by design (first/last seen); the test tenant's are
        # removed so reruns start clean. Title matches cascade from the catalog row.
        await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_(hashes)))
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.commit()


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


async def test_sweep_fills_the_catalog_and_the_counts(db, jamf: FakeJamf, connection, catalog_rows) -> None:
    from app.api.jamf_patch import title_device_counts, title_version_counts
    from app.catalog.service import refresh_tenant
    from app.mdm.service import sync_connection
    from app.models.schema import AppCatalogEntry, AppCatalogTitleMatch, Device, InstalledApp

    await _forget_fixture_apps(db, jamf)
    result = await sync_connection(db, connection)
    assert result.ok and result.device_count == 2, result

    real = (await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == jamf.real["id"]))).scalar_one()
    apps = {row.name: row for row in (await db.execute(select(InstalledApp).where(InstalledApp.device_id == real.id))).scalars().all()}
    assert len(apps) == 83

    # One catalog row per distinct (name, bundle ID, version) the device showed, first == last seen on a first sweep.
    entries = {e.version_hash: e for e in (await db.execute(select(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_([a.version_hash for a in apps.values()])))).scalars().all()}
    assert len(entries) == len({a.version_hash for a in apps.values()})
    xcode_entry = entries[apps["Xcode.app"].version_hash]
    assert xcode_entry.first_seen_at == xcode_entry.last_seen_at and xcode_entry.evaluated_signature
    assert xcode_entry.jamf_title_ids == ["0C3"] and xcode_entry.patch_state == "latest" and xcode_entry.is_latest is True
    assert xcode_entry.released_at is not None and xcode_entry.this_version_seen is True

    # The copies on the device's rows.
    xcode = apps["Xcode.app"]
    assert xcode.jamf_title_ids == ["0C3"] and xcode.patch_state == "latest" and xcode.is_compliant is True and xcode.patch_available is False
    safari = apps["Safari.app"]
    assert safari.patch_state == "ahead" and safari.this_version_seen is False and safari.is_compliant is False and safari.patch_available is False
    camtasia = apps["Camtasia 2022.app"]
    assert camtasia.jamf_title_ids == ["608", "514"] and camtasia.patch_state == "latest" and camtasia.is_compliant is True
    slack = apps["Slack.app"]
    assert slack.patch_state == "behind" and slack.patch_available is True and slack.patch_available_since is not None
    assert slack.releases_missed is not None and slack.releases_missed > 0
    unmatched = next(row for row in apps.values() if row.jamf_title_ids is None)
    assert unmatched.is_compliant is None and unmatched.last_patch_check_at is not None

    # The title matches, one per (catalog row, title).
    match_rows = (await db.execute(select(AppCatalogTitleMatch).where(AppCatalogTitleMatch.app_catalog_id.in_([e.id for e in entries.values()])))).scalars().all()
    by_entry: dict[int, list] = {}
    for row in match_rows:
        by_entry.setdefault(row.app_catalog_id, []).append(row)
    assert len(match_rows) == 13 and len(by_entry) == 11
    assert all(row.releases_missed is not None for row in match_rows)
    wireshark = {row.title_id: row for row in by_entry[entries[apps["Wireshark.app"].version_hash].id]}
    assert set(wireshark) == {"5F6", "612"} and all(row.basis == "requirements" and row.state == "behind" for row in wireshark.values())
    assert entries[apps["PyCharm.app"].version_hash].id not in by_entry  # attribute-only title: not considered

    # What the Jamf Patch page reads, through the catalog row (tenant-scoped by RLS):
    # (devices, on latest, genuinely behind).
    counts = await title_device_counts(db, ["0C3", "5F6", "240"])
    assert counts["0C3"][0] >= 1 and counts["0C3"][1] >= 1 and counts["0C3"][2] == 0  # Xcode, on latest
    assert counts["5F6"][0] >= 1 and counts["5F6"][1] == 0 and counts["5F6"][2] >= 1  # Wireshark 4.2, behind
    # Apple Safari, the case the third number exists for (#314). The fake serves two records
    # and Safari resolves differently on each — AHEAD of the catalog on the beta, behind on the
    # other — so no device is on latest while only one is actually behind. `device_count -
    # devices_on_latest` therefore OVER-COUNTS the laggards, which is exactly the derivation
    # https://github.com/LoonSecIO/LoonInspect/issues/110's tile is specified to rank by, and
    # exactly the bug #314 corrected one layer up in `patch.titles_with_laggards`. Chrome and
    # Safari sit ahead of Jamf's catalog on essentially every Mac fleet, so this is the common
    # case, not the corner one.
    devices, on_latest, behind = counts["240"]
    assert on_latest == 0
    assert behind < devices - on_latest, "the ahead device must not be counted as behind"
    assert (await title_version_counts(db, "5F6")).get("4.2.0", 0) >= 1

    # A second sweep seconds later: nothing is written for the catalog — last_seen is answered
    # to LAST_SEEN_GRANULARITY (so a sweep writes it once per distinct app, not once per device),
    # the copies on the app rows are not re-stamped, rows are not duplicated or re-judged.
    first_seen, last_seen = xcode_entry.first_seen_at, xcode_entry.last_seen_at
    checked = xcode.last_patch_check_at
    await sync_connection(db, connection)
    await db.refresh(xcode_entry)
    await db.refresh(xcode)
    assert xcode_entry.first_seen_at == first_seen and xcode_entry.last_seen_at == last_seen
    assert xcode.last_patch_check_at == checked
    again = (await db.execute(select(func.count()).select_from(AppCatalogTitleMatch).where(AppCatalogTitleMatch.app_catalog_id.in_([e.id for e in entries.values()])))).scalar_one()
    assert again == 13

    # Once the row is older than the granularity, the next device process moves last_seen.
    from datetime import timedelta

    from app.catalog.service import LAST_SEEN_GRANULARITY

    xcode_entry.last_seen_at = last_seen - LAST_SEEN_GRANULARITY - timedelta(seconds=1)
    await db.commit()
    await sync_connection(db, connection)
    await db.refresh(xcode_entry)
    assert xcode_entry.last_seen_at > last_seen - timedelta(seconds=1) and xcode_entry.first_seen_at == first_seen

    # A forced refresh re-judges every row of the tenant and leaves the same answers.
    judged = await refresh_tenant(db, force=True)
    assert judged >= len(entries)
    await db.refresh(xcode_entry)
    assert xcode_entry.jamf_title_ids == ["0C3"]

    # THE TWO COPY PATHS WRITE THE SAME COLUMNS (#311). `copy_answer` runs per app row at
    # device process; `refresh_tenant` runs a bulk UPDATE per catalog row after a catalog
    # sync — and for a stable fleet the second is the one that maintains `installed_apps`,
    # because `copy_answer` only fires on a row that is new or whose catalog row just moved.
    # They used to spell the column list twice, which made a column added to one of them
    # permanently null everywhere the other path maintained. Now both read `answer_columns`,
    # and this asserts the property rather than the implementation: refresh, then copy, and
    # the row does not move.
    from app.catalog.service import answer_columns, copy_answer

    await db.refresh(xcode)
    after_refresh = {column: getattr(xcode, column) for column in answer_columns(xcode_entry)}
    assert set(after_refresh) == set(answer_columns(xcode_entry))
    copy_answer(xcode_entry, xcode, now=xcode.last_patch_check_at)
    assert {column: getattr(xcode, column) for column in after_refresh} == after_refresh
    # And the list really is every answer column on the row — a new one added to the model
    # without being added to `answer_columns` is caught here rather than in production.
    assert set(answer_columns(xcode_entry)) == {
        "jamf_title_ids", "patch_state", "is_compliant", "patch_available", "patch_available_since",
        "releases_missed", "this_version_seen", "latest_version", "latest_released_at", "ea_assumed",
        "reference_title_id", "sentence_title_id",
    }
    # Xcode matches one title, so it is its own reference and has no sentence.
    assert xcode.reference_title_id == "0C3" and xcode.sentence_title_id is None
