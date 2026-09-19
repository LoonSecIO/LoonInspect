"""The app catalog's lookup and list against a real Postgres: the index rebuilt from the catalog
slice, the local lookup by the hashes an installed app carries, and the tenant list with the
fleet on it after a sweep of the fake tenant. Gated on RUN_DB_TESTS."""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core.runs import TRIGGER_SWEEP
from tests.jamf_fake import HOST, FakeJamf

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

FIXTURES = Path(__file__).parent / "fixtures" / "jamf"


async def _list(db, **overrides):
    """`GET /api/catalog` through its route function, with every parameter given by name.

    The function is not a request, so a parameter left out arrives as FastAPI's `Query(...)`
    sentinel rather than as its documented default — and since #529 one of them, `vuln`,
    decides whether the read is refused at all. Shared with `test_vuln_answer_db.py`, which
    exercises the filter itself, so the defaults live in one place.
    """
    from app.api.catalog import list_catalog

    params = {"q": None, "jamf": "all", "installed_only": True, "app_hash": None}
    params |= {"vuln": "all", "band": None, "order": "exposure", "page": 1, "page_size": 100}
    return await list_catalog(db=db, **(params | overrides))


@pytest_asyncio.fixture(loop_scope="session")
async def indexed(db):
    from app.catalog.index import rebuild_index
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
    rows = await rebuild_index(db)
    yield rows
    reset_catalog_cache()


@pytest_asyncio.fixture(loop_scope="session")
async def connection(db):
    from app.models.schema import AppCatalogEntry, Device, DeviceExtensionAttribute, InstalledApp, MdmConnection, MdmSyncState

    row = MdmConnection(
        name=f"catalog jamf {uuidlib.uuid4().hex[:8]}",
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
    assert (
        answer.tenant is None
        and answer.jamf_title_ids == ["0C3"]
        and answer.is_latest is True
        and answer.this_version_seen is True
    )
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
    from app.api.catalog import _lookup
    from app.mdm.collections import run_enabled_collections
    from app.models.schema import Device, InstalledApp

    await _forget_fixture_apps(db, jamf)
    result = await run_enabled_collections(db, connection, trigger=TRIGGER_SWEEP)
    assert result.ok
    real = (
        await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == jamf.real["id"]))
    ).scalar_one()
    xcode = (
        await db.execute(select(InstalledApp).where(InstalledApp.device_id == real.id, InstalledApp.name == "Xcode.app"))
    ).scalar_one()

    # Every parameter by name, including #529's three: this is the route function, not a
    # request, so an omitted one arrives as FastAPI's `Query(...)` sentinel rather than its
    # documented default — and `vuln` decides whether the read is refused at all.
    listing = await _list(db, q="Xcode", page_size=50)
    (entry,) = [item for item in listing.items if item.version_hash == xcode.version_hash]
    assert entry.device_count >= 1 and entry.jamf_titles[0].name == "Apple Xcode" and entry.patch_state == "latest"
    assert entry.first_seen_at == entry.last_seen_at
    assert listing.summary.installed >= 1 and listing.summary.matched >= 1

    # #299: one application's record, the counts scoped inside the join, and no summary
    # rather than a wrong one.
    record = await _list(db, installed_only=False, page_size=500, app_hash=xcode.app_hash)
    assert record.items and all(item.app_hash == xcode.app_hash for item in record.items)
    (scoped,) = [item for item in record.items if item.version_hash == xcode.version_hash]
    assert scoped.device_count == entry.device_count, "a scoped device count must equal the unscoped one for the same build"
    assert record.summary is None
    assert listing.summary is not None

    unmatched = await _list(db, jamf="unmatched", page_size=5000)
    assert unmatched.total >= 60  # the /System apps and the rest Jamf does not track
    assert all(item.jamf_title_ids is None for item in unmatched.items)

    (answer,) = await _lookup(db, version_hashes=[xcode.version_hash], key_fulls=[], app_hashes=[])
    assert answer.tenant is not None and answer.tenant.device_count >= 1
    assert answer.jamf_title_ids == ["0C3"] and answer.is_latest is True and answer.latest == "26.6"
    (by_app,) = await _lookup(db, version_hashes=[], key_fulls=[], app_hashes=[xcode.app_hash])
    assert by_app.tenant is not None and by_app.tenant.version == "26.6"


async def test_the_device_read_and_the_applications_list_carry_the_patch_answer(db, jamf: FakeJamf, connection, indexed) -> None:
    """#313: what the wire has said since #311, on the two reads the pages make.

    Wireshark 4.2.0 on the real record matches two titles. The device read names both,
    says which one #68's sentence is about (the 4.2 line, 14 missed) and which one
    `latestVersion` is about (the rolling title, 4.6.8), and carries the assumption fold —
    false here, both matched on their requirements. The applications list answers the
    same question at its own grain: how many of the Macs carrying the app matched a title
    at all, and how many of those have a patch available.
    """
    from app.api.applications import list_applications
    from app.api.devices import get_device
    from app.mdm.collections import run_enabled_collections
    from app.models.schema import Device

    await _forget_fixture_apps(db, jamf)
    assert (await run_enabled_collections(db, connection, trigger=TRIGGER_SWEEP)).ok
    real = (
        await db.execute(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == jamf.real["id"]))
    ).scalar_one()

    detail = await get_device(device_id=real.id, db=db)
    by_name = {app.name: app for app in detail.apps}
    wireshark = by_name["Wireshark.app"]
    assert wireshark.jamf_title_ids == ["612", "5F6"]
    assert [(ref.id, ref.name) for ref in wireshark.jamf_titles] == [("612", "Wireshark"), ("5F6", "Wireshark 4.2")]
    assert (wireshark.patch_state, wireshark.latest_version, wireshark.reference_title_id) == ("behind", "4.6.8", "612")
    assert (wireshark.releases_missed, wireshark.sentence_title_id) == (14, "5F6")
    assert wireshark.ea_assumed is False
    # Matched on one title: the subject columns still name it — REST carries them as stored,
    # and it is the page that shows a subject only when there is more than one.
    xcode = by_name["Xcode.app"]
    assert xcode.patch_state == "latest" and xcode.sentence_title_id is None
    assert xcode.reference_title_id == xcode.jamf_title_ids[0]
    # No title at all: no names, and the assumption fold is null rather than false.
    mail = by_name["Mail.app"]
    assert mail.jamf_title_ids is None and mail.jamf_titles == [] and mail.ea_assumed is None
    # And the app #386 brought in from that state: matched on Jamf's `bundleId` column alone,
    # with the attribute the title scopes by assumed TRUE, which is what the fold is for.
    pycharm = by_name["PyCharm.app"]
    assert pycharm.jamf_title_ids == ["0EE"] and pycharm.ea_assumed is True

    async def row_for(app):
        listing = await list_applications(db=db, q=app.name, page=1, page_size=50)
        (row,) = [item for item in listing.items if item.app_hash == app.app_hash]
        return row

    behind = await row_for(wireshark)
    assert behind.device_count >= 1
    assert behind.matched_device_count == behind.device_count == behind.patch_available_device_count
    latest = await row_for(xcode)
    assert latest.matched_device_count == latest.device_count >= 1 and latest.patch_available_device_count == 0
    untitled = await row_for(mail)
    assert untitled.device_count >= 1 and (untitled.matched_device_count, untitled.patch_available_device_count) == (0, 0)
    # And the same list for an app matched only through #386's admission: counted as matched
    # like any other, because the answer is an answer whichever witness Jamf detects it by.
    ea_detected = await row_for(pycharm)
    assert ea_detected.matched_device_count == ea_detected.device_count >= 1
