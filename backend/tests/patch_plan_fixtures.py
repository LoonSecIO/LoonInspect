"""Synthetic inventory for application patch-plan integration tests."""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core import fleet_catalog as fc
from app.core.content_keys import app_full_key, app_title_key
from app.core.hashing import compute_app_hash, compute_version_hash
from app.models.schema import (
    Device,
    DeviceChange,
    DeviceExtensionAttribute,
    FleetAppVersion,
    InstalledApp,
    MdmConnection,
    SubjectDeparture,
)
from tests.test_fleet_catalog_db import ALPHA, GAMMA, accounts, admin, flag_off, flag_on, github, viewer  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="requires a disposable PostgreSQL database"),
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest_asyncio.fixture(loop_scope="session")
async def inventory(db, github):  # noqa: F811
    now = datetime.now(UTC)
    old = now - timedelta(days=90)
    name = "migration-test-" + uuid.uuid4().hex
    source = MdmConnection(name=name, provider="jamf", base_url="https://jamf.example.invalid")
    other = MdmConnection(name=name + "-other", provider="jamf", base_url="https://jamf2.example.invalid")
    db.add_all([source, other])
    await db.flush()
    source_ids = [source.id, other.id]

    def mac(identifier, contact, inventory_at, *, connection=source.id, platform="macos"):
        return Device(
            mdm_connection_id=connection,
            mdm_provider="jamf",
            external_id=identifier,
            platform=platform,
            serial_number="serial-" + identifier,
            hostname="host-" + identifier,
            last_check_in=contact,
            last_inventory_at=inventory_at,
        )

    active, old_contact, no_contact = mac("1", now, old), mac("2", old, now), mac("3", None, None)
    gone, elsewhere, ipad = mac("4", now, now), mac("1", now, now, connection=other.id), mac("1", now, now, platform="ipados")
    db.add_all([active, old_contact, no_contact, gone, elsewhere, ipad])
    await db.flush()
    db.add(SubjectDeparture(mdm_connection_id=source.id, subject_kind="computer", subject_id="4", departed_at=old))

    def app(device, label, bundle, version):
        return InstalledApp(
            device_id=device.id,
            name=label,
            bundle_id=bundle,
            version=version,
            app_hash=compute_app_hash(label, bundle),
            version_hash=compute_version_hash(label, bundle, version),
            key_title=app_title_key(label, bundle),
            key_full=app_full_key(label, bundle, version, None),
        )

    gamma_id = compute_app_hash("Gamma", GAMMA)
    db.add_all(
        [
            app(active, "Alpha", ALPHA, "1.0"),
            app(active, "Alpha", ALPHA, "2.0"),
            app(active, "Alpha Beta", ALPHA, "99"),
            app(old_contact, "Alpha", ALPHA, "2.0"),
            app(no_contact, "Alpha", ALPHA, "unread"),
            app(gone, "Alpha", ALPHA, "77"),
            app(elsewhere, "Alpha", ALPHA, "88"),
            app(ipad, "Alpha", ALPHA, "101"),
            app(active, "Unmatched", "org.internal", "1"),
            app(active, "No ID", "No ID", "1"),
            app(active, "Gamma", GAMMA, "6"),
        ]
    )
    db.add(
        DeviceChange(
            mdm_connection_id=source.id,
            subject_kind="computer",
            subject_id="1",
            section="applications",
            change="updated",
            entry_identity={"name": "Alpha", "bundleId": ALPHA, "path": "/Applications/Alpha.app"},
            old_value={"version": "1"},
            new_value={"version": "2"},
            observed_at=now,
            collected_at=now,
            trigger="sweep",
            level="normal",
            policy_version="1",
        )
    )
    await db.commit()
    github.put("gamma@6+", "Gamma Variant", GAMMA, "6")
    await fc.check(db, transport=github.transport)
    db.add(FleetAppVersion(slug="alpha", version="1.5", seen_at=now, commit_sha="a" * 40))
    await db.commit()
    try:
        yield source.id, compute_app_hash("Alpha", ALPHA), gamma_id
    finally:
        await db.rollback()
        our_devices = select(Device.id).where(Device.mdm_connection_id.in_(source_ids))
        await db.execute(delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(our_devices)))
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(our_devices)))
        await db.execute(delete(Device).where(Device.mdm_connection_id.in_(source_ids)))
        await db.execute(delete(MdmConnection).where(MdmConnection.id.in_(source_ids)))
        await db.commit()
