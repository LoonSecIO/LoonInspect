"""The migration report (#895) on Postgres: main's device filter, the route's gate, and another organization."""

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import delete, select, update

from app.api.fleet_migration import read_migration
from app.core.database import session_for_tenant, unscoped_session
from app.core.feature_flags import FLEET_MAINTAINED_APPS_FLAG
from app.core.hashing import compute_app_hash
from app.main import app
from app.models.schema import Device, FeatureFlag, FleetCatalogState, InstalledApp, Tenant
from app.schemas.patch_plans import DeviceScope
from tests.patch_plan_fixtures import accounts, admin, flag_off, flag_on, github, inventory, viewer  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="requires a disposable PostgreSQL database"),
    pytest.mark.asyncio(loop_scope="session"),
]

REPORT = "/api/fleet-catalog/migration"
UNMATCHED, NO_ID = compute_app_hash("Unmatched", "org.internal"), compute_app_hash("No ID", "No ID")
INVALID = "The device filter is invalid. Check each condition or clear the filter and try again."


def _filter(source, *within_30):
    rules = [{"field": field, "operator": "within", "value": "30"} for field in within_30]
    return {"deviceScope": json.dumps({"connectionId": source, "rules": rules})}


async def _read(client, params=None):
    response = await client.get(REPORT, params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def test_read_is_flag_gated(admin, flag_off):  # noqa: F811
    report = await _read(admin)
    assert not report["enabled"] and not report["items"] and not report["fleetDeviceCounts"] and not any(report["scope"].values())


async def test_population_and_identity_share_a_cohort(db, inventory, viewer, flag_on):  # noqa: F811
    source, alpha, gamma = inventory
    report = await _read(viewer, _filter(source, "contact"))
    assert report["scope"] == {"eligibleMacs": 3, "selectedMacs": 1, "unknownContactMacs": 1, "unknownInventoryMacs": 1}
    rows = {item["appHash"]: item for item in report["items"]}
    assert (rows[alpha]["macs"], rows[alpha]["versionCount"], rows[alpha]["match"]) == (1, 2, "exact")
    assert rows[gamma]["match"] == "ambiguous" and [c["slug"] for c in rows[gamma]["fleetCandidates"]] == ["gamma", "gamma@6+"]
    assert rows[UNMATCHED]["match"] == "none" and rows[NO_ID]["match"] == "unknown"
    assert report["fleetDeviceCounts"]["alpha"] == 1  # Alpha and Alpha Beta share its bundle identifier on that Mac.
    # No conditions: the departed Mac, the other connection's Mac and the iPad still count nowhere.
    every = await _read(viewer, _filter(source))
    rows = {item["appHash"]: item for item in every["items"]}
    assert every["scope"]["selectedMacs"] == 3 and (rows[alpha]["macs"], rows[alpha]["versionCount"]) == (3, 3)
    assert every["fleetDeviceCounts"]["alpha"] == 3
    mac = await db.scalar(select(Device).where(Device.mdm_connection_id == source, Device.external_id == "3"))
    mac.last_inventory_at = datetime.now(UTC) + timedelta(days=1)
    await db.commit()
    future = (await _read(viewer, _filter(source, "inventory")))["scope"]
    assert (future["selectedMacs"], future["unknownInventoryMacs"]) == (1, 1)  # A future date is unknown, not selected.
    await db.execute(update(InstalledApp).where(InstalledApp.app_hash == alpha).values(jamf_title_ids=["absent-1", "absent-2"]))
    await db.commit()
    claimed = {item["appHash"]: item for item in (await _read(viewer, _filter(source)))["items"]}[alpha]
    assert (claimed["match"], claimed["hasJamfMatch"]) == ("ambiguous", False)  # Two claimed titles, though neither is cached.


async def test_counts_need_device_read_and_a_valid_filter(admin, flag_on):  # noqa: F811
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://policy.example.com") as client:
        for scopes, status in ((["app:read"], 403), (["app:read", "device:read"], 200)):
            minted = await admin.post("/api/auth/tokens", json={"name": "fleet migration", "scopes": scopes, "expiresInDays": 1})
            assert minted.status_code == 201, minted.text
            response = await client.get(REPORT, headers={"Authorization": f"Bearer {minted.json()['token']}"})
            assert response.status_code == status, (scopes, response.text)
    refused = await admin.get(REPORT, params={"deviceScope": json.dumps({"rules": [{"field": "contact", "operator": "within"}]})})
    assert refused.status_code == 422 and refused.json()["detail"] == INVALID
    regex = json.dumps({"rules": [{"field": "ea", "key": "1", "operator": "matches_regex", "value": "("}]})
    assert (await admin.get(REPORT, params={"deviceScope": regex})).status_code == 422  # main's EA-regex refusal


async def test_migration_does_not_expose_another_tenants_inventory(db, inventory, flag_on):  # noqa: F811
    source = DeviceScope(connection_id=inventory[0])
    assert (await read_migration(source, db)).scope.eligible_macs == 3  # The same read, from its own organization.
    tenant_id = uuid.uuid4()
    async with unscoped_session() as global_db:
        global_db.add(Tenant(id=tenant_id, slug=f"migration-{tenant_id.hex}", name="Migration fixture", kind="operational"))
        await global_db.commit()
    try:
        async with session_for_tenant(tenant_id) as other_db:
            other_db.add(FeatureFlag(key=FLEET_MAINTAINED_APPS_FLAG, enabled=True))
            await other_db.commit()
            report = await read_migration(source, other_db)
            await other_db.execute(delete(FeatureFlag))
            await other_db.commit()
    finally:
        async with unscoped_session() as global_db:
            await global_db.execute(delete(Tenant).where(Tenant.id == tenant_id))
            await global_db.commit()
    assert report.enabled and report.scope.eligible_macs == 0 and not report.items
    assert report.fleet_device_counts["alpha"] == 0


async def test_an_incomplete_snapshot_keeps_candidates_without_judging_coverage(db, inventory, viewer, flag_on):  # noqa: F811
    source, alpha, gamma = inventory
    state = await db.get(FleetCatalogState, 1)
    state.snapshot_status = "partial"  # A completed tree with skipped manifests still has a SHA.
    await db.commit()
    report = await _read(viewer, _filter(source))
    assert report["fleetCatalogReadiness"] == "partial" and not report["fleetCatalogReady"]
    rows = {item["appHash"]: item for item in report["items"]}
    assert rows[alpha]["match"] == "unknown" and [title["slug"] for title in rows[alpha]["fleetCandidates"]] == ["alpha"]
    assert rows[UNMATCHED]["match"] == "unknown" and rows[gamma]["match"] == "ambiguous"
