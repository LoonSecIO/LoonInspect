"""Exact scope, saved evidence, permissions, research and PDF against non-superuser PostgreSQL."""

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import delete, select

from app.core.device_scope import scoped_devices
from app.core.patch_plans import checksum
from app.models.schema import ApplicationPatchPlan, Device, DeviceExtensionAttribute, InstalledApp
from app.schemas.patch_plans import DeviceScope
from tests.patch_plan_fixtures import (  # noqa: F401
    accounts,
    admin,
    flag_off,
    flag_on,
    github,
    inventory,
    viewer,
)

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="requires disposable PostgreSQL"),
    pytest.mark.asyncio(loop_scope="session"),
]
BASE = "/api/application-patch-plans"


async def test_plan_without_fleet_and_exact_export_revision(db, inventory, admin, flag_off):  # noqa: F811
    connection, app_hash, _ = inventory
    scope = {"connectionId": connection, "match": "all", "rules": [{"field": "contact", "operator": "within", "value": "14"}]}
    response = await admin.post(BASE, json={"appHashes": [app_hash], "scope": scope, "title": "Auditor patch plan"})
    assert response.status_code == 201, response.text
    plan = response.json()
    snap = plan["snapshot"]
    assert snap["scopedDevices"] == 1 and snap["applicationDevices"] == 1
    assert snap["applications"][0]["devices"] == 1
    assert len(snap["applications"][0]["versions"]) == 2
    assert not any(o["source"] == "Fleet" for o in snap["applications"][0]["options"])
    assert plan["sha256"] == checksum({k: v for k, v in plan.items() if k != "sha256"})
    # Changing live inventory does not rewrite a saved report.
    await db.execute(delete(InstalledApp).where(InstalledApp.app_hash == app_hash))
    await db.commit()
    held = (await admin.get(f"{BASE}/{plan['id']}")).json()
    assert held["snapshot"] == snap and held["sha256"] == plan["sha256"]
    pdf = await admin.get(f"{BASE}/{plan['id']}/pdf?revision=1")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert pdf.headers["cache-control"] == "no-store"
    assert (await admin.get(f"{BASE}/{plan['id']}/pdf?revision=2")).status_code == 409
    await db.execute(delete(ApplicationPatchPlan).where(ApplicationPatchPlan.id == uuid.UUID(plan["id"])))
    await db.commit()


async def test_unknown_device_values_are_not_negative_matches(db, inventory):  # noqa: F811
    source, _, _ = inventory
    devices = (
        await db.scalars(
            select(Device).where(Device.mdm_connection_id == source, Device.platform == "macos").order_by(Device.external_id)
        )
    ).all()
    devices[0].managed = True
    devices[1].managed = False
    db.add(
        DeviceExtensionAttribute(
            device_id=devices[0].id, definition_id="19", name="Update Ring", values=["Pilot"], source="general"
        )
    )
    db.add(
        DeviceExtensionAttribute(
            device_id=devices[1].id, definition_id="19", name="Update Ring", values=["Production"], source="general"
        )
    )
    await db.commit()

    async def matching(rules, match="all"):
        population = scoped_devices(DeviceScope.model_validate({"connectionId": source, "match": match, "rules": rules}))
        return set((await db.scalars(select(population.c.id))).all())

    assert await matching([{"field": "ea", "key": "19", "operator": "is_not", "value": "Pilot"}]) == {devices[1].id}
    assert await matching([{"field": "managed", "value": "true"}, {"field": "ea", "key": "19", "value": "Pilot"}]) == {
        devices[0].id
    }
    assert await matching([{"field": "managed", "value": "false"}, {"field": "ea", "key": "19", "value": "Pilot"}], "any") == {
        devices[0].id,
        devices[1].id,
    }
    assert await matching([{"field": "contact", "operator": "older", "value": "14"}]) == {devices[1].id}


async def test_read_only_role_cannot_build_or_investigate(db, inventory, admin, viewer, flag_off):  # noqa: F811
    source, app_hash, _ = inventory
    request = {"appHashes": [app_hash], "scope": {"connectionId": source}}
    assert (await viewer.post(BASE, json=request)).status_code == 403
    plan = (await admin.post(BASE, json=request)).json()
    assert (await viewer.get(f"{BASE}/{plan['id']}")).status_code == 200
    assert (await viewer.get(f"{BASE}/{plan['id']}/pdf?revision=1")).status_code == 200
    assert (await viewer.post(f"{BASE}/{plan['id']}/research", json={})).status_code == 403
    from app.core.database import session_for_tenant
    from app.core.tenancy import ROOT_TENANT_ID

    async with session_for_tenant(ROOT_TENANT_ID) as other:
        assert await other.get(ApplicationPatchPlan, uuid.UUID(plan["id"])) is None
    await db.execute(delete(ApplicationPatchPlan).where(ApplicationPatchPlan.id == uuid.UUID(plan["id"])))
    await db.commit()


async def test_background_research_and_restart_recovery(db, inventory, admin, flag_off, monkeypatch):  # noqa: F811
    from app.core import patch_plan_research as research

    monkeypatch.setattr(research, "transport_override", httpx.MockTransport(lambda r: httpx.Response(503)))
    source, app_hash, _ = inventory
    plan = (await admin.post(BASE, json={"appHashes": [app_hash], "scope": {"connectionId": source}})).json()
    response = await admin.post(f"{BASE}/{plan['id']}/research", json={"installomator": True})
    assert response.status_code == 202, response.text
    current = (await admin.get(f"{BASE}/{plan['id']}")).json()
    assert current["researchStatus"] == "completed" and current["revision"] == 3
    assert current["research"]["applications"][0]["status"] == "unavailable"
    assert (await admin.get(f"{BASE}/{plan['id']}/pdf?revision=1")).status_code == 409
    row = await db.get(ApplicationPatchPlan, uuid.UUID(plan["id"]))
    row.research_status = "running"
    row.research_started_at = datetime.now(UTC) - timedelta(minutes=7)
    await db.commit()
    current = (await admin.get(f"{BASE}/{plan['id']}")).json()
    assert current["researchStatus"] == "interrupted" and "retry" in current["research"]["detail"]
    await db.execute(delete(ApplicationPatchPlan).where(ApplicationPatchPlan.id == row.id))
    await db.commit()


async def test_invalid_scope_and_app_selection_fail_explicitly(inventory, admin):  # noqa: F811
    source, _, _ = inventory
    response = await admin.post(BASE, json={"appHashes": ["a" * 32], "scope": {"connectionId": source}})
    assert response.status_code == 409
    assert (await admin.get("/api/catalog", params={"deviceScope": json.dumps({"match": "bad"})})).status_code == 422


async def test_operator_review_is_versioned_and_conflicts_do_not_lose_notes(db, inventory, admin, flag_off):  # noqa: F811
    source, app_hash, _ = inventory
    plan = (await admin.post(BASE, json={"appHashes": [app_hash], "scope": {"connectionId": source}})).json()
    saved = await admin.patch(
        f"{BASE}/{plan['id']}", json={"revision": 1, "owner": "Endpoint engineering", "pilot": "Engineering pilot Macs"}
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["revision"] == 2
    assert saved.json()["snapshot"]["operatorReview"]["owner"] == "Endpoint engineering"
    assert (await admin.patch(f"{BASE}/{plan['id']}", json={"revision": 1, "owner": "Old review"})).status_code == 409
    assert (await admin.get(f"{BASE}/{plan['id']}/pdf?revision=1")).status_code == 409
    assert (await admin.get(f"{BASE}/{plan['id']}/pdf?revision=2")).status_code == 200
    await db.execute(delete(ApplicationPatchPlan).where(ApplicationPatchPlan.id == uuid.UUID(plan["id"])))
    await db.commit()


async def test_group_filters_require_observed_membership_and_connection(db, inventory, admin):  # noqa: F811
    from app.models.schema import ObservationEntry, ObservationSection, ObservationSpan

    source, _, _ = inventory
    now = datetime.now(UTC)

    def digest():
        return "v0:" + uuid.uuid4().hex + uuid.uuid4().hex

    entry_digest, member_digest, empty_digest = digest(), digest(), digest()
    db.add(ObservationEntry(digest=entry_digest, kind="group_membership", body={"groupId": "41", "smartGroup": True}))
    db.add(ObservationSection(digest=member_digest, section="group_memberships", entry_digests=[entry_digest], entry_count=1))
    db.add(ObservationSection(digest=empty_digest, section="group_memberships", entry_digests=[], entry_count=0))
    for external, section in [("1", member_digest), ("2", empty_digest)]:
        db.add(
            ObservationSpan(
                mdm_connection_id=source,
                subject_kind="computer",
                subject_id=external,
                contract_version="v0",
                aperture_digest=digest(),
                head_digest=digest(),
                section_digests={"group_memberships": section},
                first_observed_at=now,
                last_observed_at=now,
                first_collected_at=now,
                last_collected_at=now,
                last_trigger="sweep",
            )
        )
    await db.commit()

    async def matches(operator):
        population = scoped_devices(
            DeviceScope.model_validate(
                {"connectionId": source, "rules": [{"field": "group", "key": str(source), "value": "41", "operator": operator}]}
            )
        )
        return set((await db.scalars(select(population.c.external_id))).all())

    assert await matches("is") == {"1"}
    assert await matches("is_not") == {"2"}  # No-contact Mac has no observed group section, not an empty one.
    rule = {"field": "group", "key": str(source), "value": "41", "operator": "is_not"}
    response = await admin.get("/api/devices", params={"scope": json.dumps({"rules": [rule]})})
    assert response.status_code == 200, response.text
    assert [row["externalId"] for row in response.json()["items"]] == ["2"]
    await db.execute(delete(ObservationSpan).where(ObservationSpan.mdm_connection_id == source))
    await db.execute(delete(ObservationSection).where(ObservationSection.digest.in_([member_digest, empty_digest])))
    await db.execute(delete(ObservationEntry).where(ObservationEntry.digest == entry_digest))
    await db.commit()


async def test_catalog_counts_use_the_same_device_scope_as_plan(db, inventory, admin, flag_off):  # noqa: F811
    from app.catalog.service import record_device_apps

    source, app_hash, _ = inventory
    for device in await db.scalars(select(Device).where(Device.mdm_connection_id == source)):
        await record_device_apps(db, device)
    await db.commit()
    scope = {"connectionId": source, "rules": [{"field": "contact", "operator": "within", "value": "14"}]}
    response = await admin.get("/api/catalog", params={"deviceScope": json.dumps(scope), "appHash": app_hash})
    assert response.status_code == 200, response.text
    assert {row["version"]: row["deviceCount"] for row in response.json()["items"]} == {"1.0": 1, "2.0": 1}
    installed = await admin.get("/api/applications", params={"deviceScope": json.dumps(scope)})
    assert installed.status_code == 200, installed.text
    app = next(row for row in installed.json()["items"] if row["appHash"] == app_hash)
    assert app["deviceCount"] == 1


async def test_partial_jamf_matches_within_one_version_need_identity_review(db, inventory, flag_on):  # noqa: F811
    from app.core.patch_plans import build_snapshot
    from app.models.schema import JamfPatchTitle
    from app.schemas.patch_plans import BuildPlan

    source, app_hash, _ = inventory
    title_id = "plan-test-" + uuid.uuid4().hex
    title = JamfPatchTitle(id=title_id, name="Alpha", current_version="3.0", last_modified="test-revision")
    db.add(title)
    await db.execute(delete(InstalledApp).where(InstalledApp.app_hash == app_hash, InstalledApp.version != "2.0"))
    rows = (await db.scalars(select(InstalledApp).where(InstalledApp.app_hash == app_hash))).all()
    assert len(rows) == 2
    for row in rows:
        row.ea_assumed = False
        row.last_patch_check_at = datetime.now(UTC)
        row.jamf_title_ids = None
    await db.commit()
    request = BuildPlan(appHashes=[app_hash], scope={"connectionId": source})
    fleet_only = (await build_snapshot(db, request, "Test"))["applications"][0]
    assert fleet_only["targetVersion"] == "2.0"
    rows[0].jamf_title_ids = [title_id]
    rows[1].jamf_title_ids = None
    await db.commit()
    partial = (await build_snapshot(db, request, "Test"))["applications"][0]
    assert partial["devices"] == 2
    assert partial["options"][0]["status"] == "identity_review"
    assert partial["targetVersion"] is None
    rows[1].jamf_title_ids = [title_id]
    await db.commit()
    complete = (await build_snapshot(db, request, "Test"))["applications"][0]
    assert complete["options"][0]["status"] == "catalog_match"
    assert complete["targetVersion"] == "3.0"
    await db.delete(title)
    await db.commit()
