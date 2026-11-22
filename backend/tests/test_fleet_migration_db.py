"""Migration reports use the same tenant, source, time window and device identity throughout."""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core import fleet_catalog as fc
from app.core.content_keys import app_full_key, app_title_key
from app.core.hashing import compute_app_hash, compute_version_hash
from app.models.schema import Device, DeviceChange, FleetAppVersion, InstalledApp, MdmConnection, SubjectDeparture
from tests.test_fleet_catalog_db import ALPHA, BETA, GAMMA, accounts, admin, flag_off, flag_on, github, viewer  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="requires a disposable PostgreSQL database"),
    pytest.mark.asyncio(loop_scope="session"),
]

REPORT = "/api/fleet-catalog/migration"


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
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(our_devices)))
        await db.execute(delete(Device).where(Device.mdm_connection_id.in_(source_ids)))
        await db.execute(delete(MdmConnection).where(MdmConnection.id.in_(source_ids)))
        await db.commit()


async def test_read_and_detail_are_flag_gated(admin, flag_off):  # noqa: F811
    report = (await admin.get(REPORT)).json()
    assert not report["enabled"] and not report["connections"] and not report["items"] and not report["assessments"]
    assert (await admin.get(f"{REPORT}/titles/alpha")).status_code == 409
    assert (await admin.get(f"{REPORT}/apps/{'0' * 32}")).status_code == 409


async def test_population_and_identity_share_a_cohort(inventory, viewer, flag_on):  # noqa: F811
    source, alpha, gamma = inventory
    params = {"connectionId": source, "clock": "contact", "days": 30}
    response = await viewer.get(REPORT, params=params)
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["scope"] == {
        "connectionId": source,
        "clock": "contact",
        "days": 30,
        "eligibleMacs": 3,
        "activeMacs": 1,
        "staleMacs": 1,
        "unknownMacs": 1,
    }
    assert report["fleetDeviceCounts"]["alpha"] == 1
    rows = {item["appHash"]: item for item in report["items"]}
    assert rows[alpha]["macs"] == 1 and rows[alpha]["versionCount"] == 2
    assert set(report["appAssessments"]) == {alpha, compute_app_hash("Alpha Beta", ALPHA)}
    assert rows[gamma]["match"] == "ambiguous"
    assert {c["slug"] for c in rows[gamma]["fleetCandidates"]} == {"gamma", "gamma@6+"}
    assert rows[compute_app_hash("Unmatched", "org.internal")]["match"] == "none"
    assert rows[compute_app_hash("No ID", "No ID")]["match"] == "unknown"
    detail = (await viewer.get(f"{REPORT}/apps/{alpha}", params={**params, "targetVersion": "1.5"})).json()
    assert detail["installedMacs"] == 1 and {b["version"] for b in detail["builds"]} == {"1.0", "2.0"}
    assert detail["observedChanges"]["versionChanges"] == 1
    assert detail["impact"] == {"targetVersion": "1.5", "installedMacs": 1, "olderMacs": 1, "atOrAboveMacs": 0, "unknownMacs": 0}
    assert detail["appAssessments"][alpha]["targetVersion"] == "1.5"
    detail = (await viewer.get(f"{REPORT}/apps/{alpha}", params={**params, "clock": "inventory", "targetVersion": "1.5"})).json()
    assert detail["scope"]["activeMacs"] == 1 and detail["impact"]["olderMacs"] == 0 and detail["observedChanges"]["macs"] == 0
    all_macs = (await viewer.get(f"{REPORT}/apps/{alpha}", params={"connectionId": source, "targetVersion": "2.0"})).json()
    assert all_macs["impact"] == {
        "targetVersion": "2.0",
        "installedMacs": 3,
        "olderMacs": 1,
        "atOrAboveMacs": 1,
        "unknownMacs": 1,
    }
    assert (await viewer.get(f"{REPORT}/apps/{alpha}", params={**params, "targetVersion": "never-listed"})).status_code == 422


async def test_future_inventory_timestamp_is_unusable_for_a_dated_report(db):
    from app.core.fleet_migration import device_scope

    now = datetime.now(UTC)
    key = uuid.uuid4().hex
    connection = MdmConnection(name=key, provider="jamf", base_url="https://jamf.example.invalid")
    db.add(connection)
    await db.flush()
    db.add(
        Device(
            mdm_connection_id=connection.id,
            mdm_provider="jamf",
            platform="macos",
            external_id=key,
            serial_number=key,
            hostname="synthetic",
            last_inventory_at=now + timedelta(days=1),
        )
    )
    await db.flush()
    scope, _ = await device_scope(db, connection.id, "inventory", 7, now)
    assert (scope.eligible_macs, scope.active_macs, scope.stale_macs, scope.unknown_macs) == (1, 0, 0, 1)
    await db.rollback()


async def test_title_with_no_installs_or_ambiguous_local_identity(inventory, viewer, flag_on):  # noqa: F811
    source, _, gamma = inventory
    params = {"connectionId": source}
    empty = (await viewer.get(f"{REPORT}/titles/beta", params=params)).json()
    assert empty["title"]["bundleId"] == BETA and empty["installedMacs"] == 0 and empty["items"] == []
    ambiguous = (await viewer.get(f"{REPORT}/titles/gamma%406%2B", params={**params, "targetVersion": "6"})).json()
    assert ambiguous["installedMacs"] == 1 and ambiguous["impact"] is None and ambiguous["assessments"] == {}
    assert (await viewer.get("/api/fleet-catalog/gamma%406%2B/history")).status_code == 200
    local = (await viewer.get(f"{REPORT}/apps/{gamma}", params=params)).json()
    assert local["item"]["match"] == "ambiguous" and local["appAssessments"] == {}


async def test_adoption_lag_dates_each_first_observed_upgrade_once_per_mac_and_version(db, inventory, viewer, flag_on):  # noqa: F811
    source, alpha, gamma = inventory
    now = datetime.now(UTC)

    def before(days):
        return now - timedelta(days=days)

    def change(mac, previous, version, days, *, name="Alpha", bundle=ALPHA, short=None):
        new = {"version": version}
        if short is not None:
            new["cfBundleShortVersionString"] = short
        return DeviceChange(
            mdm_connection_id=source,
            subject_kind="computer",
            subject_id=mac,
            section="applications",
            change="updated",
            entry_identity={"name": name, "bundleId": bundle},
            old_value={"version": previous},
            new_value=new,
            observed_at=before(days),
            collected_at=now,
            trigger="sweep",
            level="normal",
            policy_version="1",
        )

    db.add_all(
        [
            FleetAppVersion(slug=slug, version=version, seen_at=before(days), commit_sha="c" * 40)
            for slug, version, days in [
                ("alpha", "2.1", 10),
                ("alpha", "3.0", 10),
                ("alpha", "3.1", 5),
                ("alpha", "4.0", 10),
                ("alpha", "9.0", 120),
                ("alpha", "9.1", -1),
                ("gamma", "5.1", 10),
            ]
        ]
    )
    db.add_all(
        [
            change("1", "1", "2.1", 7),
            change("1", "2.0", "2.1", 4),  # Earliest observation is 3 days after the manifest.
            change("1", "2.1", "3.0", 8),
            change("2", "1", "2.1", 4),  # 2 and 6 days.
            change("1", "5.0", "4.0", 2),
            change("1", "2", "4.0", 1, short="4.1"),
            change("1", "v2-beta", "4.0", 1),
            change("1", "3", "4.0", -1),
            change("1", "3", "9.1", 1),
            change("1", "2", "3.1", 6),
            change("1", "3.0", "3.1", 4),  # First observed before Fleet.
            change("1", "1", "9.0", 99),
            change("1", "3", "9.0", 1),  # First observed outside the window.
            change("1", "3", "4.0", 1, name="Different app"),
            change("4", "3", "4.0", 1),  # Wrong identity / departed Mac.
            change("1", "5.0", "5.1", 2, name="Gamma", bundle=GAMMA),  # Shared channel identity.
        ]
    )
    await db.commit()

    for location in (f"apps/{alpha}", "titles/alpha"):
        response = await viewer.get(f"{REPORT}/{location}", params={"connectionId": source})
        assert response.status_code == 200, response.text
        observed = response.json()["observedChanges"]
        assert observed["adoptionSamples"] == 3 and observed["medianDaysAfterFleetPublication"] == 3.0
    active = await viewer.get(f"{REPORT}/apps/{alpha}", params={"connectionId": source, "days": 30})
    observed = active.json()["observedChanges"]
    assert observed["adoptionSamples"] == 2 and observed["medianDaysAfterFleetPublication"] == 2.5
    for location in (f"apps/{gamma}", "titles/gamma"):
        uncertain = await viewer.get(f"{REPORT}/{location}", params={"connectionId": source})
        observed = uncertain.json()["observedChanges"]
        assert observed["versionChanges"] == 1 and observed["adoptionSamples"] == 0
        assert observed["medianDaysAfterFleetPublication"] is None


async def test_migration_does_not_expose_another_tenants_inventory(inventory, viewer, flag_on):  # noqa: F811
    from app.api.fleet_migration import Cohort, read_migration
    from app.core.database import session_for_tenant, unscoped_session
    from app.core.feature_flags import FLEET_MAINTAINED_APPS_FLAG
    from app.models.schema import FeatureFlag, Tenant

    tenant_id = uuid.uuid4()
    async with unscoped_session() as global_db:
        global_db.add(Tenant(id=tenant_id, slug=f"migration-{tenant_id.hex}", name="Migration fixture", kind="operational"))
        await global_db.commit()
    try:
        async with session_for_tenant(tenant_id) as other_db:
            other_db.add(FeatureFlag(key=FLEET_MAINTAINED_APPS_FLAG, enabled=True))
            await other_db.commit()
            scoped = await read_migration(Cohort(inventory[0], "contact", None), other_db, show_connections=True)
            assert scoped.enabled and not scoped.items and not scoped.connections and scoped.scope.eligible_macs == 0
            assert scoped.fleet_device_counts["alpha"] == 0 and not scoped.app_assessments
            await other_db.execute(delete(FeatureFlag))
            await other_db.commit()
    finally:
        async with unscoped_session() as global_db:
            await global_db.execute(delete(Tenant).where(Tenant.id == tenant_id))
            await global_db.commit()
    assert (await viewer.get(REPORT)).json()["connections"] == []


async def test_tree_invalidation_reconciles_legacy_cache_without_reloading_manifests(db, github, flag_on):  # noqa: F811
    from importlib import import_module

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    from app.models.schema import FleetCatalogState

    await fc.check(db, transport=github.transport)
    github.put("python@3.13+", "Versioned title", "org.fixture.versioned", "3.13")
    state = await db.get(FleetCatalogState, 1)
    # A pre-upgrade reader saw this complete upstream tree but skipped its special slug.
    state.tree_sha = github.tree_sha
    await db.commit()

    def migrate(sync_db):
        migration = import_module("migrations.versions.b13008440001_fleet_catalog_slug_refresh")
        with Operations.context(MigrationContext.configure(sync_db.connection())):
            migration.downgrade()  # Restore the shipped schema before exercising the new upgrade.
            migration.upgrade()

    await db.run_sync(migrate)
    await db.commit()
    db.expire_all()
    state = await db.get(FleetCatalogState, 1)
    assert state.tree_sha is None and state.snapshot_status == "partial" and fc.due(state, datetime.now(UTC))
    state.outcome = fc.OUTCOME_REFUSED
    assert not fc.due(state, datetime.now(UTC))
    github.requests.clear()
    await fc.check(db, transport=github.transport)
    manifests = [r.url.path for r in github.requests if r.url.path.endswith("/darwin.json")]
    assert len(manifests) == 1 and manifests[0].endswith("/python@3.13+/darwin.json")
    github.requests.clear()
    assert (await fc.check(db, transport=github.transport)).outcome == "unchanged"
    assert len(github.requests) == 1


async def test_an_incomplete_snapshot_keeps_candidates_without_judging_coverage_or_a_target(db, inventory, viewer, flag_on):  # noqa: F811
    from app.models.schema import FleetCatalogState

    source, alpha, gamma = inventory
    state = await db.get(FleetCatalogState, 1)
    state.snapshot_status = "partial"  # A completed tree with skipped manifests still has a SHA.
    await db.commit()
    params = {"connectionId": source}
    report = (await viewer.get(REPORT, params=params)).json()
    assert report["fleetCatalogReadiness"] == "partial" and not report["fleetCatalogReady"]
    found = {item["appHash"]: item for item in report["items"]}
    assert found[alpha]["match"] == "unknown" and [t["slug"] for t in found[alpha]["fleetCandidates"]] == ["alpha"]
    assert found[compute_app_hash("Unmatched", "org.internal")]["match"] == "unknown"
    assert found[gamma]["match"] == "ambiguous" and report["appAssessments"] == {}
    for path in [f"apps/{alpha}", "titles/alpha", "titles/beta"]:
        detail = (await viewer.get(f"{REPORT}/{path}", params=params)).json()
        assert detail["fleetCatalogReadiness"] == "partial" and detail["impact"] is None
        assert detail["assessments"] == detail["appAssessments"] == {}


async def test_finding_ids_require_vulnerability_read_on_both_detail_routes(inventory, admin, flag_on, monkeypatch):  # noqa: F811
    import httpx

    from app.core import fleet_assessment
    from app.main import app
    from tests.test_fleet_assessment import A, B, assessed

    source, alpha, _ = inventory

    async def corpus(_db):
        from types import SimpleNamespace

        return SimpleNamespace(as_of=datetime.now(UTC).date())

    async def answers(_db, keys, _signature):
        old = app_full_key("Alpha", ALPHA, "1.0", None)
        target = app_full_key("Alpha", ALPHA, "2.0", None)
        return {key: answer for key, answer in [(old, assessed([A])), (target, assessed([B]))] if key in keys}

    monkeypatch.setattr(fleet_assessment, "earned_corpus", corpus)
    monkeypatch.setattr(fleet_assessment, "_answers", answers)
    minted = await admin.post("/api/auth/tokens", json={"name": "migration counts", "scopes": ["app:read"], "expiresInDays": 1})
    assert minted.status_code == 201
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://policy.example.com") as client:
        client.headers["Authorization"] = f"Bearer {minted.json()['token']}"
        for location, field, key in [(f"apps/{alpha}", "appAssessments", alpha), ("titles/alpha", "assessments", "alpha")]:
            for reader, expected in [(client, (None, None, None)), (admin, ([A], [B], []))]:
                response = await reader.get(f"{REPORT}/{location}", params={"connectionId": source})
                assert response.status_code == 200, response.text
                row = next(r for r in response.json()[field][key]["builds"] if r["name"] == "Alpha" and r["version"] == "1.0")
                assert (row["addresses"], row["introduces"], row["remains"]) == (1, 1, 0)
                assert (row["addressedIds"], row["introducedIds"], row["remainingIds"]) == expected
