"""The migration report (#895) on Postgres: main's device filter, the route's gate, and another organization."""

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import delete, select, update

from app.api import fleet_migration
from app.api.fleet_catalog import _not_held
from app.api.fleet_migration import _detail, read_migration
from app.core import fleet_assessment, fleet_catalog
from app.core.content_keys import app_full_key
from app.core.database import session_for_tenant, unscoped_session
from app.core.device_scope import scoped_devices
from app.core.feature_flags import FLEET_MAINTAINED_APPS_FLAG
from app.core.fleet_migration import local_changes
from app.core.hashing import compute_app_hash
from app.main import app
from app.models.schema import (
    AppCatalogEntry,
    Device,
    DeviceChange,
    FeatureFlag,
    FleetAppVersion,
    FleetCatalogState,
    InstalledApp,
    JamfPatchTitle,
    Tenant,
)
from app.schemas.patch_plans import DeviceScope
from tests.patch_plan_fixtures import accounts, admin, flag_off, flag_on, github, inventory, viewer  # noqa: F401
from tests.test_fleet_assessment import A, B, assessed
from tests.test_fleet_assessment_db import ALPHA_BETA, AS_OF, EPOCH, answer, behind, catalog_row, counts, install, statements
from tests.test_fleet_catalog_db import ALPHA, BETA, GAMMA
from tests.test_patching_policy_db import unstated  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="requires a disposable PostgreSQL database"),
    pytest.mark.asyncio(loop_scope="session"),
]

REPORT = "/api/fleet-catalog/migration"
UNMATCHED, NO_ID = compute_app_hash("Unmatched", "org.internal"), compute_app_hash("No ID", "No ID")
INVALID = "The device filter is invalid. Check each condition or clear the filter and try again."
NOT_LISTED = (
    "Fleet's version history, as this instance holds it, does not list never-listed for Alpha. Choose Fleet's latest "
    "version (2.0) or a version the title's history lists; Read history reads that history again."
)


def _filter(source, *within_30):
    rules = [{"field": field, "operator": "within", "value": "30"} for field in within_30]
    return {"deviceScope": json.dumps({"connectionId": source, "rules": rules})}


async def _read(client, params=None, path=""):
    response = await client.get(REPORT + path, params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def test_read_is_flag_gated(admin, flag_off):  # noqa: F811
    report = await _read(admin)
    assert not report["enabled"] and not report["items"] and not report["fleetDeviceCounts"] and not any(report["scope"].values())
    assert report["installedEvidence"] == report["appAssessments"] == {}
    with statements() as seen:
        for path in (f"/apps/{'0' * 32}", "/titles/alpha"):  # The detail refuses at the flag, before any inventory is read.
            refused = await admin.get(REPORT + path)
            assert (refused.status_code, refused.json()["detail"]) == (409, fleet_catalog.FLAG_OFF)
    assert not [sql for sql, _ in seen if "device_changes" in sql]  # Nor the change log (#900).


def _answering(monkeypatch, as_of):
    async def earned(session):
        return SimpleNamespace(as_of=as_of)

    monkeypatch.setattr(fleet_migration, "earned_corpus", earned)
    monkeypatch.setattr(fleet_migration, "loaded_epoch_signature", lambda: EPOCH)


async def test_installed_evidence_repeats_each_apps_stored_answers(db, inventory, viewer, flag_on, monkeypatch):  # noqa: F811
    source, alpha, _ = inventory
    await answer(db, alpha, {"1.0": counts(3, high=3), "2.0": counts(9, kev=1), "unread": counts(0)})
    with statements() as seen:
        _answering(monkeypatch, None)  # No corpus, or data sharing off.
        off = await _read(viewer, _filter(source))
        _answering(monkeypatch, AS_OF)
        report = await _read(viewer, _filter(source))
    nobody_looked = dict.fromkeys(("affectedBuilds", "highOrCriticalBuilds", "kevBuilds"))
    assert off["installedEvidence"] == {
        item["appHash"]: {"assessment": "off", "asOf": None, "assessedBuilds": 0, "unknownBuilds": item["versionCount"]}
        | nobody_looked
        for item in off["items"]
    }
    evidence = report["installedEvidence"]
    assert set(evidence) == {item["appHash"] for item in report["items"]}
    assert evidence[alpha] == {"assessment": "covered", "asOf": "2026-11-24", "assessedBuilds": 3, "unknownBuilds": 0} | {
        "affectedBuilds": 2,
        "highOrCriticalBuilds": 1,
        "kevBuilds": 1,
    }
    assert not [sql for sql, _ in seen if "vuln_corpus_release_rows" in sql or "vuln_library_rows" in sql]


async def test_population_and_identity_share_a_cohort(db, github, inventory, viewer, flag_on):  # noqa: F811
    source, alpha, gamma = inventory
    report = await _read(viewer, _filter(source, "contact"))
    assert report["scope"] == {"eligibleMacs": 3, "selectedMacs": 1, "unknownContactMacs": 1, "unknownInventoryMacs": 1}
    rows = {item["appHash"]: item for item in report["items"]}
    assert (rows[alpha]["macs"], rows[alpha]["versionCount"], rows[alpha]["match"]) == (1, 2, "exact")
    assert rows[gamma]["match"] == "ambiguous" and [c["slug"] for c in rows[gamma]["fleetCandidates"]] == ["gamma", "gamma@6+"]
    assert rows[UNMATCHED]["match"] == "none" and rows[NO_ID]["match"] == "unknown"
    assert report["fleetDeviceCounts"]["alpha"] == 1  # Alpha and Alpha Beta share its bundle identifier on that Mac.
    assessed = report["appAssessments"]
    assert set(assessed) == {alpha, ALPHA_BETA}  # The two `exact` items, and no per-build rows on the list.
    assert [assessed[alpha][key] for key in ("targetVersion", "behindBuilds", "builds")] == ["2.0", 1, []]
    # The detail (#899) counts the same Macs, each once: older when any copy is older, unknown when one cannot be ordered.
    detail = await _read(viewer, _filter(source, "contact") | {"targetVersion": "1.5"}, f"/apps/{alpha}")
    assert detail["scope"] == report["scope"] and detail["installedMacs"] == 1 and detail["impactUnavailable"] is None
    assert [b["version"] for b in detail["builds"]] == ["1.0", "2.0"] and list(detail["installedEvidence"]) == [alpha]
    assert detail["impact"] == {"targetVersion": "1.5", "installedMacs": 1, "olderMacs": 1, "atOrAboveMacs": 0, "unknownMacs": 0}
    assert detail["observedChanges"]["versionChanges"] == 1  # Mac 1 carries the fixture's one change row (#900).
    later = await _read(viewer, _filter(source, "inventory") | {"targetVersion": "1.5"}, f"/apps/{alpha}")
    assert (later["impact"]["installedMacs"], later["impact"]["olderMacs"], later["observedChanges"]["macs"]) == (1, 0, 0)
    whole = await _read(viewer, _filter(source), f"/apps/{alpha}")  # No target named: Fleet's latest, 2.0.
    assert whole["impact"] == {"targetVersion": "2.0", "installedMacs": 3, "olderMacs": 1, "atOrAboveMacs": 1, "unknownMacs": 1}
    assert (await _read(viewer, _filter(source), f"/apps/{UNMATCHED}"))["impactUnavailable"] == "no_fleet_title"
    unlisted = await viewer.get(f"{REPORT}/apps/{alpha}", params=_filter(source) | {"targetVersion": "never-listed"})
    assert (unlisted.status_code, unlisted.json()["detail"]) == (422, NOT_LISTED)
    db.add(FleetAppVersion(slug="beta", version="3.3", seen_at=datetime.now(UTC), commit_sha="b" * 40))
    await db.commit()  # A version Beta's history lists is still not one of Alpha's.
    elsewhere = await viewer.get(f"{REPORT}/apps/{alpha}", params=_filter(source) | {"targetVersion": "3.3"})
    assert elsewhere.status_code == 422
    for path, params in ((f"/apps/{'f' * 32}", _filter(source)), (f"/apps/{gamma}", _filter(source, "inventory"))):
        missing = await viewer.get(REPORT + path, params=params)  # No such app; Gamma's one Mac is left out.
        assert (missing.status_code, missing.json()["detail"]) == (404, fleet_migration._NOT_IN_SCOPE)
    unheld = await viewer.get(f"{REPORT}/titles/never-held")
    assert (unheld.status_code, unheld.json()["detail"]) == (404, _not_held("never-held").detail)
    # No conditions: the departed Mac, the other connection's Mac and the iPad still count nowhere.
    every = await _read(viewer, _filter(source))
    rows = {item["appHash"]: item for item in every["items"]}
    assert every["scope"]["selectedMacs"] == 3 and (rows[alpha]["macs"], rows[alpha]["versionCount"]) == (3, 3)
    assert every["fleetDeviceCounts"]["alpha"] == 3
    mac = await db.scalar(select(Device).where(Device.mdm_connection_id == source, Device.external_id == "3"))
    mac.last_inventory_at = datetime.now(UTC) + timedelta(days=1)
    db.add_all([install(mac, "Alpha", ALPHA, "1.0") for _ in range(2)])  # Two copies beside the unread one, now not unknown.
    await db.commit()
    future = (await _read(viewer, _filter(source, "inventory")))["scope"]
    assert (future["selectedMacs"], future["unknownInventoryMacs"]) == (1, 1)  # A future date is unknown, not selected.
    spread = await _read(viewer, _filter(source), f"/apps/{alpha}")
    impact, macs = spread["impact"], {build["version"]: build["macs"] for build in spread["builds"]}
    assert (impact["olderMacs"], impact["atOrAboveMacs"], impact["unknownMacs"], macs["1.0"]) == (2, 1, 0, 2)  # Macs 1 and 3.
    github.put("alpha", "Alpha", ALPHA, "2.0-b")  # A qualified latest is answered, each Mac it cannot order unknown.
    await fleet_catalog.check(db, transport=github.transport)
    qualified = (await _read(viewer, _filter(source), f"/apps/{alpha}"))["impact"]
    assert (qualified["targetVersion"], qualified["olderMacs"], qualified["unknownMacs"]) == ("2.0-b", 0, 3)
    github.put("alpha", "Alpha", ALPHA, "latest")  # One with no number in it is not.
    await fleet_catalog.check(db, transport=github.transport)
    word = await _read(viewer, _filter(source), f"/apps/{alpha}")
    assert (word["impact"], word["impactUnavailable"]) == (None, "unordered_target")
    await db.execute(update(InstalledApp).where(InstalledApp.app_hash == alpha).values(jamf_title_ids=["absent-1", "absent-2"]))
    await db.commit()
    claimed = {item["appHash"]: item for item in (await _read(viewer, _filter(source)))["items"]}[alpha]
    assert (claimed["match"], claimed["hasJamfMatch"]) == ("ambiguous", False)  # Two claimed titles, though neither is cached.
    uncached = await _read(viewer, _filter(source), f"/apps/{alpha}")  # Answered: only cached ids are looked up by name.
    assert (uncached["jamfTitles"], uncached["impactUnavailable"]) == ([], "identity_review")
    await db.execute(update(InstalledApp).where(InstalledApp.app_hash == ALPHA_BETA).values(ea_assumed=True))
    await db.commit()
    assumed = {item["appHash"]: item for item in (await _read(viewer, _filter(source)))["items"]}[ALPHA_BETA]
    assert (assumed["match"], len(assumed["fleetCandidates"])) == ("ambiguous", 1)  # One Fleet title, but an EA-assumed build.


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
    source, now = DeviceScope(connection_id=inventory[0]), datetime.now(UTC)
    own = await read_migration(source, db)  # The same read, from its own organization.
    assert own.scope.eligible_macs == 3 and own.items and set(own.installed_evidence) == {item.app_hash for item in own.items}
    assert own.app_assessments
    alpha = [item for item in own.items if item.app_hash == inventory[1]]
    assert (await local_changes(db, scoped_devices(source, now), alpha, now, "alpha")).version_changes == 1
    tenant_id = uuid.uuid4()
    async with unscoped_session() as global_db:
        global_db.add(Tenant(id=tenant_id, slug=f"migration-{tenant_id.hex}", name="Migration fixture", kind="operational"))
        await global_db.commit()
    try:
        async with session_for_tenant(tenant_id) as other_db:
            other_db.add(FeatureFlag(key=FLEET_MAINTAINED_APPS_FLAG, enabled=True))
            await other_db.commit()
            report = await read_migration(source, other_db)
            with pytest.raises(HTTPException) as refused:  # This organization's app, asked for by the other.
                await _detail(other_db, source, inventory[1], None, None, include_ids=True)
            observed = await local_changes(other_db, scoped_devices(source, now), alpha, now, "alpha")  # Its rows, here.
            await other_db.execute(delete(FeatureFlag))
            await other_db.commit()
    finally:
        async with unscoped_session() as global_db:
            await global_db.execute(delete(Tenant).where(Tenant.id == tenant_id))
            await global_db.commit()
    assert report.enabled and report.scope.eligible_macs == 0 and not report.items
    assert report.fleet_device_counts["alpha"] == 0 and report.installed_evidence == report.app_assessments == {}
    assert (refused.value.status_code, refused.value.detail) == (404, fleet_migration._NOT_IN_SCOPE)
    assert (observed.version_changes, observed.macs, observed.adoption_samples) == (0, 0, 0)  # devices and device_changes RLS


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
    assert report["appAssessments"] == {}
    for path in (f"/apps/{alpha}", "/titles/alpha", "/titles/beta"):
        detail = await _read(viewer, _filter(source), path)
        assert (detail["fleetCatalogReadiness"], detail["impact"]) == ("partial", None)
        assert detail["observedChanges"]["adoptionSamples"] is None  # Timing needs a complete snapshot (#900).
        assert detail["impactUnavailable"] == "catalog_incomplete" and detail["assessments"] == detail["appAssessments"] == {}


async def test_title_with_no_installs_or_ambiguous_local_identity(db, inventory, viewer, flag_on):  # noqa: F811
    source, _, gamma = inventory
    mac = await db.scalar(select(Device).where(Device.mdm_connection_id == source, Device.external_id == "3"))
    db.add(install(mac, BETA, BETA, "1"))  # Named for Beta's bundle ID, which is how inventory stores an app with none.
    await db.commit()
    empty = await _read(viewer, _filter(source), "/titles/beta")
    assert empty["title"]["bundleId"] == BETA and empty["installedMacs"] == 0 and empty["items"] == []
    measured = {"windowDays": 90, "versionChanges": 0, "macs": 0, "lastAt": None}  # Measured, and nothing found (#900).
    assert empty["observedChanges"] == measured | {"adoptionSamples": 0, "medianDaysAfterFleetPublication": None}
    ambiguous = await _read(viewer, _filter(source) | {"targetVersion": "6"}, "/titles/gamma%406%2B")
    assert ambiguous["installedMacs"] == 1 and ambiguous["impact"] is None and ambiguous["item"] is None
    assert ambiguous["assessments"] == ambiguous["appAssessments"] == {}
    local = await _read(viewer, _filter(source), f"/apps/{gamma}")
    assert local["item"]["match"] == "ambiguous" and local["appAssessments"] == {}
    assert ambiguous["impactUnavailable"] == local["impactUnavailable"] == "identity_review"


async def test_finding_ids_require_vulnerability_read_on_both_detail_routes(db, inventory, admin, flag_on, unstated, monkeypatch):  # noqa: F811
    source, alpha, _ = inventory
    _answering(monkeypatch, AS_OF)  # `_evidence`'s one corpus read, with EPOCH answering.
    target = app_full_key("Alpha", ALPHA, "1.5", None)  # In the title's history and on no Mac, so only it asks the library.

    async def library(session, keys, signature):
        return {target: assessed([B])} if signature == EPOCH and target in keys else {}

    monkeypatch.setattr(fleet_assessment, "_answers", library)
    entry, title_id = catalog_row("Alpha", ALPHA, "1.0", [A], EPOCH), uuid.uuid4().hex  # Alpha 1.0's served stored answer.
    db.add(entry)
    await behind(db, entry, title_id, days=30)  # Its one Jamf Patch title, a newer release out 30 days.
    (await db.get(JamfPatchTitle, title_id)).name = "Alpha Patch"  # `jamfTitles` names it, not its id.
    await db.execute(update(InstalledApp).where(InstalledApp.app_hash == alpha).values(jamf_title_ids=[title_id]))
    await db.commit()
    try:
        override = await admin.put(f"/api/settings/patching-policy/overrides/{title_id}", json={"maxDaysBehind": 14})
        assert override.status_code == 200, override.text  # A confirmed rule, where Rules() reads `no_rule` (#898's verifier).
        assert (await _read(admin, _filter(source)))["appAssessments"][alpha]["outOfPolicyBuilds"] == 1
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://policy.example.com") as client:
            for vuln, ids in (([], (None, None, None)), (["vuln:read"], ([A], [B], []))):
                scopes = ["app:read", "device:read", *vuln]
                minted = await admin.post("/api/auth/tokens", json={"name": "fleet detail", "scopes": scopes, "expiresInDays": 1})
                client.headers["Authorization"] = f"Bearer {minted.json()['token']}"
                for path, field, key in ((f"/apps/{alpha}", "appAssessments", alpha), ("/titles/alpha", "assessments", "alpha")):
                    detail = await _read(client, _filter(source) | {"targetVersion": "1.5"}, path)
                    row = next(r for r in detail[field][key]["builds"] if (r["name"], r["version"]) == ("Alpha", "1.0"))
                    assert (row["addresses"], row["introduces"], row["remains"], row["policyState"]) == (1, 1, 0, "out")
                    assert (row["addressedIds"], row["introducedIds"], row["remainingIds"]) == ids
                    assert detail["jamfTitles"] == [{"id": title_id, "name": "Alpha Patch"}]
    finally:
        await db.rollback()
        await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id == title_id))  # Its match goes with it.
        await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.app_hash == alpha))
        await db.commit()


async def test_adoption_lag_dates_each_first_observed_upgrade_once_per_mac_and_version(db, inventory, viewer, flag_on):  # noqa: F811
    source, alpha, gamma = inventory
    now = datetime.now(UTC)
    row = {"mdm_connection_id": source, "subject_kind": "computer", "section": "applications", "change": "updated"}
    row |= {"collected_at": now, "trigger": "sweep", "level": "normal", "policy_version": "1"}

    def change(mac, previous, version, days, *, name="Alpha", bundle=ALPHA, short=None):
        new = {"version": version} | ({"cfBundleShortVersionString": short} if short else {})
        moved = {"old_value": {"version": previous}, "new_value": new, "observed_at": now - timedelta(days=days)}
        return DeviceChange(**row, subject_id=mac, entry_identity={"name": name, "bundleId": bundle}, **moved)

    dates = [("alpha", "2.1", 10), ("alpha", "3.0", 10), ("alpha", "3.1", 5), ("alpha", "4.0", 10), ("alpha", "9.0", 120)]
    for slug, version, days in [*dates, ("alpha", "9.1", -1), ("gamma", "5.1", 10)]:
        db.add(FleetAppVersion(slug=slug, version=version, seen_at=now - timedelta(days=days), commit_sha="c" * 40))
    db.add_all(
        [
            change("1", "1", "2.1", 7),
            change("1", "2.0", "2.1", 4),  # Its first upgrade to 2.1 counts: 3 days after Fleet's date.
            change("1", "2.1", "3.0", 8),  # 2 days.
            change("2", "1", "2.1", 4),  # 6 days.
            change("2", "5.0", "3.0", 100),  # A rollback before the window does not drop the upgrade after it...
            change("2", "2.1", "3.0", 5),  # ...5 days.
            change("1", "5.0", "4.0", 2),
            change("1", "2", "4.0", 1, short="4.1"),
            change("1", "v2-beta", "4.0", 1),
            change("1", "3", "4.0", -1),
            change("1", "3", "9.1", 1),
            change("1", "2", "3.1", 6),
            change("1", "3.0", "3.1", 4),  # First recorded before Fleet's date.
            change("1", "1", "9.0", 99),
            change("1", "3", "9.0", 1),  # First recorded before the window.
            change("1", "3", "4.0", 1, name="Different app"),
            change("4", "3", "4.0", 1),  # A departed Mac.
            change("1", "5.0", "5.1", 2, name="Gamma", bundle=GAMMA),  # Two Fleet titles share its bundle ID.
            change("1", "1", "2", 3, name="No ID", bundle=None),  # Inventory stores it under its name.
        ]
    )
    await db.commit()

    async def observed(path, *within_30):
        return (await _read(viewer, _filter(source, *within_30), path))["observedChanges"]

    with statements() as seen:
        for path in (f"/apps/{alpha}", "/titles/alpha"):
            timed = await observed(path)
            assert (timed["adoptionSamples"], timed["medianDaysAfterFleetPublication"]) == (4, 4.0)
        timed = await observed(f"/apps/{alpha}", "contact")  # Mac 2 last checked in 90 days ago.
        assert (timed["adoptionSamples"], timed["medianDaysAfterFleetPublication"]) == (2, 2.5)
    reads = [sql for sql, _ in seen if "FROM device_changes" in sql]  # Each bounded by the window, or to the paired Macs.
    assert reads and all("device_changes.observed_at >=" in sql or "device_changes.subject_id = ANY" in sql for sql in reads)
    for path in (f"/apps/{gamma}", "/titles/gamma", f"/apps/{NO_ID}"):  # Not timed: Gamma's two Fleet titles; no bundle ID.
        got = await observed(path)
        assert (got["versionChanges"], got["adoptionSamples"], got["medianDaysAfterFleetPublication"]) == (1, None, None)
