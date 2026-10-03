"""The patching rules through the running routes: confirmed by `system:write` alone, a
title's own rule replacing the organization's, and — the part with two implementations —
the list's out-of-policy device count agreeing with the title page's per-version verdicts.

`policy.judge` is Python and `jamf_patch.out_of_policy` is SQL; they are one predicate, and
this is where they are held together, on a real matched fleet. Gated on RUN_DB_TESTS.
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.models.schema import AppCatalogEntry, Device, InstalledApp, JamfPatchTitle, MdmConnection, PatchingPolicy
from tests.test_patching_policy_db import ADMIN, accounts, admin, viewer  # noqa: F401
from tests.test_vuln_answer_db import _device, _pointer, _set_tier, acting_tenant  # noqa: F401
from tests.test_vuln_library import _rewritten, _row
from tests.test_vuln_library_db import _serving

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

TITLE_ID = "LOONPOLICY"
NAME, BUNDLE_ID = "LoonVD Fixture Policy.app", "io.loonsec.fixture.policy"
RULE, OVERRIDE = "/api/settings/patching-policy/rule", f"/api/settings/patching-policy/overrides/{TITLE_ID}"


def _released(days_ago: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest_asyncio.fixture(loop_scope="session")
async def fleet(db):
    """One title with three listed releases — 3.0 thirty days ago, 2.0 a hundred, 1.0 older —
    and four Macs: on the latest, one release back, two back, and ahead of the catalog."""
    from app.catalog.service import record_device_apps
    from app.mdm.patch.matching import reset_catalog_cache

    await db.execute(delete(PatchingPolicy))
    bundle_test = {"name": "Application Bundle ID", "operator": "is", "type": "recon", "value": BUNDLE_ID}
    await db.merge(
        JamfPatchTitle(
            id=TITLE_ID,
            name="LoonVD Fixture Policy",
            app_name=NAME,
            bundle_id=BUNDLE_ID,
            current_version="3.0",
            last_modified=_released(30),
            patches=[
                {"version": "3.0", "releaseDate": _released(30)},
                {"version": "2.0", "releaseDate": _released(100)},
                {"version": "1.0", "releaseDate": _released(400)},
            ],
            requirements=[{"operator": "and", "tests": [bundle_test]}],
            extension_attributes=[],
        )
    )
    connection = MdmConnection(
        name=f"patch policy {uuidlib.uuid4().hex[:8]}",
        provider="jamf",
        base_url="https://jamf.example.com",
        credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
    )
    db.add(connection)
    await db.commit()
    connection_id = connection.id
    reset_catalog_cache()
    for serial, version in (("C02POL0001", "3.0"), ("C02POL0002", "2.0"), ("C02POL0003", "1.0"), ("C02POL0004", "9.9")):
        device = await _device(db, connection, serial, ((NAME, BUNDLE_ID, version),))
        await record_device_apps(db, device, now=datetime.now(UTC))
    await db.commit()
    try:
        yield
    finally:
        await db.rollback()
        device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
        hashes = select(InstalledApp.version_hash).where(InstalledApp.device_id.in_(device_ids))
        await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_(hashes)))
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
        await db.execute(delete(MdmConnection).where(MdmConnection.id == connection_id))
        await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id == TITLE_ID))
        await db.execute(delete(PatchingPolicy))
        await db.commit()
        reset_catalog_cache()


async def _listed(client) -> dict:
    response = await client.get(f"/api/jamf-patch/titles?q={BUNDLE_ID}&pageSize=10")
    assert response.status_code == 200, response.text
    return next(item for item in response.json()["items"] if item["id"] == TITLE_ID)


async def _detail(client) -> dict:
    response = await client.get(f"/api/jamf-patch/titles/{TITLE_ID}")
    assert response.status_code == 200, response.text
    return response.json()


def _out_devices(detail: dict) -> int:
    """The title page's own arithmetic: devices on a version whose verdict is `out`."""
    versions = detail["policy"]["versions"]
    return sum(count for version, count in detail["versionDeviceCounts"].items() if versions[version]["state"] == "out")


async def test_nothing_is_judged_until_a_rule_is_confirmed(admin, fleet) -> None:  # noqa: F811
    listed, detail = await _listed(admin), await _detail(admin)
    assert listed["deviceCount"] == 4
    # Null, never zero: nobody has said what out of policy means.
    assert listed["devicesOutOfPolicy"] is None and listed["policySource"] is None
    assert detail["policy"] is None


async def test_only_system_write_confirms_a_rule_and_it_is_read_back_with_its_author(admin, viewer, fleet) -> None:  # noqa: F811
    assert (await viewer.put(RULE, json={"maxDaysBehind": 14})).status_code == 403
    assert (await viewer.put(OVERRIDE, json={"exempt": True})).status_code == 403
    assert (await viewer.delete(OVERRIDE)).status_code == 403

    confirmed = await admin.put(RULE, json={"maxDaysBehind": 60})
    assert confirmed.status_code == 200, confirmed.text
    rules = confirmed.json()["rules"]
    assert rules["default"] == {"maxDaysBehind": 60, "maxReleasesBehind": None, "maxDaysBehindSevere": None}
    assert rules["updatedBy"] == ADMIN[0] and rules["updatedAt"] is not None
    # The statement's own author is not the rule's: nothing was stated.
    assert confirmed.json()["updatedBy"] is None

    read = await viewer.get("/api/settings/patching-policy")
    assert read.status_code == 200 and read.json()["rules"]["default"]["maxDaysBehind"] == 60

    # Restating the sentence leaves the rule where it was.
    restated = await admin.put("/api/settings/patching-policy", json={"statement": "Within sixty days."})
    assert restated.json()["rules"]["default"]["maxDaysBehind"] == 60

    # Cleared by sending no limit at all, and then nothing judges again.
    cleared = await admin.put(RULE, json={})
    assert cleared.status_code == 200 and cleared.json()["rules"]["default"] is None
    assert (await _listed(admin))["devicesOutOfPolicy"] is None


@pytest.mark.parametrize(
    ("rule", "out_versions", "reason"),
    [
        # 2.0's first newer release is 30 days old and 1.0's is 100: only 1.0 is past 60.
        ({"maxDaysBehind": 60}, {"1.0"}, "days"),
        ({"maxDaysBehind": 14}, {"1.0", "2.0"}, "days"),
        ({"maxReleasesBehind": 1}, {"1.0"}, "releases"),
        ({"maxReleasesBehind": 0}, {"1.0", "2.0"}, "releases"),
        ({"maxDaysBehind": 365, "maxReleasesBehind": 5}, set(), None),
    ],
)
async def test_the_lists_count_and_the_title_pages_verdicts_are_one_predicate(admin, fleet, rule, out_versions, reason) -> None:  # noqa: F811
    assert (await admin.put(RULE, json=rule)).status_code == 200
    listed, detail = await _listed(admin), await _detail(admin)
    versions = detail["policy"]["versions"]

    assert {version for version, verdict in versions.items() if verdict["state"] == "out"} == out_versions
    assert all(versions[version]["reason"] == reason for version in out_versions)
    # On the latest, and ahead of the catalog, are within — never out, never unjudged.
    assert versions["3.0"]["state"] == versions["9.9"]["state"] == "within"
    assert detail["policy"]["source"] == listed["policySource"] == "default"
    # SQL and Python, one answer.
    assert listed["devicesOutOfPolicy"] == detail["devicesOutOfPolicy"] == _out_devices(detail) == len(out_versions)


async def test_a_titles_own_rule_replaces_the_organizations_and_exempt_is_null_not_zero(admin, fleet) -> None:  # noqa: F811
    assert (await admin.put(RULE, json={"maxDaysBehind": 14})).status_code == 200
    assert (await _listed(admin))["devicesOutOfPolicy"] == 2

    own = await admin.put(OVERRIDE, json={"maxDaysBehind": 60})
    assert own.status_code == 200, own.text
    assert own.json()["rules"]["overrides"] == [
        {
            "titleId": TITLE_ID,
            "titleName": "LoonVD Fixture Policy",
            "maxDaysBehind": 60,
            "maxReleasesBehind": None,
            "maxDaysBehindSevere": None,
            "exempt": False,
        }
    ]
    listed, detail = await _listed(admin), await _detail(admin)
    assert (listed["devicesOutOfPolicy"], listed["policySource"]) == (1, "override")
    assert detail["policy"]["source"] == "override" and detail["policy"]["maxDaysBehind"] == 60

    assert (await admin.put(OVERRIDE, json={"exempt": True})).status_code == 200
    listed, detail = await _listed(admin), await _detail(admin)
    assert (listed["devicesOutOfPolicy"], listed["policySource"]) == (None, "exempt")
    assert detail["policy"]["exempt"] is True and detail["policy"]["versions"] == {}

    # The override judges on its own, with no organization rule behind it.
    assert (await admin.put(OVERRIDE, json={"maxReleasesBehind": 0})).status_code == 200
    assert (await admin.put(RULE, json={})).status_code == 200
    assert (await _listed(admin))["devicesOutOfPolicy"] == 2

    removed = await admin.delete(OVERRIDE)
    assert removed.status_code == 200 and removed.json()["rules"]["overrides"] == []
    assert (await _listed(admin))["devicesOutOfPolicy"] is None
    # Removing it again answers the same policy rather than failing.
    assert (await admin.delete(OVERRIDE)).status_code == 200


async def test_an_override_that_could_judge_nothing_is_refused_in_words(admin, fleet) -> None:  # noqa: F811
    missing = await admin.put("/api/settings/patching-policy/overrides/NO-SUCH-TITLE", json={"exempt": True})
    assert missing.status_code == 404
    assert "No Jamf Patch title has the id NO-SUCH-TITLE" in missing.json()["detail"]
    assert (await admin.put(OVERRIDE, json={"exempt": True, "maxDaysBehind": 3})).status_code == 422
    assert (await admin.put(OVERRIDE, json={})).status_code == 422
    assert (await admin.put(RULE, json={"maxDaysBehind": -1})).status_code == 422


# --- the severe limit: the corpus's answer for the build decides which days apply ----------


@pytest_asyncio.fixture(loop_scope="session")
async def assessed(db, fleet, acting_tenant):  # noqa: F811
    """The fleet, judged by an epoch that holds 2.0 with a high finding and 1.0 with only a
    medium one, and nothing for 3.0 or 9.9. Torn down to where every container starts:
    nothing loaded, tier off."""
    from app.catalog.service import rejudge_epoch
    from app.core.content_keys import app_full_key
    from app.core.vuln import forget_tenant_tiers
    from app.core.vuln_library import load_epoch_if_new, refresh_from_db
    from app.models.schema import VulnLibraryEpoch, VulnLibraryRow, VulnLibraryTitle

    medium = {"total": 1, "kev": 0, "critical": 0, "high": 0, "medium": 1, "low": 0}
    dated = {"total": "2026-01-01T00:00:00Z", "critical": None, "high": None, "medium": "2026-01-01T00:00:00Z", "low": None}
    bundle, signature = _rewritten(
        rows=[
            _row(key_full=app_full_key(NAME, BUNDLE_ID, "2.0", None)),  # the default row: one high finding
            _row(key_full=app_full_key(NAME, BUNDLE_ID, "1.0", None), counts=medium, oldest_published=dated),
        ]
    )
    await _set_tier(db, "keys")
    assert await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle)) is not None
    await rejudge_epoch(db)
    await db.commit()
    try:
        yield
    finally:
        await db.rollback()
        for model in (VulnLibraryRow, VulnLibraryTitle, VulnLibraryEpoch):
            await db.execute(delete(model))
        await db.commit()
        await refresh_from_db(db)
        await _set_tier(db, "off")
        forget_tenant_tiers()


async def test_a_build_with_a_high_finding_takes_the_severe_limit_in_the_count_and_the_verdict(
    admin,  # noqa: F811
    db,
    assessed,
) -> None:
    # 2.0 is 30 days behind and severe; 1.0 is 100 days behind and only medium.
    assert (await admin.put(RULE, json={"maxDaysBehind": 200, "maxDaysBehindSevere": 14})).status_code == 200
    detail = await _detail(admin)
    listed = await _listed(admin)
    versions = detail["policy"]["versions"]

    assert (versions["2.0"]["state"], versions["2.0"]["limitDays"], versions["2.0"]["severe"]) == ("out", 14, True)
    assert (versions["1.0"]["state"], versions["1.0"]["limitDays"], versions["1.0"]["severe"]) == ("within", 200, False)
    # 3.0 has no row in the epoch: on the latest, so within, and its severity is not known.
    assert (versions["3.0"]["state"], versions["3.0"]["severe"]) == ("within", None)
    assert detail["policy"]["maxDaysBehindSevere"] == 14 and detail["policy"]["severityAnswering"] is True
    # SQL and Python, one answer — now with the corpus in it.
    assert listed["devicesOutOfPolicy"] == detail["devicesOutOfPolicy"] == _out_devices(detail) == 1

    # The severe limit alone: nothing judges a build that is not severe.
    assert (await admin.put(RULE, json={"maxDaysBehindSevere": 14})).status_code == 200
    detail = await _detail(admin)
    assert detail["policy"]["versions"]["1.0"]["state"] == "within"
    assert detail["devicesOutOfPolicy"] == _out_devices(detail) == 1

    # Longer than the ordinary limit is refused in words.
    looser = await admin.put(RULE, json={"maxDaysBehind": 14, "maxDaysBehindSevere": 60})
    assert looser.status_code == 422 and "shorter of the two" in looser.text


async def test_with_nothing_answering_the_severe_limit_judges_nothing_and_the_response_says_so(
    admin,  # noqa: F811
    db,
    assessed,
) -> None:
    assert (await admin.put(RULE, json={"maxDaysBehind": 200, "maxDaysBehindSevere": 14})).status_code == 200
    await _set_tier(db, "off")
    try:
        detail = await _detail(admin)
        page = await admin.get(f"/api/jamf-patch/titles?q={BUNDLE_ID}&pageSize=10")
        # Every build is judged by the ordinary limit; none is called severe, none is called clean.
        assert detail["policy"]["severityAnswering"] is False and page.json()["severityAnswering"] is False
        two = detail["policy"]["versions"]["2.0"]
        assert (two["state"], two["severe"]) == ("within", None)
        assert detail["devicesOutOfPolicy"] == _out_devices(detail) == 0
    finally:
        await _set_tier(db, "keys")

    # And a rule that reads no severity says nothing about the corpus at all.
    assert (await admin.put(RULE, json={"maxDaysBehind": 200})).status_code == 200
    page = await admin.get(f"/api/jamf-patch/titles?q={BUNDLE_ID}&pageSize=10")
    assert page.json()["severityAnswering"] is None and (await _detail(admin))["policy"]["severityAnswering"] is None
