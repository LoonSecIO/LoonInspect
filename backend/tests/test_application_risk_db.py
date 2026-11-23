"""Risk scope uses current assessed builds and the same tenant/device population as the list."""

import json
from datetime import date
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.models.schema import InstalledApp
from tests.patch_plan_fixtures import accounts, admin, flag_off, github, inventory  # noqa: F401
from tests.test_application_patch_plans_db import pytestmark as pytestmark


@pytest.fixture
def corpus(monkeypatch):
    from app.api import applications

    async def earned(db):
        return SimpleNamespace(as_of=date(2026, 11, 23))

    monkeypatch.setattr(applications, "earned_corpus", earned)
    monkeypatch.setattr(applications, "loaded_epoch_signature", lambda: "risk-epoch")


def counts(total, *, high=0, low=0, kev=0):
    return {"total": total, "critical": 0, "high": high, "medium": 0, "low": low, "kev": kev}


async def seed_answers(db, app_hash):
    rows = (await db.scalars(select(InstalledApp).where(InstalledApp.app_hash == app_hash))).all()
    for row in rows:
        if row.version in {"1.0", "2.0"}:
            row.vuln_assessment = "covered"
            row.vuln_signature = "risk-epoch"
            row.vuln_counts = counts(6, high=6, kev=1) if row.version == "1.0" else counts(2, low=2)
    await db.commit()
    return rows


async def test_scoped_totals_deduplicate_builds_and_keep_unknown_devices_out_of_average(db, inventory, admin, corpus):  # noqa: F811
    source, app_hash, _ = inventory
    rows = await seed_answers(db, app_hash)
    first = next(row for row in rows if row.version == "1.0")
    duplicate = InstalledApp(
        **{column.name: getattr(first, column.name) for column in InstalledApp.__table__.columns if column.name != "id"}
    )
    db.add(duplicate)
    await db.commit()
    response = await admin.get("/api/applications", params={"q": "Alpha", "deviceScope": json.dumps({"connectionId": source})})
    assert response.status_code == 200, response.text
    body = response.json()
    app = next(row for row in body["items"] if row["appHash"] == app_hash)
    assert app["deviceCount"] == 3
    risk = app["vulnerabilities"]
    assert risk["assessment"] == "partial"
    assert risk["counts"] == counts(10, high=6, low=4, kev=1)
    assert risk["assessedDeviceCount"] == 2 and risk["devicesWithUnknownBuilds"] == 1
    assert risk["assessedBuildCount"] == 3 and risk["unknownBuildCount"] == 1
    assert risk["averagePerAssessedDevice"] == 5
    assert body["corpusRelease"] == "risk-epoch" and body["corpusAsOf"] == "2026-11-23"


async def test_risk_filters_before_pagination_and_compose_with_device_scope(db, inventory, admin, corpus):  # noqa: F811
    source, app_hash, _ = inventory
    await seed_answers(db, app_hash)
    scope = json.dumps({"connectionId": source, "rules": [{"field": "contact", "operator": "older", "value": "14"}]})
    params = {"deviceScope": scope, "severity": "low", "pageSize": 1}
    result = (await admin.get("/api/applications", params=params)).json()
    assert result["total"] == 1 and result["items"][0]["appHash"] == app_hash
    assert result["items"][0]["vulnerabilities"]["counts"]["total"] == 2
    result = (await admin.get("/api/applications", params={**params, "page": 2})).json()
    assert result["total"] == 1 and result["items"] == []
    result = (await admin.get("/api/applications", params={**params, "hasKev": True})).json()
    assert result["total"] == 0
    result = (
        await admin.get(
            "/api/applications",
            params=[
                ("severity", "critical"),
                ("severity", "high"),
                ("hasKev", "true"),
                ("deviceScope", json.dumps({"connectionId": source})),
            ],
        )
    ).json()
    assert result["total"] == 1 and result["items"][0]["appHash"] == app_hash


async def test_stale_and_malformed_answers_are_unknown(db, inventory, admin, corpus):  # noqa: F811
    source, app_hash, _ = inventory
    rows = await seed_answers(db, app_hash)
    for row in rows:
        if row.version == "1.0":
            row.vuln_signature = "old-epoch"
        else:
            row.vuln_counts = counts(2) | {"total": "invalid"}
    await db.commit()
    params = {"q": "Alpha", "deviceScope": json.dumps({"connectionId": source})}
    response = await admin.get("/api/applications", params=params)
    assert response.status_code == 200, response.text
    app = next(row for row in response.json()["items"] if row["appHash"] == app_hash)
    assert app["vulnerabilities"]["assessment"] == "unknown_app"
    assert app["vulnerabilities"]["counts"] is None and app["vulnerabilities"]["averagePerAssessedDevice"] is None
    assert (await admin.get("/api/applications", params=params | {"severity": "high"})).json()["total"] == 0


async def test_no_corpus_refuses_a_risk_filter_instead_of_claiming_empty(db, inventory, admin, monkeypatch):  # noqa: F811
    from app.api import applications

    async def off(db):
        return SimpleNamespace(as_of=None)

    monkeypatch.setattr(applications, "earned_corpus", off)
    _source, app_hash, _ = inventory
    await seed_answers(db, app_hash)
    response = await admin.get("/api/applications", params={"q": "Alpha"})
    assert response.status_code == 200
    assert all(
        row["vulnerabilities"]["assessment"] == "off"
        and row["vulnerabilities"]["counts"] is None
        and row["vulnerabilities"]["unknownBuildCount"] > 0
        for row in response.json()["items"]
    )
    for params in ({"hasKev": True}, {"severity": "low"}):
        response = await admin.get("/api/applications", params=params)
        assert response.status_code == 409 and "Drop the filter" in response.json()["detail"]


async def test_plan_holds_risk_scope_and_refuses_apps_outside_it(db, inventory, admin, corpus, flag_off, monkeypatch):  # noqa: F811
    import uuid

    from sqlalchemy import delete

    from app.api import applications
    from app.core import patch_plans
    from app.models.schema import ApplicationPatchPlan

    monkeypatch.setattr(patch_plans, "earned_corpus", applications.earned_corpus)
    monkeypatch.setattr(patch_plans, "loaded_epoch_signature", applications.loaded_epoch_signature)
    source, app_hash, gamma = inventory
    await seed_answers(db, app_hash)
    payload = {
        "scope": {"connectionId": source},
        "applicationScope": {"severities": ["high"], "hasKev": True},
        "appHashes": [app_hash],
    }
    response = await admin.post("/api/application-patch-plans", json=payload)
    assert response.status_code == 201, response.text
    plan = response.json()
    try:
        snap = plan["snapshot"]
        assert snap["applicationScope"]["hasKev"] is True
        assert snap["applications"][0]["vulnerabilities"]["averagePerAssessedDevice"] == 5
        assert snap["vulnerabilitySource"]["release"] == "risk-epoch"
        pdf = await admin.get(f"/api/application-patch-plans/{plan['id']}/pdf?revision=1")
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
        response = await admin.post("/api/application-patch-plans", json=payload | {"appHashes": [app_hash, gamma]})
        assert response.status_code == 409 and "application filters" in response.json()["detail"]
    finally:
        await db.execute(delete(ApplicationPatchPlan).where(ApplicationPatchPlan.id == uuid.UUID(plan["id"])))
        await db.commit()


async def test_nested_brackets_change_population_without_treating_unknown_as_negative(db, inventory):  # noqa: F811
    from app.core.device_scope import scoped_devices
    from app.models.schema import Device
    from app.schemas.patch_plans import DeviceScope

    source, _, _ = inventory
    devices = (
        await db.scalars(
            select(Device).where(Device.mdm_connection_id == source, Device.platform == "macos").order_by(Device.external_id)
        )
    ).all()
    devices[0].managed = False
    devices[1].managed = True
    devices[2].managed = True
    await db.commit()
    recent = {"field": "contact", "operator": "within", "value": "14"}
    old = {"field": "contact", "operator": "older", "value": "14"}
    managed = {"field": "managed", "value": "true"}

    async def matching(rules, match="all"):
        population = scoped_devices(DeviceScope.model_validate({"connectionId": source, "match": match, "rules": rules}))
        return set((await db.scalars(select(population.c.id))).all())

    assert await matching([managed, {"match": "any", "rules": [recent, old]}]) == {devices[1].id}
    assert await matching([recent, {"match": "all", "rules": [managed, old]}], "any") == {devices[0].id, devices[1].id}
