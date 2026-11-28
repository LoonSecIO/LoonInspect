"""EA, calendar and enrollment comparisons against real PostgreSQL inventory."""

import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text, update

from app.core.device_scope import scoped_devices
from app.core.device_scope_queries import guard_scope_queries, prepare_scope
from app.models.schema import Device, DeviceExtensionAttribute, SubjectDeparture
from app.schemas.patch_plans import DeviceScope
from tests.patch_plan_fixtures import accounts, admin, flag_off, github, inventory  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="requires disposable PostgreSQL"),
    pytest.mark.asyncio(loop_scope="session"),
]


async def matches(db, source, rules, *, mode="advanced_search", now=None):
    scope = DeviceScope(connectionId=source, rules=rules, mode=mode)
    await prepare_scope(db, scope)
    population = scoped_devices(scope, now)
    return set(await db.scalars(select(population.c.external_id)))


async def macs(db, source):
    return list(
        await db.scalars(
            select(Device).where(Device.mdm_connection_id == source, Device.platform == "macos").order_by(Device.external_id)
        )
    )


async def test_supervision_is_independent_and_smart_group_restricts_root(db, inventory):  # noqa: F811
    source, _, _ = inventory
    devices = await macs(db, source)
    for device, managed, supervised in zip(devices, [True, False, None, True], [False, True, None, True], strict=True):
        device.managed, device.supervised = managed, supervised
    await db.commit()
    assert await matches(db, source, [{"field": "supervised", "value": "true"}]) == {"2"}
    assert await matches(db, source, [{"field": "supervised", "value": "false"}]) == {"1"}
    assert await matches(db, source, [{"field": "supervised", "operator": "unknown"}]) == {"3"}
    assert await matches(db, source, [], mode="smart_group") == {"1"}
    # Root OR cannot bypass the managed-only restriction or include departed Macs.
    assert await matches(
        db,
        source,
        [{"match": "any", "rules": [{"field": "supervised", "value": "true"}, {"field": "supervised", "value": "false"}]}],
        mode="smart_group",
    ) == {"1"}


async def test_ea_substrings_regex_multivalue_and_unknowns(db, inventory):  # noqa: F811
    source, _, _ = inventory
    devices = await macs(db, source)
    for device, values in zip(devices, [["Pilot", "100%_ready"], ["Production", "Secondary"], [], ["Pilot"]], strict=True):
        db.add(DeviceExtensionAttribute(device_id=device.id, definition_id="19", name="Ring", values=values, source="general"))
    await db.commit()

    async def ea(operator, value, key="19"):
        return await matches(db, source, [{"field": "ea", "key": key, "operator": operator, "value": value}])

    assert await ea("like", "ILo") == {"1"}
    assert await ea("not_like", "pilot") == {"2"}
    assert await ea("like", "%_") == {"1"}
    assert await ea("like", "\\") == set()
    assert await ea("matches_regex", "^(pilot|secondary)$") == {"1", "2"}
    assert await ea("matches_regex", "^prod") == {"2"}
    assert await ea("does_not_match_regex", "^pilot$") == {"2"}
    assert await ea("does_not_match_regex", "^pilot$", key="missing") == set()
    assert await ea("unknown", "") == {"3"}
    assert await ea("is", "Pilot") == {"1"}


@pytest.mark.parametrize("field", ["contact", "inventory"])
async def test_calendar_boundaries_exclude_selected_day_and_unknowns(db, inventory, field):  # noqa: F811
    source, _, _ = inventory
    devices = await macs(db, source)
    column = "last_check_in" if field == "contact" else "last_inventory_at"
    day = datetime(2024, 2, 29, tzinfo=UTC)
    now = day + timedelta(days=10)
    await db.execute(
        update(SubjectDeparture).where(SubjectDeparture.mdm_connection_id == source).values(departed_at=day - timedelta(days=30))
    )

    async def on(operator, value="2024-02-29"):
        return await matches(db, source, [{"field": field, "operator": operator, "value": value}], now=now)

    for device, stamp in zip(devices[:3], [day - timedelta(microseconds=1), day, day + timedelta(days=1)], strict=True):
        setattr(device, column, stamp)
    await db.commit()
    assert await on("before") == {"1"}
    assert await on("after") == {"3"}
    setattr(devices[1], column, day + timedelta(days=1, microseconds=-1))
    await db.commit()
    assert await on("before") == {"1"} and await on("after") == {"3"}
    setattr(devices[0], column, None)
    setattr(devices[2], column, now + timedelta(days=1))
    await db.commit()
    assert await on("after") == set() and await on("before", "9999-12-31") == {"2"}
    assert await on("after", "9999-12-31") == set()
    assert await on("unknown", "") == {"1", "3"}


async def test_invalid_regex_fails_before_even_an_empty_inventory_query(admin, flag_off):  # noqa: F811
    scope = {
        "connectionId": 2147483647,
        "rules": [{"field": "ea", "key": "19", "operator": "does_not_match_regex", "value": "["}],
    }
    for route in ["/api/applications", "/api/catalog", "/api/application-patch-plans/scope-options"]:
        response = await admin.get(route, params={"deviceScope": json.dumps(scope)})
        assert response.status_code == 422, response.text
        assert "regular expression is invalid" in response.json()["detail"]
    response = await admin.post("/api/application-patch-plans", json={"scope": scope, "appHashes": ["a" * 32]})
    assert response.status_code == 422 and "regular expression is invalid" in response.json()["detail"]
    assert (await admin.get("/api/application-patch-plans/scope-options")).status_code == 200


async def test_regex_timeout_respects_stricter_limit_and_does_not_leak(db):
    await db.execute(text("SET LOCAL statement_timeout = '10ms'"))
    scope = DeviceScope(rules=[{"field": "ea", "key": "19", "operator": "matches_regex", "value": "^Pilot$"}])
    await prepare_scope(db, scope)
    assert await db.scalar(text("SHOW statement_timeout")) == "10ms"
    with pytest.raises(HTTPException, match="database time limit") as exc:
        async with guard_scope_queries(db):
            await db.execute(text("SELECT pg_sleep(0.1)"))
    assert exc.value.status_code == 408
    await db.rollback()
    assert await db.scalar(text("SHOW statement_timeout")) != "10ms"


async def test_device_list_intersects_nested_scope_with_flat_filters_and_pages(db, inventory, admin):  # noqa: F811
    source, _, _ = inventory
    devices = await macs(db, source)
    for device, site in zip(devices, ["North", "South", "East", "North"], strict=True):
        device.hostname = "shared-name"
        device.site = site
    await db.commit()
    scope = json.dumps(
        {
            "connectionId": source,
            "rules": [{"match": "any", "rules": [{"field": "site", "value": "North"}, {"field": "site", "value": "South"}]}],
        }
    )

    async def listed(**params):
        response = await admin.get("/api/devices", params={"scope": scope, **params})
        assert response.status_code == 200, response.text
        return response.json()

    expected = sorted([devices[0].id, devices[1].id])
    whole = await listed()
    assert [row["id"] for row in whole["items"]] == expected
    for number, identifier in enumerate(expected, start=1):
        page = await listed(page=number, pageSize=1)
        assert page["total"] == 2
        assert [row["id"] for row in page["items"]] == [identifier]
    assert (await listed(page=3, pageSize=1))["items"] == []
    flat = await listed(site="South", includeDeparted="true")
    assert flat["total"] == 1 and flat["items"][0]["id"] == devices[1].id


async def test_device_list_refuses_invalid_scope(admin):  # noqa: F811
    response = await admin.get("/api/devices", params={"scope": '{"rules":[{"field":"unsupported"}]}'})
    assert response.status_code == 422
    assert response.json()["detail"] == "The device filter is invalid. Check each condition or clear the filter and try again."
