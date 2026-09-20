# ruff: noqa: F811 — imported pytest fixtures are injected by name.
"""History source correlation, real ingestion, preferences and RLS on Postgres (#605)."""

import os
from datetime import timedelta

import pytest
from sqlalchemy import delete, func, select

from tests.test_device_observation_db import connection  # noqa: F401
from tests.test_tenant_switch_db import accounts, admin, second_tenant  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres"),
    pytest.mark.asyncio(loop_scope="session"),
]


async def ingest(db, connection, jamf):
    from app.mdm.collections import run_enabled_collections
    from app.models.schema import Device

    result = await run_enabled_collections(db, connection, trigger="sweep")
    assert result.ok
    return await db.scalar(select(Device).where(Device.mdm_connection_id == connection.id, Device.external_id == jamf.real["id"]))


async def test_live_ingest_timeline_preferences_and_source_receipts(admin, db, connection, jamf):
    from app.models.schema import DeviceHistoryPoint as Point
    from app.models.schema import DeviceHistoryPreference as Pref
    from app.models.schema import EventOutbox
    from app.observations.history_capture import retain_summary

    device = await ingest(db, connection, jamf)
    url = f"/api/devices/{device.id}/history"
    timeline = (await admin.get(url)).json()
    assert len(timeline["items"]) == 1
    key = timeline["items"][0]["id"]
    detail = (await admin.get(url + "/point", params={"point": key})).json()
    assert len(detail["values"]) == 6 and detail["baseline"]
    assert next(v for v in detail["values"] if v["key"] == "applications.count")["value"] == len(jamf.real["applications"])
    await ingest(db, connection, jamf)
    assert await db.scalar(select(func.count()).select_from(Point).where(Point.device_id == device.id)) == 1
    point = await db.scalar(select(Point).where(Point.device_id == device.id))
    await retain_summary(db, point.source_id + 1000000, "completed", "Wrong source")
    await db.refresh(point)
    assert point.summary is None
    await retain_summary(db, point.source_id, "completed", "A source-correlated summary.", "apple_fm")
    await db.commit()
    detail = (await admin.get(url + "/point", params={"point": key})).json()
    assert detail["summary"]["text"] == "A source-correlated summary."
    # Durable even when its delivery/summary queues are gone.
    await db.execute(delete(EventOutbox).where(EventOutbox.id == point.source_id))
    await db.commit()
    assert (await admin.get(url + "/point", params={"point": key})).json()["summary"]["text"] == "A source-correlated summary."
    try:
        saved = await admin.put(url + "/preferences", json={"point": key, "slots": ["security.firewallEnabled"]})
        assert saved.status_code == 200, saved.text
        assert len((await admin.get(url + "/point", params={"point": key})).json()["values"]) == 1
        assert (
            await admin.put(url + "/preferences", json={"point": key, "slots": ["security.firewallEnabled"] * 7})
        ).status_code == 422
        assert (await admin.put(url + "/preferences", json={"point": key, "slots": ["invented.field"]})).status_code == 422
    finally:
        await db.execute(delete(Pref))
        await db.commit()


async def test_twenty_slots_can_be_saved_but_twenty_one_are_refused(admin, db, connection, jamf):
    from app.models.schema import DeviceHistoryPreference as Pref

    device = await ingest(db, connection, jamf)
    url = f"/api/devices/{device.id}/history"
    key = (await admin.get(url)).json()["items"][0]["id"]
    detail = (await admin.get(url + "/point", params={"point": key})).json()
    choices = [c["key"] for c in detail["choices"] if c["enabled"]]
    try:
        assert (await admin.put(url + "/preferences", json={"point": key, "slots": choices[:20]})).status_code == 200
        assert len((await admin.get(url + "/point", params={"point": key})).json()["values"]) == 20
        assert (await admin.put(url + "/preferences", json={"point": key, "slots": choices[:21]})).status_code == 422
    finally:
        await db.execute(delete(Pref))
        await db.commit()


async def test_legacy_states_and_pagination_do_not_invent_assessments(admin, db, connection, jamf):
    from app.models.schema import DeviceHistoryPoint as Point
    from app.models.schema import ObservationSpan as Span

    device = await ingest(db, connection, jamf)
    await db.execute(delete(Point).where(Point.device_id == device.id))
    span = await db.scalar(select(Span).where(Span.mdm_connection_id == connection.id, Span.subject_id == device.external_id))
    for i in range(13):
        db.add(
            Span(
                mdm_connection_id=connection.id,
                subject_kind="computer",
                subject_id=device.external_id,
                contract_version=span.contract_version,
                aperture_digest=span.aperture_digest,
                head_digest=span.head_digest,
                section_digests=span.section_digests,
                first_observed_at=span.first_observed_at - timedelta(days=i + 1),
                last_observed_at=span.last_observed_at - timedelta(days=i + 1),
                first_collected_at=span.first_collected_at - timedelta(days=i + 1),
                last_collected_at=span.last_collected_at - timedelta(days=i + 1),
                last_trigger="sweep",
                is_current=False,
            )
        )
    await db.commit()
    url = f"/api/devices/{device.id}/history"
    first = (await admin.get(url)).json()
    second = (await admin.get(url, params={"page": 2})).json()
    assert len(first["items"]) == 12 and first["hasMore"]
    assert len(second["items"]) == 2 and not second["hasMore"]
    point = (await admin.get(url + "/point", params={"point": first["items"][0]["id"]})).json()
    assert point["assessment"] is None and not point["baseline"]
    assert next(v for v in point["values"] if v["key"] == "findings.total")["state"] == "not_recorded"


async def test_same_user_has_separate_tenant_layout_and_foreign_points_are_404(admin, db, connection, jamf, second_tenant):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import DeviceHistoryPoint as Point
    from app.models.schema import DeviceHistoryPreference as Pref

    device = await ingest(db, connection, jamf)
    url = f"/api/devices/{device.id}/history"
    point = (await admin.get(url)).json()["items"][0]["id"]
    assert (
        await admin.put(url + "/preferences", json={"point": point, "slots": ["security.firewallEnabled"]})
    ).status_code == 200
    try:
        response = await admin.post("/api/auth/switch-tenant", json={"tenantId": str(second_tenant)})
        assert response.status_code == 200
        admin.headers["X-CSRF-Token"] = admin.cookies.get("loon_csrf", "")
        assert (await admin.get(url)).status_code == 404
        assert (await admin.get(url + "/point", params={"point": point})).status_code == 404
        account_id = response.json()["id"]
        async with session_for_tenant(second_tenant) as other:
            assert await other.scalar(select(Point).where(Point.device_id == device.id)) is None
            assert await other.get(Pref, (second_tenant, account_id)) is None
            # The same account can save a different preference in its acting tenant.
            other.add(Pref(account_id=account_id, slots=[]))
            await other.commit()
        await admin.post("/api/auth/switch-tenant", json={"tenantId": str(OPERATIONAL_TENANT_ID)})
        admin.headers["X-CSRF-Token"] = admin.cookies.get("loon_csrf", "")
        body = (await admin.get(url + "/point", params={"point": point})).json()
        assert [v["key"] for v in body["values"]] == ["security.firewallEnabled"]
    finally:
        async with session_for_tenant(second_tenant) as other:
            await other.execute(delete(Pref))
            await other.commit()
        await db.execute(delete(Pref))
        await db.commit()


async def test_retained_import_is_idempotent_and_uses_stored_counts(admin, db, connection, jamf):
    from app.models.schema import DeviceHistoryPoint as Point
    from app.models.schema import EventOutbox
    from app.observations.history_import import import_retained

    device = await ingest(db, connection, jamf)
    point = await db.scalar(select(Point).where(Point.device_id == device.id))
    original = point.assessment
    source_id = point.source_id
    await db.execute(delete(Point).where(Point.device_id == device.id))
    await db.commit()
    await import_retained(db)
    imported = await db.scalar(select(Point).where(Point.source_id == source_id))
    assert imported and imported.assessment == {k: v for k, v in original.items() if k != "lastCheckIn"}
    assert "lastCheckIn" not in imported.assessment, "The event did not retain this clock; never backfill today's value."
    before = await db.scalar(select(func.count()).select_from(Point))
    await import_retained(db)
    assert await db.scalar(select(func.count()).select_from(Point)) == before
    # A receipt without a device inventory clock cannot manufacture a historical point.
    event = await db.get(EventOutbox, source_id)
    event.payload = {**event.payload, "deviceMeta": {**event.payload["deviceMeta"], "lastReportDate": None}}
    await db.execute(delete(Point).where(Point.device_id == device.id))
    await db.commit()
    await import_retained(db)
    assert await db.scalar(select(Point).where(Point.source_id == source_id)) is None


async def test_two_users_in_one_tenant_do_not_share_layouts(admin, db, connection, jamf):
    from app.core.bootstrap import create_account
    from app.models.schema import Account, LoginAttempt
    from app.models.schema import DeviceHistoryPreference as Pref
    from tests.test_tenant_switch_db import _signed_in

    credentials = ("history-reader@example.com", "history-reader-password")
    if not await db.scalar(select(Account).where(Account.email == credentials[0])):
        await create_account(db, email=credentials[0], display_name="History reader", password=credentials[1], roles=("viewer",))
    await db.execute(delete(LoginAttempt).where(LoginAttempt.identifier == credentials[0]))
    await db.commit()
    device = await ingest(db, connection, jamf)
    url = f"/api/devices/{device.id}/history"
    point = (await admin.get(url)).json()["items"][0]["id"]
    assert (await admin.put(url + "/preferences", json={"point": point, "slots": []})).status_code == 200
    reader = await _signed_in(credentials)
    try:
        body = (await reader.get(url + "/point", params={"point": point})).json()
        assert len(body["values"]) == 6
        assert (await reader.put(url + "/preferences", json={"point": point, "slots": ["applications.count"]})).status_code == 200
        assert (await admin.get(url + "/point", params={"point": point})).json()["values"] == []
    finally:
        await reader.aclose()
        await db.execute(delete(Pref))
        await db.commit()
