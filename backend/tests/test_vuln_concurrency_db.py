# ruff: noqa: F811 — pytest injects imported fixtures by name.
"""Concurrent ingest, reads and evidence preserve the selected release (#621)."""

import asyncio
from copy import deepcopy

import pytest
from sqlalchemy import delete, select, text

from app.core.config import settings
from app.core.database import session_for_tenant
from app.core.tenancy import OPERATIONAL_TENANT_ID
from app.core.vuln_library import load_epoch_if_new
from app.core.vuln_selection import assess_and_select, record_acquisition
from app.mdm import service
from app.models.schema import AppCatalogEntry, Device, InstalledApp, MdmConnection, VulnCorpusAcquisition, VulnCorpusSelection
from tests.test_device_history_db import ingest
from tests.test_device_observation_db import accounts, admin, connection  # noqa: F401
from tests.test_vuln_answer_db import NOW, acting_tenant, fleet  # noqa: F401
from tests.test_vuln_library import BUNDLE, SIGNATURE, WIRESHARK_BUILD, _rewritten
from tests.test_vuln_library_db import _pointer, _serving, empty, foreign_tenant  # noqa: F401
from tests.test_vuln_retention_db import retained  # noqa: F401
from tests.test_vuln_selected_serving_db import selected  # noqa: F401
from tests.test_vuln_selection_db import pytestmark

pytestmark = pytestmark


async def test_real_ingest_and_assessment_do_not_invert_locks(db, connection, jamf, retained, monkeypatch):
    monkeypatch.setattr(settings, "vuln_tenant_selection", True)
    connection_id = connection.id
    tasks = []
    try:
        await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
        await record_acquisition(db, SIGNATURE)
        await db.commit()
        device = await ingest(db, connection, jamf)
        device_id = device.id
        bundle, signature = _rewritten(rows=[], manifest={"asof": "2026-09-12T20:00:00Z"})
        await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle))
        await record_acquisition(db, signature)
        await db.commit()
        raw = deepcopy(jamf.real)
        raw["applications"][0]["version"] = "999.0"
        flushed, proceed, selecting = asyncio.Event(), asyncio.Event(), asyncio.Event()
        original = service.record_device_apps
        pid = None

        async def pause_after_inventory_writes(session, current):
            flushed.set()
            await asyncio.wait_for(proceed.wait(), timeout=10)
            return await original(session, current)

        monkeypatch.setattr(service, "record_device_apps", pause_after_inventory_writes)

        async def inventory():
            async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
                conn = await session.get(MdmConnection, connection_id)
                await service.ingest_computer(session, conn, raw, aperture_digest="a" * 64, trigger="sweep")

        async def assessment():
            nonlocal pid
            async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
                pid = await session.scalar(text("SELECT pg_backend_pid()"))
                selecting.set()
                await assess_and_select(session, signature)
                await session.commit()

        tasks.append(asyncio.create_task(inventory()))
        await asyncio.wait_for(flushed.wait(), timeout=10)
        tasks.append(asyncio.create_task(assessment()))
        await asyncio.wait_for(selecting.wait(), timeout=5)
        # Wait for an actual database lock wait, not an assumed scheduler ordering.
        async with asyncio.timeout(5):
            while not await db.scalar(text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"), {"pid": pid}):  # noqa: ASYNC110 — observe PostgreSQL, not an in-process event
                await asyncio.sleep(0.01)
        proceed.set()
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
        assert await db.scalar(select(VulnCorpusSelection.signature)) == signature
        assert set(await db.scalars(select(InstalledApp.vuln_signature).where(InstalledApp.device_id == device_id))) == {
            signature
        }
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await db.rollback()
        await db.execute(delete(VulnCorpusSelection))
        await db.execute(delete(VulnCorpusAcquisition))
        hashes = select(InstalledApp.version_hash).join(Device).where(Device.mdm_connection_id == connection_id)
        await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_(hashes)))
        await db.commit()
        monkeypatch.setattr(settings, "vuln_tenant_selection", False)


@pytest.mark.parametrize("surface", ["catalog", "devices", "device", "finding"])
async def test_api_read_remains_coherent_across_selection_commit(admin, db, selected, monkeypatch, surface):
    from app.api import catalog, devices, vulnerabilities
    from app.catalog.service import record_device_apps

    _, device = selected
    await record_acquisition(db, SIGNATURE)
    await record_device_apps(db, device, now=NOW)
    await db.commit()
    bundle, signature = _rewritten(rows=[], manifest={"asof": "2026-09-12T20:00:00Z"})
    await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle))
    await record_acquisition(db, signature)
    await db.commit()
    ready, proceed = asyncio.Event(), asyncio.Event()
    finding_ids = await db.scalar(select(InstalledApp.vuln_ids).where(InstalledApp.key_full == WIRESHARK_BUILD))
    routes = {
        "catalog": (catalog, "/api/catalog?vuln=findings"),
        "devices": (devices, "/api/devices?vuln=findings"),
        "device": (devices, f"/api/devices/{device.id}"),
        "finding": (vulnerabilities, f"/api/vulnerabilities/{finding_ids[0]}"),
    }
    module, url = routes[surface]
    original = module.earned_corpus

    async def pause_after_metadata(session):
        if surface == "device":
            # Detail reads apps before metadata: commit in the opposite gap as well.
            ready.set()
            await asyncio.wait_for(proceed.wait(), timeout=10)
            return await original(session)
        corpus = await original(session)
        ready.set()
        await asyncio.wait_for(proceed.wait(), timeout=10)
        return corpus

    monkeypatch.setattr(module, "earned_corpus", pause_after_metadata)
    reader = asyncio.create_task(admin.get(url))
    try:
        await asyncio.wait_for(ready.wait(), timeout=5)
        # A reader must not hold up selection, nor mix old metadata with new answers.
        await asyncio.wait_for(assess_and_select(db, signature), timeout=5)
        await db.commit()
        proceed.set()
        response = await asyncio.wait_for(reader, timeout=5)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["corpusAsOf"] == "2026-09-10", body
        if surface == "devices":
            assert body["total"] > 0 and body["items"][0]["vulnApps"]["withFindings"] > 0, body
        else:
            rows = body[{"catalog": "items", "device": "apps", "finding": "builds"}[surface]]
            assert any((row["vuln"].get("counts") or {}).get("total") == 17 for row in rows), body
        monkeypatch.setattr(module, "earned_corpus", original)
        fresh = await admin.get(url)
        assert fresh.status_code == 200, fresh.text
        latest = fresh.json()
        assert latest["corpusAsOf"] == "2026-09-12", latest
        if surface in ("catalog", "devices"):
            assert latest["total"] == 0
        elif surface == "finding":
            assert latest["builds"] == []
        else:
            assert all(app["vuln"]["assessment"] == "unknown_app" for app in latest["apps"])
    finally:
        if not reader.done():
            reader.cancel()
        await asyncio.gather(reader, return_exceptions=True)


@pytest.mark.parametrize("skip_first", [False, True])
async def test_reemit_refreshes_release_after_batch_commit(db, connection, jamf, retained, monkeypatch, skip_first):
    from app.core.runs import LOCK_RE_EMIT, TRIGGER_MANUAL, acquire, finish
    from app.mdm import reemit
    from tests.test_re_emit_db import _max_event_id, _snapshots_after

    monkeypatch.setattr(settings, "vuln_tenant_selection", True)
    connection_id = connection.id
    try:
        await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
        await record_acquisition(db, SIGNATURE)
        await db.commit()
        await ingest(db, connection, jamf)
        bundle, signature = _rewritten(rows=[], manifest={"asof": "2026-09-12T20:00:00Z"})
        await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle))
        await record_acquisition(db, signature)
        await db.commit()
        acquisition = await acquire(db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_RE_EMIT)
        assert acquisition.started
        before = await _max_event_id(db)
        original = reemit.beat
        batches = 0

        async def select_between_batches(session, run):
            nonlocal batches
            await original(session, run)
            if batches == 0:
                async with session_for_tenant(OPERATIONAL_TENANT_ID) as writer:
                    await asyncio.wait_for(assess_and_select(writer, signature), timeout=5)
                    await writer.commit()
            batches += 1

        original_observation = reemit.observation_from_ledger
        seen = 0

        async def skip_first_observation(*args, **kwargs):
            nonlocal seen
            seen += 1
            if skip_first and seen == 1:
                return None
            return await original_observation(*args, **kwargs)

        monkeypatch.setattr(reemit, "observation_from_ledger", skip_first_observation)
        monkeypatch.setattr(reemit, "_BATCH", 1)
        monkeypatch.setattr(reemit, "beat", select_between_batches)
        result = await reemit.re_emit_connection(db, connection, run=acquisition.run)
        assert result.devices_processed == 2 - int(skip_first) and result.devices_failed == 0
        snapshots = list((await _snapshots_after(db, connection_id, before)).values())
        dates = [{app["vuln"]["corpusAsOf"] for app in row.payload["app"]} for row in snapshots]
        assert dates[0] == ({"2026-09-12"} if skip_first else {"2026-09-10"})
        assert all(date == {"2026-09-12"} for date in dates[1:]), dates
        assert await finish(db, acquisition.run, ok=True)
    finally:
        await db.rollback()
        await db.execute(delete(VulnCorpusSelection))
        await db.execute(delete(VulnCorpusAcquisition))
        hashes = select(InstalledApp.version_hash).join(Device).where(Device.mdm_connection_id == connection_id)
        await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_(hashes)))
        await db.commit()
        monkeypatch.setattr(settings, "vuln_tenant_selection", False)


@pytest.mark.parametrize("enabled", [False, True])
async def test_read_snapshot_keeps_tenant_binding_and_restores_pool_isolation(db, monkeypatch, enabled):
    from app.core.database import get_vuln_read_db
    from app.core.tenancy import TENANT_GUC

    monkeypatch.setattr(settings, "vuln_tenant_selection", enabled)
    assert await db.scalar(text("SHOW transaction_isolation")) == "read committed"
    transaction = db.sync_session.get_transaction()
    dependency = get_vuln_read_db(db)
    assert await anext(dependency) is db
    assert await db.scalar(text("SHOW transaction_isolation")) == ("repeatable read" if enabled else "read committed")
    assert await db.scalar(text("SELECT current_setting(:name)"), {"name": TENANT_GUC}) == str(OPERATIONAL_TENANT_ID)
    if not enabled:
        assert db.sync_session.get_transaction() is transaction
    await dependency.aclose()
    await db.commit()
    assert await db.scalar(text("SHOW transaction_isolation")) == "read committed"


async def test_posture_counts_keep_one_release_while_selection_waits(db, selected, monkeypatch):
    from app.catalog.service import record_device_apps
    from app.core import posture

    _, device = selected
    await record_acquisition(db, SIGNATURE)
    await record_device_apps(db, device, now=NOW)
    await db.commit()
    bundle, signature = _rewritten(rows=[], manifest={"asof": "2026-09-12T20:00:00Z"})
    await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle))
    await record_acquisition(db, signature)
    await db.commit()
    ready, proceed, selecting = asyncio.Event(), asyncio.Event(), asyncio.Event()
    original = posture._count
    pid = None

    async def pause_after_metadata(session, statement):
        ready.set()
        await asyncio.wait_for(proceed.wait(), timeout=10)
        return await original(session, statement)

    async def capture():
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
            values = await posture._vuln_values(session, NOW)
            await session.commit()
            return values

    async def assessment():
        nonlocal pid
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
            pid = await session.scalar(text("SELECT pg_backend_pid()"))
            selecting.set()
            await assess_and_select(session, signature)
            await session.commit()

    monkeypatch.setattr(posture, "_count", pause_after_metadata)
    reader = asyncio.create_task(capture())
    tasks = [reader]
    try:
        await asyncio.wait_for(ready.wait(), timeout=5)
        tasks.append(asyncio.create_task(assessment()))
        await asyncio.wait_for(selecting.wait(), timeout=5)
        async with asyncio.timeout(5):
            while not await db.scalar(text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"), {"pid": pid}):  # noqa: ASYNC110 — observe PostgreSQL, not an in-process event
                await asyncio.sleep(0.01)
        proceed.set()
        old, _ = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
        assert old["vuln.apps_affected"] == 1 and old["vuln.devices_affected"] == 1
        latest = await posture._vuln_values(db, NOW)
        assert latest["vuln.apps_affected"] == latest["vuln.devices_affected"] == 0
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
