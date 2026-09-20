# ruff: noqa: F811 — pytest injects imported fixtures by name.
"""Release transitions are append-only entries in the existing device history (#621)."""

from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.catalog.service import record_device_apps, refresh_tenant
from app.core.vuln_library import load_epoch_if_new
from app.core.vuln_selection import assess_and_select, record_acquisition, selected_signature
from app.models.schema import DeviceHistoryPoint, InstalledApp, ObservationSpan
from app.observations.history_capture import capture
from tests.test_device_observation_db import connection  # noqa: F401
from tests.test_vuln_answer_db import NOW, _block, acting_tenant, fleet  # noqa: F401
from tests.test_vuln_library import SIGNATURE, WIRESHARK_BUILD, _rewritten, _row
from tests.test_vuln_library_db import _pointer, _serving, empty, foreign_tenant  # noqa: F401
from tests.test_vuln_retention_db import retained  # noqa: F401
from tests.test_vuln_selected_serving_db import selected  # noqa: F401
from tests.test_vuln_selection_db import pytestmark

pytestmark = pytestmark


async def receipt(db, device, source):
    rows = (await db.scalars(select(InstalledApp).where(InstalledApp.device_id == device.id))).all()
    apps = []
    for row in rows:
        block = await _block(db, device, row.key_full)
        apps.append(
            {
                "app": {"name": row.name, "bundleId": row.bundle_id, "version": row.version},
                "vuln": block.model_dump(mode="json", by_alias=True),
            }
        )
    return SimpleNamespace(id=source, created_at=datetime.now(UTC), payload={"app": apps})


async def points(db, device_id):
    return (
        await db.scalars(
            select(DeviceHistoryPoint)
            .where(DeviceHistoryPoint.device_id == device_id)
            .order_by(DeviceHistoryPoint.collected_at, DeviceHistoryPoint.id)
        )
    ).all()


@pytest_asyncio.fixture(loop_scope="session")
async def observed(db, selected):
    connection, device = selected
    span = ObservationSpan(
        mdm_connection_id=connection.id,
        subject_kind="computer",
        subject_id=device.external_id,
        contract_version="v1",
        aperture_digest="a" * 64,
        head_digest="b" * 64,
        section_digests={"applications": "c" * 64},
        first_observed_at=NOW,
        last_observed_at=NOW,
        first_collected_at=NOW,
        last_collected_at=NOW,
        last_trigger="sweep",
    )
    db.add(span)
    await record_acquisition(db, SIGNATURE)
    await record_device_apps(db, device, now=NOW)
    await db.commit()
    await capture(db, device=device, event=await receipt(db, device, 987621))
    await db.commit()
    return device


async def test_correction_and_rollback_append_without_rewriting_evidence_or_quiet_sweeps(db, observed):
    device = observed
    (first,) = await points(db, device.id)
    original = deepcopy(first.assessment)
    evidence = original["vulnerabilityEvidence"]
    build = next(b for b in evidence["builds"] if b["keyFull"] == WIRESHARK_BUILD)
    assert build["counts"]["total"] == 17 and build["evaluatedAt"] is not None
    assert evidence["releaseDigest"] == SIGNATURE
    assert first.observed_at == NOW and first.source_id == 987621
    await refresh_tenant(db, force=True)  # another evaluation clock alone is not another assertion
    await capture(db, device=device, event=await receipt(db, device, 987622))
    await db.commit()
    assert len(await points(db, device.id)) == 1

    newer, signature = _rewritten(rows=[_row(key_full=WIRESHARK_BUILD)], manifest={"asof": "2026-09-11T20:00:00Z"})
    await load_epoch_if_new(db, _pointer(signature), transport=_serving(newer))
    await record_acquisition(db, signature)
    await assess_and_select(db, signature)
    await db.commit()
    previous, current = await points(db, device.id)
    assert previous.assessment == original
    assert current.source_id is None and current.assessment["basis"] == "corpus_assessment"
    assert current.observed_at == first.observed_at
    assert current.collected_at > first.collected_at
    assert current.assessment["vulnerabilityEvidence"]["releaseDigest"] == signature
    assert current.assessment["total"] == 1
    # A repeated selection and the next inventory receipt must not duplicate this assertion.
    assert not await assess_and_select(db, signature)
    device_id = device.id
    db.expire_all()
    from app.models.schema import Device

    device = await db.get(Device, device_id)
    await capture(db, device=device, event=await receipt(db, device, 987623))
    await db.commit()
    assert len(await points(db, device.id)) == 2
    await assess_and_select(db, SIGNATURE)
    await db.commit()
    history = await points(db, device.id)
    assert len(history) == 3 and history[0].assessment == original
    assert history[-1].assessment["vulnerabilityEvidence"]["releaseDigest"] == SIGNATURE
    from app.api.device_history import history as timeline

    response = await timeline(device.id, page=1, db=db)
    assert [p["kind"] for p in response["items"]] == ["assessment", "assessment", "inventory"]


async def test_evidence_failure_and_outer_rollback_leave_selection_and_history_together(db, observed, monkeypatch):
    from app.observations import assessment_evidence

    device_id = observed.id
    newer, signature = _rewritten(rows=[])
    await load_epoch_if_new(db, _pointer(signature), transport=_serving(newer))
    await record_acquisition(db, signature)
    await db.commit()
    real = assessment_evidence.capture_release_transition

    async def fail(session, digest):
        await real(session, digest)
        raise RuntimeError("injected evidence failure")

    with monkeypatch.context() as patch:
        patch.setattr(assessment_evidence, "capture_release_transition", fail)
        with pytest.raises(RuntimeError, match="evidence failure"):
            await assess_and_select(db, signature)
    assert len(await points(db, device_id)) == 1
    assert await selected_signature(db) == SIGNATURE
    await assess_and_select(db, signature)
    await db.rollback()
    assert len(await points(db, device_id)) == 1
    assert await selected_signature(db) == SIGNATURE


async def test_foreign_tenant_cannot_read_or_append_our_evidence(db, observed, foreign_tenant):
    from sqlalchemy.exc import DBAPIError

    (point,) = await points(db, observed.id)
    assert (await foreign_tenant.scalars(select(DeviceHistoryPoint).where(DeviceHistoryPoint.id == point.id))).all() == []
    from sqlalchemy import insert

    with pytest.raises(DBAPIError):
        async with foreign_tenant.begin_nested():
            await foreign_tenant.execute(
                insert(DeviceHistoryPoint).values(
                    tenant_id=point.tenant_id,
                    device_id=point.device_id,
                    span_id=point.span_id,
                    source_id=None,
                    observed_at=NOW,
                    collected_at=NOW,
                    assessment={},
                )
            )


async def test_missing_coverage_and_truncation_remain_explicit_and_previous_assertions_survive(db, observed):
    device_id = observed.id
    (first,) = await points(db, device_id)
    original = deepcopy(first.assessment)
    row = _row(
        key_full=WIRESHARK_BUILD,
        truncated=True,
        counts={"total": 100, "kev": 0, "critical": 0, "high": 100, "medium": 0, "low": 0},
    )
    for rows in ([row], []):
        bundle, signature = _rewritten(rows=rows)
        await load_epoch_if_new(db, _pointer(signature), transport=_serving(bundle))
        await record_acquisition(db, signature)
        await assess_and_select(db, signature)
        await db.commit()
    history = await points(db, device_id)
    assert len(history) == 3 and history[0].assessment == original
    capped = next(b for b in history[1].assessment["vulnerabilityEvidence"]["builds"] if b["keyFull"] == WIRESHARK_BUILD)
    assert capped["counts"]["total"] == 100 and capped["idsTruncated"] and len(capped["ids"]) == 1
    assert history[-1].assessment["total"] is None and history[-1].assessment["covered"] == 0
    assert all(b["counts"] is None for b in history[-1].assessment["vulnerabilityEvidence"]["builds"])
    from app.observations.history_capture import retain_summary

    await retain_summary(db, None, "completed", "Must not attach to assessment entries")
    await db.commit()
    assert all(point.summary is None for point in await points(db, device_id))


async def test_migration_keeps_legacy_receipts_and_refuses_lossy_downgrade(db):
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    path = Path(__file__).parents[1] / "migrations/versions/c621f4a8e902_assessment_history_sources.py"
    spec = importlib.util.spec_from_file_location("evidence_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    async def run(fn):
        connection = await db.connection()

        def apply(sync):
            with Operations.context(MigrationContext.configure(sync)):
                fn()

        await connection.run_sync(apply)

    try:
        await db.execute(text("CREATE SCHEMA evidence_migration_test"))
        await db.execute(text("SET LOCAL search_path TO evidence_migration_test, public"))
        await db.execute(
            text("CREATE TABLE device_history_points (source_id INTEGER NOT NULL UNIQUE, assessment JSONB NOT NULL)")
        )
        await db.execute(text("INSERT INTO device_history_points VALUES (42, jsonb_build_object('legacy', true))"))
        await run(migration.upgrade)
        assert await db.scalar(text("SELECT assessment FROM device_history_points WHERE source_id=42")) == {"legacy": True}
        await db.execute(text("INSERT INTO device_history_points VALUES (NULL, jsonb_build_object('new', true))"))
        with pytest.raises(DBAPIError, match="downgrade would lose evidence"):
            async with db.begin_nested():
                await run(migration.downgrade)
        assert await db.scalar(text("SELECT count(*) FROM device_history_points")) == 2
        await db.execute(text("DELETE FROM device_history_points WHERE source_id IS NULL"))
        await run(migration.downgrade)
        assert await db.scalar(text("SELECT source_id FROM device_history_points")) == 42
    finally:
        await db.rollback()


async def test_real_ingest_records_current_provenance_without_inventing_old_history(db, connection, jamf, retained, monkeypatch):
    from sqlalchemy import delete

    from app.core.config import settings
    from app.models.schema import AppCatalogEntry, Device, VulnCorpusAcquisition, VulnCorpusSelection
    from tests.test_device_history_db import ingest
    from tests.test_vuln_library import BUNDLE

    monkeypatch.setattr(settings, "vuln_tenant_selection", True)
    connection_id = connection.id
    try:
        await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
        await record_acquisition(db, SIGNATURE)
        await db.commit()
        device = await ingest(db, connection, jamf)
        history = await points(db, device.id)
        assert len(history) == 1
        evidence = history[0].assessment["vulnerabilityEvidence"]
        assert evidence["releaseDigest"] == SIGNATURE and evidence["builds"]
        assert history[0].source_id is not None
        await ingest(db, connection, jamf)
        assert len(await points(db, device.id)) == 1
    finally:
        await db.rollback()
        await db.execute(delete(VulnCorpusSelection))
        await db.execute(delete(VulnCorpusAcquisition))
        hashes = select(InstalledApp.version_hash).join(Device).where(Device.mdm_connection_id == connection_id)
        await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_(hashes)))
        await db.commit()
        monkeypatch.setattr(settings, "vuln_tenant_selection", False)


async def test_no_application_observation_means_no_fabricated_assessment_point(db, observed):
    from sqlalchemy import update

    from app.observations.assessment_evidence import capture_release_transition

    await db.execute(update(ObservationSpan).where(ObservationSpan.subject_id == observed.external_id).values(section_digests={}))
    await capture_release_transition(db, SIGNATURE)
    assert len(await points(db, observed.id)) == 1
    await db.rollback()
