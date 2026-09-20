"""Actual assessment/copy/read isolation for retained tenant releases (#621)."""

import pytest
import pytest_asyncio
from sqlalchemy import delete, insert, select

from app.catalog.service import record_device_apps, rejudge_epoch
from app.core.config import settings
from app.core.vuln import NO_CORPUS, loaded_corpus
from app.core.vuln_library import earned_corpus, load_epoch_if_new, loaded_epoch_signature
from app.core.vuln_selection import assess_and_select, record_acquisition, selected_signature
from app.models.schema import AppCatalogEntry, VulnCorpusAcquisition, VulnCorpusSelection
from tests.test_vuln_answer_db import (  # noqa: F401
    NOW,
    _block,
    _set_tier,
    _snapshot,
    _stored,
    acting_tenant,
    fleet,
)
from tests.test_vuln_library import BUNDLE, SIGNATURE, WIRESHARK_BUILD, WIRESHARK_TITLE, _rewritten, _row
from tests.test_vuln_library_db import FOREIGN_TENANT_ID, _pointer, _serving, empty, foreign_tenant  # noqa: F401
from tests.test_vuln_retention_db import retained  # noqa: F401
from tests.test_vuln_selection_db import acting, pytestmark

# Re-exported fixtures above are consumed by pytest.
pytestmark = pytestmark


@pytest_asyncio.fixture(loop_scope="session")
async def selected(db, fleet, retained, foreign_tenant, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "vuln_tenant_selection", True)
    for session in (db, foreign_tenant):
        await session.execute(delete(VulnCorpusSelection))
        await session.execute(delete(VulnCorpusAcquisition))
        await session.commit()
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    try:
        yield fleet
    finally:
        for session in (db, foreign_tenant):
            await session.rollback()
            await session.execute(delete(VulnCorpusSelection))
            await session.execute(delete(VulnCorpusAcquisition))
            await session.execute(delete(AppCatalogEntry).where(AppCatalogEntry.name == "selected-serving-foreign"))
            await session.commit()
        # Legacy fixtures assert that teardown leaves the legacy process gate empty.
        monkeypatch.setattr(settings, "vuln_tenant_selection", False)


async def test_real_join_bootstraps_grant_and_survives_consent_off_and_other_tenant_update(db, selected, foreign_tenant):  # noqa: F811
    connection, device = selected
    assert (await earned_corpus(db)) is NO_CORPUS
    await record_acquisition(db, SIGNATURE)
    await record_device_apps(db, device, now=NOW)
    await db.commit()
    assert await selected_signature(db) == SIGNATURE
    assert await _stored(db, device, WIRESHARK_BUILD) == ("covered", SIGNATURE)
    original = await _block(db, device, WIRESHARK_BUILD)
    assert original.counts.total == 17

    await _set_tier(db, "off")
    newer, digest = _rewritten(
        rows=[
            _row(
                key_full=WIRESHARK_BUILD,
                ids=[],
                counts=dict.fromkeys(("total", "kev", "critical", "high", "medium", "low"), 0),
                oldest_published=dict.fromkeys(("total", "critical", "high", "medium", "low")),
            )
        ],
        manifest={"asof": "2026-09-11T20:00:00Z"},
    )
    await load_epoch_if_new(db, _pointer(digest), transport=_serving(newer))
    with acting(FOREIGN_TENANT_ID):
        assert (await earned_corpus(foreign_tenant)) is NO_CORPUS
        await foreign_tenant.execute(
            insert(AppCatalogEntry).values(
                name="selected-serving-foreign",
                bundle_id="test.foreign",
                version="1",
                app_hash="8" * 32,
                version_hash="9" * 32,
                key_full=WIRESHARK_BUILD,
                key_title=WIRESHARK_TITLE,
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
        )
        await record_acquisition(foreign_tenant, digest)
        await assess_and_select(foreign_tenant, digest)
        await foreign_tenant.commit()
        assert (await earned_corpus(foreign_tenant)).as_of.isoformat() == "2026-09-11"
        assert loaded_epoch_signature() == digest
        assert (
            await foreign_tenant.scalar(
                select(AppCatalogEntry.vuln_counts["total"].as_integer()).where(
                    AppCatalogEntry.name == "selected-serving-foreign"
                )
            )
            == 0
        )
    # A tenant switch cannot use B's task state, even before reloading A's selection.
    assert loaded_corpus() is NO_CORPUS
    await rejudge_epoch(db)
    await db.commit()
    assert await selected_signature(db) == SIGNATURE
    assert await _block(db, device, WIRESHARK_BUILD) == original
    from tests.test_vuln_answer_db import _list

    listed = await _list(db, vuln="findings")
    assert WIRESHARK_BUILD in [item.key_full for item in listed.items]
    captured = await _snapshot(db, connection)
    assert captured["vuln.apps_affected"] == 1
    assert captured["vuln.devices_affected"] == 1


async def test_actual_copy_failure_rolls_back_answers_selection_and_read_date(db, selected, monkeypatch):
    from app.catalog import service

    _, device = selected
    device_id = device.id
    await record_acquisition(db, SIGNATURE)
    await record_device_apps(db, device, now=NOW)
    await db.commit()
    newer, digest = _rewritten(
        rows=[
            _row(
                key_full=WIRESHARK_BUILD,
                ids=[],
                counts=dict.fromkeys(("total", "kev", "critical", "high", "medium", "low"), 0),
                oldest_published=dict.fromkeys(("total", "critical", "high", "medium", "low")),
            )
        ],
        manifest={"asof": "2026-09-11T20:00:00Z"},
    )
    await load_epoch_if_new(db, _pointer(digest), transport=_serving(newer))
    await record_acquisition(db, digest)
    await db.commit()
    original_copy = service.copy_vuln_answers

    async def broken(session):
        await original_copy(session)
        raise RuntimeError("injected failure after actual answer copy")

    with monkeypatch.context() as patch:
        patch.setattr(service, "copy_vuln_answers", broken)
        with pytest.raises(RuntimeError, match="injected failure"):
            await assess_and_select(db, digest)
    assert await selected_signature(db) == SIGNATURE
    assert await db.scalar(select(AppCatalogEntry.vuln_signature).where(AppCatalogEntry.key_full == WIRESHARK_BUILD)) == SIGNATURE
    await assess_and_select(db, digest)
    await db.rollback()
    assert await selected_signature(db) == SIGNATURE
    assert (await earned_corpus(db)).as_of.isoformat() == "2026-09-10"
    await assess_and_select(db, digest)
    await db.commit()
    from app.models.schema import Device

    device = await db.get(Device, device_id)
    db.expire_all()
    device = await db.get(Device, device_id)
    block = await _block(db, device, WIRESHARK_BUILD)
    assert block.counts.total == 0
    assert block.corpus_as_of.isoformat() == "2026-09-11"
    # Supported rollback re-assesses retained rows, including copies, before moving back.
    await assess_and_select(db, SIGNATURE)
    await db.commit()
    db.expire_all()
    device = await db.get(Device, device_id)
    assert (await _block(db, device, WIRESHARK_BUILD)).counts.total == 17


@pytest.mark.parametrize("legacy_import", [False, True])
async def test_successful_exchange_of_already_held_bytes_grants_only_recipient(
    db,
    selected,
    foreign_tenant,  # noqa: F811
    monkeypatch,
    legacy_import,
):
    from app.core import sharing
    from app.models.schema import ShareLog
    from tests.test_vuln_answer_db import _exchange_serving

    _, device = selected
    await record_device_apps(db, device, now=NOW)
    await db.commit()
    assert await selected_signature(db) is None
    if legacy_import:
        from tests.test_vuln_retention_db import ARCHIVE

        for model in ARCHIVE:
            await db.execute(delete(model))
        await db.commit()
    monkeypatch.setattr(settings, "community_sharing", True)
    try:
        log = await sharing.run_exchange(db, transport=_exchange_serving(BUNDLE, SIGNATURE))
        assert log.outcome == "sent"
        assert await selected_signature(db) == SIGNATURE
        assert await _stored(db, device, WIRESHARK_BUILD) == ("covered", SIGNATURE)
        with acting(FOREIGN_TENANT_ID):
            assert await selected_signature(foreign_tenant) is None
            assert await foreign_tenant.scalar(select(VulnCorpusAcquisition.signature)) is None
    finally:
        await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
        await db.commit()


@pytest.mark.parametrize("failure", ["unknown", "truncated", "stale"])
async def test_lost_or_incomplete_coverage_does_not_resolve_held_findings(db, selected, failure):
    from app.core.findings import reconcile_device_findings as reconcile
    from app.models.schema import DeviceFinding, InstalledApp

    _, device = selected
    await record_acquisition(db, SIGNATURE)
    await record_device_apps(db, device, now=NOW)
    await db.commit()
    await earned_corpus(db)
    query = select(InstalledApp).where(InstalledApp.device_id == device.id).execution_options(populate_existing=True)
    rows = list((await db.scalars(query)).all())
    await reconcile(db, device=device, rows=rows, observed_at=NOW, device_is_new=True)
    await db.commit()
    held = list((await db.scalars(select(DeviceFinding).where(DeviceFinding.device_id == device.id))).all())
    assert held
    for row in rows:
        if row.key_full == WIRESHARK_BUILD:
            row.vuln_ids = []
            if failure == "unknown":
                row.vuln_assessment = None
            elif failure == "truncated":
                row.vuln_ids_truncated = True
            else:
                row.vuln_signature = "f" * 64
    assert await reconcile(db, device=device, rows=rows, observed_at=NOW) == {}
    assert all(row.resolved_at is None for row in held)
    await db.rollback()


async def test_concurrent_inventory_writer_uses_selection_committed_while_it_waited(db, selected):
    import asyncio

    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Device

    _, device = selected
    device_id = device.id
    await record_acquisition(db, SIGNATURE)
    await record_device_apps(db, device, now=NOW)
    await db.commit()
    newer, digest = _rewritten(rows=[], manifest={"asof": "2026-09-11T20:00:00Z"})
    await load_epoch_if_new(db, _pointer(digest), transport=_serving(newer))
    await record_acquisition(db, digest)
    await db.commit()
    ready = asyncio.Event()

    async def inventory():
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
            await earned_corpus(session)
            assert loaded_epoch_signature() == SIGNATURE
            current = await session.get(Device, device_id)
            ready.set()
            await record_device_apps(session, current, now=NOW)
            await session.commit()
            assert loaded_epoch_signature() == digest

    # Hold the selection transaction open. The new writer starts with an old read
    # context, but must wait before reading/writing the catalog's answers.
    await assess_and_select(db, digest)
    writer = asyncio.create_task(inventory())
    try:
        await asyncio.wait_for(ready.wait(), timeout=5)
        await db.commit()
        await asyncio.wait_for(writer, timeout=5)
    finally:
        if not writer.done():
            writer.cancel()
            await asyncio.gather(writer, return_exceptions=True)
    assert await selected_signature(db) == digest
    assert await db.scalar(select(AppCatalogEntry.vuln_signature).where(AppCatalogEntry.key_full == WIRESHARK_BUILD)) == digest


async def test_exchange_failed_assessment_keeps_prior_answers_and_retry_selects_same_digest(db, selected, monkeypatch, caplog):
    from app.catalog import service
    from app.core import sharing
    from app.models.schema import ShareLog
    from tests.test_vuln_answer_db import _exchange_serving

    _, device = selected
    device_id = device.id
    await record_acquisition(db, SIGNATURE)
    await record_device_apps(db, device, now=NOW)
    await db.commit()
    newer, digest = _rewritten(rows=[], manifest={"asof": "2026-09-11T20:00:00Z"})
    monkeypatch.setattr(settings, "community_sharing", True)

    async def fail(session):
        raise RuntimeError("injected assessment failure")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(service, "copy_vuln_answers", fail)
            log = await sharing.run_exchange(db, transport=_exchange_serving(newer, digest))
        assert log.outcome == "sent"
        assert await selected_signature(db) == SIGNATURE
        assert "previous answers remain selected" in caplog.text
        assert "retry Send now" in caplog.text
        from app.models.schema import Device

        current = await db.get(Device, device_id)
        assert await _stored(db, current, WIRESHARK_BUILD) == ("covered", SIGNATURE)
        await sharing.run_exchange(db, transport=_exchange_serving(newer, digest))
        assert await selected_signature(db) == digest
        assert await _stored(db, current, WIRESHARK_BUILD) == (None, digest)
    finally:
        await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
        await db.commit()


async def test_installed_and_per_title_targets_stay_on_retained_release(db, selected):
    from app.models.schema import AppCatalogTitleMatch
    from tests.test_vuln_answer_db import THERE, _epoch_with_target, _with_titles

    _, device = selected
    await _with_titles(db)
    digest = await _epoch_with_target(
        db, {"ids": THERE, "counts": {"total": 94, "kev": 0, "critical": 1, "high": 26, "medium": 66, "low": 1}}
    )
    await record_acquisition(db, digest)
    await record_device_apps(db, device, now=NOW)
    await db.commit()
    # The global latest has no matching target, but this tenant has not acquired it.
    newer, other = _rewritten(rows=[], manifest={"asof": "2026-09-12T20:00:00Z"})
    await load_epoch_if_new(db, _pointer(other), transport=_serving(newer))
    from app.catalog.service import refresh_tenant

    await refresh_tenant(db, force=True)
    await db.commit()
    assert (
        await db.scalar(
            select(AppCatalogEntry.vuln_target_counts["total"].as_integer()).where(AppCatalogEntry.key_full == WIRESHARK_BUILD)
        )
        == 94
    )
    targets = (
        await db.scalars(
            select(AppCatalogTitleMatch.vuln_target_counts["total"].as_integer())
            .join(AppCatalogEntry, AppCatalogEntry.id == AppCatalogTitleMatch.app_catalog_id)
            .where(AppCatalogEntry.key_full == WIRESHARK_BUILD)
        )
    ).all()
    assert 94 in targets
    assert await selected_signature(db) == digest
