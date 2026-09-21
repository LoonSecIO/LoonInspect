"""Manual corpus cleanup preserves cross-tenant rights, races and transaction atomicity."""

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import SQLAlchemyError

from app.core import vuln_pruning
from app.core.database import unscoped_session
from app.core.vuln_selection import record_acquisition, select_after_assessment
from app.models.schema import VulnCorpusRelease
from tests.test_vuln_library import SIGNATURE
from tests.test_vuln_library_db import FOREIGN_TENANT_ID, acting_tenant, empty, foreign_tenant  # noqa: F401
from tests.test_vuln_retention_db import _archive, retained  # noqa: F401
from tests.test_vuln_selection_db import acting, no_assessment, releases  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]


async def test_preview_apply_and_repeat_keep_active_projection(db, releases):  # noqa: F811
    before = datetime.now(UTC)
    original = await _archive(db)
    preview = await vuln_pruning.prune_releases(db, before=before)
    assert preview == {"examined": 2, "protected": 1, "eligible": 1, "deleted": 0}
    assert await _archive(db) == original
    await db.rollback()
    result = await vuln_pruning.prune_releases(db, before=before, apply=True)
    assert result == {**preview, "deleted": 1}
    await db.commit()
    after = await _archive(db)
    for old, new in zip(original, after, strict=True):
        assert new == [row for row in old if row["signature"] == releases]
    assert (await vuln_pruning.prune_releases(db, before=before, apply=True))["deleted"] == 0
    await db.commit()


@pytest.mark.parametrize("selected", [False, True])
async def test_foreign_acquisition_protects_entire_release_even_without_selection(db, releases, foreign_tenant, selected):  # noqa: F811
    with acting(FOREIGN_TENANT_ID):
        await record_acquisition(foreign_tenant, SIGNATURE)
        if selected:
            await select_after_assessment(foreign_tenant, SIGNATURE, assess=no_assessment)
        await foreign_tenant.commit()
    original = await _archive(db)
    result = await vuln_pruning.prune_releases(db, before=datetime.now(UTC), apply=True)
    await db.commit()
    assert result == {"examined": 2, "protected": 2, "eligible": 0, "deleted": 0}
    assert await _archive(db) == original


async def test_concurrent_acquisition_after_inspection_restores_child_rows(db, releases, foreign_tenant, monkeypatch):  # noqa: F811
    original = await _archive(db)
    read = vuln_pruning._acquired

    async def acquire_after_read(session, signatures):
        held = await read(session, signatures)
        with acting(FOREIGN_TENANT_ID):
            await record_acquisition(foreign_tenant, SIGNATURE)
            await foreign_tenant.commit()
        return held

    monkeypatch.setattr(vuln_pruning, "_acquired", acquire_after_read)
    result = await vuln_pruning.prune_releases(db, before=datetime.now(UTC), apply=True)
    await db.commit()
    assert result["protected"] == 2
    assert result["deleted"] == 0
    assert await _archive(db) == original


async def test_cutoff_uses_local_load_not_old_source_date(db, releases):  # noqa: F811
    cutoff = datetime.now(UTC) - timedelta(days=1)
    await db.execute(update(VulnCorpusRelease).values(asof=cutoff - timedelta(days=30), loaded_at=cutoff))
    await db.commit()
    result = await vuln_pruning.prune_releases(db, before=cutoff, apply=True)
    assert result["examined"] == 0  # strict cutoff; stale source date alone never deletes
    await db.rollback()
    for bad in (datetime.now(), datetime.now(UTC) + timedelta(days=1)):
        with pytest.raises(ValueError, match="past cleanup cutoff"):
            await vuln_pruning.prune_releases(db, before=bad, apply=True)


async def test_command_failure_rolls_back_all_deletions_and_explains_retry(db, releases, monkeypatch, capsys):  # noqa: F811
    original = await _archive(db)
    prune = vuln_pruning.prune_releases

    async def fail_after_prune(*args, **kwargs):
        assert (await prune(*args, **kwargs))["deleted"] == 1
        raise SQLAlchemyError("simulated failure")

    monkeypatch.setattr(vuln_pruning, "prune_releases", fail_after_prune)
    assert await vuln_pruning.run(before=datetime.now(UTC), apply=True) == 1
    assert "retry the preview" in capsys.readouterr().out
    assert await _archive(db) == original


async def test_cleanup_waits_for_import_lock_and_rechecks_active(db, releases):  # noqa: F811
    started = asyncio.Event()

    async def cleanup():
        async with unscoped_session() as session:
            started.set()
            result = await vuln_pruning.prune_releases(session, before=datetime.now(UTC), apply=True)
            await session.commit()
            return result

    async with unscoped_session() as importing:
        await importing.execute(text("SELECT pg_advisory_xact_lock(621, 1)"))
        task = asyncio.create_task(cleanup())
        try:
            await asyncio.wait_for(started.wait(), timeout=5)
            # The singleton pointer moves under exactly the lock held by store_epoch.
            await importing.execute(text("UPDATE vuln_library_epoch SET signature = :signature"), {"signature": SIGNATURE})
            await importing.commit()
            result = await asyncio.wait_for(task, timeout=5)
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    assert result["deleted"] == 1
    assert list(await db.scalars(select(VulnCorpusRelease.signature))) == [SIGNATURE]
