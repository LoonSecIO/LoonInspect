# ruff: noqa: F811 — pytest injects imported fixtures by name.
"""Thirty-day cleanup protects real rollback pairs, including other tenants' selections."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.core import vuln_pruning
from app.core.vuln_library import load_epoch_if_new
from app.core.vuln_selection import record_acquisition, select_after_assessment
from app.models.schema import VulnCorpusAcquisition, VulnCorpusRelease, VulnCorpusSelection
from tests.test_vuln_library import SIGNATURE, _rewritten, _row
from tests.test_vuln_library_db import FOREIGN_TENANT_ID, _pointer, _serving, acting_tenant, empty, foreign_tenant  # noqa: F401
from tests.test_vuln_retention_db import _archive, retained  # noqa: F401
from tests.test_vuln_selection_db import acting, no_assessment, pytestmark, releases  # noqa: F401

pytestmark = pytestmark
MIGRATION = Path(__file__).resolve().parents[1] / "migrations/versions/d621a30f7b12_previous_corpus_selection.py"


async def pair(db):
    return (await db.execute(select(VulnCorpusSelection.signature, VulnCorpusSelection.previous_signature))).one()


@pytest_asyncio.fixture(loop_scope="session")
async def chain(db, releases):
    bundle, third = _rewritten(rows=[_row()], manifest={"asof": "2026-09-12T20:00:00Z"})
    await load_epoch_if_new(db, _pointer(third), transport=_serving(bundle))
    for signature in (SIGNATURE, releases, third):
        await record_acquisition(db, signature)
        await select_after_assessment(db, signature, assess=no_assessment)
    await db.execute(update(VulnCorpusAcquisition).values(acquired_at=datetime.now(UTC) - timedelta(days=60)))
    await db.commit()
    return SIGNATURE, releases, third


async def test_success_failure_repeat_outer_rollback_and_rollback_swap(db, chain):
    first, previous, current = chain
    assert await pair(db) == (current, previous)
    assert not await select_after_assessment(db, current, assess=no_assessment)
    assert await pair(db) == (current, previous)

    async def fail(session, signature):
        raise ValueError("assessment failed")

    with pytest.raises(ValueError, match="assessment failed"):
        await select_after_assessment(db, first, assess=fail)
    assert await pair(db) == (current, previous)
    await select_after_assessment(db, first, assess=no_assessment)
    await db.rollback()
    assert await pair(db) == (current, previous)
    await select_after_assessment(db, previous, assess=no_assessment)
    await db.commit()
    assert await pair(db) == (previous, current)
    with pytest.raises(IntegrityError):
        async with db.begin_nested():
            await db.execute(delete(VulnCorpusAcquisition).where(VulnCorpusAcquisition.signature == current))


async def test_preview_then_retire_old_grant_and_bytes_preserving_pair_and_rls_context(db, chain):
    _, previous, current = chain
    before = datetime.now(UTC)
    original = await _archive(db)
    context = await db.scalar(text("SELECT current_setting('looninspect.tenant_id')"))
    preview = await vuln_pruning.prune_releases(db, before=before, retire_acquisitions=True)
    assert preview["acquisitionsEligible"] == preview["eligible"] == 1
    assert preview["acquisitionsRetired"] == preview["deleted"] == 0
    assert await _archive(db) == original
    assert await db.scalar(text("SELECT current_setting('looninspect.tenant_id')")) == context
    await db.rollback()
    result = await vuln_pruning.prune_releases(db, before=before, apply=True, retire_acquisitions=True)
    assert result["deleted"] == result["acquisitionsRetired"] == 1
    await db.commit()
    assert set(await db.scalars(select(VulnCorpusAcquisition.signature))) == {previous, current}
    assert set(await db.scalars(select(VulnCorpusRelease.signature))) == {previous, current}
    await select_after_assessment(db, previous, assess=no_assessment)
    await db.commit()
    assert await pair(db) == (previous, current)


async def test_another_tenant_keeps_shared_bytes_without_keeping_expired_grant(db, chain, foreign_tenant):
    first, previous, current = chain
    with acting(FOREIGN_TENANT_ID):
        await record_acquisition(foreign_tenant, first)
        await select_after_assessment(foreign_tenant, first, assess=no_assessment)
        await foreign_tenant.commit()
    result = await vuln_pruning.prune_releases(db, before=datetime.now(UTC), apply=True, retire_acquisitions=True)
    await db.commit()
    assert result["acquisitionsRetired"] == 1 and result["deleted"] == 0
    assert set(await db.scalars(select(VulnCorpusAcquisition.signature))) == {previous, current}
    assert await db.get(VulnCorpusRelease, first) is not None
    assert await pair(foreign_tenant) == (first, None)


async def test_recent_grant_and_unknown_previous_are_conservatively_retained(db, chain):
    first, _, _ = chain
    await db.execute(
        update(VulnCorpusAcquisition)
        .where(VulnCorpusAcquisition.signature == first)
        .values(acquired_at=datetime.now(UTC) - timedelta(days=29))
    )
    await db.commit()
    result = await vuln_pruning.prune_releases(db, before=datetime.now(UTC), apply=True, retire_acquisitions=True)
    assert result["acquisitionsRetired"] == result["deleted"] == 0
    await db.execute(update(VulnCorpusAcquisition).values(acquired_at=datetime.now(UTC) - timedelta(days=60)))
    await db.execute(update(VulnCorpusSelection).values(previous_signature=None))
    await db.commit()
    result = await vuln_pruning.prune_releases(db, before=datetime.now(UTC), apply=True, retire_acquisitions=True)
    assert result["acquisitionsRetired"] == result["deleted"] == 0
    await db.commit()


async def test_command_failure_restores_retired_grants_and_release_bytes(db, chain, monkeypatch, capsys):
    original = await _archive(db)
    prune = vuln_pruning.prune_releases

    async def fail(*args, **kwargs):
        result = await prune(*args, **kwargs)
        assert result["acquisitionsRetired"] == result["deleted"] == 1
        raise SQLAlchemyError("simulated failure after retirement")

    monkeypatch.setattr(vuln_pruning, "prune_releases", fail)
    assert await vuln_pruning.run(before=datetime.now(UTC), apply=True, retire_acquisitions=True) == 1
    assert "retry the preview" in capsys.readouterr().out
    assert await _archive(db) == original
    assert set(await db.scalars(select(VulnCorpusAcquisition.signature))) == set(chain)


async def test_cleanup_waits_for_selection_and_protects_the_new_pair(db, chain):
    import asyncio

    from app.core.database import session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    entered, proceed = asyncio.Event(), asyncio.Event()

    async def assess(session, signature):
        entered.set()
        await asyncio.wait_for(proceed.wait(), timeout=5)

    async def select_first():
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
            await select_after_assessment(session, chain[0], assess=assess)
            await session.commit()

    async def cleanup():
        async with unscoped_session() as session:
            result = await vuln_pruning.prune_releases(session, before=datetime.now(UTC), apply=True, retire_acquisitions=True)
            await session.commit()
            return result

    selecting = asyncio.create_task(select_first())
    await asyncio.wait_for(entered.wait(), timeout=5)
    pruning = asyncio.create_task(cleanup())
    try:
        proceed.set()
        _, result = await asyncio.wait_for(asyncio.gather(selecting, pruning), timeout=5)
        assert result["acquisitionsRetired"] == result["deleted"] == 1
        assert await pair(db) == (chain[0], chain[2])
        assert set(await db.scalars(select(VulnCorpusAcquisition.signature))) == {chain[0], chain[2]}
    finally:
        for task in (selecting, pruning):
            if not task.done():
                task.cancel()
        await asyncio.gather(selecting, pruning, return_exceptions=True)


async def test_migration_preserves_unknown_history_and_downgrade_keeps_grants(db, chain):
    import importlib.util

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    spec = importlib.util.spec_from_file_location("rollback_migration", MIGRATION)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    connection = await db.connection()

    def exercise(sync):
        context = sync.scalar(text("SELECT current_setting('looninspect.tenant_id')"))
        sync.execute(text("CREATE SCHEMA rollback_migration_test"))
        sync.execute(
            text(
                "CREATE TABLE rollback_migration_test.vuln_corpus_acquisitions "
                "(LIKE public.vuln_corpus_acquisitions INCLUDING ALL)"
            )
        )
        sync.execute(
            text("INSERT INTO rollback_migration_test.vuln_corpus_acquisitions SELECT * FROM public.vuln_corpus_acquisitions")
        )
        sync.execute(
            text(
                "CREATE TABLE rollback_migration_test.vuln_corpus_selections AS "
                "SELECT tenant_id, signature, selected_at FROM public.vuln_corpus_selections"
            )
        )
        sync.execute(text("SET LOCAL search_path TO rollback_migration_test"))
        original = sync.execute(text("SELECT * FROM vuln_corpus_selections")).all()
        with Operations.context(MigrationContext.configure(sync)):
            migration.upgrade()
            assert sync.scalar(text("SELECT current_setting('looninspect.tenant_id')")) == context
            assert sync.scalar(text("SELECT previous_signature FROM vuln_corpus_selections")) is None
            sync.execute(text("UPDATE vuln_corpus_selections SET previous_signature = :signature"), {"signature": chain[1]})
            with pytest.raises(IntegrityError), sync.begin_nested():
                sync.execute(text("DELETE FROM vuln_corpus_acquisitions WHERE signature = :signature"), {"signature": chain[1]})
            migration.downgrade()
            assert sync.execute(text("SELECT * FROM vuln_corpus_selections")).all() == original
            assert sync.scalar(text("SELECT count(*) FROM vuln_corpus_acquisitions")) == 3

    try:
        await connection.run_sync(exercise)
    finally:
        await db.rollback()
