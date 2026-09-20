"""#621's storage foundation: retained projections survive replacement and failed writes.

Real PostgreSQL exercises the insert-on-conflict, transaction boundary and migration.
The serving gate is deliberately still the existing consent gate in this first slice.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
from pathlib import Path

import pytest
import pytest_asyncio
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import delete, select, text
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.vuln_library import load_epoch_if_new, read_bundle, store_epoch, stored_signature
from app.models.schema import (
    VulnCorpusRelease,
    VulnCorpusReleaseRow,
    VulnCorpusReleaseTitle,
    VulnLibraryEpoch,
    VulnLibraryRow,
    VulnLibraryTitle,
)
from tests.test_vuln_library import BUNDLE, SIGNATURE, WIRESHARK_BUILD, _rewritten, _row
from tests.test_vuln_library_db import _corrupt_rows, _pointer, _serving, acting_tenant, empty  # noqa: F401 — fixtures

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]
ARCHIVE = (VulnCorpusReleaseRow, VulnCorpusReleaseTitle, VulnCorpusRelease)
MIGRATION_PATH = Path(__file__).resolve().parents[1] / "migrations/versions/a621e9c4b730_retained_corpus_releases.py"


@pytest_asyncio.fixture(loop_scope="session")
async def retained(db, empty, monkeypatch):  # noqa: F811 — pytest fixture
    monkeypatch.setattr(settings, "vuln_release_retention", True)
    for model in ARCHIVE:
        await db.execute(delete(model))
    await db.commit()
    yield
    await db.rollback()
    for model in ARCHIVE:
        await db.execute(delete(model))
    await db.commit()


async def _archive(db) -> list[list[dict]]:
    return [
        [dict(row) for row in (await db.execute(select(model.__table__).order_by(*model.__table__.primary_key))).mappings()]
        for model in ARCHIVE
    ]


async def test_replacement_and_rollback_preserve_original_projection(db, retained) -> None:
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    original = await _archive(db)
    assert original[2][0]["manifest"] == read_bundle(BUNDLE, signature=SIGNATURE).manifest
    smaller, signature = _rewritten(rows=[_row()])
    await load_epoch_if_new(db, _pointer(signature), transport=_serving(smaller))
    assert await stored_signature(db) == signature
    assert await db.get(VulnLibraryRow, WIRESHARK_BUILD) is None
    assert await db.get(VulnCorpusReleaseRow, (SIGNATURE, WIRESHARK_BUILD)) is not None
    # Rollback compares digests by equality, never their ordering; do not overwrite
    # the first load clock or duplicate rows when the earlier epoch is acquired again.
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    assert await stored_signature(db) == SIGNATURE
    for before, after in zip(original, await _archive(db), strict=True):
        assert before == [row for row in after if row["signature"] == SIGNATURE]


async def test_disabled_retention_does_not_accumulate_or_change_serving(db, retained, monkeypatch) -> None:
    monkeypatch.setattr(settings, "vuln_release_retention", False)
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    assert await stored_signature(db) == SIGNATURE
    assert await _archive(db) == [[], [], []]
    # Enabling later captures both the previously installed and incoming projections.
    monkeypatch.setattr(settings, "vuln_release_retention", True)
    smaller, signature = _rewritten(rows=[_row()])
    await load_epoch_if_new(db, _pointer(signature), transport=_serving(smaller))
    releases = (await db.execute(select(VulnCorpusRelease).order_by(VulnCorpusRelease.signature))).scalars().all()
    assert {row.signature for row in releases} == {SIGNATURE, signature}
    previous = next(row for row in releases if row.signature == SIGNATURE)
    assert previous.manifest is None  # no invented provenance for an older stored projection


async def test_refused_bundle_never_enters_retention(db, retained) -> None:
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    before = await _archive(db)
    assert await load_epoch_if_new(db, _pointer("a" * 64), transport=_serving(_corrupt_rows(BUNDLE))) is None
    assert await _archive(db) == before
    assert await stored_signature(db) == SIGNATURE


async def test_failed_retention_rolls_back_active_and_archive_together(db, retained, monkeypatch, caplog) -> None:
    await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    before = await _archive(db)
    smaller, signature = _rewritten(rows=[_row()])
    from app.core import vuln_library

    original = vuln_library.retain_current_release

    async def fail_after_write(session, *, manifest=None):
        await original(session, manifest=manifest)
        if manifest is not None:
            raise SQLAlchemyError("simulated storage failure")

    monkeypatch.setattr(vuln_library, "retain_current_release", fail_after_write)
    assert await load_epoch_if_new(db, _pointer(signature), transport=_serving(smaller)) is None
    assert await stored_signature(db) == SIGNATURE
    assert await _archive(db) == before
    assert "Check database availability and free storage" in caplog.text


async def test_concurrent_imports_leave_complete_releases_and_one_active_projection(db, retained):
    from app.core.database import unscoped_session

    smaller, signature = _rewritten(rows=[_row()])

    async def publish(bundle, digest):
        async with unscoped_session() as session:
            await store_epoch(session, read_bundle(bundle, signature=digest))

    await asyncio.gather(publish(BUNDLE, SIGNATURE), publish(smaller, signature), publish(BUNDLE, SIGNATURE))
    assert set((await db.execute(select(VulnCorpusRelease.signature))).scalars()) == {SIGNATURE, signature}
    for bundle, digest in ((BUNDLE, SIGNATURE), (smaller, signature)):
        expected = read_bundle(bundle, signature=digest)
        keys = (await db.execute(select(VulnCorpusReleaseRow.key_full).where(VulnCorpusReleaseRow.signature == digest))).scalars()
        assert set(keys) == set(expected.rows)
    selected = await stored_signature(db)
    held = BUNDLE if selected == SIGNATURE else smaller
    assert set((await db.execute(select(VulnLibraryRow.key_full))).scalars()) == set(read_bundle(held, signature=selected).rows)


@pytest.mark.parametrize("installed", [False, True])
async def test_migration_preserves_installed_library_and_downgrade_only_drops_retention(db, empty, installed):  # noqa: F811
    if installed:
        await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
    # An isolated schema copies the pre-migration tables without downgrading the test
    # database underneath other tests. Rollback removes the schema even on assertion failure.
    spec = importlib.util.spec_from_file_location("retention_migration", MIGRATION_PATH)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    connection = await db.connection()

    def exercise(sync):
        sync.execute(text("CREATE SCHEMA retention_migration_test"))
        for model in (VulnLibraryEpoch, VulnLibraryRow, VulnLibraryTitle):
            name = model.__tablename__
            sync.execute(text(f"CREATE TABLE retention_migration_test.{name} (LIKE public.{name} INCLUDING ALL)"))
            sync.execute(text(f"INSERT INTO retention_migration_test.{name} SELECT * FROM public.{name}"))
        sync.execute(text("SET LOCAL search_path TO retention_migration_test"))
        with Operations.context(MigrationContext.configure(sync)):
            migration.upgrade()
            assert sync.execute(select(VulnCorpusRelease.signature)).scalars().all() == ([SIGNATURE] if installed else [])
            if installed:
                for source, target in ((VulnLibraryRow, VulnCorpusReleaseRow), (VulnLibraryTitle, VulnCorpusReleaseTitle)):
                    names = tuple(source.__table__.columns.keys())
                    old = sync.execute(select(*(getattr(source, n) for n in names)).order_by(*source.__table__.primary_key)).all()
                    new = sync.execute(
                        select(*(getattr(target, n) for n in names)).order_by(
                            *(getattr(target, n.name) for n in source.__table__.primary_key)
                        )
                    ).all()
                    assert old == new
                assert sync.execute(select(VulnCorpusRelease.manifest)).scalar_one() is None
            migration.downgrade()
            assert sync.execute(select(VulnLibraryEpoch.signature)).scalars().all() == ([SIGNATURE] if installed else [])

    try:
        await connection.run_sync(exercise)
    finally:
        await db.rollback()
