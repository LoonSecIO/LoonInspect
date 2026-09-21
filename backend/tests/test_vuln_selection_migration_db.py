"""Upgrade acquires only the installed release for consenting tenants; selection waits (#621)."""

from __future__ import annotations

import importlib.util
import os
import uuid
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import insert, select, text

from app.core.config import settings
from app.core.vuln_library import load_epoch_if_new
from app.models.schema import DataSharingSettings, Tenant, VulnCorpusAcquisition, VulnCorpusRelease, VulnCorpusSelection
from tests.test_vuln_library import BUNDLE, SIGNATURE, _rewritten, _row
from tests.test_vuln_library_db import _pointer, _serving, acting_tenant, empty  # noqa: F401 — fixtures
from tests.test_vuln_retention_db import retained  # noqa: F401 — fixtures

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]
MIGRATION = Path(__file__).resolve().parents[1] / "migrations/versions/b621d8a4f930_tenant_corpus_selection.py"
TABLES = (
    "tenants",
    "data_sharing_settings",
    "vuln_library_epoch",
    "vuln_library_rows",
    "vuln_library_titles",
    "vuln_corpus_releases",
    "vuln_corpus_release_rows",
    "vuln_corpus_release_titles",
)


@pytest.mark.parametrize("installed", [False, True])
async def test_only_existing_contributors_acquire_current_projection_without_inventing_selection(
    db,
    retained,  # noqa: F811 — fixture
    installed,
    monkeypatch,
):
    current = None
    if installed:
        await load_epoch_if_new(db, _pointer(), transport=_serving(BUNDLE))
        # The active corpus can change while retention is disabled between upgrades.
        monkeypatch.setattr(settings, "vuln_release_retention", False)
        newer, current = _rewritten(rows=[_row()])
        await load_epoch_if_new(db, _pointer(current), transport=_serving(newer))
    spec = importlib.util.spec_from_file_location("selection_migration", MIGRATION)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    connection = await db.connection()

    def exercise(sync):
        sync.execute(text("CREATE SCHEMA selection_migration_test"))
        for name in TABLES:
            sync.execute(text(f"CREATE TABLE selection_migration_test.{name} (LIKE public.{name} INCLUDING ALL)"))
            if name not in ("tenants", "data_sharing_settings"):
                sync.execute(text(f"INSERT INTO selection_migration_test.{name} SELECT * FROM public.{name}"))
        sync.execute(text("SET LOCAL search_path TO selection_migration_test"))
        sync.execute(text("ALTER TABLE data_sharing_settings ENABLE ROW LEVEL SECURITY"))
        sync.execute(text("ALTER TABLE data_sharing_settings FORCE ROW LEVEL SECURITY"))
        sync.execute(
            text(
                "CREATE POLICY tenant_isolation ON data_sharing_settings "
                "USING (tenant_id = current_setting('looninspect.tenant_id')::uuid) "
                "WITH CHECK (tenant_id = current_setting('looninspect.tenant_id')::uuid)"
            )
        )
        cases = [(uuid.UUID(int=62100 + n), tier) for n, tier in enumerate(("keys", "reveal", "off", None))]
        for tenant, tier in cases:
            sync.execute(insert(Tenant).values(id=tenant, slug=str(tenant), name="selection-migration", kind="operational"))
            sync.execute(text("SELECT set_config('looninspect.tenant_id', :tenant, true)"), {"tenant": str(tenant)})
            if tier is not None:
                sync.execute(insert(DataSharingSettings).values(tier=tier))
        before_tenant = sync.scalar(text("SELECT current_setting('looninspect.tenant_id')"))
        with Operations.context(MigrationContext.configure(sync)):
            migration.upgrade()
            assert sync.scalar(text("SELECT current_setting('looninspect.tenant_id')")) == before_tenant
            for tenant, tier in cases:
                sync.execute(text("SELECT set_config('looninspect.tenant_id', :tenant, true)"), {"tenant": str(tenant)})
                grants = sync.execute(select(VulnCorpusAcquisition.signature, VulnCorpusAcquisition.basis)).all()
                assert grants == ([(current, "legacy_consent")] if installed and tier in ("keys", "reveal") else [])
                assert sync.execute(select(VulnCorpusSelection.signature)).first() is None
                assert sync.scalar(select(DataSharingSettings.tier)) == tier
            if installed:
                assert set(sync.execute(select(VulnCorpusRelease.signature)).scalars()) == {SIGNATURE, current}
                assert sync.scalar(select(VulnCorpusRelease.manifest).where(VulnCorpusRelease.signature == current)) is None
            policies = sync.execute(
                text(
                    "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE relnamespace = 'selection_migration_test'::regnamespace "
                    "AND relname IN ('vuln_corpus_acquisitions','vuln_corpus_selections')"
                )
            ).all()
            assert len(policies) == 2 and all(enabled and forced for _, enabled, forced in policies)
            migration.downgrade()
            assert sync.scalar(text("SELECT signature FROM vuln_library_epoch")) == current
            assert sync.scalar(select(DataSharingSettings.tier)) is None  # never-configured tenant stays absent

    try:
        await connection.run_sync(exercise)
    finally:
        await db.rollback()
