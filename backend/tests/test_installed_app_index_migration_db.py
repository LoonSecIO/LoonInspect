"""The tenant/device lookup index preserves populated rows and RLS across upgrade/rollback."""

import importlib.util
import os
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import text

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres"),
    pytest.mark.asyncio(loop_scope="session"),
]

MIGRATION = Path(__file__).resolve().parents[1] / "migrations/versions/e621c4a8b903_installed_apps_tenant_device.py"


async def test_populated_index_upgrade_downgrade_preserves_answers_and_isolation(db):
    spec = importlib.util.spec_from_file_location("installed_app_index", MIGRATION)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    def exercise(connection):
        connection.execute(text("CREATE SCHEMA installed_app_index_test"))
        connection.execute(text("SET LOCAL search_path TO installed_app_index_test"))
        connection.execute(
            text(
                "CREATE TABLE installed_apps (tenant_id uuid NOT NULL, device_id integer NOT NULL, "
                "vuln_counts jsonb, vuln_signature text)"
            )
        )
        connection.execute(text("CREATE INDEX ix_installed_apps_tenant_id ON installed_apps (tenant_id)"))
        connection.execute(text("ALTER TABLE installed_apps ENABLE ROW LEVEL SECURITY"))
        connection.execute(text("ALTER TABLE installed_apps FORCE ROW LEVEL SECURITY"))
        connection.execute(
            text(
                "CREATE POLICY tenant_isolation ON installed_apps "
                "USING (tenant_id = current_setting('looninspect.tenant_id')::uuid) "
                "WITH CHECK (tenant_id = current_setting('looninspect.tenant_id')::uuid)"
            )
        )
        tenants = ["00000000-0000-0000-0000-000000062101", "00000000-0000-0000-0000-000000062102"]
        for tenant in tenants:
            connection.execute(text("SELECT set_config('looninspect.tenant_id', :tenant, true)"), {"tenant": tenant})
            connection.execute(
                text("INSERT INTO installed_apps VALUES (:tenant, 1, '{\"total\":\"unreadable\"}', 'held-release')"),
                {"tenant": tenant},
            )
        with Operations.context(MigrationContext.configure(connection)):
            for operation in (migration.upgrade, migration.downgrade, migration.upgrade):
                operation()
                for tenant in tenants:
                    connection.execute(text("SELECT set_config('looninspect.tenant_id', :tenant, true)"), {"tenant": tenant})
                    rows = connection.execute(
                        text("SELECT tenant_id::text, vuln_counts, vuln_signature FROM installed_apps")
                    ).all()
                    assert rows == [(tenant, {"total": "unreadable"}, "held-release")]
            connection.execute(text("SET LOCAL enable_seqscan = off"))
            plan = connection.scalar(text("EXPLAIN (FORMAT JSON) SELECT * FROM installed_apps WHERE device_id = 1"))[0]["Plan"]
            assert plan["Index Name"] == "ix_installed_apps_tenant_device"
            assert "tenant_id" in plan["Index Cond"] and "device_id" in plan["Index Cond"]

    try:
        await (await db.connection()).run_sync(exercise)
    finally:
        await db.rollback()
