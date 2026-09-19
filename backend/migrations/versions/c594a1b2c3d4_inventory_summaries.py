"""Tenant-scoped inventory summary settings, evidence state and expiring jobs (#594)."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "c594a1b2c3d4"
down_revision = "b8d4f1a6c2e7"
branch_labels = None
depends_on = None


def tenant(primary=False):
    return sa.Column(
        "tenant_id",
        sa.Uuid(),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        primary_key=primary,
        nullable=False,
        server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
    )


def upgrade():
    op.create_table(
        "inventory_summary_settings",
        tenant(True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("preprompt", sa.String(500), nullable=False),
        sa.Column("enabled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
    )
    op.create_table(
        "inventory_summary_states",
        tenant(True),
        sa.Column("device_key", sa.String(64), primary_key=True),
        sa.Column("facts", pg.JSONB(), nullable=False),
        sa.Column("source_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "inventory_summary_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        tenant(),
        sa.Column("source_id", sa.Integer(), unique=True, nullable=False),
        *[
            sa.Column(n, sa.DateTime(timezone=True), nullable=False)
            for n in ("created_at", "expires_at", "source_at", "next_attempt_at")
        ],
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("config_key", sa.String(64), nullable=False),
        sa.Column("cache_key", sa.String(64), nullable=False),
        sa.Column("evidence", pg.JSONB(), nullable=False),
        sa.Column("correlation", pg.JSONB(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("summary", sa.Text()),
        sa.Column("reason", sa.String(64)),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer()),
        sa.Column("overloads", sa.Integer(), nullable=False),
    )
    op.create_index("ix_inventory_summary_jobs_tenant_id", "inventory_summary_jobs", ["tenant_id"])
    op.create_index("ix_summary_pending", "inventory_summary_jobs", ["tenant_id", "status", "created_at"])
    op.create_index("ix_summary_cache", "inventory_summary_jobs", ["tenant_id", "cache_key", "status"])
    for table in ("inventory_summary_settings", "inventory_summary_states", "inventory_summary_jobs"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        predicate = "tenant_id = current_setting('looninspect.tenant_id')::uuid"
        op.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate})")


def downgrade():
    for table in ("inventory_summary_jobs", "inventory_summary_states", "inventory_summary_settings"):
        op.drop_table(table)
