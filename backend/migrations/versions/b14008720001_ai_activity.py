"""Expand AI usage with stable service identity and metadata-only lifecycle facts.

The v1.3 daily table and its primary key remain compatible with old writers/readers.
"""

import sqlalchemy as sa
from alembic import op

revision = "b14008720001"
down_revision = "d860a1b2c3d4"
branch_labels = None
depends_on = None
MIN_READABLE_RELEASE = "v1.3.0"
# release-note: Additive AI metadata; v1.3.0 remains the rollback floor. Earlier releases need their backup.


def tenant(primary=False):
    return sa.Column(
        "tenant_id",
        sa.Uuid(),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        primary_key=primary,
        nullable=False,
        server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
    )


def identity():
    return [
        sa.Column(name, sa.String(size), nullable=False)
        for name, size in (("feature", 64), ("provider", 32), ("service_id", 64), ("service_label", 80), ("service_kind", 24))
    ]


def timestamp(name, nullable=True):
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade():
    op.add_column(
        "ai_provider_configs", sa.Column("service_id", sa.Uuid(), nullable=True, server_default=sa.text("gen_random_uuid()"))
    )
    for name, kind in (("service_label", sa.String(64)), ("service_kind", sa.String(24))):
        op.add_column("ai_provider_configs", sa.Column(name, kind, nullable=True))
    op.create_table(
        "ai_usage_work",
        sa.Column("id", sa.Uuid(), primary_key=True),
        tenant(),
        *identity(),
        sa.Column("requested", sa.String(200), nullable=False, server_default=""),
        timestamp("arrived_at", False),
        timestamp("started_at"),
        timestamp("finished_at"),
        timestamp("deadline_at", False),
        sa.Column("outcome", sa.String(32), nullable=False, server_default="waiting"),
        sa.Column("reason", sa.String(64)),
    )
    op.create_table(
        "ai_usage_attempts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        tenant(),
        sa.Column("work_id", sa.Uuid(), nullable=False),
        *identity(),
        *(sa.Column(n, sa.String(200), nullable=False, server_default="") for n in ("requested", "reported")),
        timestamp("started_at", False),
        timestamp("dispatched_at"),
        timestamp("finished_at"),
        sa.Column("outcome", sa.String(64), nullable=False, server_default="waiting"),
        sa.Column("legacy_outcome", sa.String(64)),
        sa.Column("work_outcome", sa.String(32)),
        sa.Column("attempt_number", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("fallback", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status_code", sa.Integer()),
        *(
            sa.Column(n, sa.BigInteger())
            for n in ("wait_ms", "request_ms", "total_ms", "input_tokens", "output_tokens", "cached_tokens", "provider_ms")
        ),
    )
    op.create_table(
        "ai_usage_coverage",
        tenant(True),
        timestamp("first_measured_at", False),
        timestamp("last_recorded_at", False),
        timestamp("degraded_since"),
        timestamp("last_gap_at"),
    )
    for table, window in (("ai_usage_work", "arrived_at"), ("ai_usage_attempts", "started_at"), ("ai_usage_coverage", None)):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        rule = "tenant_id = current_setting('looninspect.tenant_id')::uuid"
        op.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({rule}) WITH CHECK ({rule})")
        if window:
            op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])
    op.create_index("ix_ai_work_window", "ai_usage_work", ["tenant_id", "arrived_at"])
    op.create_index("ix_ai_attempt_window", "ai_usage_attempts", ["tenant_id", "started_at"])
    op.create_index("ix_ai_work_finished", "ai_usage_work", ["tenant_id", "finished_at"])
    op.create_index("ix_ai_attempt_finished", "ai_usage_attempts", ["tenant_id", "finished_at"])
    op.create_index("ix_ai_usage_attempts_work_id", "ai_usage_attempts", ["work_id"])
    op.execute("UPDATE schema_release SET min_readable_release = 'v1.3.0' WHERE id = 1")


def downgrade():
    for table in ("ai_usage_attempts", "ai_usage_work", "ai_usage_coverage"):
        op.drop_table(table)
    for name in ("service_kind", "service_label", "service_id"):
        op.drop_column("ai_provider_configs", name)
    op.execute("UPDATE schema_release SET min_readable_release = 'v1.3.0' WHERE id = 1")
