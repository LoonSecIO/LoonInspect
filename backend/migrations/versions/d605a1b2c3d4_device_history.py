"""Device history assessment points and tenant/account preferences (#605)."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "d605a1b2c3d4"
down_revision = "a9d4e7b2c610"
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
        "device_history_points",
        sa.Column("id", sa.Uuid(), primary_key=True),
        tenant(),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("span_id", sa.Uuid(), sa.ForeignKey("observation_spans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.Integer(), unique=True, nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assessment", pg.JSONB(), nullable=False),
        sa.Column("summary_status", sa.String(24), nullable=False),
        sa.Column("summary", sa.Text()),
        sa.Column("summary_provider", sa.String(32)),
        sa.Column("summary_reason", sa.String(64)),
    )
    op.create_index("ix_device_history_order", "device_history_points", ["tenant_id", "device_id", "collected_at", "id"])
    op.create_index("ix_device_history_points_tenant_id", "device_history_points", ["tenant_id"])
    op.create_index("ix_device_history_points_span_id", "device_history_points", ["span_id"])
    # Accounts live at home; the principal carries their stable identity across a switch.
    op.create_table(
        "device_history_preferences",
        tenant(True),
        sa.Column("account_id", sa.String(36), sa.ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("slots", pg.JSONB(), nullable=False),
    )
    for table in ("device_history_points", "device_history_preferences"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        predicate = "tenant_id = current_setting('looninspect.tenant_id')::uuid"
        op.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({predicate}) WITH CHECK ({predicate})")


def downgrade():
    op.drop_table("device_history_preferences")
    op.drop_table("device_history_points")
