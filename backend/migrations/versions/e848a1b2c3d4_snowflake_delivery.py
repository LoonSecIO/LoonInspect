"""Durable native Snowflake delivery and tenant-scoped source identity (#848).

Additive columns and forced-RLS tables; existing destination delivery is unchanged.
Unresolved batches retain their immutable event bytes until committed row accounting.

Revision ID: e848a1b2c3d4
Revises: d860a1b2c3d4
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "e848a1b2c3d4"
down_revision = "d860a1b2c3d4"
branch_labels = None
depends_on = None
MIN_READABLE_RELEASE = "v1.3.0"

_TENANT = "current_setting('looninspect.tenant_id')::uuid"
_PREDICATE = f"tenant_id = {_TENANT}"


def upgrade() -> None:
    op.execute(f"UPDATE schema_release SET min_readable_release = '{MIN_READABLE_RELEASE}' WHERE id = 1")
    # Separate ADD from SET DEFAULT: a volatile UUID default on ADD would rewrite
    # every retained event, including installations that never enable Snowflake.
    # Legacy null identities are assigned under the tenant worker lock on export.
    op.add_column("event_outbox", sa.Column("export_event_id", sa.Uuid(), nullable=True))
    op.alter_column("event_outbox", "export_event_id", server_default=sa.text("gen_random_uuid()"))
    op.add_column("destinations", sa.Column("snowflake_config", JSONB(), nullable=True))
    op.add_column(
        "outbox_deliveries", sa.Column("snowflake_single_row", sa.Boolean(), nullable=False, server_default=sa.text("false"))
    )
    op.create_table(
        "snowflake_sources",
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            primary_key=True,
            server_default=sa.text(_TENANT),
        ),
        sa.Column("source_id", sa.Uuid(), nullable=False),
    )
    op.create_table(
        "snowflake_batches",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
            server_default=sa.text(_TENANT),
        ),
        sa.Column(
            "destination_id", sa.Integer(), sa.ForeignKey("destinations.id", ondelete="CASCADE"), nullable=False, unique=True
        ),
        sa.Column("delivery_ids", JSONB(), nullable=False),
        sa.Column("source_keys", JSONB(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("baseline", JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_snowflake_batches_tenant_id", "snowflake_batches", ["tenant_id"])
    for table in ("snowflake_sources", "snowflake_batches"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    op.execute("UPDATE schema_release SET min_readable_release = 'v1.3.0' WHERE id = 1")
    op.drop_table("snowflake_batches")
    op.drop_table("snowflake_sources")
    op.drop_column("outbox_deliveries", "snowflake_single_row")
    op.drop_column("destinations", "snowflake_config")
    op.drop_column("event_outbox", "export_event_id")
