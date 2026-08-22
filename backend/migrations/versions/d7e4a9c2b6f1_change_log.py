"""change log: device_changes and per-tenant change policies

Revision ID: d7e4a9c2b6f1
Revises: c5d2e8f1a7b4
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "d7e4a9c2b6f1"
down_revision: Union[str, Sequence[str], None] = "c5d2e8f1a7b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def _tenant_id() -> sa.Column:
    return sa.Column(
        "tenant_id",
        sa.Uuid(),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
    )


def upgrade() -> None:
    op.create_table(
        "change_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant_id(),
        sa.Column("version", sa.String(8), nullable=False),
        sa.Column("overrides", JSONB, nullable=False, server_default="{}"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by_account_id", sa.String(36), nullable=True),
        sa.UniqueConstraint("tenant_id", name="uq_change_policy_tenant"),
    )
    op.create_index("ix_change_policies_tenant_id", "change_policies", ["tenant_id"])

    op.create_table(
        "device_changes",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant_id(),
        sa.Column("mdm_connection_id", sa.Integer(), sa.ForeignKey("mdm_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject_kind", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.String(255), nullable=False),
        sa.Column("subject_label", sa.String(255), nullable=True),
        sa.Column("serial_number", sa.String(64), nullable=True),
        sa.Column("udid", sa.String(64), nullable=True),
        sa.Column("span_id", sa.Uuid(), sa.ForeignKey("observation_spans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("previous_span_id", sa.Uuid(), sa.ForeignKey("observation_spans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("section", sa.String(32), nullable=False),
        sa.Column("field", sa.String(128), nullable=True),
        sa.Column("entry_kind", sa.String(32), nullable=True),
        sa.Column("entry_identity", JSONB, nullable=True),
        sa.Column("entry_label", sa.String(255), nullable=True),
        sa.Column("change", sa.String(16), nullable=False),
        sa.Column("old_value", JSONB, nullable=True),
        sa.Column("new_value", JSONB, nullable=True),
        sa.Column("level", sa.String(8), nullable=False),
        sa.Column("details", JSONB, nullable=True),
        sa.Column("policy_version", sa.String(8), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_device_changes_tenant_id", "device_changes", ["tenant_id"])
    op.create_index("ix_device_changes_mdm_connection_id", "device_changes", ["mdm_connection_id"])
    op.create_index("ix_device_changes_level", "device_changes", ["level"])
    op.create_index("ix_device_changes_recent", "device_changes", ["tenant_id", "observed_at"])
    op.create_index(
        "ix_device_changes_subject",
        "device_changes",
        ["tenant_id", "mdm_connection_id", "subject_kind", "subject_id", "observed_at"],
    )
    op.create_index("ix_device_changes_section", "device_changes", ["tenant_id", "section", "observed_at"])

    for table in ("change_policies", "device_changes"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})"
        )


def downgrade() -> None:
    op.drop_table("device_changes")
    op.drop_table("change_policies")
