"""share_log table and pending reveal keys

Revision ID: e2a9c46b8d13
Revises: b7d3e91f4a20
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "e2a9c46b8d13"
down_revision: Union[str, Sequence[str], None] = "b7d3e91f4a20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def upgrade() -> None:
    op.add_column(
        "data_sharing_settings",
        sa.Column("pending_reveal_keys", JSONB, nullable=False, server_default="[]"),
    )

    op.create_table(
        "share_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tier", sa.String(16), nullable=False),
        sa.Column("endpoint", sa.String(255), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("payload", JSONB, nullable=True),
        sa.Column("reveal_requests", JSONB, nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index("ix_share_log_tenant_id", "share_log", ["tenant_id"])
    op.create_index("ix_share_log_occurred_at", "share_log", ["occurred_at"])
    op.execute("ALTER TABLE share_log ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE share_log FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON share_log "
        f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})"
    )


def downgrade() -> None:
    op.drop_table("share_log")
    op.drop_column("data_sharing_settings", "pending_reveal_keys")
