"""data_sharing_settings: per-tenant consent for community data sharing

Revision ID: b7d3e91f4a20
Revises: 9c41d20a77e1
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "b7d3e91f4a20"
down_revision: Union[str, Sequence[str], None] = "9c41d20a77e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Matches the baseline's TENANT_GUC; written out so this migration keeps meaning
# what it meant when it ran.
_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def upgrade() -> None:
    op.create_table(
        "data_sharing_settings",
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            primary_key=True,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
        sa.Column("tier", sa.String(16), nullable=False, server_default="reveal"),
        sa.Column("submission_uuid", sa.Uuid(), nullable=False),
        sa.Column("exclude_globs", JSONB, nullable=False, server_default="[]"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Same three-part treatment as every tenant-scoped table in the baseline:
    # ENABLE, FORCE (the app role owns the table and would otherwise be exempt),
    # and WITH CHECK alongside USING.
    op.execute("ALTER TABLE data_sharing_settings ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE data_sharing_settings FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON data_sharing_settings "
        f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})"
    )


def downgrade() -> None:
    op.drop_table("data_sharing_settings")
