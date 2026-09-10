"""patching_policies — the org states its patching policy, as typed text (#116)

One row per tenant, created on first write: the statement an auditor reads beside the
measured numbers on the Jamf Patch page ("we require every update to the latest version
within 2 weeks, or the latest the hardware supports"). Display and evidence context only —
never a threshold. Fixed-target comparisons still require a ruled policy
(docs/v-never.md), and the day an org-stated target is legitimized is a separate ruling.

Revision ID: b8e1d4c7a2f9
Revises: a4c8e2f6b1d3
Create Date: 2026-09-10
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b8e1d4c7a2f9"
down_revision: Union[str, Sequence[str], None] = "a4c8e2f6b1d3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def upgrade() -> None:
    op.create_table(
        "patching_policies",
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            primary_key=True,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
        sa.Column("statement", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(255), nullable=True),
    )
    op.execute("ALTER TABLE patching_policies ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE patching_policies FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON patching_policies USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    op.drop_table("patching_policies")
