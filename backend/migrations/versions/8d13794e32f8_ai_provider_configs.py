"""ai_provider_configs — a Settings > AI card's Save, kept (the Changes Prompt bar)

One row per provider per tenant: the endpoint URL as judged, the model, the host reach and
reasoning effort the card chose, and the key encrypted like a Jamf client secret (Fernet,
app.core.crypto — declared TEXT here because Alembic does not see the type decorator).
Until now the key travelled browser → process → endpoint on every test and nothing was
stored; a feature a viewer can use needs the endpoint without the admin in the loop
(ruled by Kyle, 2026-09-14: configs saved server-side, keys encrypted).

Revision ID: 8d13794e32f8
Revises: e6b2d9f4a8c1
Create Date: 2026-09-14
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "8d13794e32f8"
down_revision: Union[str, Sequence[str], None] = "e6b2d9f4a8c1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def upgrade() -> None:
    op.create_table(
        "ai_provider_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("host_reach", sa.String(32), nullable=True),
        sa.Column("base_url", sa.String(255), nullable=False),
        sa.Column("model", sa.String(200), nullable=False),
        sa.Column("reasoning_effort", sa.String(16), nullable=True),
        sa.Column("api_key_encrypted", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=True),
        sa.UniqueConstraint("tenant_id", "provider", name="uq_ai_provider_configs_tenant_provider"),
    )
    op.execute("ALTER TABLE ai_provider_configs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ai_provider_configs FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON ai_provider_configs USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    op.drop_table("ai_provider_configs")
