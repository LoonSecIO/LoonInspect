"""Tenant-owned encrypted fleet text, addressed by SHA-256 (#976)."""

import sqlalchemy as sa
from alembic import op

revision = "e976bf7182ac"
down_revision = "c614b3d2e8f4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    tenant = "current_setting('looninspect.tenant_id')::uuid"
    op.create_table(
        "sensitive_text",
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
                  primary_key=True, server_default=sa.text(tenant)),
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("body", sa.Text(), nullable=False),
    )
    op.execute("ALTER TABLE sensitive_text ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE sensitive_text FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON sensitive_text USING (tenant_id = {tenant}) WITH CHECK (tenant_id = {tenant})")


def downgrade() -> None:
    op.drop_table("sensitive_text")
