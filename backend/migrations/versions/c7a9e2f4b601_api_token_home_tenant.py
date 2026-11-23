"""Keep switched-organization API tokens beside their owner's home account.

The credential index names both the acting organization and the home organization,
matching session_tenants. NULL preserves all existing same-organization credentials.
This is additive; the existing minimum-readable-release stamp remains unchanged.
Older images still read ordinary tokens and refuse new cross-organization tokens.
"""

import sqlalchemy as sa
from alembic import op

revision = "c7a9e2f4b601"
down_revision = "b13008520001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "api_token_tenants",
        sa.Column("home_tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("api_token_tenants", "home_tenant_id")
