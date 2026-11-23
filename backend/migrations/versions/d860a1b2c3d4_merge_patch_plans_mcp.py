"""Join the independent patch-plan and MCP migrations for v1.3.0.

Both branches are additive. Keep their revision identities so databases upgraded
through either reviewed branch can reach the same schema without replaying work.
"""

revision = "d860a1b2c3d4"
down_revision = ("b6eb2a2e4161", "c7a9e2f4b601")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
