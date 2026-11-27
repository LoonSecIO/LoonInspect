"""Join the independent AI Activity and Snowflake additions for combined validation.

Both branches preserve the v1.3.0 schema contract. This revision changes no tables.
"""

revision = "f14000000001"
down_revision = ("b14008720001", "e848a1b2c3d4")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
