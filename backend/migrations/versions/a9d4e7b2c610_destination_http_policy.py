"""Persist each destination's HTTP choice; existing rows inherit the deployment flag."""

import sqlalchemy as sa
from alembic import op

revision = "a9d4e7b2c610"
down_revision = "c594a1b2c3d4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("destinations", sa.Column("allow_insecure_http", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("destinations", "allow_insecure_http")
