"""When LoonSec last confirmed its patch-policy document current, beside the feed's state (#614).

`patch_policy_feed_state.built_at`: the `built_at` the exchange's `patch_policy` entry carries,
written with the attempt that found the document current (`stored` or `unchanged`). The page's
`stale` state is judged from it when it is known, and from the held copy's own `as_of` when it is
not, which is how every row written before this column reads.

Additive only: one nullable column on a table an earlier release reads and never writes with
this name. Downgrade drops it; the next exchange after an upgrade writes it again.

Revision ID: c614b3d2e8f4
Revises: c614a2f1e7d3
Create Date: 2026-11-24
"""

import sqlalchemy as sa
from alembic import op

revision = "c614b3d2e8f4"
down_revision = "c614a2f1e7d3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("patch_policy_feed_state", sa.Column("built_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("patch_policy_feed_state", "built_at")
