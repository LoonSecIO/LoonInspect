"""share log reveals_shed: the 413 path sheds the reveals and retries, so the row's
payload is a superset of the body that earned the 200 — this marks which days those were

Revision ID: c1a6f83b7e42
Revises: b3f8d2c6e9a1
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c1a6f83b7e42"
down_revision: Union[str, Sequence[str], None] = "b3f8d2c6e9a1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # NOT NULL with a false server_default: existing rows predate the marker and none
    # of them can be known to have shed, so false is the honest backfill as well as
    # the only one that lets the column be added without rewriting history.
    op.add_column(
        "share_log",
        sa.Column("reveals_shed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("share_log", "reveals_shed")
