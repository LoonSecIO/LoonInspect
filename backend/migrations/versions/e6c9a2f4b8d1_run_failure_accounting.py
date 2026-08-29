"""failure accounting on the run: devices processed and devices failed, so a run that
survives isolated device failures can say so instead of hiding them in `succeeded`

Revision ID: e6c9a2f4b8d1
Revises: d9f3b6e21a7c
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e6c9a2f4b8d1"
down_revision: Union[str, Sequence[str], None] = "d9f3b6e21a7c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default rather than backfill: rows that predate per-device isolation
    # recorded no failures, and zero is the honest reading of that history.
    op.add_column(
        "runs", sa.Column("devices_processed", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column(
        "runs", sa.Column("devices_failed", sa.Integer(), nullable=False, server_default="0")
    )


def downgrade() -> None:
    op.drop_column("runs", "devices_failed")
    op.drop_column("runs", "devices_processed")
