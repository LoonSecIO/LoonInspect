"""sweep page size on the connection: devices per computers-inventory page at full
sections, null meaning the default

Revision ID: c8e4f1a92b6d
Revises: a2f6b83d5c17
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c8e4f1a92b6d"
down_revision: Union[str, Sequence[str], None] = "a2f6b83d5c17"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("mdm_connections", sa.Column("sweep_page_size", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("mdm_connections", "sweep_page_size")
