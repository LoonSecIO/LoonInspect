"""page size on the collection: a narrow collection may take bigger pages than the
connection's full-section worst case, null inheriting the connection

Revision ID: d9f3b6e21a7c
Revises: c8e4f1a92b6d
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d9f3b6e21a7c"
down_revision: Union[str, Sequence[str], None] = "c8e4f1a92b6d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("collections", sa.Column("page_size", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("collections", "page_size")
