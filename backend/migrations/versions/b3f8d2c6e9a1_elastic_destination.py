"""elastic destination: the index (or data stream) a bulk POST targets, null meaning
the data-stream-friendly default

Revision ID: b3f8d2c6e9a1
Revises: f8b2d4a6c1e9
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b3f8d2c6e9a1"
down_revision: Union[str, Sequence[str], None] = "f8b2d4a6c1e9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("destinations", sa.Column("elastic_index", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("destinations", "elastic_index")
