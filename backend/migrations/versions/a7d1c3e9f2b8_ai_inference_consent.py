"""AI-inference consent on the data-sharing settings row: the flag turns the AI
feature area on, this governs whether any byte may leave the pod for inference

Revision ID: a7d1c3e9f2b8
Revises: e6c9a2f4b8d1
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a7d1c3e9f2b8"
down_revision: Union[str, Sequence[str], None] = "e6c9a2f4b8d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "data_sharing_settings",
        sa.Column("ai_inference", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("data_sharing_settings", "ai_inference")
