"""alerts.closed_reason — which of the two closes this was (#476)

A `new_app` latch closed because the app went, and one closed because the Mac left the fleet at
the end of #183's seven-day tail, are different facts wearing one `closed_at`. Nothing else tells
them apart: the app-gone close deletes the `installed_apps` row as part of the close, while the
departure close deletes nothing — the row, the spans and the change history all stay (erasure is
#180, v5) — so a closed latch on a departed Mac would read as an uninstall that never happened.

Nullable and not back-filled. A row closed before this column existed carries no reason because
none was recorded, and inventing one would be the tape's own failure mode — a value that reads as
evidence and is a guess.

Revision ID: c3f8a1d7e964
Revises: b7e3f1a9c4d2
Create Date: 2026-09-16
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c3f8a1d7e964"
down_revision: Union[str, Sequence[str], None] = "b7e3f1a9c4d2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("closed_reason", sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column("alerts", "closed_reason")
