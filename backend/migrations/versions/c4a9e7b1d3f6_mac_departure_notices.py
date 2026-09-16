"""subject_departures.notice_day / removed_notified_at — what the Mac tail already said (#495)

#179's 4.5 gives a departing Mac a seven-day tail on the wire: `state: departed` with `noticeDay`
1..7, **one per UTC day**, and a guaranteed terminal `state: removed` when the tail runs out. The
census is the heartbeat and a connection can sweep every fifteen minutes, so "which day has this
Mac already been noticed on" has to be written down or the tail sends ninety-six notices a day.

`notice_day` is the last notice emitted (0 before the first). `removed_notified_at` stamps the
terminal, which is deliberately wall-clock rather than census-driven — a fleet whose sweeps were
all scoped or lossy still has Macs whose seven days ran out, and a receiver that watched a Mac
start a tail must never hold a state that silently never closes. Both are emission marks and
neither is fleet state: `left_the_fleet` still decides what Devices and the Overview show.

Existing rows backfill to 0 / NULL, which is correct rather than convenient: nothing has been sent
about them, so the next census sends the day they are actually on and the terminal fires once.

Revision ID: c4a9e7b1d3f6
Revises: c3f8a1d7e964
Create Date: 2026-09-16
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c4a9e7b1d3f6"
down_revision: Union[str, Sequence[str], None] = "c3f8a1d7e964"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "subject_departures",
        sa.Column("notice_day", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.add_column("subject_departures", sa.Column("removed_notified_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("subject_departures", "removed_notified_at")
    op.drop_column("subject_departures", "notice_day")
