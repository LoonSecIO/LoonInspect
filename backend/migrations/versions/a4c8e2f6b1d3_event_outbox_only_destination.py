"""event_outbox.only_destination_id — a re-emit scoped to one destination (#356)

The redrive (#91) covers the half of an outage whose events still exist. The re-emit
covers the other half: an operator-triggered run that emits the current snapshot of every
device on a connection, regardless of delta, optionally for one destination only — the
one that was down — so the re-send does not land on the destinations that were not.

Fan-out is the only reader. When the column is set, the event gets a delivery row for that
destination alone; when the destination no longer exists, the event is considered against
nothing and marked fanned out with no delivery. No foreign key, on purpose: SET NULL would
have widened a scoped re-send to every destination the day its target was deleted.

Revision ID: a4c8e2f6b1d3
Revises: d9e4b7c2a8f3
Create Date: 2026-09-10
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a4c8e2f6b1d3"
down_revision: Union[str, Sequence[str], None] = "d9e4b7c2a8f3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("event_outbox", sa.Column("only_destination_id", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("event_outbox", "only_destination_id")
