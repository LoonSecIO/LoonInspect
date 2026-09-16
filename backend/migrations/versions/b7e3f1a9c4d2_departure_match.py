"""subject_departures.matched_by / prior_jamf_pro_id — how a Mac came back (#475)

A departure closed because the census named the same computer id, and one closed because it named
the same *serial* under a new id, are different events — and the second is the ordinary way a Mac
returns: a wipe and rebuild, a re-enrolment, a board repair all mint a new id and keep the serial.
`matched_by` is `jamf_id` or `serial`; `prior_jamf_pro_id` is filled only on a serial match, so a
non-null value is itself "it came back under a different id, and here is the old one" — on the row,
not derived, because #179's return event needs both and the next census recovers neither.

Revision ID: b7e3f1a9c4d2
Revises: f1b6c48a3e29
Create Date: 2026-09-16
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b7e3f1a9c4d2"
down_revision: Union[str, Sequence[str], None] = "f1b6c48a3e29"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("subject_departures", sa.Column("matched_by", sa.String(length=16), nullable=True))
    op.add_column("subject_departures", sa.Column("prior_jamf_pro_id", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("subject_departures", "prior_jamf_pro_id")
    op.drop_column("subject_departures", "matched_by")
