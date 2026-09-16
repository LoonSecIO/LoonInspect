"""subject_departures.matched_by / prior_jamf_pro_id — how a Mac came back (#475)

A departure closed because the census named the same computer id, and one closed because it named
the same *serial and UDID* under a new id, are different events — and the second is the ordinary way
a Mac returns: a wipe and rebuild or a re-enrolment mints a new id and keeps both hardware keys.
`matched_by` is `jamfProID` or `serialNumber`, the spelling #179's `matchedBy` carries; on a serial
match the row is re-keyed to the id the Mac came back under and `prior_jamf_pro_id` holds the id it
departed under, which is `priorJamfProID` on the wire and the only thing saying that old id is dead
in Jamf — it must never re-enter a census population, or it departs once every two sweeps, and a
census that names it again clears it rather than leaving a live Mac out of the fleet for good.

Revision ID: b7e3f1a9c4d2
Revises: b3e7d1a9c5f0
Create Date: 2026-09-16
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b7e3f1a9c4d2"
down_revision: Union[str, Sequence[str], None] = "b3e7d1a9c5f0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("subject_departures", sa.Column("matched_by", sa.String(length=16), nullable=True))
    op.add_column("subject_departures", sa.Column("prior_jamf_pro_id", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("subject_departures", "prior_jamf_pro_id")
    op.drop_column("subject_departures", "matched_by")
