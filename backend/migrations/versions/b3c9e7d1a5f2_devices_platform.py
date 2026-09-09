"""devices.platform — one Jamf ID space per platform (#233)

Jamf Pro numbers computers and mobile devices in separate sequences that both start
at 1, and `devices` was unique on `(mdm_connection_id, external_id)`: computer 42 and
iPad 42 would have been one row, alternating on every sweep, with every app removed
and re-added each time and the churn published to the SIEM as change. The column is
the discriminator the current-state tables never got (the ledger already keys on
`subject_kind`), and the unique constraint takes it now, while exactly one platform
exists and no duplicate can.

The vocabulary is the content-key OS spelling — `macos`, `ios`, `ipados`, `tvos`,
`visionos` (docs/mobile-devices.md §2) — not the sourcetype segment's `mac`. The default
is a fact, not a guess: every existing row is a Mac by construction.

Revision ID: b3c9e7d1a5f2
Revises: 28b0d447bc53
Create Date: 2026-09-09
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b3c9e7d1a5f2"
down_revision: Union[str, Sequence[str], None] = "28b0d447bc53"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("platform", sa.String(length=16), nullable=False, server_default="macos"),
    )
    op.drop_constraint("uq_device_connection_external_id", "devices", type_="unique")
    op.create_unique_constraint(
        "uq_device_connection_platform_external_id", "devices", ["mdm_connection_id", "platform", "external_id"]
    )


def downgrade() -> None:
    # Only safe while one platform exists: with two, the narrower key would refuse the
    # second row of every pair. Nothing enforces that here — KNOWN_ISSUES.md §6 records
    # that the downgrade path is manual and order-dependent.
    op.drop_constraint("uq_device_connection_platform_external_id", "devices", type_="unique")
    op.create_unique_constraint("uq_device_connection_external_id", "devices", ["mdm_connection_id", "external_id"])
    op.drop_column("devices", "platform")
