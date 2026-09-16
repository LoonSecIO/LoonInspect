"""os_build, model_identifier and cpu_arch on devices (#481)

The other two thirds of the v1 `os` content key and the whole of `hw`
(docs/data-sharing.md). Both keys were frozen and published; neither had the columns to
hash. `os_key` was called with `None` for the build on every exchange — a stable,
wrong-grained key that says one thing for every build of a point release — and `hw_key`
had no caller at all, so `snapshot["hardware"]` shipped `[]` from every container. Jamf's
aperture already admits all three fields (`operatingSystem.build`,
`hardware.modelIdentifier`, `hardware.processorArchitecture`); nothing read through it.

Nullable, and deliberately NOT backfilled — the decision a7d3e15c2b94 recorded for
`key_bundle` one revision back, for a stronger reason here: there is nothing to backfill
*from*. These are values of the Mac, not of a row this database already holds, so the only
way to learn them is to read the device. Each device stamps them on its next inventory
read, under the section that carries them (`app.mdm.service.process_sync` writes a scalar
only for a section the read's aperture covered, #98), so one full sweep does the whole
fleet. Until it runs, a fleet mid-restamp sends the build-less os key it has always sent
for the devices it has not re-read, and a `hardware` list shorter than its device count —
the same shape an older container produces, which is one case for the cloud rather than
two. NULL is "not read yet"; a device with no model identifier is absent from the hardware
rows rather than hashed over the empty string.

Unindexed, unlike `key_bundle`: these three are grouped over in one aggregate a day and
nothing joins or looks up on them. An index carried for a query nobody makes is a write
cost on every sweep.

Revision ID: c6e1b9d3a742
Revises: f1b6c48a3e29
Create Date: 2026-09-16
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c6e1b9d3a742"
down_revision: Union[str, Sequence[str], None] = "f1b6c48a3e29"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("os_build", sa.String(32), nullable=True))
    op.add_column("devices", sa.Column("model_identifier", sa.String(64), nullable=True))
    op.add_column("devices", sa.Column("cpu_arch", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "cpu_arch")
    op.drop_column("devices", "model_identifier")
    op.drop_column("devices", "os_build")
