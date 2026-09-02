"""posture_snapshot names the population it counted: platform (#230)

The tape recorded numbers without recording who they were about. `posture_snapshot`
stored `(tenant_id, metric_key, value, captured_at, full_sweep_run_id)` and nothing that
says which population the number covered, and `devices` has no platform column either,
so nothing in the row and nothing it joins to could answer it.

That is true and harmless while v0 reads computers only (docs/mobile-devices.md): the
population is Macs by construction. It stops being harmless the first night a mobile
sweep writes into the same tables, and by then the fix is gone. Eleven of the 25 active
keys change population that night — the four `devices.*`, the five `catalog.*`,
`apps.distinct` and `changes.notable_24h` — and the two moves available afterwards are
both bad. Redefining a key in place is forbidden by the immutability rule and silent.
Minting `devices.macos.total` obeys the rule and starts with no history behind it, which
no-zero-priming makes permanently unbackfillable. `catalog.matched` is the sharpest of
the eleven: Jamf Patch carries macOS titles only, so an iOS app can never enter that
numerator, and patch coverage would collapse on the graph while nothing about the fleet
got worse. The five `patch.*` keys are safe for the same reason the matched key is not —
they count pairs reached through a matched title, and there are no mobile titles.

`server_default='macos'` backfills the rows pod `loon` has already captured, and is then
dropped in the same migration. Every existing row is a Mac by construction, so the
backfill is a fact rather than a guess; keeping the default afterwards would let a v5
writer that forgets to stamp record mobile numbers under the Mac population, silently,
which is the exact failure this column exists to make impossible. Without it an
unstamped INSERT is a NOT NULL violation and the night gets loud.

`uq_posture_snapshot_capture` is the uniqueness the original table never declared. Once
a v5 capture writes both a `platform='macos'` row and an `all` roll-up row for one key,
any reader filtering on `metric_key` alone silently doubles. It lands now, while there is
one row per key per capture and the constraint can be created without a cleanup pass.
Its backing index carries `(tenant_id, metric_key, platform, captured_at)` in that order,
which *is* the series read shape — one key's history for one tenant for one population,
in time order — so `ix_posture_snapshot_series` is dropped rather than widened into a
second identical four-column btree.

Revision ID: a4e1c9d7b352
Revises: b2e6f9a4c7d1
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a4e1c9d7b352"
down_revision: Union[str, Sequence[str], None] = "b2e6f9a4c7d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "posture_snapshot",
        sa.Column("platform", sa.Text(), nullable=False, server_default="macos"),
    )
    # The default did its one job — the rows already on disk are Macs. Drop it so an
    # unstamped write fails loudly instead of inheriting a population it did not count.
    op.alter_column("posture_snapshot", "platform", server_default=None)
    # The unique constraint's index is the series read shape; a separate one would be a
    # duplicate of it, column for column.
    op.drop_index("ix_posture_snapshot_series", table_name="posture_snapshot")
    op.create_unique_constraint(
        "uq_posture_snapshot_capture",
        "posture_snapshot",
        ["tenant_id", "metric_key", "platform", "captured_at"],
    )


def downgrade() -> None:
    op.create_index(
        "ix_posture_snapshot_series", "posture_snapshot", ["tenant_id", "metric_key", "captured_at"]
    )
    op.drop_constraint("uq_posture_snapshot_capture", "posture_snapshot", type_="unique")
    op.drop_column("posture_snapshot", "platform")
