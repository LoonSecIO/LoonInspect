"""device_meta on device_changes: the Mac's own dimensions, stamped at derive time (#447)

The change feed could only be filtered by what its table shows. The dimensions an operator
filters by — the model, the OS version, the department, whether the Mac is managed — live in
the ledger's sections, one join and one point-in-time problem away: joined from `devices`,
a filter would label a three-week-old change with the department the Mac is in today.

So each row carries its own, written when the row is derived, exactly as the Splunk wire
writes `deviceMeta` onto every sub-event (#189). Sixteen keys, nulls dropped;
`app.changes.derive.DEVICE_META_KEYS` is the list and the cap.

Nullable with no backfill. Every row written before this migration has no stamp and cannot
match a dimension filter — which is why `app.api.changes` states the bound rather than
letting an older row read as "not a MacBook Air". A backfill is possible (the row is derived
and the spans still hold the sections) and is deliberately not run here: it would rewrite
1.8M rows in the operator's transaction on upgrade.

No index. The dimension predicates compose with `ix_device_changes_recent`, which drives the
newest-first walk and stops early under LIMIT, and the same measurement that refused a GIN
index for the `artifact` search applies (see `app.api.changes.change_conditions`): the count
beside the page is the scan that costs, and buying it with an index that needs an extension
at migration time is the wrong trade this side of the flip.

Revision ID: c4e8b1d7a9f3
Revises: 8d13794e32f8
Create Date: 2026-09-15
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c4e8b1d7a9f3"
down_revision: Union[str, Sequence[str], None] = "8d13794e32f8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("device_changes", sa.Column("device_meta", postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column("device_changes", "device_meta")
