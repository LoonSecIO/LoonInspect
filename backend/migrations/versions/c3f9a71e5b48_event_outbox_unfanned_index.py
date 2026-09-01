"""event_outbox gets the partial index the bounded fan-out tick orders by

`fan_out_pending` now takes at most 1,000 rows per tick, oldest first
(`ORDER BY id LIMIT 1000`). That ordering is the reason this index exists, and the
reason it is partial.

A queue defeats the planner's uniformity assumption. Un-fanned rows are always the
newest rows, so they cluster at the *end* of id order — but the planner only knows
what fraction of the table is un-fanned, not where they are, so it expects an
`ORDER BY id LIMIT 1000` to find its thousand early and walks the primary key from the
front. It then discards the entire settled retention window before reaching the first
live row. That mis-estimate is not bad luck; it is structural, and it recurs on every
tick for as long as the backlog lasts.

Measured as the application role with the tenant GUC bound, so the RLS predicate
applies exactly as the worker runs it. 43,000 rows, 3,000 of them un-fanned:

    before   Index Scan using event_outbox_pkey ... Rows Removed by Filter: 40000
             Buffers: shared hit=1114        Execution Time: 2.479 ms
    after    Index Scan using ix_event_outbox_unfanned (no filter removal)
             Buffers: shared hit=25 read=4   Execution Time: 0.367 ms

The cost of the "before" plan scales with the settled window, not the backlog, so it
grows for the life of the deployment while the work it does stays the same size.

Partial rather than a plain (fanned_out, id) composite: the predicate is the whole
point. This index carries only rows still awaiting fan-out — 88 kB at a 3,000-event
backlog, and empty in the steady state, where the composite would index every row the
seven-day window keeps in order to describe the handful that still matter.

`outbox_deliveries` deliberately gets nothing here. The same measurement was run for
`deliver_pending`'s bounded select against a candidate
`(next_attempt_at, id) WHERE status = 'pending'`, and the planner declined it in both
regimes — it uses `ix_outbox_deliveries_status` when the due set is small (39 buffers)
and `ix_outbox_deliveries_next_attempt_at` when it is large (19 buffers). An index
nothing reads is a write cost on every delivery attempt, so it was not added.

Operators note: on an already-populated table `CREATE INDEX` takes a write lock for
the duration of the build. The predicate keeps the build proportional to the un-fanned
backlog rather than the table, so this is quick even on a large installation. It is
not built CONCURRENTLY because Alembic runs migrations inside a transaction and no
other migration in this project does either.

Revision ID: c3f9a71e5b48
Revises: d5b1e7c4a930
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c3f9a71e5b48"
down_revision: Union[str, Sequence[str], None] = "d5b1e7c4a930"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_event_outbox_unfanned",
        "event_outbox",
        ["id"],
        postgresql_where=sa.text("fanned_out IS false"),
    )


def downgrade() -> None:
    op.drop_index("ix_event_outbox_unfanned", table_name="event_outbox")
