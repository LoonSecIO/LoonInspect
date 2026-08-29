"""run.failed is default-on: every existing destination that spells out a
subscription list gets the new type appended, so a failed run is loud everywhere
unless an org deliberately unsubscribes (#103)

Null and empty `subscribed_events` already mean "every event" — fan-out treats them as
unfiltered — so those rows receive run.failed with no change here, and touching them
would narrow their meaning. New destinations default to null and are covered the same
way. Only the rows that opted into an explicit list predate this event and would
silently never hear about a failure; those get the append.

Revision ID: a9d4c7e1f3b8
Revises: e6c9a2f4b8d1
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a9d4c7e1f3b8"
down_revision: Union[str, Sequence[str], None] = "e6c9a2f4b8d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Module-level rather than inline so tests can exercise the exact transformation
# against real rows. The `@>` guard makes the append idempotent: a re-run, or a row
# an admin already subscribed by hand, never collects a duplicate entry.
ADD_RUN_FAILED = (
    "UPDATE destinations "
    "SET subscribed_events = subscribed_events || '[\"run.failed\"]'::jsonb "
    "WHERE subscribed_events IS NOT NULL "
    "AND jsonb_typeof(subscribed_events) = 'array' "
    "AND jsonb_array_length(subscribed_events) > 0 "
    "AND NOT subscribed_events @> '[\"run.failed\"]'::jsonb"
)

REMOVE_RUN_FAILED = (
    "UPDATE destinations "
    "SET subscribed_events = subscribed_events - 'run.failed' "
    "WHERE subscribed_events IS NOT NULL "
    "AND jsonb_typeof(subscribed_events) = 'array' "
    "AND subscribed_events @> '[\"run.failed\"]'::jsonb"
)


def _for_each_tenant(statement: str) -> None:
    """destinations is behind FORCEd row-level security with no owner bypass — an
    unbound connection raises rather than updating zero rows (the baseline migration
    documents why). So the update walks tenants and binds each in turn, the same dance
    as the content-keys and collections migrations; `tenants` itself is deliberately
    outside the policy set and readable here."""
    bind = op.get_bind()
    tenant_ids = bind.execute(sa.text("SELECT id FROM tenants")).scalars().all()
    for tenant_id in tenant_ids:
        bind.execute(
            sa.text("SELECT set_config('looninspect.tenant_id', :tid, true)"),
            {"tid": str(tenant_id)},
        )
        bind.execute(sa.text(statement))


def upgrade() -> None:
    _for_each_tenant(ADD_RUN_FAILED)


def downgrade() -> None:
    # Removes the entry from every explicit list, including any an admin added by
    # hand after the upgrade — a downgrade cannot tell the two apart, and leaving a
    # then-unknown type behind would fail subscribed_events validation on the next
    # edit of the destination.
    _for_each_tenant(REMOVE_RUN_FAILED)
