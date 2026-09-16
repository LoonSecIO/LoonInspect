"""subject.departure and subject.returned are default-on: every existing destination
that spells out a subscription list gets BOTH types appended (#179, ruled 2026-09-16)

The `run.failed` treatment (a9d4c7e1f3b8), not the `device.inventory` one, and the
reason is the pairing. Null and empty `subscribed_events` already mean "every event", so
those rows receive both types with no change here and touching them would narrow their
meaning; new destinations default to null and are covered the same way. A destination
that curated an explicit list predates these types and would receive **departures without
returns** — a fleet that only ever shrinks, which is worse than not subscribing at all.
The two types ship as a pair or not at all, so both are appended in one upgrade and both
come back out in one downgrade.

Revision ID: bd51c7a9e402
Revises: f1b6c48a3e29
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "bd51c7a9e402"
down_revision: Union[str, Sequence[str], None] = "f1b6c48a3e29"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Spelled out rather than imported from `app.core.wire_vocabulary`: a migration is a
# record of what ran on a given day, and an import would let a later rename silently
# rewrite history.
DEPARTURE_TYPES = ("subject.departure", "subject.returned")


def _append(event_type: str) -> str:
    """The `@>` guard is what makes the append idempotent: a re-run, or a row an admin
    already subscribed by hand, never collects a duplicate entry."""
    return (
        "UPDATE destinations "
        f"SET subscribed_events = subscribed_events || '[\"{event_type}\"]'::jsonb "
        "WHERE subscribed_events IS NOT NULL "
        "AND jsonb_typeof(subscribed_events) = 'array' "
        "AND jsonb_array_length(subscribed_events) > 0 "
        f"AND NOT subscribed_events @> '[\"{event_type}\"]'::jsonb"
    )


def _remove(event_type: str) -> str:
    return (
        "UPDATE destinations "
        f"SET subscribed_events = subscribed_events - '{event_type}' "
        "WHERE subscribed_events IS NOT NULL "
        "AND jsonb_typeof(subscribed_events) = 'array' "
        f"AND subscribed_events @> '[\"{event_type}\"]'::jsonb"
    )


# Module-level so tests can exercise the exact transformation against real rows.
ADD_DEPARTURE_TYPES = tuple(_append(event_type) for event_type in DEPARTURE_TYPES)
REMOVE_DEPARTURE_TYPES = tuple(_remove(event_type) for event_type in DEPARTURE_TYPES)


def _for_each_tenant(statements: Sequence[str]) -> None:
    """destinations is behind FORCEd row-level security with no owner bypass — an unbound
    connection raises rather than updating zero rows. So the update walks tenants and binds
    each in turn, the same dance a9d4c7e1f3b8 does; `tenants` is deliberately outside the
    policy set and readable here."""
    bind = op.get_bind()
    tenant_ids = bind.execute(sa.text("SELECT id FROM tenants")).scalars().all()
    for tenant_id in tenant_ids:
        bind.execute(sa.text("SELECT set_config('looninspect.tenant_id', :tid, true)"), {"tid": str(tenant_id)})
        for statement in statements:
            bind.execute(sa.text(statement))


def upgrade() -> None:
    _for_each_tenant(ADD_DEPARTURE_TYPES)


def downgrade() -> None:
    # Removes both entries from every explicit list, including any an admin added by hand
    # after the upgrade — a downgrade cannot tell the two apart, and leaving a then-unknown
    # type behind would fail subscribed_events validation on the next edit of the
    # destination. Both go, because half a pair is the state this migration exists to
    # prevent.
    _for_each_tenant(REMOVE_DEPARTURE_TYPES)
