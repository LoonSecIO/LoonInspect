"""community data sharing defaults to off: consent is something someone wrote, never
something we assumed

Two halves. The column default moves 'reveal' -> 'off', so a row created by anything
other than an answered question is a row that does not share — the ORM always supplies
the value, but a schema whose stated default is the most permissive tier is a loaded
gun left for the next hand-written INSERT.

The second half is the backfill, and it is the one worth arguing about. A row with
`updated_at IS NULL` was never written by an operator action: until this change, the
wizard's *unchecked* box issued a PUT (which stamps `updated_at`) while its *checked*
box wrote nothing at all, and a container bootstrapped from INITIAL_ADMIN_* — or one
nobody has signed into yet — got its row materialized by the exchange tick reading it.
So a null `updated_at` covers both "never asked" and "asked, said yes, and we didn't
write it down", and nothing in the schema separates them. Consent that cannot be
produced is not consent, and the side to err on when the data is device inventory from
identifiable employees' machines is off. The cost is real and one-directional: an
operator who did tick the box re-ticks it under Settings → Data Sharing, where the
answer is now recorded.

Revision ID: d5b1e7c4a930
Revises: b4d17e9c3a25
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d5b1e7c4a930"
down_revision: Union[str, Sequence[str], None] = "b4d17e9c3a25"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Idempotent by the `<> 'off'` guard, like the run.failed migration's `@>` guard: a
# re-run touches nothing, and neither does a row an admin has since turned off.
WITHDRAW_UNRECORDED_CONSENT = (
    "UPDATE data_sharing_settings SET tier = 'off' WHERE updated_at IS NULL AND tier <> 'off'"
)


def _for_each_tenant(statement: str) -> None:
    """data_sharing_settings is behind FORCEd row-level security with no owner bypass —
    an unbound connection raises rather than updating zero rows. Same dance as the
    run.failed and content-keys migrations: walk `tenants`, which is deliberately
    outside the policy set, and bind each in turn."""
    bind = op.get_bind()
    tenant_ids = bind.execute(sa.text("SELECT id FROM tenants")).scalars().all()
    for tenant_id in tenant_ids:
        bind.execute(
            sa.text("SELECT set_config('looninspect.tenant_id', :tid, true)"),
            {"tid": str(tenant_id)},
        )
        bind.execute(sa.text(statement))


def upgrade() -> None:
    op.execute("ALTER TABLE data_sharing_settings ALTER COLUMN tier SET DEFAULT 'off'")
    _for_each_tenant(WITHDRAW_UNRECORDED_CONSENT)


def downgrade() -> None:
    # The default comes back; the flipped rows do not. A downgrade cannot tell a row
    # this migration turned off from one an admin turned off, and inventing consent on
    # the way down would be a worse bug than the one on the way up.
    op.execute("ALTER TABLE data_sharing_settings ALTER COLUMN tier SET DEFAULT 'reveal'")
