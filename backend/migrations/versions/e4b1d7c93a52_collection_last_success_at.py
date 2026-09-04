"""last_success_at on the collection: when it last succeeded, not when it was last
attempted — the mark the staleness check needs and that last_run_at cannot carry (#106)

Revision ID: e4b1d7c93a52
Revises: d7e3b9c5a1f4
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e4b1d7c93a52"
down_revision: Union[str, Sequence[str], None] = "d7e3b9c5a1f4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Seed from the cached outcome the row already carries. A row whose last run is recorded
# as ok did succeed at that instant — `last_run_at` is the attempt's start, which is
# exactly what the forward path writes into the new column — so this is a transcription,
# not a guess. Without it every existing pod would call its whole fleet stale on the
# first page load after upgrading, until each collection happened to run again.
#
# Idempotent by the IS NULL guard: a re-run touches nothing, and neither does a row that
# has succeeded since.
SEED_FROM_THE_LAST_OK_RUN = (
    "UPDATE collections SET last_success_at = last_run_at "
    "WHERE last_success_at IS NULL AND last_run_status = 'ok' AND last_run_at IS NOT NULL"
)


def _for_each_tenant(statement: str) -> None:
    """`collections` is behind FORCEd row-level security with no owner bypass — an
    unbound connection raises rather than updating zero rows. Same dance as the
    consent-defaults and run.failed migrations: walk `tenants`, which is deliberately
    outside the policy set, and bind each in turn."""
    bind = op.get_bind()
    for tenant_id in bind.execute(sa.text("SELECT id FROM tenants")).scalars().all():
        bind.execute(sa.text("SELECT set_config('looninspect.tenant_id', :tid, true)"), {"tid": str(tenant_id)})
        bind.execute(sa.text(statement))


def upgrade() -> None:
    op.add_column("collections", sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True))
    _for_each_tenant(SEED_FROM_THE_LAST_OK_RUN)


def downgrade() -> None:
    op.drop_column("collections", "last_success_at")
