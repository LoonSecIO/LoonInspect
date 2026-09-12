"""share log trigger: an exchange row says whether the schedule or an administrator's
Send now started it (#408)

Before Send now, the tick was the only thing that could write an exchange row, so the log
never had to say why a row existed. Now two rows can land on one day, beside a document
that says one conversation per tenant per day, and the row itself has to carry the reason.

Nullable, because the AI-inference rows that share this log are not exchanges and have no
trigger to state. Every exchange row that already exists was written by the tick — there
was no other writer — so `scheduled` is the honest backfill, and the AI rows keep NULL.

The backfill walks tenants and binds each in turn, the same dance as 88a6f0da5041: the
table is behind FORCEd row-level security with no owner bypass, and an unbound UPDATE
raises rather than touching zero rows.

Revision ID: f4c8a2d6e1b3
Revises: b3e7c1d5f9a2
Create Date: 2026-09-12
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f4c8a2d6e1b3"
down_revision: Union[str, Sequence[str], None] = "b3e7c1d5f9a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

BACKFILL = "UPDATE share_log SET trigger = 'scheduled' WHERE tier <> 'ai' AND trigger IS NULL"


def _for_each_tenant(statement: str) -> None:
    bind = op.get_bind()
    tenant_ids = bind.execute(sa.text("SELECT id FROM tenants")).scalars().all()
    for tenant_id in tenant_ids:
        bind.execute(sa.text("SELECT set_config('looninspect.tenant_id', :tid, true)"), {"tid": str(tenant_id)})
        bind.execute(sa.text(statement))


def upgrade() -> None:
    op.add_column("share_log", sa.Column("trigger", sa.String(16), nullable=True))
    _for_each_tenant(BACKFILL)


def downgrade() -> None:
    op.drop_column("share_log", "trigger")
