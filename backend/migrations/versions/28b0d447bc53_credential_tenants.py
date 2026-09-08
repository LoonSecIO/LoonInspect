"""Which tenant a credential acts for: the one lookup that may cross tenants (#35)

Resolving a session means reading `sessions`, which is tenant-scoped like everything
else, so every request has been bound to `IDENTITY_RESOLUTION_TENANT_ID` before
authentication could run — and that constant is the operational tenant. With one
operational tenant the scope wide enough to find any session and the tenant the session
acts for are the same value; with two they are not, and a session belonging to the
second tenant could never be found.

The issue specified a `SECURITY DEFINER` function owned by a `BYPASSRLS` role: take a
token hash, return a tenant id, read nothing else. That primitive needs a role Alembic
cannot create — the application role is `NOSUPERUSER NOBYPASSRLS` by design, and the
only privileged step in this deployment model is the first-boot init script, which every
existing install has already run. So the same one-lookup surface is built without a
bypass at all: two tables outside row-level security, each holding a credential's hash
and the tenant it acts for and nothing else. A hash of a 256-bit token unlocks nothing;
the row it points to is still behind the policy on its own table; and the application
role, which already reads `tenants` whole, reads these whole too. What it cannot do is
what it never could — read another tenant's session row.

`ON DELETE CASCADE` from the credential's own row keeps the index exact: the hourly
session purge and a token's deletion take their index row with them (referential actions
run beneath row-level security, as the baseline migration notes). The backfill walks
tenants and binds each in turn, the same dance as a9d4c7e1f3b8, so no live session or
token is signed out by the upgrade.

Revision ID: 28b0d447bc53
Revises: 88a6f0da5041
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "28b0d447bc53"
down_revision: Union[str, Sequence[str], None] = "88a6f0da5041"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_INDEXES = (
    ("session_tenants", "sessions"),
    ("api_token_tenants", "api_tokens"),
)


def _for_each_tenant(statement: str) -> None:
    bind = op.get_bind()
    tenant_ids = bind.execute(sa.text("SELECT id FROM tenants")).scalars().all()
    for tenant_id in tenant_ids:
        bind.execute(sa.text("SELECT set_config('looninspect.tenant_id', :tid, true)"), {"tid": str(tenant_id)})
        bind.execute(sa.text(statement))


def upgrade() -> None:
    for table, parent in _INDEXES:
        op.create_table(
            table,
            sa.Column(
                "token_hash",
                sa.String(length=64),
                sa.ForeignKey(f"{parent}.token_hash", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )
        # Deliberately no ENABLE / FORCE ROW LEVEL SECURITY: this table is the lookup that
        # has to answer before a tenant is known.
        _for_each_tenant(
            f"INSERT INTO {table} (token_hash, tenant_id) "
            f"SELECT token_hash, tenant_id FROM {parent} WHERE revoked_at IS NULL "
            "ON CONFLICT (token_hash) DO NOTHING"
        )


def downgrade() -> None:
    for table, _parent in reversed(_INDEXES):
        op.drop_table(table)
