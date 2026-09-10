"""account_tenants — which tenants an account may act for, and the switch (#36)

Ruled 2026-09-10: membership. An account lives in one tenant (its row, its password, its
home roles) and may hold roles in others through this table. Like `session_tenants` and
`api_token_tenants` (#35) it sits OUTSIDE row-level security on purpose: it is the lookup
that has to answer "which tenants may this account act for" before an acting tenant is
known, and it holds ids and role names — no PII, no secrets.

`session_tenants.home_tenant_id` says which tenant a session's own row and its account
live in when a session acts for another tenant; NULL means the acting tenant is home,
which is every session minted before this migration and every ordinary login.

`accounts.email` becomes unique across the deployment (#30's open question, answered
by the same ruling): one person is one account, in one home tenant, with memberships
elsewhere — never one account per tenant sharing an address.

Revision ID: c9f2a5e8b3d1
Revises: b8e1d4c7a2f9
Create Date: 2026-09-10
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "c9f2a5e8b3d1"
down_revision: Union[str, Sequence[str], None] = "b8e1d4c7a2f9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "account_tenants",
        sa.Column("account_id", sa.String(36), sa.ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("roles", JSONB, nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    # Deliberately no ENABLE / FORCE ROW LEVEL SECURITY: the lookup that answers before a
    # tenant is known, exactly as 28b0d447bc53 says of the credential indexes.
    op.add_column(
        "session_tenants",
        sa.Column("home_tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=True),
    )
    op.create_unique_constraint("uq_account_email", "accounts", ["email"])


def downgrade() -> None:
    op.drop_constraint("uq_account_email", "accounts", type_="unique")
    op.drop_column("session_tenants", "home_tenant_id")
    op.drop_table("account_tenants")
