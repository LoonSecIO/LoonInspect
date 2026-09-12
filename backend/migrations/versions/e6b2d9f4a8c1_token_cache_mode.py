"""what a connection keeps of its Jamf Pro sign-in between runs (#412)

Every webhook built a new client and signed in from scratch — a token exchange and a TLS
handshake, about 350–380 ms of a ~1 s webhook, and one token request per webhook against a
tenant that rate-limits them. The connection now chooses what it keeps: `no_cache` (the old
behaviour), `cache_and_hold` (its token and a pooled connection, reused while the token is
live) or `perpetual` (the same, renewed before the token expires). app.mdm.jamf.sign_in has
the three and what each costs Jamf.

Non-null, with the default as the server default — ruled by Kyle, 2026-09-12 — so every
connection that exists before this migration comes up in `cache_and_hold`, the way
`collections.enabled` came up on (c5d2e8f1a7b4). A check constraint keeps the column to the
three words the code knows, rather than trusting every writer to.

Revision ID: e6b2d9f4a8c1
Revises: b3e7c1d5f9a2
Create Date: 2026-09-12
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e6b2d9f4a8c1"
down_revision: Union[str, Sequence[str], None] = "b3e7c1d5f9a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "mdm_connections",
        sa.Column("token_cache_mode", sa.String(16), nullable=False, server_default="cache_and_hold"),
    )
    op.create_check_constraint(
        "ck_mdm_connections_token_cache_mode",
        "mdm_connections",
        "token_cache_mode IN ('no_cache', 'cache_and_hold', 'perpetual')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_mdm_connections_token_cache_mode", "mdm_connections", type_="check")
    op.drop_column("mdm_connections", "token_cache_mode")
