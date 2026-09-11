"""vuln_library — the corpus epoch this container has loaded (#248)

Ruled 2026-09-10: the Jamf-derived vulnerability corpus ships complete, once a day, as a
consent-gated signed link riding the data-sharing exchange, downloaded only when its
signature moves, joined locally. These three tables are what one downloaded epoch becomes.

Global, and deliberately NOT under row-level security — the same decision as
`jamf_patch_titles` and `app_catalog_versions` in b4c7e9d2a1f6: the corpus is published to
every consenting container, holds no customer data and no per-tenant scoping, and is
joined to a fleet only by a content key the fleet already computes. Scoping it per tenant
would store one copy of a public artifact per tenant and give a reader nothing.

`vuln_library_epoch` holds at most one row, enforced by a check constraint rather than by
convention: two epochs loaded at once is the state in which "which one answered?" has no
answer. It is written last in the import transaction, so it and the rows can never
describe different epochs.

Revision ID: d1f8b6a34e07
Revises: c9f2a5e8b3d1
Create Date: 2026-09-10
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "d1f8b6a34e07"
down_revision: Union[str, Sequence[str], None] = "c9f2a5e8b3d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vuln_library_epoch",
        # Not a sequence: the id is always 1, and a serial would hand the second insert a
        # 2 that the constraint below then refuses — a confusing way to say "one row".
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("epoch_id", sa.String(32), nullable=False),
        sa.Column("signature", sa.String(64), nullable=False),
        sa.Column("asof", sa.DateTime(timezone=True), nullable=False),
        sa.Column("loaded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("title_count", sa.Integer(), nullable=False, server_default="0"),
        sa.CheckConstraint("id = 1", name="ck_vuln_library_epoch_single_row"),
    )
    op.create_table(
        "vuln_library_rows",
        sa.Column("key_full", sa.String(67), primary_key=True),
        sa.Column("ids", JSONB, nullable=False, server_default="[]"),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("counts", JSONB, nullable=False, server_default="{}"),
        sa.Column("oldest_published", JSONB, nullable=False, server_default="{}"),
    )
    op.create_table(
        "vuln_library_titles",
        # Jamf's own title id, and what the published object is unique on (ruling R-D,
        # 2026-09-11). `key_title` is NOT unique — sixteen Wireshark titles in Jamf's
        # catalog hash to one `app.title` key — so it is an index here and never the key:
        # a primary key on it would have silently kept one of the sixteen and let its
        # catalog stamp answer for all of them.
        sa.Column("title_id", sa.String(64), primary_key=True),
        sa.Column("key_title", sa.String(67), nullable=False),
        sa.Column("catalog_last_modified", sa.String(64), nullable=False),
        sa.Column("versions_compiled", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_vuln_library_titles_key_title", "vuln_library_titles", ["key_title"])


def downgrade() -> None:
    op.drop_index("ix_vuln_library_titles_key_title", table_name="vuln_library_titles")
    op.drop_table("vuln_library_titles")
    op.drop_table("vuln_library_rows")
    op.drop_table("vuln_library_epoch")
