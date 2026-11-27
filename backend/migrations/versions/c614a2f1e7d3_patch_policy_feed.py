"""LoonSec's patch-policy reference document, and what the last attempt to receive it found (#614).

Two global tables, outside tenancy and row-level security like `vuln_library_epoch`: the
document is one object for every app LoonSec references, the same for every consenting
container, with no customer data in it. `patch_policy_docs` holds the last two copies (the
current one and the one before), each gzip-compressed as it arrived, keyed by the document's
own `doc_id`; a partial unique index holds that at most one is current.
`patch_policy_feed_state` is one row: when the last attempt was, where it looked (the
exchange's link or `PATCH_POLICY_FEED_FILE`), its outcome word, the link's host or the file's
path, an HTTP status when one answered, and the reason in the operator's words.

Additive only: nothing an earlier release reads is touched, and both tables stay empty until
an exchange carries the document or the file is set. Downgrade drops both; the next exchange
after an upgrade downloads the document again.

Revision ID: c614a2f1e7d3
Revises: b14008720001
Create Date: 2026-11-24
"""

import sqlalchemy as sa
from alembic import op

revision = "c614a2f1e7d3"
down_revision = "b14008720001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "patch_policy_docs",
        sa.Column("doc_id", sa.String(64), primary_key=True),
        sa.Column("schema", sa.Integer(), nullable=False),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("as_of", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("body_gz", sa.LargeBinary(), nullable=False),
        sa.Column("current", sa.Boolean(), nullable=False),
    )
    op.create_index(
        "uq_patch_policy_docs_current",
        "patch_policy_docs",
        ["current"],
        unique=True,
        postgresql_where=sa.text("current"),
    )
    op.create_table(
        "patch_policy_feed_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("host", sa.Text(), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.CheckConstraint("id = 1", name="ck_patch_policy_feed_state_single_row"),
    )


def downgrade() -> None:
    op.drop_table("patch_policy_feed_state")
    op.drop_index("uq_patch_policy_docs_current", table_name="patch_policy_docs")
    op.drop_table("patch_policy_docs")
