"""Fleet's catalogue: each title's version history, read from Fleet's commits (#838).

`fleet_app_versions` is a global reference table beside `fleet_maintained_apps`, outside
tenancy and row-level security for the same reason: a public catalogue's history, with no
customer data in it. One row per title and version: the date GitHub records for the first
commit whose manifest carried the version, that commit, and the version it replaced. Rows go
with their title.

`fleet_maintained_apps` gains what the reads reached for each title (when it was last read,
the oldest and newest change reached, whether the oldest was the title's first, and a sentence
when something was left undated), and `fleet_catalog_state` the last history read's outcome and sentence.

Additive only: every new column is nullable or has a server default, so a v1.1.0 image that
meets this schema reads and writes the catalogue as it did. Downgrade drops what this adds;
the history is read again after the next upgrade.

Revision ID: d838a2c4e6f1
Revises: e819a4c2f6b3
Create Date: 2026-11-21
"""

import sqlalchemy as sa
from alembic import op

revision = "d838a2c4e6f1"
down_revision = "e819a4c2f6b3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fleet_app_versions",
        sa.Column(
            "slug",
            sa.String(128),
            sa.ForeignKey("fleet_maintained_apps.slug", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("version", sa.String(64), primary_key=True),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("commit_sha", sa.String(40), nullable=False),
        sa.Column("previous_version", sa.String(64), nullable=True),
    )
    op.add_column("fleet_maintained_apps", sa.Column("history_read_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("fleet_maintained_apps", sa.Column("history_since", sa.DateTime(timezone=True), nullable=True))
    op.add_column("fleet_maintained_apps", sa.Column("history_through", sa.DateTime(timezone=True), nullable=True))
    op.add_column("fleet_maintained_apps", sa.Column("history_last_sha", sa.String(40), nullable=True))
    op.add_column(
        "fleet_maintained_apps",
        sa.Column("history_complete", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column("fleet_maintained_apps", sa.Column("history_detail", sa.Text(), nullable=True))
    op.add_column("fleet_catalog_state", sa.Column("history_checked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("fleet_catalog_state", sa.Column("history_outcome", sa.String(32), nullable=True))
    op.add_column("fleet_catalog_state", sa.Column("history_detail", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("fleet_catalog_state", "history_detail")
    op.drop_column("fleet_catalog_state", "history_outcome")
    op.drop_column("fleet_catalog_state", "history_checked_at")
    op.drop_column("fleet_maintained_apps", "history_detail")
    op.drop_column("fleet_maintained_apps", "history_complete")
    op.drop_column("fleet_maintained_apps", "history_last_sha")
    op.drop_column("fleet_maintained_apps", "history_through")
    op.drop_column("fleet_maintained_apps", "history_since")
    op.drop_column("fleet_maintained_apps", "history_read_at")
    op.drop_table("fleet_app_versions")
