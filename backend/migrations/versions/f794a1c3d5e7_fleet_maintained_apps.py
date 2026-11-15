"""Fleet's maintained-apps catalogue: the titles, and what the last check found (#794).

Two global reference tables, outside tenancy and row-level security like `jamf_patch_titles`
and `vuln_library_epoch`: a public catalogue read from Fleet's repository, with no customer
data in it. `fleet_maintained_apps` holds one row per Mac title (name, bundle identifier,
current version, the version before the last move seen and when). `fleet_catalog_state` is
one row: the catalogue folder's git tree sha as of the last complete read, when GitHub was
last asked, and the last check's outcome with its sentence.

Additive only: nothing an earlier release reads is touched, and both tables stay empty until
an organization turns on the `fleet_maintained_apps` flag. Downgrade drops both; the next
check after an upgrade reads the catalogue again.

Revision ID: f794a1c3d5e7
Revises: c793a1f5d2e8
Create Date: 2026-11-15
"""

import sqlalchemy as sa
from alembic import op

revision = "f794a1c3d5e7"
down_revision = "c793a1f5d2e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fleet_maintained_apps",
        sa.Column("slug", sa.String(128), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("bundle_id", sa.String(255), nullable=False),
        sa.Column("latest_version", sa.String(64), nullable=False),
        sa.Column("previous_version", sa.String(64), nullable=True),
        sa.Column("version_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("manifest_sha", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_fleet_maintained_apps_bundle_id", "fleet_maintained_apps", ["bundle_id"])
    op.create_table(
        "fleet_catalog_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("tree_sha", sa.String(40), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome", sa.String(32), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("app_count", sa.Integer(), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_fleet_catalog_state_single_row"),
    )


def downgrade() -> None:
    op.drop_table("fleet_catalog_state")
    op.drop_index("ix_fleet_maintained_apps_bundle_id", table_name="fleet_maintained_apps")
    op.drop_table("fleet_maintained_apps")
