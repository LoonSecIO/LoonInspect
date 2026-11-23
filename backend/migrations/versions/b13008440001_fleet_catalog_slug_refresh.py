"""Reconcile cached Fleet trees once after admitting + and @ in manifest slugs."""

import sqlalchemy as sa
from alembic import op

revision = "b13008440001"
down_revision = "b13008520001"
branch_labels = None
depends_on = None


def upgrade():
    # Preserve downloaded manifests and version history. The next eligible check
    # compares their blob hashes with the full listing and reads only new/changed titles.
    op.add_column("fleet_catalog_state", sa.Column("snapshot_status", sa.String(16), nullable=False, server_default="unread"))
    op.execute(
        "UPDATE fleet_catalog_state SET tree_sha = NULL, snapshot_status = 'partial' WHERE tree_sha IS NOT NULL OR app_count > 0"
    )


def downgrade():
    op.drop_column("fleet_catalog_state", "snapshot_status")
