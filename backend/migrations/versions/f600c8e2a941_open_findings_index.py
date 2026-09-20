"""Index the open finding rows used by Seen here (#600).

The page groups open findings by build to find the earliest observation. Existing indexes
start with a device or finding ID, so neither narrows this build-based read. Use a partial
(tenant_id, build_key_full) index with first_observed_at included: resolved history never
participates, and the included clock permits an index-only read when visibility allows it.
The tenant leads because forced RLS adds that equality to every request. Compared with a
full (tenant_id, build_key_full, resolved_at) index, closed investigation history costs no
index entries here. The Catalog list already skips this query; no new caller gate is needed.

A regular transactional index build follows the repository's migration convention; it can
block finding writes while upgrading. Downgrade drops only this derived index.
"""

import sqlalchemy as sa
from alembic import op

revision = "f600c8e2a941"
down_revision = "d605a1b2c3d4"
branch_labels = None
depends_on = None

INDEX = "ix_device_findings_open_build"


def upgrade() -> None:
    op.create_index(
        INDEX,
        "device_findings",
        ["tenant_id", "build_key_full"],
        postgresql_where=sa.text("resolved_at IS NULL"),
        postgresql_include=["first_observed_at"],
    )


def downgrade() -> None:
    op.drop_index(INDEX, table_name="device_findings")
