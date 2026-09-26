"""Index tenant-scoped device app lookups without repeatedly scanning tenant membership (#621).

Under underestimated row counts, PostgreSQL combined the separate tenant and device
indexes inside a nested loop, rebuilding the tenant bitmap once per device. The
composite key satisfies both the RLS predicate and device lookup in a single scan.
It replaces the tenant-only index, preserving that leading-key access path. Other
indexes stay available; answers and policies do not change.

Like the project's other index migrations, this builds transactionally rather than
CONCURRENTLY. It blocks writes while building: schedule an upgrade maintenance window
and allow disk space for both indexes while the replacement is built.

Revision ID: e621c4a8b903
Revises: d621a30f7b12
"""

# release-note: this rebuilds the installed-apps index as the new image starts, and the instance answers nothing until it finishes, so update in a maintenance window and do not restart the container while it runs. The new index needs free disk beside the old one until the old one is dropped (26 MB at one million installed apps, docs/vulnerability-scale-validation.md); how long it takes on a large table is not measured yet.

from alembic import op

revision = "e621c4a8b903"
down_revision = "d621a30f7b12"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_installed_apps_tenant_device", "installed_apps", ["tenant_id", "device_id"])
    op.drop_index("ix_installed_apps_tenant_id", table_name="installed_apps")


def downgrade() -> None:
    op.create_index("ix_installed_apps_tenant_id", "installed_apps", ["tenant_id"])
    op.drop_index("ix_installed_apps_tenant_device", table_name="installed_apps")
