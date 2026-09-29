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

# release-note: this rebuilds the installed-apps index as the new image starts, and the instance answers nothing until it finishes, so update in a maintenance window and do not restart the container while it runs. On 600,000 installed apps (10,000 devices with 60 each) it took 2.4 s and 1.2 s of wall clock in #624's two timed walks from v1.0.0, about a second of each the tooling's own start-up; it takes longer on a larger table. The new index needs free disk beside the old one until the old one is dropped (4.3 MB at 600,000 installed apps on that walk, 26 MB at one million after the scale run's churn, docs/vulnerability-scale-validation.md).

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
