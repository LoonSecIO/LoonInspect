"""v1 content keys on installed_apps

The canonical SHA-256 keys from docs/data-sharing.md, materialized alongside the
internal MD5 pair. Backfill runs in Python, not SQL: canonicalization includes NFC
Unicode normalization, which Postgres cannot be trusted to reproduce byte-for-byte.

Revision ID: 9c41d20a77e1
Revises: 7fb9f43202ba
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from app.core.content_keys import app_full_key, app_title_key

revision: str = "9c41d20a77e1"
down_revision: Union[str, Sequence[str], None] = "7fb9f43202ba"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("installed_apps", sa.Column("key_title", sa.String(67), nullable=True))
    op.add_column("installed_apps", sa.Column("key_full", sa.String(67), nullable=True))

    # installed_apps is behind FORCEd row-level security with no owner bypass — an
    # unbound connection raises rather than seeing zero rows (the baseline migration
    # documents why). So the backfill walks tenants and binds each in turn; `tenants`
    # itself is deliberately outside the policy set and readable here.
    bind = op.get_bind()
    update = sa.text(
        "UPDATE installed_apps SET key_title = :kt, key_full = :kf WHERE id = :id"
    )
    tenant_ids = bind.execute(sa.text("SELECT id FROM tenants")).scalars().all()
    for tenant_id in tenant_ids:
        bind.execute(
            sa.text("SELECT set_config('looninspect.tenant_id', :tid, true)"),
            {"tid": str(tenant_id)},
        )
        rows = bind.execute(
            sa.text("SELECT id, name, bundle_id, version, short_version FROM installed_apps")
        ).fetchall()
        for row in rows:
            bind.execute(
                update,
                {
                    "kt": app_title_key(row.name, row.bundle_id),
                    "kf": app_full_key(row.name, row.bundle_id, row.version, row.short_version),
                    "id": row.id,
                },
            )

    op.alter_column("installed_apps", "key_title", nullable=False)
    op.alter_column("installed_apps", "key_full", nullable=False)
    op.create_index("ix_installed_apps_key_title", "installed_apps", ["key_title"])
    op.create_index("ix_installed_apps_key_full", "installed_apps", ["key_full"])


def downgrade() -> None:
    op.drop_index("ix_installed_apps_key_full", table_name="installed_apps")
    op.drop_index("ix_installed_apps_key_title", table_name="installed_apps")
    op.drop_column("installed_apps", "key_full")
    op.drop_column("installed_apps", "key_title")
