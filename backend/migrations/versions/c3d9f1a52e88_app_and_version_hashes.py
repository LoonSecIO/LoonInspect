"""two-tier app hashing: app_hash and version_hash

Revision ID: c3d9f1a52e88
Revises: b2c8e5a41f77
Create Date: 2026-08-04 17:05:00.000000

"""
import hashlib
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d9f1a52e88'
down_revision: Union[str, Sequence[str], None] = 'b2c8e5a41f77'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Deliberately duplicated from app.core.hashing rather than imported. A migration is a
# snapshot of intent at a point in time; importing application code means this file
# silently changes behaviour whenever that code does, and a re-run would then produce
# different values than it did originally.
def _md5(*parts: str) -> str:
    return hashlib.md5(":".join(parts).encode("utf-8")).hexdigest()


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('installed_apps', sa.Column('short_version', sa.String(length=64), nullable=True))
    op.add_column('installed_apps', sa.Column('app_hash', sa.String(length=32), nullable=True))
    op.add_column('installed_apps', sa.Column('version_hash', sa.String(length=32), nullable=True))

    # Backfill from the columns that are already present. Existing rows have no short
    # version, so their version hash is the three-component form — the same value the
    # application would compute for them today.
    connection = op.get_bind()
    rows = connection.execute(
        sa.text("SELECT id, name, bundle_id, version FROM installed_apps")
    ).fetchall()

    for row in rows:
        name = row.name or ""
        bundle_id = row.bundle_id or ""
        version = row.version or ""
        connection.execute(
            sa.text(
                "UPDATE installed_apps SET app_hash = :app_hash, version_hash = :version_hash "
                "WHERE id = :id"
            ),
            {
                "app_hash": _md5(name, bundle_id),
                "version_hash": _md5(name, bundle_id, version),
                "id": row.id,
            },
        )

    # Batch mode because SQLite cannot alter a column in place — it rebuilds the table.
    with op.batch_alter_table('installed_apps') as batch:
        batch.alter_column('app_hash', existing_type=sa.String(length=32), nullable=False)
        batch.alter_column('version_hash', existing_type=sa.String(length=32), nullable=False)
        batch.drop_index('ix_installed_apps_full_hash')
        batch.drop_column('full_hash')

    op.create_index(op.f('ix_installed_apps_app_hash'), 'installed_apps', ['app_hash'], unique=False)
    op.create_index(op.f('ix_installed_apps_version_hash'), 'installed_apps', ['version_hash'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.add_column('installed_apps', sa.Column('full_hash', sa.String(length=32), nullable=True))

    connection = op.get_bind()
    rows = connection.execute(
        sa.text("SELECT id, bundle_id, version FROM installed_apps")
    ).fetchall()

    # The old hash was md5(bundle_id:version) — recomputable, so a downgrade doesn't
    # lose data.
    for row in rows:
        connection.execute(
            sa.text("UPDATE installed_apps SET full_hash = :full_hash WHERE id = :id"),
            {"full_hash": _md5(row.bundle_id or "", row.version or ""), "id": row.id},
        )

    op.drop_index(op.f('ix_installed_apps_version_hash'), table_name='installed_apps')
    op.drop_index(op.f('ix_installed_apps_app_hash'), table_name='installed_apps')

    with op.batch_alter_table('installed_apps') as batch:
        batch.alter_column('full_hash', existing_type=sa.String(length=32), nullable=False)
        batch.drop_column('version_hash')
        batch.drop_column('app_hash')
        batch.drop_column('short_version')

    op.create_index(op.f('ix_installed_apps_full_hash'), 'installed_apps', ['full_hash'], unique=False)
