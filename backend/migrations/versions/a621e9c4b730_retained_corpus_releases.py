"""Retain the installed corpus projection ahead of tenant selection (#621).

These are global reference tables, not tenant inventory or acquisition grants. Keep
only what the old tables actually know; original manifests and unknown objects cannot
be reconstructed. The old serving tables and their constraints remain intact.

Upgrade copies the currently installed projection once. Continued accumulation is an
explicit, default-off setting until selection and safe pruning are implemented.
Downgrade discards retained projections, never the currently serving library.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "a621e9c4b730"
down_revision = "f526e8b3d901"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Older application processes do not know the new advisory import lock. Hold
    # their source tables against writes so metadata and contents come from one epoch.
    # Use the importer's delete order to avoid a conflicting lock acquisition order.
    op.execute("LOCK TABLE vuln_library_rows, vuln_library_titles, vuln_library_epoch IN SHARE MODE")
    op.create_table(
        "vuln_corpus_releases",
        sa.Column("signature", sa.String(64), primary_key=True),
        sa.Column("epoch_id", sa.String(32), nullable=False),
        sa.Column("asof", sa.DateTime(timezone=True), nullable=False),
        sa.Column("loaded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("manifest", JSONB, nullable=True),
        sa.Column("row_count", sa.Integer(), nullable=False),
        sa.Column("title_count", sa.Integer(), nullable=False),
    )
    op.create_table(
        "vuln_corpus_release_rows",
        sa.Column("signature", sa.String(64), sa.ForeignKey("vuln_corpus_releases.signature", ondelete="RESTRICT"), primary_key=True),
        sa.Column("key_full", sa.String(67), primary_key=True),
        sa.Column("ids", JSONB, nullable=False),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("counts", JSONB, nullable=False),
        sa.Column("oldest_published", JSONB, nullable=False),
    )
    op.create_table(
        "vuln_corpus_release_titles",
        sa.Column("signature", sa.String(64), sa.ForeignKey("vuln_corpus_releases.signature", ondelete="RESTRICT"), primary_key=True),
        sa.Column("title_id", sa.String(64), primary_key=True),
        sa.Column("key_title", sa.String(67), nullable=False),
        sa.Column("catalog_last_modified", sa.String(64), nullable=False),
        sa.Column("versions_compiled", sa.Integer(), nullable=False),
    )
    op.execute("""
        INSERT INTO vuln_corpus_releases (signature, epoch_id, asof, loaded_at, row_count, title_count)
        SELECT signature, epoch_id, asof, loaded_at, row_count, title_count FROM vuln_library_epoch
    """)
    op.execute("""
        INSERT INTO vuln_corpus_release_rows
        SELECT e.signature, r.key_full, r.ids, r.truncated, r.counts, r.oldest_published
        FROM vuln_library_rows r CROSS JOIN vuln_library_epoch e
    """)
    op.execute("""
        INSERT INTO vuln_corpus_release_titles
        SELECT e.signature, t.title_id, t.key_title, t.catalog_last_modified, t.versions_compiled
        FROM vuln_library_titles t CROSS JOIN vuln_library_epoch e
    """)


def downgrade() -> None:
    op.drop_table("vuln_corpus_release_titles")
    op.drop_table("vuln_corpus_release_rows")
    op.drop_table("vuln_corpus_releases")
