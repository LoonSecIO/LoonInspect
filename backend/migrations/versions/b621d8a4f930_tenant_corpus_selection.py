"""Tenant acquisition and selected-release pointers (#621, second slice).

Seed acquisition only for consenting operational tenants and only for the currently
installed release. Do not reconstruct old grants or pretend a new assessment succeeded:
selection stays empty until the transactional assessment path selects a release.
"""

from alembic import op
import sqlalchemy as sa

revision = "b621d8a4f930"
down_revision = "a621e9c4b730"
branch_labels = None
depends_on = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def upgrade() -> None:
    op.create_table(
        "vuln_corpus_acquisitions",
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True,
                  server_default=sa.text("current_setting('looninspect.tenant_id')::uuid")),
        sa.Column("signature", sa.String(64), sa.ForeignKey("vuln_corpus_releases.signature", ondelete="RESTRICT"), primary_key=True),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("basis", sa.String(20), nullable=False),
        sa.CheckConstraint("basis IN ('legacy_consent', 'delivery')", name="ck_vuln_acquisition_basis"),
    )
    op.create_index("ix_vuln_acquisitions_signature", "vuln_corpus_acquisitions", ["signature"])
    op.create_table(
        "vuln_corpus_selections",
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True,
                  server_default=sa.text("current_setting('looninspect.tenant_id')::uuid")),
        sa.Column("signature", sa.String(64), nullable=False),
        sa.Column("selected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id", "signature"],
                                ["vuln_corpus_acquisitions.tenant_id", "vuln_corpus_acquisitions.signature"],
                                ondelete="RESTRICT", name="fk_vuln_selection_acquisition"),
    )
    for table in ("vuln_corpus_acquisitions", "vuln_corpus_selections"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")
    # Retention is default-off, so the active epoch may have changed since #626's
    # migration. Serialize with even an older importer, and freeze consent for this copy.
    op.execute("LOCK TABLE vuln_library_rows, vuln_library_titles, vuln_library_epoch, data_sharing_settings IN SHARE MODE")
    bind = op.get_bind()
    inserted = bind.execute(sa.text("""
        INSERT INTO vuln_corpus_releases (signature, epoch_id, asof, loaded_at, row_count, title_count)
        SELECT signature, epoch_id, asof, loaded_at, row_count, title_count FROM vuln_library_epoch
        ON CONFLICT (signature) DO NOTHING RETURNING signature
    """)).scalar_one_or_none()
    if inserted is not None:
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
    previous = bind.execute(sa.text("SELECT current_setting('looninspect.tenant_id', true)")).scalar_one_or_none()
    tenant_ids = bind.execute(sa.text("SELECT id FROM tenants WHERE kind = 'operational'")).scalars().all()
    for tenant in tenant_ids:
        bind.execute(sa.text("SELECT set_config('looninspect.tenant_id', :tenant, true)"), {"tenant": str(tenant)})
        # The acquisition clock is migration time, not a fabricated original delivery.
        bind.execute(sa.text("""
            INSERT INTO vuln_corpus_acquisitions (signature, basis)
            SELECT signature, 'legacy_consent' FROM vuln_library_epoch
            WHERE EXISTS (SELECT 1 FROM data_sharing_settings
                          WHERE tenant_id = :tenant AND tier IN ('keys', 'reveal'))
        """), {"tenant": tenant})
    # On an exception the whole migration transaction rolls back, including its GUC.
    bind.execute(sa.text("SELECT set_config('looninspect.tenant_id', :tenant, true)"), {"tenant": previous or ""})


def downgrade() -> None:
    op.drop_table("vuln_corpus_selections")
    op.drop_index("ix_vuln_acquisitions_signature", table_name="vuln_corpus_acquisitions")
    op.drop_table("vuln_corpus_acquisitions")
    # Retained and serving reference data remain intact; there is no consent mutation.
