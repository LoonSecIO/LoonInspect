"""Protect each tenant's previous successful corpus selection (#621).

Existing previous selections are unknown: do not infer one from acquisition order.
Cleanup conservatively retains their grants until a real selection establishes a pair.
"""
from alembic import op
import sqlalchemy as sa

revision = "d621a30f7b12"
down_revision = "c621f4a8e902"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("vuln_corpus_selections", sa.Column("previous_signature", sa.String(64), nullable=True))
    # FK validation can evaluate forced-RLS policy expressions, even with all values
    # NULL. Bind a syntactically valid context; adding the nullable column guarantees
    # every pre-existing previous_signature is NULL across all tenants.
    bind = op.get_bind()
    previous = bind.scalar(sa.text("SELECT current_setting('looninspect.tenant_id', true)"))
    bind.execute(sa.text("SELECT set_config('looninspect.tenant_id', '00000000-0000-0000-0000-000000000000', true)"))
    op.create_foreign_key(
        "fk_vuln_previous_acquisition", "vuln_corpus_selections", "vuln_corpus_acquisitions",
        ["tenant_id", "previous_signature"], ["tenant_id", "signature"], ondelete="RESTRICT",
    )
    bind.execute(sa.text("SELECT set_config('looninspect.tenant_id', :tenant, true)"), {"tenant": previous or ""})


def downgrade():
    op.drop_constraint("fk_vuln_previous_acquisition", "vuln_corpus_selections", type_="foreignkey")
    op.drop_column("vuln_corpus_selections", "previous_signature")
