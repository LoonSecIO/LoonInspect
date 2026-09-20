"""Allow assessment-only entries in the existing device history ledger (#621).

No past receipt is changed or backfilled. A NULL source identifies assessment of held
inventory rather than a newly emitted inventory event. Existing forced RLS still applies.
"""
from alembic import op
import sqlalchemy as sa

revision = "c621f4a8e902"
down_revision = "b621d8a4f930"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column("device_history_points", "source_id", existing_type=sa.Integer(), nullable=True)


def downgrade():
    # Constraint validation scans all tenants without relying on a tenant-scoped read.
    # Refuse rather than silently delete the evidence needed to satisfy NOT NULL.
    op.execute("""
        DO $$ BEGIN
            ALTER TABLE device_history_points ALTER COLUMN source_id SET NOT NULL;
        EXCEPTION WHEN not_null_violation THEN
            RAISE EXCEPTION 'Assessment history exists. Keep this schema or restore a pre-upgrade backup; downgrade would lose evidence.';
        END $$;
    """)
