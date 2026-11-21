"""Persist poll windows and provenance for daily coverage checks."""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision = "b13008500001"
down_revision = "d838a2c4e6f1"
branch_labels = None
depends_on = None

# v1.2 validates collection kinds and frequencies on every collection read.
# release-note: Returning to v1.2.0 requires restoring a pre-upgrade backup. Its collection API cannot read recent-activity schedules.
MIN_READABLE_RELEASE = "v1.3.0"



def upgrade():
    op.execute(f"UPDATE schema_release SET min_readable_release = '{MIN_READABLE_RELEASE}'")
    op.add_column("runs", sa.Column("coverage_scope", postgresql.JSONB()))
    op.add_column("observation_spans", sa.Column("first_run_id", sa.Uuid()))
    op.add_column("observation_spans", sa.Column("report_at", sa.DateTime(timezone=True)))
    op.create_index("ix_observation_spans_first_run_id", "observation_spans", ["first_run_id"])


def downgrade():
    bind = op.get_bind()
    prior = bind.scalar(sa.text("SELECT current_setting('looninspect.tenant_id',true)"))
    for tenant in bind.execute(sa.text("SELECT id FROM tenants")).scalars():
        bind.execute(sa.text("SELECT set_config('looninspect.tenant_id',:tid,true)"), {"tid":str(tenant)})
        bind.execute(sa.text("DELETE FROM collections WHERE kind='recent_activity'"))
    bind.execute(sa.text("SELECT set_config('looninspect.tenant_id',:tid,true)"), {"tid":prior or ""})
    op.execute("UPDATE schema_release SET min_readable_release = 'v1.1.0'")
    op.drop_index("ix_observation_spans_first_run_id", table_name="observation_spans")
    op.drop_column("observation_spans", "report_at")
    op.drop_column("observation_spans", "first_run_id")
    op.drop_column("runs", "coverage_scope")
