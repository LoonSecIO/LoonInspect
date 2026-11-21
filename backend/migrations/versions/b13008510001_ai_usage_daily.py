"""Tenant-scoped daily counters for AI usage and logical queue events."""
import sqlalchemy as sa
from alembic import op

revision = "b13008510001"
down_revision = "b13008500001"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("ai_usage_daily",
        sa.Column("tenant_id",sa.Uuid(),sa.ForeignKey("tenants.id",ondelete="RESTRICT"),primary_key=True,
                  server_default=sa.text("current_setting('looninspect.tenant_id')::uuid")),
        sa.Column("day",sa.Date(),primary_key=True),
        *(sa.Column(name,sa.String(size),primary_key=True) for name,size in (
            ("feature",64),("provider",32),("requested",200),("reported",200),("outcome",64),("kind",16))),
        *(sa.Column(name,sa.BigInteger(),nullable=False,server_default="0") for name in (
            "events","request_ms","input_tokens","input_reports","output_tokens","output_reports","cached_tokens","cache_reports",
            "provider_ms","provider_reports","queue_wait_ms","max_queue_wait_ms")))
    op.execute("ALTER TABLE ai_usage_daily ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ai_usage_daily FORCE ROW LEVEL SECURITY")
    p = "tenant_id = current_setting('looninspect.tenant_id')::uuid"
    op.execute(f"CREATE POLICY tenant_isolation ON ai_usage_daily USING ({p}) WITH CHECK ({p})")


def downgrade():
    op.drop_table("ai_usage_daily")
