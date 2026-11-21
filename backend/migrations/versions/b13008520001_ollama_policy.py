"""Opt-in Ollama model selection and cached briefing provenance."""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision = "b13008520001"
down_revision = "b13008510001"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("ai_provider_configs",sa.Column("ollama_policy",postgresql.JSONB()))
    op.add_column("inventory_summary_jobs",sa.Column("requested_model",sa.String(200)))
    op.add_column("inventory_summary_jobs",sa.Column("reported_model",sa.String(200)))


def downgrade():
    op.drop_column("inventory_summary_jobs","reported_model")
    op.drop_column("inventory_summary_jobs","requested_model")
    op.drop_column("ai_provider_configs","ollama_policy")
