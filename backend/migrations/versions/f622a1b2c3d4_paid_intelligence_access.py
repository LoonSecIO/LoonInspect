"""Independent paid credential and status on the existing tenant/RLS consent row (#622)."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'f622a1b2c3d4'
down_revision = 'e621c4a8b903'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('data_sharing_settings', sa.Column('intelligence_credential', sa.Text(), nullable=True))
    op.add_column('data_sharing_settings', sa.Column('intelligence_status', postgresql.JSONB(), nullable=False,
                                                   server_default=sa.text("'{}'::jsonb")))


def downgrade():
    op.drop_column('data_sharing_settings', 'intelligence_status')
    op.drop_column('data_sharing_settings', 'intelligence_credential')
