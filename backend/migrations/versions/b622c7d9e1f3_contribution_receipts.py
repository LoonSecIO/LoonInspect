"""Encrypted contribution receipt and its status on the tenant/RLS consent row (#622)."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'b622c7d9e1f3'
down_revision = 'f622a1b2c3d4'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('data_sharing_settings', sa.Column('participation_receipt', sa.Text(), nullable=True))
    op.add_column('data_sharing_settings', sa.Column('participation_status', postgresql.JSONB(), nullable=False,
                                                   server_default=sa.text("'{}'::jsonb")))


def downgrade():
    op.drop_column('data_sharing_settings', 'participation_status')
    op.drop_column('data_sharing_settings', 'participation_receipt')
