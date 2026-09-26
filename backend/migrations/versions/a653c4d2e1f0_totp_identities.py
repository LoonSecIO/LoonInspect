"""TOTP on local accounts (#653): the encrypted secret, recovery codes, confirmation and the
last accepted step on auth_identities, and the enrolment policy on tenants."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'a653c4d2e1f0'
down_revision = 'b622c7d9e1f3'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('auth_identities', sa.Column('secret_encrypted', sa.Text(), nullable=True))
    op.add_column('auth_identities', sa.Column('recovery_codes', postgresql.JSONB(), nullable=False,
                                              server_default=sa.text("'[]'::jsonb")))
    op.add_column('auth_identities', sa.Column('confirmed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('auth_identities', sa.Column('last_otp_step', sa.BigInteger(), nullable=True))
    op.add_column('tenants', sa.Column('mfa_required', sa.String(length=16), nullable=False, server_default='off'))


def downgrade():
    op.drop_column('tenants', 'mfa_required')
    for column in ('last_otp_step', 'confirmed_at', 'recovery_codes', 'secret_encrypted'):
        op.drop_column('auth_identities', column)
