"""auth accounts, identities, roles, sessions

Revision ID: a1f4c7d92b30
Revises: 2beb909af055
Create Date: 2026-08-03 23:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1f4c7d92b30'
down_revision: Union[str, Sequence[str], None] = '2beb909af055'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'accounts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('email', sa.String(length=320), nullable=False),
        sa.Column('display_name', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('is_break_glass', sa.Boolean(), nullable=False),
        sa.Column('is_service_account', sa.Boolean(), nullable=False),
        sa.Column('external_source', sa.String(length=32), nullable=True),
        sa.Column('external_id', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('external_source', 'external_id', name='uq_account_external_identity'),
    )
    op.create_index(op.f('ix_accounts_email'), 'accounts', ['email'], unique=True)
    op.create_index(op.f('ix_accounts_username'), 'accounts', ['username'], unique=True)
    op.create_index(op.f('ix_accounts_status'), 'accounts', ['status'], unique=False)
    op.create_index(op.f('ix_accounts_external_id'), 'accounts', ['external_id'], unique=False)

    op.create_table(
        'auth_identities',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('account_id', sa.String(length=36), nullable=False),
        sa.Column('provider', sa.String(length=64), nullable=False),
        sa.Column('subject', sa.String(length=255), nullable=False),
        sa.Column('secret_hash', sa.String(length=255), nullable=True),
        sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('provider', 'subject', name='uq_auth_identity_provider_subject'),
    )
    op.create_index(op.f('ix_auth_identities_account_id'), 'auth_identities', ['account_id'], unique=False)

    op.create_table(
        'account_roles',
        sa.Column('account_id', sa.String(length=36), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('source', sa.String(length=16), nullable=False),
        sa.Column('granted_by', sa.String(length=36), nullable=True),
        sa.Column('granted_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id']),
        sa.PrimaryKeyConstraint('account_id', 'role', 'source'),
    )

    op.create_table(
        'sessions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('account_id', sa.String(length=36), nullable=False),
        sa.Column('identity_id', sa.String(length=36), nullable=True),
        sa.Column('auth_method', sa.String(length=32), nullable=False),
        sa.Column('csrf_token', sa.String(length=64), nullable=False),
        sa.Column('idp_session_id', sa.String(length=255), nullable=True),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.Column('user_agent', sa.String(length=512), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id']),
        sa.ForeignKeyConstraint(['identity_id'], ['auth_identities.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_sessions_token_hash'), 'sessions', ['token_hash'], unique=True)
    op.create_index(op.f('ix_sessions_account_id'), 'sessions', ['account_id'], unique=False)
    op.create_index(op.f('ix_sessions_expires_at'), 'sessions', ['expires_at'], unique=False)

    op.create_table(
        'login_attempts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('identifier', sa.String(length=320), nullable=False),
        sa.Column('ip', sa.String(length=64), nullable=False),
        sa.Column('failure_count', sa.Integer(), nullable=False),
        sa.Column('last_failure_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('identifier', 'ip', name='uq_login_attempt_identifier_ip'),
    )
    op.create_index(op.f('ix_login_attempts_identifier'), 'login_attempts', ['identifier'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('login_attempts')
    op.drop_table('sessions')
    op.drop_table('account_roles')
    op.drop_table('auth_identities')
    op.drop_table('accounts')
