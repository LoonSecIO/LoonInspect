"""destinations and event outbox

Revision ID: d4e7f2a68b91
Revises: c3d9f1a52e88
Create Date: 2026-08-05 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e7f2a68b91'
down_revision: Union[str, Sequence[str], None] = 'c3d9f1a52e88'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'destinations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('type', sa.String(length=32), nullable=False),
        sa.Column('url', sa.String(length=1024), nullable=False),
        sa.Column('auth_type', sa.String(length=16), nullable=False),
        sa.Column('auth_header_name', sa.String(length=255), nullable=True),
        sa.Column('auth_secret_encrypted', sa.String(length=1024), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('subscribed_events', sa.JSON(), nullable=True),
        sa.Column('last_success_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_failure_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'event_outbox',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('request_id', sa.String(length=64), nullable=True),
        sa.Column('fanned_out', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_event_outbox_event_type'), 'event_outbox', ['event_type'], unique=False)
    op.create_index(op.f('ix_event_outbox_created_at'), 'event_outbox', ['created_at'], unique=False)
    op.create_index(op.f('ix_event_outbox_fanned_out'), 'event_outbox', ['fanned_out'], unique=False)

    op.create_table(
        'outbox_deliveries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('outbox_event_id', sa.Integer(), nullable=False),
        sa.Column('destination_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('attempt_count', sa.Integer(), nullable=False),
        sa.Column('next_attempt_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_attempted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.String(length=2000), nullable=True),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['outbox_event_id'], ['event_outbox.id']),
        sa.ForeignKeyConstraint(['destination_id'], ['destinations.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('outbox_event_id', 'destination_id', name='uq_outbox_delivery_event_destination'),
    )
    op.create_index(op.f('ix_outbox_deliveries_outbox_event_id'), 'outbox_deliveries', ['outbox_event_id'], unique=False)
    op.create_index(op.f('ix_outbox_deliveries_destination_id'), 'outbox_deliveries', ['destination_id'], unique=False)
    op.create_index(op.f('ix_outbox_deliveries_status'), 'outbox_deliveries', ['status'], unique=False)
    op.create_index(op.f('ix_outbox_deliveries_next_attempt_at'), 'outbox_deliveries', ['next_attempt_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('outbox_deliveries')
    op.drop_table('event_outbox')
    op.drop_table('destinations')
