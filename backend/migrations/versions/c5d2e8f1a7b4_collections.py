"""collections: what to collect from a connection, and when

Revision ID: c5d2e8f1a7b4
Revises: 4a8c1f2e7b93
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.core.config import settings
from app.core.scheduling import Schedule, next_due
from app.mdm.jamf.contract import V0_SECTIONS

revision: str = "c5d2e8f1a7b4"
down_revision: Union[str, Sequence[str], None] = "4a8c1f2e7b93"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def upgrade() -> None:
    op.create_table(
        "collections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
        sa.Column(
            "mdm_connection_id",
            sa.Integer(),
            sa.ForeignKey("mdm_connections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("sections", JSONB, nullable=False, server_default="[]"),
        sa.Column("selector", sa.Text(), nullable=True),
        sa.Column("quarantined_extension_attributes", JSONB, nullable=False, server_default="[]"),
        sa.Column("frequency", sa.String(16), nullable=True),
        sa.Column("interval_n", sa.Integer(), nullable=True),
        sa.Column("at_hour", sa.Integer(), nullable=True),
        sa.Column("at_minute", sa.Integer(), nullable=True),
        sa.Column("weekday", sa.Integer(), nullable=True),
        sa.Column("timezone", sa.String(64), nullable=True),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_status", sa.String(16), nullable=True),
        sa.Column("last_run_summary", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("mdm_connection_id", "name", name="uq_collection_connection_name"),
    )
    op.create_index("ix_collections_tenant_id", "collections", ["tenant_id"])
    op.create_index("ix_collections_mdm_connection_id", "collections", ["mdm_connection_id"])
    op.create_index("ix_collections_kind", "collections", ["kind"])
    op.create_index("ix_collections_due", "collections", ["enabled", "next_due_at"])
    op.execute("ALTER TABLE collections ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE collections FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON collections "
        f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})"
    )

    _backfill_defaults()


def _backfill_defaults() -> None:
    """Every existing Jamf connection gets the three default collections, so the day
    this lands nothing that used to sync stops syncing: the full device sweep keeps the
    old global SYNC_HOUR / SYNC_MINUTE / SYNC_TIMEZONE as its own schedule.

    Walks tenants and binds each in turn — `collections` is behind FORCEd row-level
    security, so an unbound connection raises rather than inserting (the content-keys
    migration documents the same dance).
    """
    bind = op.get_bind()
    now = datetime.now(timezone.utc)
    insert = sa.text(
        "INSERT INTO collections (mdm_connection_id, name, kind, enabled, sections, selector, "
        "quarantined_extension_attributes, frequency, interval_n, at_hour, at_minute, weekday, "
        "timezone, next_due_at, created_at, updated_at) VALUES (:cid, :name, :kind, :enabled, "
        "CAST(:sections AS jsonb), NULL, '[]'::jsonb, :frequency, NULL, :at_hour, :at_minute, NULL, "
        ":tz, :next_due_at, :now, :now)"
    )
    sections = json.dumps(list(V0_SECTIONS))
    tenant_ids = bind.execute(sa.text("SELECT id FROM tenants")).scalars().all()
    for tenant_id in tenant_ids:
        bind.execute(
            sa.text("SELECT set_config('looninspect.tenant_id', :tid, true)"),
            {"tid": str(tenant_id)},
        )
        rows = bind.execute(
            sa.text("SELECT id, capability_webhooks FROM mdm_connections WHERE provider = 'jamf'")
        ).fetchall()
        for row in rows:
            sweep = Schedule(
                frequency="daily",
                timezone=settings.sync_timezone,
                at_hour=settings.sync_hour,
                at_minute=settings.sync_minute,
            )
            catalog = Schedule(frequency="hourly", timezone=settings.sync_timezone, at_minute=(row.id * 7 + 11) % 60)
            bind.execute(
                insert,
                {
                    "cid": row.id, "name": "Full device sweep", "kind": "device_sweep", "enabled": True,
                    "sections": sections, "frequency": "daily", "at_hour": settings.sync_hour,
                    "at_minute": settings.sync_minute, "tz": settings.sync_timezone,
                    "next_due_at": next_due(sweep, now), "now": now,
                },
            )
            bind.execute(
                insert,
                {
                    "cid": row.id, "name": "Smart group definitions", "kind": "catalog", "enabled": True,
                    "sections": "[]", "frequency": "hourly", "at_hour": None,
                    "at_minute": catalog.at_minute, "tz": settings.sync_timezone,
                    "next_due_at": next_due(catalog, now), "now": now,
                },
            )
            bind.execute(
                insert,
                {
                    "cid": row.id, "name": "Webhook", "kind": "webhook", "enabled": True,
                    "sections": sections, "frequency": None, "at_hour": None, "at_minute": None,
                    "tz": None, "next_due_at": None, "now": now,
                },
            )


def downgrade() -> None:
    op.drop_table("collections")
