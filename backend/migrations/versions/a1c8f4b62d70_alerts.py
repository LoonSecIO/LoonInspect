"""alerts: the derived latch, open while it is true of the fleet and closed by the same
code path that opened it (#101)

Revision ID: a1c8f4b62d70
Revises: e4b1d7c93a52
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a1c8f4b62d70"
down_revision: Union[str, Sequence[str], None] = "e4b1d7c93a52"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def _tenant_id() -> sa.Column:
    return sa.Column(
        "tenant_id",
        sa.Uuid(),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
    )


def _rls(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant_id(),
        sa.Column("kind", sa.String(length=32), nullable=False),
        # The change log's closed `high | normal | low`, never a minted `severity`.
        sa.Column("level", sa.String(length=8), nullable=False),
        # CASCADE: a device that is gone has no fleet-state left to assert.
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        # md5(name:bundle_id) — the app, not the build. Keying on version_hash would make
        # every update a NEW-app alert.
        sa.Column("app_hash", sa.String(length=32), nullable=False),
        # Denormalised because the close *is* the deletion of the installed_apps row: a
        # closed alert must still be able to say what it was about.
        sa.Column("app_name", sa.String(length=255), nullable=False),
        sa.Column("bundle_id", sa.String(length=255), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        # SET NULL for the same reason posture_snapshot.full_sweep_run_id is: runs purge
        # after 30 days and the latch has to outlive the sweep that noticed it.
        sa.Column("opened_run_id", sa.Uuid(), sa.ForeignKey("runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("closed_run_id", sa.Uuid(), sa.ForeignKey("runs.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_alerts_tenant_id", "alerts", ["tenant_id"])
    # device_id, and deliberately not kind or app_hash: those two sit inside the composite
    # below, whose leading columns serve a kind filter and whose full width serves the
    # close, so single-column copies would be write cost on the sweep's hot path for
    # nothing. device_id earns its own — the CASCADE from `devices` and the closed-row
    # history read both need it, and neither can use a partial index.
    op.create_index("ix_alerts_device_id", "alerts", ["device_id"])
    # The concurrency guard, not a nicety. Webhook ingests never take the sweep lock, so
    # two passes over one device can race the same open; the writer relies on this index
    # for ON CONFLICT DO NOTHING. Partial, so a re-install after a close opens a new row.
    op.create_index(
        "uq_alerts_open",
        "alerts",
        ["tenant_id", "kind", "device_id", "app_hash"],
        unique=True,
        postgresql_where=sa.text("closed_at IS NULL"),
    )
    # The open list's read shape.
    op.create_index(
        "ix_alerts_open", "alerts", ["tenant_id", "opened_at"], postgresql_where=sa.text("closed_at IS NULL")
    )
    # `alerts.opened_24h` counts rows that have since closed, so it cannot use the partial
    # index above. Named for its window: `ix_alerts_open` and `ix_alerts_opened` sitting
    # beside each other is a trap in an EXPLAIN.
    op.create_index("ix_alerts_opened_window", "alerts", ["tenant_id", "opened_at"])
    _rls("alerts")


def downgrade() -> None:
    op.drop_table("alerts")
