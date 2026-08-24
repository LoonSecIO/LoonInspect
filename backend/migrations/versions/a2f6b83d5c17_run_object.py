"""the run as a first-class object: the row that is the mutex, the jobID, the _time window,
and the run log it scopes

Revision ID: a2f6b83d5c17
Revises: b4c7e9d2a1f6
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "a2f6b83d5c17"
down_revision: Union[str, Sequence[str], None] = "b4c7e9d2a1f6"
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
        "runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        _tenant_id(),
        sa.Column(
            "mdm_connection_id",
            sa.Integer(),
            sa.ForeignKey("mdm_connections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "collection_id",
            sa.Integer(),
            sa.ForeignKey("collections.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("comparison", sa.String(16), nullable=False),
        sa.Column("lock_class", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("device_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("group_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("observations", JSONB, nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("actor_label", sa.String(255), nullable=True),
    )
    op.create_index("ix_runs_tenant_id", "runs", ["tenant_id"])
    op.create_index("ix_runs_mdm_connection_id", "runs", ["mdm_connection_id"])
    op.create_index("ix_runs_collection_id", "runs", ["collection_id"])
    op.create_index("ix_runs_trigger", "runs", ["trigger"])
    op.create_index("ix_runs_status", "runs", ["status"])
    op.create_index("ix_runs_recent", "runs", ["tenant_id", "started_at"])
    op.create_index("ix_runs_connection", "runs", ["tenant_id", "mdm_connection_id", "started_at"])

    # The mutex itself. Partial on status so only live runs contend and history piles up
    # freely underneath. The key is (tenant, connection, class) and not (tenant): the
    # resource being protected is the Jamf server, which is the connection, and a cheap
    # catalog refresh has no reason to queue behind an expensive device sweep of the same
    # one. Webhooks are lock-exempt in the predicate — they get a run for the jobID and
    # the log, never the lock. See docs/ingest-scheduling.md §4.1 and §4.4.
    op.create_index(
        "uq_run_active_lock",
        "runs",
        ["tenant_id", "mdm_connection_id", "lock_class"],
        unique=True,
        postgresql_where=sa.text("status = 'running' AND lock_class <> 'webhook'"),
    )
    op.create_index(
        "ix_runs_heartbeat",
        "runs",
        ["heartbeat_at"],
        postgresql_where=sa.text("status = 'running'"),
    )

    op.create_table(
        "run_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant_id(),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("level", sa.String(8), nullable=False),
        sa.Column("message", sa.String(512), nullable=False),
        sa.Column("fields", JSONB, nullable=True),
    )
    op.create_index("ix_run_log_tenant_id", "run_log", ["tenant_id"])
    op.create_index("ix_run_log_run_id", "run_log", ["run_id"])
    op.create_index("ix_run_log_run", "run_log", ["run_id", "id"])

    for table in ("runs", "run_log"):
        _rls(table)


def downgrade() -> None:
    op.drop_table("run_log")
    op.drop_table("runs")
