"""posture_snapshot: the tape starts at launch — one row per metric per capture

Also the merge point for the a7d1c3e9f2b8 (AI consent, #118) and a9d4c7e1f3b8
(run.failed default-on, #119) heads, which both revised e6c9a2f4b8d1 as siblings —
three PRs left the same head in parallel, and this revision reunites the history.

Revision ID: f8b2d4a6c1e9
Revises: a7d1c3e9f2b8, a9d4c7e1f3b8
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f8b2d4a6c1e9"
down_revision: Union[str, Sequence[str], None] = ("a7d1c3e9f2b8", "a9d4c7e1f3b8")
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
        "posture_snapshot",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant_id(),
        # One key per row, never a wide row and never a JSON blob: adding a key is an
        # INSERT under the existing shape, and every key's history is a plain
        # (tenant, key, captured_at) scan. Definitions live in docs/posture-snapshot.md.
        sa.Column("metric_key", sa.Text(), nullable=False),
        sa.Column("value", sa.Numeric(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        # SET NULL, not RESTRICT: runs are purged after 30 days (app.core.runs.purge_runs)
        # while audit periods run 12 months — the snapshot is the only durable run
        # history, so its rows must outlive the run that stamped them.
        sa.Column(
            "full_sweep_run_id",
            sa.Uuid(),
            sa.ForeignKey("runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_posture_snapshot_tenant_id", "posture_snapshot", ["tenant_id"])
    op.create_index("ix_posture_snapshot_full_sweep_run_id", "posture_snapshot", ["full_sweep_run_id"])
    # The read shape: one key's history for one tenant, in time order.
    op.create_index("ix_posture_snapshot_series", "posture_snapshot", ["tenant_id", "metric_key", "captured_at"])
    _rls("posture_snapshot")


def downgrade() -> None:
    op.drop_table("posture_snapshot")
