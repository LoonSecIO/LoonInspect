"""subject_departures — an object absent from a clean census is gone (#181)

A smart group vanishing is not an edge case: large orgs delete them constantly, because a
group is how a phased rollout is expressed and a finished rollout is a group nobody needs.
Extension-attribute definitions go the same way. Until now nothing noticed: a deleted
group's span stayed current for ever, and every surface kept listing it as live.

Departure is derived state on the object, timestamped, and re-derivable from the census
history — never an observation. Absence opens and closes no span (#135 rider 4), so the
ledger stays clean; this table is where the derivation lands. One open departure per
subject at a time (the partial unique index); a return closes it with `returned_at`, and
a second departure is a second row, so the history is kept.

Revision ID: d9e4b7c2a8f3
Revises: c7d2f9a4b6e1
Create Date: 2026-09-09
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d9e4b7c2a8f3"
down_revision: Union[str, Sequence[str], None] = "c7d2f9a4b6e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def _rls(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON {table} USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def upgrade() -> None:
    op.create_table(
        "subject_departures",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
        sa.Column("mdm_connection_id", sa.Integer(), sa.ForeignKey("mdm_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject_kind", sa.String(length=32), nullable=False),
        sa.Column("subject_id", sa.String(length=255), nullable=False),
        sa.Column("departed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("returned_at", sa.DateTime(timezone=True), nullable=True),
        # SET NULL, not RESTRICT: runs are purged after 30 days and a departure outlives
        # the census that found it.
        sa.Column("census_run_id", sa.Uuid(), sa.ForeignKey("runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_subject_departures_tenant_id", "subject_departures", ["tenant_id"])
    op.create_index(
        "ix_subject_departures_subject",
        "subject_departures",
        ["tenant_id", "mdm_connection_id", "subject_kind", "subject_id"],
    )
    # One open departure per subject: the second census after a deletion finds it gone
    # again and must not write it gone again.
    op.create_index(
        "uq_subject_departures_open",
        "subject_departures",
        ["tenant_id", "mdm_connection_id", "subject_kind", "subject_id"],
        unique=True,
        postgresql_where=sa.text("returned_at IS NULL"),
    )
    _rls("subject_departures")


def downgrade() -> None:
    op.drop_table("subject_departures")
