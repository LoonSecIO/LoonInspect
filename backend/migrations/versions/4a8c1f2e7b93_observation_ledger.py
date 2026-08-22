"""observation ledger: spans, sections, entries, apertures

Revision ID: 4a8c1f2e7b93
Revises: e2a9c46b8d13
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "4a8c1f2e7b93"
down_revision: Union[str, Sequence[str], None] = "e2a9c46b8d13"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"

_TABLES = ("observation_spans", "observation_sections", "observation_entries", "observation_apertures")


def _tenant_id() -> sa.Column:
    return sa.Column(
        "tenant_id",
        sa.Uuid(),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
    )


def upgrade() -> None:
    op.create_table(
        "observation_spans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        _tenant_id(),
        sa.Column(
            "mdm_connection_id",
            sa.Integer(),
            sa.ForeignKey("mdm_connections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("subject_kind", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.String(255), nullable=False),
        sa.Column("label", sa.String(255), nullable=True),
        sa.Column("udid", sa.String(64), nullable=True),
        sa.Column("serial_number", sa.String(64), nullable=True),
        sa.Column("management_id", sa.String(64), nullable=True),
        sa.Column("contract_version", sa.String(8), nullable=False),
        sa.Column("aperture_digest", sa.String(67), nullable=False),
        sa.Column("head_digest", sa.String(67), nullable=False),
        sa.Column("section_digests", JSONB, nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_trigger", sa.String(16), nullable=False),
        sa.Column(
            "previous_id",
            sa.Uuid(),
            sa.ForeignKey("observation_spans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_observation_spans_tenant_id", "observation_spans", ["tenant_id"])
    op.create_index("ix_observation_spans_mdm_connection_id", "observation_spans", ["mdm_connection_id"])
    op.create_index("ix_observation_spans_head_digest", "observation_spans", ["head_digest"])
    op.create_index(
        "ix_observation_spans_subject",
        "observation_spans",
        ["tenant_id", "mdm_connection_id", "subject_kind", "subject_id"],
    )
    # At most one current span per subject. The insert is the claim.
    op.create_index(
        "uq_observation_spans_current_subject",
        "observation_spans",
        ["mdm_connection_id", "subject_kind", "subject_id"],
        unique=True,
        postgresql_where=sa.text("is_current"),
    )
    # jsonb_path_ops: smaller and faster for the one operator this index serves, the
    # containment query `section_digests @> '{"applications": "v0:…"}'`.
    op.create_index(
        "ix_observation_spans_section_digests",
        "observation_spans",
        ["section_digests"],
        postgresql_using="gin",
        postgresql_ops={"section_digests": "jsonb_path_ops"},
    )

    op.create_table(
        "observation_sections",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant_id(),
        sa.Column("digest", sa.String(67), nullable=False),
        sa.Column("section", sa.String(32), nullable=False),
        sa.Column("body", JSONB, nullable=True),
        sa.Column("entry_digests", JSONB, nullable=True),
        sa.Column("entry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "digest", name="uq_observation_section_digest"),
    )
    op.create_index("ix_observation_sections_tenant_id", "observation_sections", ["tenant_id"])
    op.create_index("ix_observation_sections_digest", "observation_sections", ["digest"])
    # Default jsonb ops here, not jsonb_path_ops: Discover asks `entry_digests ? 'v0:…'`
    # (array membership), which jsonb_path_ops cannot serve.
    op.create_index(
        "ix_observation_sections_entry_digests",
        "observation_sections",
        ["entry_digests"],
        postgresql_using="gin",
    )

    op.create_table(
        "observation_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant_id(),
        sa.Column("digest", sa.String(67), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("body", JSONB, nullable=False),
        sa.Column("label", sa.String(255), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "digest", name="uq_observation_entry_digest"),
    )
    op.create_index("ix_observation_entries_tenant_id", "observation_entries", ["tenant_id"])
    op.create_index("ix_observation_entries_digest", "observation_entries", ["digest"])
    op.create_index("ix_observation_entries_kind", "observation_entries", ["kind"])

    op.create_table(
        "observation_apertures",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant_id(),
        sa.Column(
            "mdm_connection_id",
            sa.Integer(),
            sa.ForeignKey("mdm_connections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("digest", sa.String(67), nullable=False),
        sa.Column("contract_version", sa.String(8), nullable=False),
        sa.Column("document", JSONB, nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "digest", name="uq_observation_aperture_digest"),
    )
    op.create_index("ix_observation_apertures_tenant_id", "observation_apertures", ["tenant_id"])
    op.create_index("ix_observation_apertures_mdm_connection_id", "observation_apertures", ["mdm_connection_id"])
    op.create_index("ix_observation_apertures_digest", "observation_apertures", ["digest"])

    for table in _TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})"
        )


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.drop_table(table)
