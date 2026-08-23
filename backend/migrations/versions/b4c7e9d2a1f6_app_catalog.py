"""app catalog: the tenant's distinct apps with first/last seen and Jamf's answer, the title
matches per catalog row (replacing the per-device matches), and Jamf's side as a local lookup

Revision ID: b4c7e9d2a1f6
Revises: f3a7c1d9e2b5
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "b4c7e9d2a1f6"
down_revision: Union[str, Sequence[str], None] = "f3a7c1d9e2b5"
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
        "app_catalog",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant_id(),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("bundle_id", sa.String(255), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("short_version", sa.String(64), nullable=True),
        sa.Column("app_hash", sa.String(32), nullable=False),
        sa.Column("version_hash", sa.String(32), nullable=False),
        sa.Column("key_title", sa.String(67), nullable=False),
        sa.Column("key_full", sa.String(67), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("jamf_title_ids", JSONB, nullable=True),
        sa.Column("patch_state", sa.String(16), nullable=True),
        sa.Column("is_latest", sa.Boolean(), nullable=True),
        sa.Column("patch_available", sa.Boolean(), nullable=True),
        sa.Column("patch_available_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("this_version_seen", sa.Boolean(), nullable=True),
        sa.Column("latest_version", sa.String(64), nullable=True),
        sa.Column("latest_released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evaluated_signature", sa.String(64), nullable=True),
        sa.UniqueConstraint("tenant_id", "version_hash", name="uq_app_catalog_version"),
    )
    op.create_index("ix_app_catalog_tenant_id", "app_catalog", ["tenant_id"])
    op.create_index("ix_app_catalog_key_full", "app_catalog", ["key_full"])
    op.create_index("ix_app_catalog_app", "app_catalog", ["tenant_id", "app_hash"])
    op.create_index("ix_app_catalog_last_seen", "app_catalog", ["tenant_id", "last_seen_at"])

    op.create_table(
        "app_catalog_title_matches",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant_id(),
        sa.Column("app_catalog_id", sa.Integer(), sa.ForeignKey("app_catalog.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title_id", sa.String(64), sa.ForeignKey("jamf_patch_titles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("basis", sa.String(16), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("version_known", sa.Boolean(), nullable=False),
        sa.Column("on_latest", sa.Boolean(), nullable=False),
        sa.Column("installed_version", sa.String(64), nullable=True),
        sa.Column("installed_released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("latest_version", sa.String(64), nullable=False),
        sa.Column("latest_released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_newer_released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("app_catalog_id", "title_id", name="uq_app_catalog_title_match"),
    )
    op.create_index("ix_app_catalog_title_matches_tenant_id", "app_catalog_title_matches", ["tenant_id"])
    op.create_index("ix_app_catalog_title_matches_app_catalog_id", "app_catalog_title_matches", ["app_catalog_id"])
    op.create_index("ix_app_catalog_title_matches_title", "app_catalog_title_matches", ["tenant_id", "title_id"])

    for table in ("app_catalog", "app_catalog_title_matches"):
        _rls(table)

    op.create_table(
        "app_catalog_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title_id", sa.String(64), sa.ForeignKey("jamf_patch_titles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title_name", sa.String(255), nullable=False),
        sa.Column("publisher", sa.String(255), nullable=True),
        sa.Column("app_name", sa.String(255), nullable=True),
        sa.Column("bundle_id", sa.String(255), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_latest", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("app_hash", sa.String(32), nullable=True),
        sa.Column("version_hash", sa.String(32), nullable=True),
        sa.Column("key_title", sa.String(67), nullable=True),
        sa.Column("key_full", sa.String(67), nullable=True),
    )
    op.create_index("ix_app_catalog_versions_title_id", "app_catalog_versions", ["title_id"])
    op.create_index("ix_app_catalog_versions_app_hash", "app_catalog_versions", ["app_hash"])
    op.create_index("ix_app_catalog_versions_version_hash", "app_catalog_versions", ["version_hash"])
    op.create_index("ix_app_catalog_versions_key_full", "app_catalog_versions", ["key_full"])
    op.create_index("ix_app_catalog_versions_bundle_version", "app_catalog_versions", ["bundle_id", "version"])

    # The per-device matches of #65 are derivable from the catalog row through version_hash.
    op.drop_table("installed_app_patch_matches")


def downgrade() -> None:
    op.create_table(
        "installed_app_patch_matches",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant_id(),
        sa.Column("installed_app_id", sa.Integer(), sa.ForeignKey("installed_apps.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title_id", sa.String(64), sa.ForeignKey("jamf_patch_titles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("basis", sa.String(16), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("version_known", sa.Boolean(), nullable=False),
        sa.Column("on_latest", sa.Boolean(), nullable=False),
        sa.Column("installed_version", sa.String(64), nullable=True),
        sa.Column("installed_released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("latest_version", sa.String(64), nullable=False),
        sa.Column("latest_released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_newer_released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("installed_app_id", "title_id", name="uq_installed_app_patch_match"),
    )
    op.create_index("ix_installed_app_patch_matches_tenant_id", "installed_app_patch_matches", ["tenant_id"])
    op.create_index("ix_installed_app_patch_matches_installed_app_id", "installed_app_patch_matches", ["installed_app_id"])
    op.create_index("ix_installed_app_patch_matches_title", "installed_app_patch_matches", ["tenant_id", "title_id"])
    _rls("installed_app_patch_matches")
    op.drop_table("app_catalog_versions")
    op.drop_table("app_catalog_title_matches")
    op.drop_table("app_catalog")
