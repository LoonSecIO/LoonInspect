"""jamf patch matching: per-app title matches and the summary columns

Revision ID: f3a7c1d9e2b5
Revises: d7e4a9c2b6f1
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "f3a7c1d9e2b5"
down_revision: Union[str, Sequence[str], None] = "d7e4a9c2b6f1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def upgrade() -> None:
    # Null marks rows fetched before the column existed; the next catalog sync re-fetches them.
    op.add_column("jamf_patch_titles", sa.Column("extension_attributes", JSONB, nullable=True))

    op.add_column("installed_apps", sa.Column("jamf_title_ids", JSONB, nullable=True))
    op.add_column("installed_apps", sa.Column("patch_state", sa.String(16), nullable=True))
    op.add_column("installed_apps", sa.Column("this_version_seen", sa.Boolean(), nullable=True))
    op.add_column("installed_apps", sa.Column("latest_version", sa.String(64), nullable=True))
    op.add_column("installed_apps", sa.Column("latest_released_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "installed_app_patch_matches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
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

    op.execute("ALTER TABLE installed_app_patch_matches ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE installed_app_patch_matches FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON installed_app_patch_matches "
        f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})"
    )


def downgrade() -> None:
    op.drop_table("installed_app_patch_matches")
    for column in ("latest_released_at", "latest_version", "this_version_seen", "patch_state", "jamf_title_ids"):
        op.drop_column("installed_apps", column)
    op.drop_column("jamf_patch_titles", "extension_attributes")
