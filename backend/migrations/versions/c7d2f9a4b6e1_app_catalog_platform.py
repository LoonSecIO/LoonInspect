"""app_catalog.platform — a catalog row is judged for the platform it was seen on (#236)

Every row in `app_catalog` was judged as if installed on a Mac: `Facts.platform`
defaulted to "Mac", so a Jamf Patch title carrying a `Platform is Mac` criterion
passed for every row. Correct while every row is a Mac; wrong the first time a mobile
app enters the catalog — Jamf Patch carries macOS titles only, so for a mobile row the
only correct answer is "not matchable", and the default would have manufactured matches
and copied them onto `installed_apps` and out to the wire.

The row carries the platform of the devices that showed it, keyed beside `version_hash`
(a universal app has the same name, bundle id and version on both platforms), and the
unique constraint takes it now, while exactly one platform exists.

Revision ID: c7d2f9a4b6e1
Revises: b3c9e7d1a5f2
Create Date: 2026-09-09
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c7d2f9a4b6e1"
down_revision: Union[str, Sequence[str], None] = "b3c9e7d1a5f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "app_catalog",
        sa.Column("platform", sa.String(length=16), nullable=False, server_default="macos"),
    )
    op.drop_constraint("uq_app_catalog_version", "app_catalog", type_="unique")
    op.create_unique_constraint(
        "uq_app_catalog_platform_version", "app_catalog", ["tenant_id", "platform", "version_hash"]
    )


def downgrade() -> None:
    # Only safe while one platform exists — with two, the narrower key refuses the second
    # row of every pair. KNOWN_ISSUES.md §6 records that the downgrade path is manual.
    op.drop_constraint("uq_app_catalog_platform_version", "app_catalog", type_="unique")
    op.create_unique_constraint("uq_app_catalog_version", "app_catalog", ["tenant_id", "version_hash"])
    op.drop_column("app_catalog", "platform")
