"""the sentence for "behind": releases_missed beside patch_available_since (#68)

#68 asked whose clock `patch_available_since` keeps and how to say "behind" without
printing 961 days. The clock stands — Jamf's release date of the earliest listed version
newer than the installed one, read off the title's own patch list — because the earliest
missed update is the only date that answers "behind by more than 14 days"; the latest
version's date resets with every release, and "when LoonInspect first noticed" measures
how long the customer has owned the product. That column is untouched here.

What changes is the sentence. A surface leads with "behind since 2024-01-03 · 14
releases missed": a date does not inflate, and a count grows only when the vendor ships,
never while the customer sleeps. The count was already computed inside `classify()` and
thrown away. It lands once per (build, title) at judge time on
`app_catalog_title_matches`, folds onto `app_catalog` beside `patch_available_since`
(the same title supplies both halves, so the sentence is true of one line), and is
copied onto `installed_apps` like every other answer column — cache, don't calculate.

Nullable, no backfill: rows are re-judged by the next catalog refresh, which fills it.
Nothing reads the column before then.

Revision ID: b2e6f9a4c7d1
Revises: c3f9a71e5b48
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b2e6f9a4c7d1"
down_revision: Union[str, Sequence[str], None] = "c3f9a71e5b48"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLES = ("app_catalog_title_matches", "app_catalog", "installed_apps")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(table, sa.Column("releases_missed", sa.Integer(), nullable=True))


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.drop_column(table, "releases_missed")
