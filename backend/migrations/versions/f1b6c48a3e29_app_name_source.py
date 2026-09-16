"""jamf_patch_titles.app_name_source: where a title's app name came from (#385)

Jamf leaves the top-level `appName` null on 513 of its 1,553 patch titles — every versioned
line, "Wireshark 4.2" among them — while naming the same app in each patch's `killApps` for
the same bundle ID. That name is what a Jamf inventory reports for the installed app, so it
is the name a content key has to be computed from; without it those titles' rows carried no
`key_full`, no `key_title` and no hashes, and nothing keyed on them could answer for the very
Macs they describe. The sync now takes it (`app.mdm.patch.jamf_catalog._app_name`, the
engine's rule) and this column says which of the two gave it, so a salvaged name is never
mistaken for one Jamf published.

Three values, all written by the sync: `jamf`, `kill_apps`, and `unnamed` for a title nothing
names an app for anywhere. NULL is the fourth state and the only one this migration leaves
behind: a row written before the rule existed.

**Deliberately not backfilled, and that is the whole upgrade path.** A `jamf` backfill for
rows that already carry a name would be correct — a stored name could only have come from
Jamf's field — and it would strand the rows this change is for: `_needs_refresh` re-fetches a
title only when Jamf's `lastModified` or `currentVersion` moved, and a frozen versioned line
never moves again (Wireshark 4.2's last release was 2024), so those 513 titles would keep a
null `app_name` forever on a container that already has rows. Leaving every row NULL here
makes the next hourly sync read each title's definition once more — one pass of ~1,554
definitions at eight in flight, the same work a cold container does on its first tick — after
which every row carries a source and the clause never fires again.

Revision ID: f1b6c48a3e29
Revises: c4e8b1d7a9f3
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f1b6c48a3e29"
down_revision: Union[str, Sequence[str], None] = "a7d3e15c2b94"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "jamf_patch_titles"


def upgrade() -> None:
    op.add_column(TABLE, sa.Column("app_name_source", sa.String(length=16), nullable=True))


def downgrade() -> None:
    # The salvaged names themselves stay in `app_name`, unmarked. Dropping them would be the
    # larger loss: a row downgraded and then upgraded again is re-read by the same clause that
    # reads a row this migration has never touched, and the name is decided from the
    # definition either way.
    op.drop_column(TABLE, "app_name_source")
