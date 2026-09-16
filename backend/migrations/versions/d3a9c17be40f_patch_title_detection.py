"""jamf_patch_titles.detection: which witness says a title's software is on a Mac (#386)

Two values and a NULL, all three meant. `inventory` is a title carrying a recon test on the
bundle ID or the application title — the application inventory Jamf walks names it.
`extension_attribute` is a title whose every requirement test is an extension attribute, where
the EA is not the scoping device #65 described but the detection itself: the title exists to
tell Jamf Pro the software is there *because* recon cannot see it. NULL is a title that detects
no application at all — device-level ("Apple macOS …") and version-only titles.

**Backfilled here, and that is the whole upgrade path.** This is derived from `requirements`,
which every row already carries, so unlike #385's `app_name_source` — whose answer lived only in
a `killApps` field the sync drops on the way in — nothing has to be fetched from Jamf again. The
SQL below is `app.mdm.patch.requirements.detection_for` spelled once, for rows written before the
column existed; `sync_catalog` writes the column from that function for every row it touches
afterwards, from the same definition it writes `requirements` from.

The column does not decide admission — the matcher does, from the same rule — but it names what
changed: the 182 `extension_attribute` titles carrying a `bundleId` are admitted from here on,
so the next catalog index gains their version rows (73,347 → 78,580 on the 2026-09-16 catalog of
1,557 titles) and Macs running Firefox, Firefox ESR, Microsoft AutoUpdate, Skype, Nextcloud and
PyCharm Unified get a patch answer where they had none. Nothing is judged by this migration:
`rebuild_index` and `refresh_tenant` run on the next catalog sync, hourly, and re-judge every
tenant's rows against the wider catalog.

Revision ID: d3a9c17be40f
Revises: c3f8a1d7e964
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d3a9c17be40f"
down_revision: Union[str, Sequence[str], None] = "c3f8a1d7e964"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "jamf_patch_titles"

# `detection_for`, in SQL, over the grouped shape the sync stores: groups of tests, each test a
# `name`/`type`/`operator`/`value` object. A missing `type` is a recon test — `_convert_requirements`
# only ever sets it to `extensionAttribute` — so both halves read it with COALESCE the way the
# evaluator reads it with `!=`.
_TEST = """
    jsonb_array_elements(requirements) AS g,
    jsonb_array_elements(g->'tests') AS t
"""
_BACKFILL = f"""
UPDATE jamf_patch_titles SET detection = CASE
    WHEN EXISTS (
        SELECT 1 FROM {_TEST}
        WHERE COALESCE(t->>'type', '') <> 'extensionAttribute'
          AND t->>'name' IN ('Application Bundle ID', 'Application Title')
    ) THEN 'inventory'
    WHEN EXISTS (SELECT 1 FROM {_TEST})
     AND NOT EXISTS (
        SELECT 1 FROM {_TEST}
        WHERE COALESCE(t->>'type', '') <> 'extensionAttribute'
    ) THEN 'extension_attribute'
    ELSE NULL
END
"""


def upgrade() -> None:
    op.add_column(TABLE, sa.Column("detection", sa.String(length=24), nullable=True))
    op.execute(_BACKFILL)


def downgrade() -> None:
    # Only the published copy goes. The matcher derives the same value from `requirements` on
    # every catalog build, so a container downgraded here still admits the 182 titles and still
    # ships `patch.jamfPatch.detection`; what it loses is the column the titles list reads.
    op.drop_column(TABLE, "detection")
