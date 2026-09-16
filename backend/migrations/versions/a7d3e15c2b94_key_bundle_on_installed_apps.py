"""key_bundle on installed_apps: the build without its name (#245)

The third v1 content key from docs/data-sharing.md — `app.bundle` over (bundle_id,
version). `key_title` and `key_full` both hash the display name, so an admin who renames
an app mints keys only their own fleet holds and the corpus's reveal threshold counts one
submitter forever. Every rename of one bundle collapses onto one `key_bundle`.

Nullable, and deliberately NOT backfilled — unlike its two siblings, which this migration
is otherwise a copy of (9c41d20a77e1). Two reasons, both permanent:

* the key is genuinely absent for an app with no bundle identifier. `app_bundle_key`
  answers None rather than hashing the empty string, because identity here is the bundle
  id alone: one shared digest for every nameless app would be counted as one piece of
  software. NULL is that absence, not a missing backfill;
* rows are stamped at their next ingest — because the ingest path was taught to restamp
  them. That half does not come for free and is the reason to read this note rather than
  assume: `installed_apps` is INSERT-on-version-change, so an app pinned at one build is
  kept, not rewritten, and would never gain the key at all. `app.mdm.service.process_sync`
  therefore stamps the rows it KEEPS as well as the rows it inserts, once each, the first
  time it sees one without a key. The sibling migration had no such restamp to lean on,
  and its columns were about to be NOT NULL besides, so it paid for a per-row rewrite of
  every tenant inside the operator's upgrade transaction; this one pays an UPDATE per row
  on the first sweep after the upgrade instead — spread across the fleet, and
  self-extinguishing. Until that sweep runs the exchange row simply omits `bundle` —
  absent, never null, which is exactly how the cloud already reads a key an older
  container never sent.

Indexed per the issue's "Done when" and like its two siblings. No query in this container
uses that index yet; it is carried for the corpus-side joins the key is minted ahead of.

Revision ID: a7d3e15c2b94
Revises: c4e8b1d7a9f3
Create Date: 2026-09-16
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a7d3e15c2b94"
down_revision: Union[str, Sequence[str], None] = "c4e8b1d7a9f3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("installed_apps", sa.Column("key_bundle", sa.String(67), nullable=True))
    op.create_index("ix_installed_apps_key_bundle", "installed_apps", ["key_bundle"])


def downgrade() -> None:
    op.drop_index("ix_installed_apps_key_bundle", table_name="installed_apps")
    op.drop_column("installed_apps", "key_bundle")
