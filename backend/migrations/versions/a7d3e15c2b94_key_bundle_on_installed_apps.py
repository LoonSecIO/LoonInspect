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
* rows are stamped at their next ingest. The sibling migration walked every tenant and
  rewrote every row in the operator's upgrade transaction, because its columns were about
  to be NOT NULL; this one has nothing forcing that cost. A container's next sweep
  restamps the whole fleet through the one hashing site (`app.mdm.service.apply_hashes`),
  and until it runs the exchange row simply omits `bundle` — absent, never null, which is
  exactly how the cloud already reads a key an older container never sent.

Indexed like its siblings: the exchange aggregate reads it per group and the corpus joins
on it.

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
