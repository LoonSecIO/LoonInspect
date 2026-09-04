"""ea_assumed: the assumption, folded onto the row so the wire can say it (#311)

The matcher resolves an extension attribute the device does not carry as TRUE — Jamf's
scoping device for collisions (PyCharm Community vs Professional, Firefox vs ESR), not a
fact about the app — and records the match with `basis = "ea_assumed"` so the assumption
stays visible (Kyle, 2026-08-22). It stayed visible in exactly one place:
`app_catalog_title_matches.basis`. Nothing folded it, so nothing outside that table could
say it, and #311 put `patch.jamfPatch{}` on the wire, where a reader could not tell a
fully-evaluated match from an assumed one. That is the outcome `basis` was minted to
prevent, reproduced one layer out.

So the fold lands beside every other answer column: computed once per (build, title) at
judge time in `summarize()`, written to `app_catalog` by `_apply_summary`, copied onto
`installed_apps` by `copy_answer`. Cache, don't calculate. `basis` itself is untouched —
this is the boolean the wire can afford at one block per app per device per sync, not a
replacement for the per-title reason.

TRUE when ANY matched title assumed, not the reference title's own basis: the flag says
"some part of this answer rests on an assumption", which is the only direction that
cannot quietly clear an assumed match behind a fully-evaluated one.

Nullable, no backfill, mirroring `releases_missed` (b2e6f9a4c7d1): rows are re-judged by
the next catalog refresh, which fills it, and null reads as "not yet judged under #311"
rather than as `false`. `app_catalog_title_matches` gets no column — `basis` is already
there and is the richer form.

Revision ID: c2f7b9e41d83
Revises: a1c8f4b62d70
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c2f7b9e41d83"
down_revision: Union[str, Sequence[str], None] = "a1c8f4b62d70"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLES = ("app_catalog", "installed_apps")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(table, sa.Column("ea_assumed", sa.Boolean(), nullable=True))


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.drop_column(table, "ea_assumed")
