"""the summary names which title each scalar is about (#311)

`summarize()` folds an app's matched titles three different ways and, until now, said which
title none of them came from:

* `is_compliant`, `this_version_seen`, `ea_assumed` — `any()` over every match;
* `patch_state`, `latest_version`, `latest_released_at` — the **reference** title (the one
  that says latest, else the rolling title, so an app behind everywhere shows what the vendor
  ships now);
* `patch_available_since`, `releases_missed` — the **sentence** title, #68's rule that both
  halves of "behind since <date> · <n> releases missed" come from one line.

On a single-title app that distinction is invisible. On a multi-title app the last two groups
are routinely different titles, and the columns sit next to each other as if they were not.
Wireshark 4.2.0 on the reference record matches two:

    612  Wireshark       currentVersion 4.6.8   behind  missed 25
    5F6  Wireshark 4.2   currentVersion 4.2.14  behind  missed 14

and the row reads `latest_version = 4.6.8` (from 612) beside `releases_missed = 14` (from
5F6). Read together they say "14 releases behind 4.6.8", which is true of neither title: it is
25 behind 4.6.8, or 14 behind 4.2.14. The fold rules are deliberate and ruled (#65, #68) and
are untouched here — what was missing is the subject, and #311 put these values inside one
wire object beside a list of title ids, which makes the wrong reading the natural one.

Neither id is derivable from the row: `reference_title_id` needs the per-title
`currentVersion` comparison and `sentence_title_id` needs `first_newer_released_at` per title,
which lives only in `app_catalog_title_matches`. So they are stored beside the values they
explain, judged once per (build, title) like everything else here.

Nullable, no backfill, mirroring c2f7b9e41d83 and b2e6f9a4c7d1: the next catalog refresh fills
them, and null reads as "not yet judged under this key" rather than as an answer.

Revision ID: d4a1e8c73b29
Revises: c2f7b9e41d83
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d4a1e8c73b29"
down_revision: Union[str, Sequence[str], None] = "c2f7b9e41d83"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLES = ("app_catalog", "installed_apps")
_COLUMNS = ("reference_title_id", "sentence_title_id")


def upgrade() -> None:
    for table in _TABLES:
        for column in _COLUMNS:
            op.add_column(table, sa.Column(column, sa.String(64), nullable=True))


def downgrade() -> None:
    for table in reversed(_TABLES):
        for column in reversed(_COLUMNS):
            op.drop_column(table, column)
