"""what an update would fix: the target build's answer beside the installed one (#482)

The product shows both halves and never joins them: a `covered` build's findings come from
`vuln_library_rows`, the latest release comes from the Jamf Patch answer, and nothing says
what the second would do to the first. It cannot be inferred — the two-Mac lab of #428
found Wireshark 4.2.0 covered at 17 findings and 4.6.0 covered at 94, so *update to latest*
is not *clean*. A report has to read the target build's own answer.

`app_catalog.vuln_target_key` is `app_full_key(name, bundle_id, latest_version, None)` —
the installed build's own identity with the patch answer's version in the version slot —
and it is joined against `vuln_library_rows.key_full`, that table's primary key, in the
same `UPDATE … FROM` that already judges the build itself. The key is written on the Jamf
clock beside `latest_version`; the answer is written on the corpus clock. The key is not
copied onto `installed_apps`: a key is a judge input, not an answer.

`vuln_target_version` is the judge's own record of which version it answered about. It is
what tells a row judged before this column existed (NULL, and nothing is rendered) from one
whose target the epoch holds no row for (a version with a NULL assessment, which renders
*outside the corpus* and never *closes all of them* — ruling R-D, one row out).

Nullable, no backfill, mirroring d4a1e8c73b29: the next catalog refresh or corpus pass
fills them, and NULL reads as "not yet judged under this key" rather than as an answer.
That window is the one the judge is guarded for: until the next catalog sync every row here
has a NULL `vuln_target_key` beside a non-NULL `latest_version`, and a corpus epoch that
moves first re-judges exactly those rows — so `judge_vuln` writes `vuln_target_version`
only where the key it joins on exists, and a release nothing looked up stores nothing
rather than storing itself as "not in the corpus".
Nothing new goes on the wire (docs/vulnerabilities.md §6); this is an in-app render.

Revision ID: b3e7d1a9c5f0
Revises: f1b6c48a3e29
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "b3e7d1a9c5f0"
down_revision: Union[str, Sequence[str], None] = "f1b6c48a3e29"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLES = ("app_catalog", "installed_apps")
_ANSWER = (
    ("vuln_target_version", sa.String(64)),
    ("vuln_target_assessment", sa.String(16)),
    ("vuln_target_counts", JSONB()),
    ("vuln_target_ids", JSONB()),
    ("vuln_target_ids_truncated", sa.Boolean()),
)


def upgrade() -> None:
    op.add_column("app_catalog", sa.Column("vuln_target_key", sa.String(67), nullable=True))
    for table in _TABLES:
        for column, kind in _ANSWER:
            op.add_column(table, sa.Column(column, kind, nullable=True))


def downgrade() -> None:
    for table in reversed(_TABLES):
        for column, _ in reversed(_ANSWER):
            op.drop_column(table, column)
    op.drop_column("app_catalog", "vuln_target_key")
