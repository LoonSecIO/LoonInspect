"""the stored vulnerability answer, per distinct build (#381)

The local join, where it lands. #248 loads an epoch into three global tables; this is
where its answer for one build is *kept* — on the tenant's `app_catalog` row, judged once
per distinct build, and copied onto every `installed_apps` row carrying that build exactly
as the Jamf Patch answer already is.

Why columns rather than a lookup at read time: a device page renders ~100 apps and a
40k-device sweep fans out ~3M app items. Asking a corpus per app is the shape
"cache, don't calculate" exists to refuse, and the answer is the same for every device
carrying the build — so it belongs on the build, once.

Nullable with no server default, all of them, on purpose. NULL on `vuln_assessment` is a
meaning and not a gap: **this epoch held no row for this build**, which reads
`unknown_app` — never `covered` with zeroes (docs/vulnerabilities.md §4a, §4f). Every row
that existed before this migration is therefore correctly "not assessed by any epoch" the
moment the column appears, and the first judge pass writes the real answer.

`vuln_signature` is which epoch answered. It sits beside `evaluated_signature` rather than
inside it: `evaluated_signature` names the Jamf catalog a row was judged against, this
names the corpus epoch, a row is re-judged when either moves, and this one has to travel
with the answer onto `installed_apps`, where there is no `evaluated_signature`.

Revision ID: b3e7c1d5f9a2
Revises: d1f8b6a34e07
Create Date: 2026-09-11
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "b3e7c1d5f9a2"
down_revision: Union[str, Sequence[str], None] = "d1f8b6a34e07"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The aggregates, in the shape `vuln_library_rows` publishes them, so the judge-time join
# is a column-to-column copy in one `UPDATE … FROM` rather than a re-encoding. Built by a
# factory rather than held as `Column` objects: a `Column` belongs to the table it is
# added to, and the same instance cannot be added to two of them.
_ANSWER: tuple[tuple[str, object], ...] = (
    ("vuln_assessment", sa.String(16)),
    ("vuln_counts", JSONB),
    ("vuln_oldest_published", JSONB),
    ("vuln_ids", JSONB),
    ("vuln_ids_truncated", sa.Boolean()),
    ("vuln_signature", sa.String(64)),
)


def upgrade() -> None:
    for name, kind in _ANSWER:
        op.add_column("app_catalog", sa.Column(name, kind, nullable=True))
        op.add_column("installed_apps", sa.Column(name, kind, nullable=True))
    # The judge-time stamp, on the catalog row only — the pair of `evaluated_at`. The
    # device row's own clock is `last_patch_check_at`, which the copier already sets.
    op.add_column("app_catalog", sa.Column("vuln_evaluated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("app_catalog", "vuln_evaluated_at")
    for name, _kind in reversed(_ANSWER):
        op.drop_column("installed_apps", name)
        op.drop_column("app_catalog", name)
