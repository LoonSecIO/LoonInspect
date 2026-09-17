"""installed_apps: the index the device vulnerability filter reads (#535)

`GET /api/devices?vuln=findings|kev` asks which Macs carry a finding, which is a semi-join
over `installed_apps` — the largest table in the schema, ~100 rows per device. #381 copied
six vulnerability columns onto it and no predicate has ever read one, so without this the
question is a sequential scan of every install in the tenant, per request.

**The key is the gate, not the counts.** `app.core.vuln_answer.served` is the whole of
*served*: the copy is `covered`, and the epoch that judged it is the epoch answering now.
`vuln_assessment = 'covered'` is the partial predicate and the key is
`(device_id, vuln_signature)` — `device_id` first because that is what the semi-join
returns and what the list's per-page rollup groups by, the signature second because
equality against the loaded epoch is the rest of the gate. `ix_app_catalog_vuln_served`
(#529) is the same index one grain up, on distinct builds rather than installs.

**The counts are deliberately not in the predicate**, and the issue asked for them there:
`WHERE ((vuln_counts->>'total')::int) > 0` is the obvious way to hold only the rows with
findings, and it cannot be used. The expression is evaluated on every write, so a stored
answer that will not parse stops being writable at all — and
`tests/test_vuln_answer_db.py::test_refresh_repairs_a_stored_answer_that_will_not_parse`
writes exactly such a row (`{"total": "seventeen"}`) onto **this** table on purpose, as the
hand-edited row and the restored backup do. Postgres refuses that write the moment the
index exists. The ruled behaviour for that row is to be named and read as `unknown_app`
(`vuln_answer._unreadable`), which an index that refuses the write turns into a 500 on a
sweep and into a failed index build inside somebody's restore. #529 measured this on
`app_catalog` and ruled the same way; the reader guards the cast instead
(`vuln_answer.counted`) and the index holds what cannot fail.

Operators note: on an already-populated table `CREATE INDEX` takes a write lock for the
duration of the build. It is not built CONCURRENTLY because Alembic runs migrations inside
a transaction and no other migration in this project does either.

Revision ID: b6d2f4a9c3e7
Revises: a7c21e9f4b83
Create Date: 2026-09-17
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b6d2f4a9c3e7"
down_revision: Union[str, Sequence[str], None] = "a7c21e9f4b83"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_INDEX = "ix_installed_apps_vuln_served"


def upgrade() -> None:
    op.create_index(
        _INDEX,
        "installed_apps",
        ["device_id", "vuln_signature"],
        postgresql_where=sa.text("vuln_assessment = 'covered'"),
    )


def downgrade() -> None:
    op.drop_index(_INDEX, table_name="installed_apps")
