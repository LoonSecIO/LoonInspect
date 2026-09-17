"""app_catalog: the index the vulnerability filter reads (#529)

`GET /api/catalog?vuln=` turns the stored per-build answer into a `WHERE`, and `app_catalog`
had no index on any of its vulnerability columns — #381 added six and no predicate ever read
one. On a tenant of a few thousand builds *show me the ones with findings* was a sequential
scan per request, and the `vulnJudged` `EXISTS` beside it was a second one.

**The key is the gate, not the counts**, because the gate is on every one of these reads:
`app.core.vuln_answer.served` — the row is `covered`, and the epoch that judged it is the
epoch answering now. `vuln_assessment = 'covered'` is the partial predicate (it is the
smaller side on every tenant and it is never part of an answer, only of the gate), and the
key is `(tenant_id, vuln_signature)`: the tenant first, as `ix_app_catalog_app` and
`ix_app_catalog_last_seen` already are, and the signature second because equality against
the loaded epoch is the whole of *served* and is the entirety of `vulnJudged`'s `EXISTS`.
The counts and the bands are then a filter over the rows those two columns already narrowed
to — a JSONB read per candidate row on a table of distinct builds, never of installs.

**The counts are deliberately NOT in the key**, and this is measured rather than assumed.
`((vuln_counts->>'total')::int)` is the obvious expression to index and it cannot be: the
expression is evaluated on every write, so a stored answer that will not parse stops being
writable at all. `tests/test_vuln_answer_db.py::test_refresh_repairs_a_stored_answer_that_
will_not_parse` writes exactly such a row on purpose — the hand-edited row, the restored
backup — and Postgres refuses it (`invalid input syntax for type integer`) the moment that
index exists. The ruled behaviour for that row is to be named and read as `unknown_app`
(`vuln_answer._unreadable`), which an index that refuses the write turns into a 500 here and
a failed index build inside somebody's restore. So the reader guards the cast instead
(`app.api.catalog._counted`) and the index holds what cannot fail.

Revision ID: a7c21e9f4b83
Revises: c4a9e7b1d3f6
Create Date: 2026-09-17
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a7c21e9f4b83"
down_revision: Union[str, Sequence[str], None] = "c4a9e7b1d3f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_INDEX = "ix_app_catalog_vuln_served"


def upgrade() -> None:
    op.create_index(
        _INDEX,
        "app_catalog",
        ["tenant_id", "vuln_signature"],
        postgresql_where=sa.text("vuln_assessment = 'covered'"),
    )


def downgrade() -> None:
    op.drop_index(_INDEX, table_name="app_catalog")
