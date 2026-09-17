"""app_catalog: the index the by-id lookup probes (#533)

`GET /api/vulnerabilities/{vulnID}` asks one question of every build the tenant has shown —
does this row's stored id list contain this id (`vuln_ids @> '["CVE-…"]'`)? Without an index
that is a sequential scan with a JSONB parse per row, on the one read a person makes with an
advisory open in the other window.

`jsonb_path_ops` rather than the default operator class, for `ix_observation_spans_section_digests`'s
reason: containment is the only operator this index will ever serve — the lookup asks `@>`,
and nothing asks `?` or `?|` over these lists — and the path-ops index is smaller and faster
for exactly that.

Not partial on `vuln_assessment = 'covered'` the way `ix_app_catalog_vuln_served` is, and not
led by `tenant_id`. A GIN index stores no entry for a NULL column value, so the rows that
predicate would exclude — `unknown_app` and `off`, which carry no id list — are already
absent; and a leading `tenant_id` would need the `btree_gin` extension inside the same index,
a new extension at migration time for a predicate row-level security applies anyway. The two
served-ness comparisons are left to the heap rows containment has already narrowed to: the
number of builds naming one id is small on any fleet, which is what makes that the cheap half.

Revision ID: b8d4f1a6c2e7
Revises: b6d2f4a9c3e7
Create Date: 2026-09-17
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "b8d4f1a6c2e7"
down_revision: Union[str, Sequence[str], None] = "b6d2f4a9c3e7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_INDEX = "ix_app_catalog_vuln_ids"


def upgrade() -> None:
    op.create_index(
        _INDEX, "app_catalog", ["vuln_ids"], postgresql_using="gin", postgresql_ops={"vuln_ids": "jsonb_path_ops"}
    )


def downgrade() -> None:
    op.drop_index(_INDEX, table_name="app_catalog")
