"""Store one vulnerability update target per matched title (#526).

A build can match both a reference title and an in-branch title with different latest
versions. These nullable columns distinguish not-yet-looked-up targets from a lookup
whose corpus has no row. The versioned catalog signature triggers re-matching on the
next catalog refresh or device sweep without a startup fleet rewrite. Matching sets the
key; the single judge statement writes parent and title answers together via a CTE.
No wire schema changes. Downgrade drops only derived per-title target answers.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f526e8b3d901"
down_revision = "f600c8e2a941"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name, kind in [
        ("key", sa.String(67)),
        ("version", sa.String(64)),
        ("assessment", sa.String(16)),
        ("counts", postgresql.JSONB(none_as_null=True)),
        ("ids", postgresql.JSONB(none_as_null=True)),
        ("ids_truncated", sa.Boolean()),
    ]:
        op.add_column("app_catalog_title_matches", sa.Column(f"vuln_target_{name}", kind, nullable=True))


def downgrade() -> None:
    for name in ["ids_truncated", "ids", "counts", "assessment", "version", "key"]:
        op.drop_column("app_catalog_title_matches", f"vuln_target_{name}")
