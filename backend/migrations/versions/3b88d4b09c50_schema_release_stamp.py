"""schema_release: the oldest release whose image can read this schema (#672).

One row. `min_readable_release` names the oldest release whose image reads the schema the
migrations up to here leave. An image that finds a revision it does not carry reads it before
migrating (`app.core.database.init_db`): when its own `RELEASE` is at or above the stamp it
starts without migrating, and below it, it refuses with a sentence naming both. So from v2.0.0
on, one step back is an image swap (docs/operations.md §5).

Every release's migrations record it again: a module constant `MIN_READABLE_RELEASE = "vX.Y.Z"`,
which `upgrade()` writes with
`op.execute(f"UPDATE schema_release SET min_readable_release = '{MIN_READABLE_RELEASE}'")` and
`downgrade()` puts back with the same statement naming the value before it.
`.github/scripts/check_migration_contract.py` reads that constant and keeps it truthful: the
migrations since the last release must record that release or a later one, and a later one once
they drop or rename what it reads (docs/BRANCHING.md §1.1).

`v1.0.0` here: the migrations since v1.0.0 drop or rename nothing its models name. Its image
predates this table and never reads it, so stepping back to v1.x is still the downgrade.

Outside tenancy and row-level security, like `vuln_library_epoch`: it describes the schema, not
a tenant, and `init_db` reads it before any tenant exists. The table and column names never
change, because images older than every later migration read them.

Revision ID: 3b88d4b09c50
Revises: e623b1c4d7a9
Create Date: 2026-09-27
"""

import sqlalchemy as sa
from alembic import op

revision = "3b88d4b09c50"
down_revision = "e623b1c4d7a9"
branch_labels = None
depends_on = None

MIN_READABLE_RELEASE = "v1.0.0"


def upgrade():
    op.create_table(
        "schema_release",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("min_readable_release", sa.String(32), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_schema_release_single_row"),
    )
    op.execute(f"INSERT INTO schema_release (id, min_readable_release) VALUES (1, '{MIN_READABLE_RELEASE}')")


def downgrade():
    op.drop_table("schema_release")
