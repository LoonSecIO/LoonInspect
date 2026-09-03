"""device_extension_attributes keyed by definition id, carrying every value and its source (#197)

The current-state EA rows were `(device_id, key = name, value = first value)`. Three
defects in one shape: the key was the display name, so an admin renaming an EA read as
one attribute vanishing and another appearing; a multi-value EA kept its first element
and dropped the rest, while the ledger hashed the whole list; and nothing recorded which
of Jamf's six arrays the value came from. The observation contract and the change log
already key EAs on `definitionId` with the name as a label — this brings the row into
line with them, and gives the wire the same identity (app.schemas.payload).

The rows are a projection, rebuilt wholesale per device on every read that covers the EA
section (process_sync), and the projection's key changed: a name cannot be turned into a
definition id after the fact. So the table is emptied here rather than backfilled with
rows whose new key column would hold the wrong thing until the next sweep replaced them.
TRUNCATE rather than DELETE because the table is under row-level security and migrations
run with no tenant set — a DELETE would see no rows, leave them all in place, and the
NOT NULL columns below would then fail on them; TRUNCATE is not subject to the policies
and nothing references this table by foreign key. The next sweep — or a Run now —
repopulates every device; until then a device's detail shows no extension attributes and
the `ea=` filter matches nothing. Nothing derived depends on the rows in the meantime:
Jamf Patch matching judges at catalog level, where EAs resolve TRUE
(docs/app-catalog.md), and the ledger is untouched.

`values` is JSONB with a GIN index because the `ea=<id or name>:<value>` filter is a
containment test — any element of a multi-value EA matches — which a scalar column could
not express. The name is SQL-reserved and quoted; in psql it is `"values"`. Its server
default is kept: an unanswered EA is a row with an empty list, and that is the right
meaning for a write that says nothing.

Revision ID: d7e3b9c5a1f4
Revises: a4e1c9d7b352
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d7e3b9c5a1f4"
down_revision: Union[str, Sequence[str], None] = "a4e1c9d7b352"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "device_extension_attributes"


def upgrade() -> None:
    # A projection with a new key: emptied, not backfilled (see the module docstring).
    op.execute(f"TRUNCATE TABLE {TABLE}")
    op.drop_index("ix_device_extension_attributes_key", table_name=TABLE)
    op.drop_index("ix_device_extension_attributes_value", table_name=TABLE)
    op.drop_constraint("uq_device_extension_attribute_key", TABLE, type_="unique")
    op.drop_column(TABLE, "key")
    op.drop_column(TABLE, "value")
    op.add_column(TABLE, sa.Column("definition_id", sa.String(length=64), nullable=False))
    op.add_column(TABLE, sa.Column("name", sa.String(length=255), nullable=True))
    op.add_column(
        TABLE,
        sa.Column(
            "values",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(TABLE, sa.Column("source", sa.String(length=64), nullable=False))
    op.add_column(TABLE, sa.Column("enabled", sa.Boolean(), nullable=True))
    op.create_index("ix_device_extension_attributes_definition_id", TABLE, ["definition_id"])
    op.create_index("ix_device_extension_attributes_values", TABLE, ["values"], postgresql_using="gin")
    op.create_unique_constraint(
        "uq_device_extension_attribute_definition", TABLE, ["device_id", "definition_id"]
    )


def downgrade() -> None:
    # The same argument in reverse: a definition id cannot become the old name key.
    op.execute(f"TRUNCATE TABLE {TABLE}")
    op.drop_constraint("uq_device_extension_attribute_definition", TABLE, type_="unique")
    op.drop_index("ix_device_extension_attributes_values", table_name=TABLE)
    op.drop_index("ix_device_extension_attributes_definition_id", table_name=TABLE)
    op.drop_column(TABLE, "enabled")
    op.drop_column(TABLE, "source")
    op.drop_column(TABLE, "values")
    op.drop_column(TABLE, "name")
    op.drop_column(TABLE, "definition_id")
    op.add_column(TABLE, sa.Column("key", sa.String(length=255), nullable=False))
    op.add_column(TABLE, sa.Column("value", sa.String(length=1024), nullable=True))
    op.create_index("ix_device_extension_attributes_key", TABLE, ["key"])
    op.create_index("ix_device_extension_attributes_value", TABLE, ["value"])
    op.create_unique_constraint("uq_device_extension_attribute_key", TABLE, ["device_id", "key"])
