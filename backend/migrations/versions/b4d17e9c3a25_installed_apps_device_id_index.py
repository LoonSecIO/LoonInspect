"""installed_apps gets the index on device_id it has always read by

`device_id` is the primary access path to this table: `process_sync` fetches one
device's apps twice per device, and the table holds roughly 100 rows per device — four
million at a 40,000-device fleet, the largest in the schema. Without an index that
lookup is a parallel sequential scan over every row the tenant owns.

Measured on 4,000,000 rows as the application role with the tenant GUC bound, so the
RLS predicate applies exactly as the app runs it: 103 ms and ~143,000 buffers per
device before, 0.43 ms after. Twice per device across a 40k sweep, that is the
difference between roughly two hours of database time and roughly one minute.

`device_extension_attributes.device_id` two definitions earlier in the model has
carried `index=True` since the baseline; this column simply never got it.

Operators note: on an already-populated table `CREATE INDEX` takes a write lock for
the duration of the build, so a large existing installation should apply this during a
quiet window. It is not built CONCURRENTLY because Alembic runs migrations inside a
transaction and no other migration in this project does either.

Revision ID: b4d17e9c3a25
Revises: e7c2a9b4f1d6
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "b4d17e9c3a25"
down_revision: Union[str, Sequence[str], None] = "e7c2a9b4f1d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index("ix_installed_apps_device_id", "installed_apps", ["device_id"])


def downgrade() -> None:
    op.drop_index("ix_installed_apps_device_id", table_name="installed_apps")
