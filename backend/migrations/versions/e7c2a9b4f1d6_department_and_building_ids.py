"""devices carry Jamf's department and building ids, and jamf_org_units resolves them to names

The two columns were named for values Jamf's inventory API does not return: the device
record carries `departmentId` and `buildingId`, never `department` / `building`, so both
columns have only ever held NULL. Renaming rather than adding is therefore free — there
is nothing in them to migrate — and it makes the column say what it holds.

Revision ID: e7c2a9b4f1d6
Revises: c1a6f83b7e42
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e7c2a9b4f1d6"
down_revision: Union[str, Sequence[str], None] = "c1a6f83b7e42"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def upgrade() -> None:
    op.alter_column(
        "devices", "building", new_column_name="building_id", type_=sa.String(64), existing_type=sa.String(255)
    )
    op.alter_column(
        "devices", "department", new_column_name="department_id", type_=sa.String(64), existing_type=sa.String(255)
    )

    op.create_table(
        "jamf_org_units",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
        sa.Column(
            "mdm_connection_id",
            sa.Integer(),
            sa.ForeignKey("mdm_connections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("external_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("mdm_connection_id", "kind", "external_id", name="uq_jamf_org_unit"),
    )
    op.create_index("ix_jamf_org_units_tenant_id", "jamf_org_units", ["tenant_id"])
    op.create_index("ix_jamf_org_units_mdm_connection_id", "jamf_org_units", ["mdm_connection_id"])
    # The device filter's direction of travel: a name the operator typed, back to the
    # ids the device rows hold.
    op.create_index("ix_jamf_org_units_name", "jamf_org_units", ["tenant_id", "kind", "name"])

    op.execute("ALTER TABLE jamf_org_units ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE jamf_org_units FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON jamf_org_units USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})"
    )


def downgrade() -> None:
    op.drop_table("jamf_org_units")
    op.alter_column(
        "devices", "department_id", new_column_name="department", type_=sa.String(255), existing_type=sa.String(64)
    )
    op.alter_column(
        "devices", "building_id", new_column_name="building", type_=sa.String(255), existing_type=sa.String(64)
    )
