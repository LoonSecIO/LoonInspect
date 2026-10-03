"""The org's confirmed patching rules, beside its stated policy.

One nullable JSONB column on `patching_policies`: the organization's rule and each title's
own (`app.mdm.patch.policy`). NULL is "no rule confirmed", which is every row written before
this and every tenant that only states its policy in words — nothing is judged until someone
with `system:write` confirms a rule. Downgrade drops the rules and leaves the statements.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a4d7e1c9b2f3"
down_revision = "3b88d4b09c50"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("patching_policies", sa.Column("rules", postgresql.JSONB(none_as_null=True), nullable=True))


def downgrade() -> None:
    op.drop_column("patching_policies", "rules")
