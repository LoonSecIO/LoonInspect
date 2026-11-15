"""Promoted applications (#793): the administrator's chosen titles, and the share log's marker for them.

`app_promotions` holds one tenant-scoped row per application an administrator chose to send by
name (docs/data-sharing.md, "Promoted applications"):

- `key_title`: the `app.title` content key, the one the snapshot already sends for the title.
- `app_name`, `bundle_id`: the two fields that hash to it, as inventory held them when the title
  was promoted. They are what leaves in plain text.
- `promoted_at`, `promoted_by`: when, and the administrator's address as it read that day. The
  audit trail holds the account; this is the page's label.

A title is promoted once per organization (`uq_app_promotions_tenant_title`). The versions and
counts a promotion sends are read from `installed_apps` at each exchange, so nothing about a
fleet is copied here.

`share_log.promotions_shed` is `reveals_shed`'s sibling: true when a 413 made the exchange drop
its `promotions` array to be accepted, so the row's payload is a superset of what left. Existing
rows read false, which is what they were.

Both additions are expand-only: v1.0.0 reads neither. Nothing is backfilled.
"""

import sqlalchemy as sa
from alembic import op

revision = "c793a1f5d2e8"
down_revision = "a4d7e1c9b2f3"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "app_promotions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
        sa.Column("key_title", sa.String(67), nullable=False),
        sa.Column("app_name", sa.String(255), nullable=False),
        sa.Column("bundle_id", sa.String(255), nullable=False),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("promoted_by", sa.String(255), nullable=True),
        sa.UniqueConstraint("tenant_id", "key_title", name="uq_app_promotions_tenant_title"),
    )
    op.create_index("ix_app_promotions_tenant_id", "app_promotions", ["tenant_id"])
    op.execute("ALTER TABLE app_promotions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE app_promotions FORCE ROW LEVEL SECURITY")
    predicate = "tenant_id = current_setting('looninspect.tenant_id')::uuid"
    op.execute(f"CREATE POLICY tenant_isolation ON app_promotions USING ({predicate}) WITH CHECK ({predicate})")

    op.add_column("share_log", sa.Column("promotions_shed", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column("share_log", "promotions_shed")
    op.drop_table("app_promotions")
