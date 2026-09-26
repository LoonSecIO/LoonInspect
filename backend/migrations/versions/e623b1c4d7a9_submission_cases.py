"""Coverage requests and match corrections (#623, slice one): one tenant-scoped row per case.

The contract is Support's docs/contracts/submissions.md; app.core.submissions speaks it. What
each column holds:

- `kind` .. `finding_release`: the fields the service receives, bounded as the contract bounds
  them. A coverage request leaves `finding` and `finding_release` out of the payload.
- `case_key`: the case's idempotency key, status capability and withdrawal capability at once.
  `EncryptedString` (column type text), like the contribution receipt on `data_sharing_settings`:
  never logged, shown or written to the share log.
- `state`: `pending` until the service acknowledges the case, then the contract's word
  (received, reviewing, needs_information, accepted, declined, published, withdrawn), or
  `expired` once the service answers that it no longer knows the key.
- `received_at`, `closed_at`, `release`, `coverage`, `note`: copied from the service's answers;
  `note` is the reviewer's question or decline reason.
- `last_status_at`: when this instance last asked for status; the next ask waits 60 seconds,
  the service's own floor. `retry_at`: the service's Retry-After, honoured before the next
  attempt. `last_error`: the operator's sentence for the last attempt that settled nothing.
- `withdrawn_at`: when withdrawal settled (the service withdrew the case, or holds nothing under
  the key). Withdrawal also clears what the administrator wrote here (`public_url`, `text`,
  `contact`); the app identity stays, to label the case.
- `excluded_override`: the administrator's explicit one-time override for an app the sharing
  exclusions cover. `permission_at`: when they gave the explicit one-time permission to send,
  after the preview; nothing is sent without it. `submitted_by_account_id`: who sent it, nulled
  rather than blocking if that account is ever deleted.

Nothing is backfilled: the table starts empty, and no route writes it until the API slice lands.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "e623b1c4d7a9"
down_revision = "a653c4d2e1f0"
branch_labels = None
depends_on = None


def _at(name):
    return sa.Column(name, sa.DateTime(timezone=True), nullable=True)


def upgrade():
    op.create_table(
        "submission_cases",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("submitted_by_account_id", sa.String(36), sa.ForeignKey("accounts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("app_name", sa.String(256), nullable=False),
        sa.Column("bundle_id", sa.String(256), nullable=True),
        sa.Column("platform", sa.String(16), nullable=False),
        sa.Column("versions", pg.JSONB(), nullable=False),
        sa.Column("public_url", sa.String(512), nullable=True),
        sa.Column("text", sa.Text(), nullable=True),
        sa.Column("contact", sa.String(256), nullable=True),
        sa.Column("finding", sa.String(32), nullable=True),
        sa.Column("finding_release", sa.String(64), nullable=True),
        sa.Column("case_key", sa.Text(), nullable=False),
        sa.Column("state", sa.String(24), nullable=False, server_default="pending"),
        _at("received_at"),
        _at("closed_at"),
        sa.Column("release", sa.String(64), nullable=True),
        sa.Column("coverage", sa.Text(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        _at("last_status_at"),
        _at("retry_at"),
        sa.Column("last_error", sa.Text(), nullable=True),
        _at("withdrawn_at"),
        sa.Column("excluded_override", sa.Boolean(), nullable=False, server_default=sa.false()),
        _at("permission_at"),
        sa.CheckConstraint("kind IN ('coverage', 'correction')", name="ck_submission_cases_kind"),
    )
    op.create_index("ix_submission_cases_tenant_id", "submission_cases", ["tenant_id"])
    op.execute("ALTER TABLE submission_cases ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE submission_cases FORCE ROW LEVEL SECURITY")
    predicate = "tenant_id = current_setting('looninspect.tenant_id')::uuid"
    op.execute(f"CREATE POLICY tenant_isolation ON submission_cases USING ({predicate}) WITH CHECK ({predicate})")


def downgrade():
    op.drop_table("submission_cases")
