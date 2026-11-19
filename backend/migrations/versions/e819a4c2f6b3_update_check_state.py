"""update_check_state: when the update check is next owed, and its last answer, in one row (#819).

The update check moves from a call a page made, cached in one process's memory, to the scheduler.
No time of day belongs to an instance: every moment the check is owed at is drawn afresh at random,
from nothing else the instance holds or sends. The check carries no identifier, and a minute drawn
once and kept would be one: anyone counting arrivals per minute would see it, and the instance
never changes it, so in a small population it would follow an instance from one day to the next.
This row is what every process reads, so a restart or a second process asks nothing more, and
`/api/system/update-status` serves its answer without asking. Global, outside tenancy and
row-level security like `fleet_catalog_state`: it describes the instance, not a tenant.

The columns:

- `next_check_at`: the moment the next check is owed. Drawn here at random within the next 24
  hours, so a new instance's first check waits. An attempt sets it an hour on, the retry; an
  answered one sets it 20 to 23 hours on, drawn afresh. A check stays owed from this moment until
  one is answered, on either side of midnight, and is owed at once when this moment is more than a
  day ahead of the clock, so a clock set back does not silence it.
- `attempted_at`: the last attempt, answered or not. `tick` claims each attempt by setting it in
  one UPDATE that compares it with the value it read, before anything is asked.
- `checked_at`, `update_available`, `latest_tag`, `release_url`, `latest_sha`, `reason`: the answer
  `/api/system/update-status` serves, written by every attempt, answered or not.
- `checked_version`: the build that answer is for. Another build is served `not_checked`.
- `last_day`: the `day` LoonSec's service gave the last answered check, sent back as `last`. Empty
  until the check asks that service.
- `last_sent`: the literal body the last check sent. Empty until the check asks that service.
- `notice_pending`: an administrator is still to be told, once, that the check changed. True on a
  database that already holds an account (an instance updated to this release), false on a fresh
  install.

Expand only, and the first migration since v1.1.0, so it records that v1.1.0's image reads this
schema: that image never reads this table and keeps its own check in memory. Downgrade drops the
table and puts back the stamp 3b88d4b09c50 recorded.

Revision ID: e819a4c2f6b3
Revises: f794a1c3d5e7
Create Date: 2026-11-19
"""

import secrets
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e819a4c2f6b3"
down_revision = "f794a1c3d5e7"
branch_labels = None
depends_on = None

MIN_READABLE_RELEASE = "v1.1.0"
_PREVIOUS_RELEASE = "v1.0.0"
_FIRST_DAY_MICROSECONDS = 24 * 60 * 60 * 1_000_000


def _an_account_exists(bind) -> bool:
    """Whether any tenant holds an account. Row-level security shows a tenant's accounts only while
    that tenant is bound, so each is bound in turn, as 28b0d447bc53 does. The whole upgrade is one
    transaction, so it ends with no tenant bound rather than the last one it looked at."""
    found = False
    for tenant_id in bind.execute(sa.text("SELECT id FROM tenants")).scalars().all():
        bind.execute(sa.text("SELECT set_config('looninspect.tenant_id', :tid, true)"), {"tid": str(tenant_id)})
        if found := bool(bind.execute(sa.text("SELECT EXISTS (SELECT FROM accounts)")).scalar()):
            break
    bind.execute(sa.text("SELECT set_config('looninspect.tenant_id', '', true)"))
    return found


def upgrade() -> None:
    op.create_table(
        "update_check_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("checked_version", sa.Text(), nullable=True),
        sa.Column("update_available", sa.Boolean(), nullable=True),
        sa.Column("latest_tag", sa.Text(), nullable=True),
        sa.Column("release_url", sa.Text(), nullable=True),
        sa.Column("latest_sha", sa.Text(), nullable=True),
        sa.Column("reason", sa.String(32), nullable=True),
        sa.Column("last_day", sa.Integer(), nullable=True),
        sa.Column("last_sent", postgresql.JSONB(), nullable=True),
        sa.Column("notice_pending", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.CheckConstraint("id = 1", name="ck_update_check_state_single_row"),
    )
    bind = op.get_bind()
    first = datetime.now(UTC) + timedelta(microseconds=secrets.randbelow(_FIRST_DAY_MICROSECONDS))
    bind.execute(
        sa.text("INSERT INTO update_check_state (id, next_check_at, notice_pending) VALUES (1, :first, :notice)"),
        {"first": first, "notice": _an_account_exists(bind)},
    )
    op.execute(f"UPDATE schema_release SET min_readable_release = '{MIN_READABLE_RELEASE}'")


def downgrade() -> None:
    op.execute(f"UPDATE schema_release SET min_readable_release = '{_PREVIOUS_RELEASE}'")
    op.drop_table("update_check_state")
