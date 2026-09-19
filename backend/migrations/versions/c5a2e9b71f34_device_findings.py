"""device_findings: one row per (device, carrier, finding id), the open interval (#590)

The store #429 named and did not build, pulled forward because the page needs *since when*
before the wire does. Until this table a finding existed only as a capped id list on a
build (`installed_apps.vuln_ids`), so *when did this pod last see CVE-X on this Mac* and
*since when* had no home at all, and Posture › Vulnerabilities could offer only days since
the CVE was published — the world's clock, which on a thirty-day-old tenant reads 900 and
is taken for exposure. `app.core.findings` is the only writer; the rulings it implements
are #589's, and the three that shaped this table are below.

**The carrier is the title, never the build** (ruling 1). `carrier_key` is `key_title`,
with `build_key_full` as an attribute: Safari 18.0 → 18.1 still carrying the id keeps the
row and its `first_observed_at`. Keyed on `key_full` — #429's per-build event grain read
literally — *first detected* would reset on every update, and the number would measure
update cadence rather than exposure. One CVE can reach one Mac through two carriers, since
Apple publishes WebKit fixes against both Safari and macOS, so the carrier is inside the
unique key and the two never collide.

**The clocks are Jamf's inventory clock** (ruling 2), collection time as the fallback — the
expression `device_changes` is stamped from, never the wall clock at read and never the
epoch's load time. An epoch that adds a CVE to a build opens rows fleet-wide at the next
observation, which is the first moment this pod could have known, and that is the clock a
remediation SLA is measured on.

**`last_observed_at` is nullable because an open row is not rewritten.** "Still detected"
is asserted by the row being open, not by a nightly restamp: a sweep in which a device's
covered set did not move issues no statement against this table at all (ruling 3), which is
what keeps a 40k-device nightly from rewriting millions of rows. The column is stamped at
close, which is why #591's read is `max(open → devices.last_seen_at, closed →
last_observed_at)` rather than a column read. `capped` is the cap's guard (a row opened
from a truncated list never closes by absence from one), and `first_seen_basis` says
whether the opening clock was measured or reconstructed.

Two indexes and no more. `(tenant_id, finding_id, resolved_at)` is the per-CVE read — the
only one that does not start from a device — with `resolved_at` last so the open set is a
prefix of it. `(device_id)` is the reconcile's own SELECT and the CASCADE. Both are write
cost on the sweep's hot path, so the ones that were merely plausible (a `capped` index, a
`resolved_reason` index over four values) are not here.

No data step. #589 ruling 5 wants backfilled rows to carry the change log's arrival of
their build, and that is built — in `app.core.findings.backfill_clocks`, lazily, on each
device's first reconcile — rather than here: migrations run in-process at startup, and
walking 40k devices' change logs inside the operator's upgrade would block boot for the
whole box. The deviation is recorded on #589.

Revision ID: c5a2e9b71f34
Revises: b8d4f1a6c2e7
Create Date: 2026-09-19
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c5a2e9b71f34"
down_revision: Union[str, Sequence[str], None] = "b8d4f1a6c2e7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREDICATE = "tenant_id = current_setting('looninspect.tenant_id')::uuid"


def upgrade() -> None:
    op.create_table(
        "device_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
            server_default=sa.text("current_setting('looninspect.tenant_id')::uuid"),
        ),
        # CASCADE, as `alerts` has: deleting a connection deletes its fleet, and a finding
        # about a Mac that no longer exists has nobody to be about.
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        # `installed_apps.key_title`, the same width as the key it copies.
        sa.Column("carrier_key", sa.String(length=67), nullable=False),
        # `CVE-…` or `LoonVD-…`; `LOCAL-` is refused at the boundary (vulnerabilities.md §5).
        sa.Column("finding_id", sa.String(length=32), nullable=False),
        sa.Column("build_key_full", sa.String(length=67), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        # build_changed | app_removed | device_departed | corpus_withdrawn — the four of
        # #589 ruling 4, as a string rather than a Postgres enum, so a fifth reason is a
        # tuple entry and a doc row rather than a migration on a type.
        sa.Column("resolved_reason", sa.String(length=32), nullable=True),
        # Opened from a truncated id list, so absence from that list proves nothing.
        sa.Column("capped", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("first_seen_basis", sa.String(length=16), nullable=False),
        sa.UniqueConstraint("device_id", "carrier_key", "finding_id", name="uq_device_finding"),
    )
    op.create_index("ix_device_findings_tenant_id", "device_findings", ["tenant_id"])
    op.create_index("ix_device_findings_device_id", "device_findings", ["device_id"])
    op.create_index("ix_device_findings_finding", "device_findings", ["tenant_id", "finding_id", "resolved_at"])
    op.execute("ALTER TABLE device_findings ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE device_findings FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON device_findings USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})")


def downgrade() -> None:
    op.drop_table("device_findings")
