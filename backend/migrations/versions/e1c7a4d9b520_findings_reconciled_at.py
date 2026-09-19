"""devices.findings_reconciled_at: the marker the lazy backfill reads (#590)

A defect in `c5a2e9b71f34`'s ledger, found in review the same day and fixed here rather than
in that migration, because that one has run: a box that already holds `c5a2e9b71f34` would
never see a column added to it after the fact.

**Row presence is not "has this Mac been reconciled".** #589 ruling 5's backfill runs on a
device's first reconcile, and the first cut asked *does this device have any ledger row* to
decide whether it was the first. That conflates "never reconciled here" with "reconciled and
found clean": a Mac whose builds the loaded epoch listed nothing for writes zero rows, and is
from then on indistinguishable from one this store has never seen. Read that way the backfill
never stops firing. Months and years after the ledger ships, the first finding an epoch adds
to a build such a Mac has carried since June opens on `device_changes`'s June arrival, and
Posture › Vulnerabilities (#591) reads 110 days of *exposure* to a CVE this container could
not have known about until today.

That is #589 ruling 2 inverted — "an epoch that adds a CVE to a build opens rows fleet-wide at
the next observation, which is the first moment this pod could have known, and that is the
clock a remediation SLA is measured on" — recreated inside the store built to honour it. And
`first_seen_basis = backfill` does not cover it: that marker means *reconstructed at this
store's install moment*, one-time and bounded by the fleet's history, and nothing distinguishes
an install-time row from one minted in 2027 on an ordinary epoch update.

So the marker is a column on the **device**, stamped once on its first reconcile whether or not
that reconcile found anything, and never rewritten. Nullable, no default, no data step: every
Mac already in the table reads NULL, takes on its next sweep exactly the backfill ruling 5 owes
it, and is marked for good — which is also why `ADD COLUMN … NULL` here rewrites no row and
costs the same on a 40-device pod as on a 40k-device one.

**One title, two rows.** The same review found the diff's other silent grain. A Mac can carry
two `installed_apps` rows under one `key_title` — two copies of one application at different
versions, the shape `ENTRY_RULES` models by putting `path` in its identity — and the corpus can
list one id against both builds. The ledger row is still one, because the carrier is the title,
so `app.core.findings.detected` has to choose which build it records. It now takes the lowest
`key_full` and ORs the two `capped` flags rather than letting the last row win: `Device.apps`
carries no `order_by`, those rows are UPDATEd on every sweep (the `key_bundle` restamp, the
answer copy, `last_patch_check_at`), so heap order churns, and "whichever came last" meant an
UPDATE on every sweep for those Macs, a `build_key_full` that flips under #591's reader, and a
ruling-3 violation nobody would see, because both spellings produce correct-looking rows.

**What happens when the corpus stops answering.** `detected` reads the stored answer and does
NOT re-check `vuln_signature` against the loaded epoch the way `vuln_answer.served` does. The
reason is churn, not safety: between an epoch landing and the judge pass that rewrites a build's
row, the stored answer names an epoch that has moved, and re-gating would close and reopen a
ledger row for a fact about this container rather than about the Mac. It buys no independence
from the corpus, and the honest statement of that belongs here rather than in a comment that
claimed the opposite: a tenant whose tier flips to `off`, or a container that loses its epoch,
has `judge_vuln` clear the answer columns themselves, and each Mac's next sweep then closes its
open rows `corpus_withdrawn`. That is #590's letter — a build no longer assessed closes that way
— it is reversible, since a reopen keeps the row's original clock, and `docs/troubleshooting.md`
§5 step 9 sends the operator to the epoch and the tier first.

Revision ID: e1c7a4d9b520
Revises: c5a2e9b71f34
Create Date: 2026-09-19
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e1c7a4d9b520"
down_revision: Union[str, Sequence[str], None] = "c5a2e9b71f34"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("findings_reconciled_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "findings_reconciled_at")
