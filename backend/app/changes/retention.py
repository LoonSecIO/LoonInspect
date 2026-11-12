"""The change log's one clock (#785): `CHANGE_LOG_RETENTION_DAYS`, off by default.

`device_changes` is derived from the observation ledger and deletable without loss (the model
says so), and it is also the investigation surface — the rows a month-14 "which Macs installed
that, and when" is answered from. So the default is to keep every row for ever, as every install
has since the table existed, and this module does nothing until an operator sets the clock. Set,
it bounds the table by `observed_at` and nothing else: the ledger, the devices, the apps and the
findings stay whole (KNOWN_ISSUES.md §2 says why the ledger has no clock of its own).

Batched, because the first night after an operator sets the clock on a year-old 40k-device
instance is a delete of tens of millions of rows, and one statement for all of them holds one
transaction, one lock and one WAL burst for the duration. Ten thousand rows a statement, each
committed, is the same rows gone by morning with nothing held long enough to notice.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.schema import DeviceChange

# Rows deleted per statement. Small enough that no statement runs long; large enough that a
# night's purge is hundreds of statements, not hundreds of thousands.
BATCH_ROWS = 10_000


async def purge_changes(db: AsyncSession, retention_days: int, *, batch_rows: int = BATCH_ROWS) -> int:
    """Drop change-log rows observed more than `retention_days` ago; the count removed.

    A session scoped to one tenant sees that tenant's rows and no other's (row-level security),
    so this purges for the tenant it is called for, as the other nightly purges do. `retention_days`
    of 0 means the clock is off, and nothing is deleted.
    """
    if retention_days <= 0:
        return 0
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    total = 0
    while True:
        oldest = (
            select(DeviceChange.id).where(DeviceChange.observed_at < cutoff).order_by(DeviceChange.observed_at).limit(batch_rows)
        )
        # retention-clock: change-log — named in README.md and KNOWN_ISSUES.md §1; check-readme-claims.sh reads this token.
        result = await db.execute(sa_delete(DeviceChange).where(DeviceChange.id.in_(oldest)))
        await db.commit()
        removed = result.rowcount or 0
        total += removed
        if removed < batch_rows:
            return total
