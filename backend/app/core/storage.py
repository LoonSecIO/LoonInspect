"""What the database holds, table by table, and the clock each one is on (#786).

The answer an operator could only get from `psql` as the superuser and the arithmetic in
KNOWN_ISSUES.md §1 to §3 — which `docs/diagnosability.md` rule 5 calls a defect in the product. Sizes
are Postgres's own (`pg_total_relation_size`: heap, indexes and TOAST), rows are the planner's
estimate since the last VACUUM or ANALYZE (never a `COUNT(*)` over a 29-million-row table), and
both are physical, instance-wide numbers: this database, every tenant. The clocks are the ones
the code declares (`retention-clock:` tokens, held to README.md and KNOWN_ISSUES.md §1 by
check-readme-claims.sh) read at request time from the settings in force, so the page and the
nightly purges can never disagree about a number.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.schemas.system import StorageOut, StorageTableOut

RECORD = "record"  # the fleet's history: kept for ever unless the operator says otherwise
MACHINERY = "machinery"  # what the product prunes on its own, on a clock


@dataclass(frozen=True)
class _Clock:
    table: str
    area: str
    # The setting that names the clock, or None for a fixed one. `days()` reads it live.
    setting: str | None = None
    fixed_days: int | None = None

    def days(self) -> int | None:
        if self.setting is None:
            return self.fixed_days
        value = getattr(settings, self.setting.lower())
        return int(value) if value else None  # 0 is "for ever" (CHANGE_LOG_RETENTION_DAYS)


# Every table README.md's retention paragraph and KNOWN_ISSUES.md §1 and §2 reason about, in the order
# the page shows them. A table added here that does not exist fails tests/test_storage_db.py.
CLOCKS: tuple[_Clock, ...] = (
    _Clock("devices", RECORD),
    _Clock("installed_apps", RECORD),
    _Clock("device_extension_attributes", RECORD),
    _Clock("observation_spans", RECORD),
    _Clock("observation_sections", RECORD),
    _Clock("observation_entries", RECORD),
    _Clock("observation_apertures", RECORD),
    _Clock("device_changes", RECORD, setting="CHANGE_LOG_RETENTION_DAYS"),
    _Clock("device_findings", RECORD),
    _Clock("device_history_points", RECORD),
    _Clock("posture_snapshot", RECORD),
    _Clock("subject_departures", RECORD),
    _Clock("event_outbox", MACHINERY, setting="EVENT_OUTBOX_RETENTION_DAYS"),
    _Clock("outbox_deliveries", MACHINERY, setting="EVENT_OUTBOX_RETENTION_DAYS"),
    _Clock("runs", MACHINERY, setting="RUN_RETENTION_DAYS"),
    _Clock("run_log", MACHINERY, setting="RUN_RETENTION_DAYS"),
    _Clock("alerts", MACHINERY, setting="RUN_RETENTION_DAYS"),
    _Clock("share_log", MACHINERY, fixed_days=90),
    _Clock("inventory_summary_jobs", MACHINERY, fixed_days=8),
    _Clock("inventory_summary_metrics", MACHINERY, fixed_days=1),
    _Clock("submission_cases", MACHINERY),
    _Clock("sessions", MACHINERY, fixed_days=1),
)

_SIZES = text(
    "SELECT c.relname AS table_name, pg_total_relation_size(c.oid) AS total_bytes, "
    "GREATEST(c.reltuples, 0)::bigint AS rows_estimate "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = ANY(:names)"
)
_DATABASE = text("SELECT pg_database_size(current_database())")


async def measure_storage(db: AsyncSession) -> StorageOut:
    """The sizes as Postgres holds them now, beside the clock each table is on."""
    names = [clock.table for clock in CLOCKS]
    measured = {
        row.table_name: (int(row.total_bytes), int(row.rows_estimate))
        for row in (await db.execute(_SIZES, {"names": names})).all()
    }
    database_bytes = int((await db.execute(_DATABASE)).scalar_one())
    tables = [
        StorageTableOut(
            table=clock.table,
            area=clock.area,
            bytes=measured.get(clock.table, (0, 0))[0],
            rows_estimate=measured.get(clock.table, (0, 0))[1],
            present=clock.table in measured,
            retention_days=clock.days(),
            setting=clock.setting,
        )
        for clock in CLOCKS
    ]
    return StorageOut(database_bytes=database_bytes, measured_at=datetime.now(UTC), tables=tables)
