"""Departure: an object absent from a clean census is gone (#181).

The ruling (#135, 2026-08-31): a smart group vanishing is not an edge case — large orgs
delete them constantly, because a group is how a phased rollout is expressed and a finished
rollout is a group nobody needs — and extension-attribute definitions go the same way. This
is **detection and state**. The wire format is #179's, and nothing here emits.

Three rules, in the order they are applied:

* **Census.** The catalog pass already reads every smart group and, since #178, every
  extension-attribute definition. A subject whose current span exists and that the census
  did not name is absent, and absent from a clean census means gone.
* **Circuit breaker, mandatory.** Both fetches degrade on a missing privilege or an older
  Jamf Pro. An empty census, or one sharply smaller than the population it is measured
  against, departs nobody and says so loudly: "every group departed at once" must be
  unreachable by that path. Returns are still honoured on a collapsed census — a subject the
  census *did* name is present, whatever else the census failed to say.
* **The ledger stays clean.** Absence was never observed, so it opens and closes no span
  (#135 rider 4). Departure is a `subject_departures` row: derived, timestamped, and
  re-derivable from the spans and the census that found it. A return closes the row, and a return
  under a *new* id retires the old one (#475).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.mdm.jamf.contract import SUBJECT_COMPUTER
from app.models.schema import Device, ObservationSpan, SubjectDeparture

logger = logging.getLogger(__name__)

# The breaker's two thresholds. Below MIN_POPULATION_FOR_COLLAPSE a drop is a small
# number of deletions, not a collapse: two of three groups gone is a Tuesday in a small
# org. At or above it, a census naming fewer than COLLAPSE_RATIO of the present
# population is refused — a role that lost a privilege between two passes, an endpoint
# that paged short — and logged at warning, because the alternative is forty thousand
# "departed" rows from one bad read.
MIN_POPULATION_FOR_COLLAPSE = 10
COLLAPSE_RATIO = 0.5

# How a return was recognised (#475, Kyle's R3): wiped, rebuilt, board-repaired or re-enrolled, a Mac
# comes back under a *new* computer id, so matched on that alone its departure never closes. The
# batch is asyncpg's 32767-bind-parameter cap; the census's own serials are never bound at all.
MATCHED_BY_JAMF_ID = "jamf_id"
MATCHED_BY_SERIAL = "serial"
_DEPARTED_BATCH = 1000

SKIP_NOT_READABLE = "not_readable"
SKIP_EMPTY = "empty_census"
SKIP_COLLAPSED = "collapsed_census"

# The seven-day tail (#183, from the same ruling): an open departure row IS the tail — no column,
# no timer, because a row's age is the whole state and cannot drift from what it is derived from.
DEPARTURE_TAIL_DAYS = 7
DEPARTURE_TAIL = timedelta(days=DEPARTURE_TAIL_DAYS)


def left_the_fleet(departed_at: datetime | ColumnElement[datetime], *, at: datetime) -> Any:
    """Has this departure's tail run out by `at`? The ONE place the seven days are counted,
    because "departed_at plus a week" spelled in two languages is two definitions waiting to
    disagree about one Mac. Handed a `datetime` it answers a bool — the run log's tally; handed
    `SubjectDeparture.departed_at`, the same question as a SQL predicate — the device list, the
    fleet count. `still_gone_under_this_id` is the caller's half, and every caller below filters on it.
    """
    return departed_at <= at - DEPARTURE_TAIL


def still_gone_under_this_id() -> ColumnElement[bool]:
    """Gone under the id this row is about: never returned, or returned *as something else* (#475). A
    serial match did not put that id back — it is dead in Jamf, what came back is listed under its own
    new row — so a retired id reads everywhere exactly like an open departure: it keeps its tail, it
    leaves the fleet on day seven, and it never rejoins a census population."""
    return or_(SubjectDeparture.returned_at.is_(None), SubjectDeparture.matched_by == MATCHED_BY_SERIAL)


def gone_for_good(connection_id: Any, external_id: Any, *, at: datetime) -> ColumnElement[bool]:
    """EXISTS: this Mac's tail has run out, so it is no longer part of the fleet. Correlated
    rather than `IN` over a tuple subquery: a device whose `mdm_connection_id` is NULL — its
    connection deleted out from under it (#185) — makes `NOT IN` answer NULL and would vanish
    the row from every list. An orphan has nobody to be absent from.
    """
    return (
        select(SubjectDeparture.id)
        .where(
            SubjectDeparture.mdm_connection_id == connection_id,
            SubjectDeparture.subject_kind == SUBJECT_COMPUTER,
            SubjectDeparture.subject_id == external_id,
            still_gone_under_this_id(),
            left_the_fleet(SubjectDeparture.departed_at, at=at),
        )
        .exists()
    )


@dataclass(frozen=True)
class CensusVerdict:
    """What one census did to one subject kind under one connection."""

    subject_kind: str
    observed: int
    population: int
    departed: int
    returned: int
    skipped: str | None = None
    # How many of `returned` came back under a *new* id (#475) — not derivable afterwards.
    returned_by_serial: int = 0

    def as_log(self) -> dict[str, object]:
        return {
            "subjectKind": self.subject_kind,
            "observed": self.observed,
            "population": self.population,
            "departed": self.departed,
            "returned": self.returned,
            "returnedBySerial": self.returned_by_serial,
            "skipped": self.skipped,
        }


async def _returned_by_serial(
    db: AsyncSession, *, connection_id: int, subject_kind: str, subject_ids: list[str], serials: Mapping[str, str] | None
) -> dict[str, str]:
    """Which of these departed Macs is the census naming under a *different* Jamf id, and as what
    (#475)? `{departed id -> the id it came back under}`. Its `devices` row carries the serial it was
    last read with, and a census naming that serial found it whatever id Jamf gave it back — scoped to
    the connection, a serial being Apple's and an instance's view of it not. Computers only."""
    if subject_kind != SUBJECT_COMPUTER or not subject_ids or not serials:
        return {}
    census = {serial.strip(): jamf_id for serial, jamf_id in serials.items() if serial.strip()}
    found: dict[str, str] = {}
    for start in range(0, len(subject_ids), _DEPARTED_BATCH):
        batch = subject_ids[start : start + _DEPARTED_BATCH]
        mine = (Device.mdm_connection_id == connection_id, Device.external_id.in_(batch))
        rows = await db.execute(select(Device.external_id, Device.serial_number).where(*mine))
        found.update({device: census[(serial or "").strip()] for device, serial in rows if (serial or "").strip() in census})
    return found


async def reconcile_census(
    db: AsyncSession,
    *,
    connection_id: int,
    subject_kind: str,
    observed_ids: Iterable[str] | None,
    at: datetime,
    census_run_id: uuid.UUID | None = None,
    observed_serials: Mapping[str, str] | None = None,
) -> CensusVerdict:
    """Apply one census to the departures table. Commits nothing; the caller does.

    `observed_ids` is every subject id the census named, or None when the census could
    not be taken at all (a refused read) — which departs nobody and returns nobody.

    `observed_serials` maps every serial the same census carried to the id it carried it under (#475);
    `None` is "none to carry" — no `hardware` section — so the match is id-only and the run says so.
    """
    current_ids = set(
        (
            await db.execute(
                select(ObservationSpan.subject_id).where(
                    ObservationSpan.mdm_connection_id == connection_id,
                    ObservationSpan.subject_kind == subject_kind,
                    ObservationSpan.is_current.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    open_rows = {
        row.subject_id: row
        for row in (
            await db.execute(
                select(SubjectDeparture).where(
                    SubjectDeparture.mdm_connection_id == connection_id,
                    SubjectDeparture.subject_kind == subject_kind,
                    SubjectDeparture.returned_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    }
    # The present population: what the ledger holds minus what is already gone under that id — open
    # departures, and the ids a serial match retired, which no span closes (#475). Leave one in and it
    # departs again next census, closes again the pass after, and flaps forever.
    mine = (SubjectDeparture.mdm_connection_id == connection_id, SubjectDeparture.subject_kind == subject_kind)
    still_gone = select(SubjectDeparture.subject_id).where(*mine, still_gone_under_this_id())
    population = current_ids - set((await db.execute(still_gone)).scalars().all())

    if observed_ids is None:
        return CensusVerdict(subject_kind, 0, len(population), 0, 0, SKIP_NOT_READABLE)
    observed = set(observed_ids)

    # Returns first: a subject the census named is present, whatever else it says.
    returned = 0
    absent = []
    for subject_id, row in open_rows.items():
        if subject_id in observed:
            row.returned_at = at
            row.matched_by = MATCHED_BY_JAMF_ID
            returned += 1
        else:
            absent.append(subject_id)

    # Then by serial (#475), before the breaker for the reason the id match is: a Mac the census *did*
    # name, under any id, is present. The close retires the id the row is about, for good.
    by_serial = await _returned_by_serial(
        db, connection_id=connection_id, subject_kind=subject_kind, subject_ids=absent, serials=observed_serials
    )
    for subject_id, came_back_as in sorted(by_serial.items()):
        row = open_rows[subject_id]
        row.returned_at = at
        row.matched_by = MATCHED_BY_SERIAL
        row.returned_as_subject_id = came_back_as
        returned += 1

    if not observed and population:
        logger.warning(
            "census returned nothing; departing nobody",
            extra={"connection_id": connection_id, "subject_kind": subject_kind, "population": len(population)},
        )
        return CensusVerdict(subject_kind, 0, len(population), 0, returned, SKIP_EMPTY, len(by_serial))
    if len(population) >= MIN_POPULATION_FOR_COLLAPSE and len(observed) < COLLAPSE_RATIO * len(population):
        logger.warning(
            "census collapsed against the population; departing nobody",
            extra={
                "connection_id": connection_id,
                "subject_kind": subject_kind,
                "observed": len(observed),
                "population": len(population),
            },
        )
        return CensusVerdict(subject_kind, len(observed), len(population), 0, returned, SKIP_COLLAPSED, len(by_serial))

    departed = 0
    for subject_id in sorted(population - observed):
        db.add(
            SubjectDeparture(
                mdm_connection_id=connection_id,
                subject_kind=subject_kind,
                subject_id=subject_id,
                departed_at=at,
                census_run_id=census_run_id,
            )
        )
        departed += 1
    return CensusVerdict(subject_kind, len(observed), len(population), departed, returned, None, len(by_serial))


async def open_departures(db: AsyncSession, *, subject_kind: str) -> dict[tuple[int, str], datetime]:
    """`(connection id, subject id) -> departed_at` for every subject of the kind that is
    currently gone, retired ids included (#475) — what a surface listing current spans consults."""
    rows = (
        (
            await db.execute(
                select(SubjectDeparture).where(SubjectDeparture.subject_kind == subject_kind, still_gone_under_this_id())
            )
        )
        .scalars()
        .all()
    )
    return {(row.mdm_connection_id, row.subject_id): row.departed_at for row in rows}


async def tail_counts(db: AsyncSession, *, connection_id: int, subject_kind: str, at: datetime) -> tuple[int, int]:
    """`(still in their tail, left the fleet)` among the subjects this connection is missing — the
    two halves of the census line on the run, counted through the same `left_the_fleet` the surfaces
    ask, so the run and the list cannot disagree about one Mac."""
    gone = func.count().filter(left_the_fleet(SubjectDeparture.departed_at, at=at))
    open_rows, left = (
        await db.execute(
            select(func.count(), gone).where(
                SubjectDeparture.mdm_connection_id == connection_id,
                SubjectDeparture.subject_kind == subject_kind,
                still_gone_under_this_id(),
            )
        )
    ).one()
    return open_rows - left, left
