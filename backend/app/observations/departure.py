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
from app.models.schema import ObservationSpan, SubjectDeparture

logger = logging.getLogger(__name__)

# The breaker's two thresholds. Below MIN_POPULATION_FOR_COLLAPSE a drop is a small
# number of deletions, not a collapse: two of three groups gone is a Tuesday in a small
# org. At or above it, a census naming fewer than COLLAPSE_RATIO of the present
# population is refused — a role that lost a privilege between two passes, an endpoint
# that paged short — and logged at warning, because the alternative is forty thousand
# "departed" rows from one bad read.
MIN_POPULATION_FOR_COLLAPSE = 10
COLLAPSE_RATIO = 0.5

# How a return was recognised (#475, Kyle's R3), spelled as #179's `matchedBy` carries it: wiped,
# rebuilt or re-enrolled, a Mac comes back under a *new* computer id, so matched on that alone its
# departure never closes. The batch is asyncpg's 32767-bind cap; the census's own keys never bind.
MATCHED_BY_JAMF_ID = "jamfProID"
MATCHED_BY_SERIAL = "serialNumber"
_DEPARTED_BATCH = 1000
# One census's second key, both halves of it: (serial, UDID) -> the id it carried them under.
_Lineage = Mapping[tuple[str, str], str]

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
    """Gone under the id it departed under: never returned, or returned under *another* id (#475) — a
    serial match re-keys the row to the Mac's new life, leaving `prior_jamf_pro_id` to name and retire
    the old one. A retired id reads everywhere like an open departure — it keeps its tail, leaves on
    day seven, rejoins no census population — until a census names it, which takes the retirement
    back (`reconcile_census`): a Mac Jamf hands over is here, whatever a serial match decided."""
    return or_(SubjectDeparture.returned_at.is_(None), SubjectDeparture.prior_jamf_pro_id.isnot(None))


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
            func.coalesce(SubjectDeparture.prior_jamf_pro_id, SubjectDeparture.subject_id) == external_id,
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
    db: AsyncSession, *, connection_id: int, subject_kind: str, subject_ids: list[str], lineage: _Lineage | None
) -> dict[str, str]:
    """Which of these departed Macs is the census naming under a *different* Jamf id, and as what
    (#475)? `{departed id -> the id it came back under}`. The key is **serial and UDID together**,
    off the Mac's current span — the ledger's own lineage keys (`docs/jamf-observations.md` §3) — and
    within the connection, that walk across instances being nobody's build yet. Same serial and same
    UDID under a new id is the duplicate-record shape a re-enrolment makes; same serial under a *new*
    UDID is a board replacement, a lineage event and not a return, so it matches nothing. Computers
    only."""
    if subject_kind != SUBJECT_COMPUTER or not subject_ids or not lineage:
        return {}
    census = {(s.strip(), u.strip()): jamf_id for (s, u), jamf_id in lineage.items() if s.strip() and u.strip()}
    found: dict[str, str] = {}
    for start in range(0, len(subject_ids), _DEPARTED_BATCH):
        mine = (
            ObservationSpan.mdm_connection_id == connection_id,
            ObservationSpan.is_current.is_(True),
            ObservationSpan.subject_id.in_(subject_ids[start : start + _DEPARTED_BATCH]),
        )
        keys = select(ObservationSpan.subject_id, ObservationSpan.serial_number, ObservationSpan.udid)
        rows = await db.execute(keys.where(*mine, ObservationSpan.subject_kind == SUBJECT_COMPUTER))
        found.update({d: census[k] for d, s, u in rows if (k := ((s or "").strip(), (u or "").strip())) in census})
    return found


async def reconcile_census(
    db: AsyncSession,
    *,
    connection_id: int,
    subject_kind: str,
    observed_ids: Iterable[str] | None,
    at: datetime,
    census_run_id: uuid.UUID | None = None,
    observed_lineage: _Lineage | None = None,
) -> CensusVerdict:
    """Apply one census to the departures table. Commits nothing; the caller does.

    `observed_ids` is every subject id the census named, or None when the census could
    not be taken at all (a refused read) — which departs nobody and returns nobody.

    `observed_lineage` maps every (serial, UDID) the same census carried to the id it carried them
    under (#475); `None` is "none to carry" — no `hardware` section — so the match is id-only and the
    run says so.
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
    # Keyed by the id each row is gone under — for a row a serial match re-keyed, the one it departed
    # under, not the one it came back as (#475). The population is what the ledger holds minus exactly
    # these: absence closes no span, so a retired id left in departs again next census, forever.
    gone_rows = {
        row.prior_jamf_pro_id or row.subject_id: row
        for row in (
            await db.execute(
                select(SubjectDeparture).where(
                    SubjectDeparture.mdm_connection_id == connection_id,
                    SubjectDeparture.subject_kind == subject_kind,
                    still_gone_under_this_id(),
                )
            )
        )
        .scalars()
        .all()
    }
    population = current_ids - set(gone_rows)

    if observed_ids is None:
        return CensusVerdict(subject_kind, 0, len(population), 0, 0, SKIP_NOT_READABLE)
    observed = set(observed_ids)

    # Returns first: a subject the census named is present, whatever else it says — including an id a
    # serial match retired. Jamf handing it back says that retirement was wrong (a reused id, a
    # duplicate record, one serial on two records), so the row becomes the plain return it should have
    # been rather than holding a Mac that is right there out of the fleet for good.
    returned = 0
    absent = []
    for gone_id, row in gone_rows.items():
        if gone_id not in observed:
            if row.returned_at is None:
                absent.append(gone_id)
            continue
        row.subject_id, row.prior_jamf_pro_id = gone_id, None
        row.returned_at, row.matched_by = at, MATCHED_BY_JAMF_ID
        returned += 1

    # Then by serial and UDID (#475), before the breaker for the reason the id match is: a Mac the
    # census *did* name, under any id, is present. The close re-keys the row to the id it came back
    # under; `prior_jamf_pro_id`, the one it departed under, is what retires that old id.
    by_serial = await _returned_by_serial(
        db, connection_id=connection_id, subject_kind=subject_kind, subject_ids=absent, lineage=observed_lineage
    )
    for departed_id, came_back_as in sorted(by_serial.items()):
        row = gone_rows[departed_id]
        row.subject_id, row.prior_jamf_pro_id = came_back_as, departed_id
        row.returned_at, row.matched_by = at, MATCHED_BY_SERIAL
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
    """`(connection id, the id it is gone under) -> departed_at` for every subject of the kind that is
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
    return {(row.mdm_connection_id, row.prior_jamf_pro_id or row.subject_id): row.departed_at for row in rows}


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
