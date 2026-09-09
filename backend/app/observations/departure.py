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
  re-derivable from the spans and the census that found it. A return closes the row.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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

SKIP_NOT_READABLE = "not_readable"
SKIP_EMPTY = "empty_census"
SKIP_COLLAPSED = "collapsed_census"


@dataclass(frozen=True)
class CensusVerdict:
    """What one census did to one subject kind under one connection."""

    subject_kind: str
    observed: int
    population: int
    departed: int
    returned: int
    skipped: str | None = None

    def as_log(self) -> dict[str, object]:
        return {
            "subjectKind": self.subject_kind,
            "observed": self.observed,
            "population": self.population,
            "departed": self.departed,
            "returned": self.returned,
            "skipped": self.skipped,
        }


async def reconcile_census(
    db: AsyncSession,
    *,
    connection_id: int,
    subject_kind: str,
    observed_ids: Iterable[str] | None,
    at: datetime,
    census_run_id: uuid.UUID | None = None,
) -> CensusVerdict:
    """Apply one census to the departures table. Commits nothing; the caller does.

    `observed_ids` is every subject id the census named, or None when the census could
    not be taken at all (a refused read) — which departs nobody and returns nobody.
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
    # The present population: what the ledger holds minus what has already departed. A
    # fleet that legitimately shrank over months must not keep tripping the breaker.
    population = current_ids - set(open_rows)

    if observed_ids is None:
        return CensusVerdict(subject_kind, 0, len(population), 0, 0, SKIP_NOT_READABLE)
    observed = set(observed_ids)

    # Returns first: a subject the census named is present, whatever else it says.
    returned = 0
    for subject_id, row in open_rows.items():
        if subject_id in observed:
            row.returned_at = at
            returned += 1

    if not observed and population:
        logger.warning(
            "census returned nothing; departing nobody",
            extra={"connection_id": connection_id, "subject_kind": subject_kind, "population": len(population)},
        )
        return CensusVerdict(subject_kind, 0, len(population), 0, returned, SKIP_EMPTY)
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
        return CensusVerdict(subject_kind, len(observed), len(population), 0, returned, SKIP_COLLAPSED)

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
    return CensusVerdict(subject_kind, len(observed), len(population), departed, returned)


async def open_departures(db: AsyncSession, *, subject_kind: str) -> dict[tuple[int, str], datetime]:
    """`(connection id, subject id) -> departed_at` for every subject of the kind that is
    currently gone — what a surface listing current spans consults to say so."""
    rows = (
        (
            await db.execute(
                select(SubjectDeparture).where(
                    SubjectDeparture.subject_kind == subject_kind, SubjectDeparture.returned_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    return {(row.mdm_connection_id, row.subject_id): row.departed_at for row in rows}
