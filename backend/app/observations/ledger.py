"""The observation ledger — storage for what the contract produced.

`app.mdm.jamf.contract` turns a raw Jamf record into digests and canonical content;
this module writes that into the four ledger tables with span semantics:

  new        first observation of this subject → one span, all content written
  changed    head digest differs from the current span → old span closed, new one
             opened with `previous_id` pointing back; only the sections whose digest
             changed have content written (the rest already exist by construction)
  unchanged  same head, newer device time → the current span's count and
             last_observed_at advance; nothing else is written
  repeat     same head, same device time → we read a record Jamf already served us
             (a sweep after a webhook); no write at all
  stale      older device time than the current span → ignored. This is the monotonic
             guard from docs/ingest-scheduling.md §4.4: a sweep that read a device
             before a webhook wrote it cannot roll the record back afterwards.

Nothing here commits. The caller owns the transaction — in the sync path the ledger
write and the `devices`/`installed_apps` update for the same device commit together.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.mdm.jamf.contract import (
    CONTRACT_VERSION,
    SUBJECT_COMPUTER,
    Aperture,
    Observation,
    SectionContent,
    compute_head_digest,
)
from app.models.schema import (
    ObservationAperture,
    ObservationEntry,
    ObservationSection,
    ObservationSpan,
)

logger = logging.getLogger(__name__)

Outcome = Literal["new", "changed", "unchanged", "repeat", "stale"]

# asyncpg caps a statement at 32767 bind parameters; entries carry six columns each.
_ENTRY_BATCH = 1000

# Subject kinds whose spans are never loaded whole, because their subjects are streamed a
# page at a time — `current_spans` refuses them. A mobile-device kind (#238) belongs here
# the day it exists; a catalog kind, Jamf's or a second MDM's, does not.
_STREAMED_KINDS = frozenset({SUBJECT_COMPUTER})


@dataclass(frozen=True, slots=True)
class RecordResult:
    outcome: Outcome
    head_digest: str
    span_id: uuid.UUID | None = None
    changed_sections: tuple[str, ...] = ()
    # The span this one closed, when the outcome is `changed` — what the change log
    # diffs against.
    previous_span_id: uuid.UUID | None = None


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def ensure_aperture(db: AsyncSession, *, connection_id: int, aperture: Aperture) -> str:
    """Upsert the aperture row and return its digest. Called once per run, not per
    device — the aperture is a property of how the run looked at Jamf."""
    now = _utcnow()
    statement = (
        pg_insert(ObservationAperture)
        .values(
            mdm_connection_id=connection_id,
            digest=aperture.digest,
            contract_version=CONTRACT_VERSION,
            document=aperture.document,
            first_seen_at=now,
            last_seen_at=now,
        )
        .on_conflict_do_update(
            constraint="uq_observation_aperture_digest",
            set_={"last_seen_at": now},
        )
    )
    await db.execute(statement)
    return aperture.digest


async def current_span(db: AsyncSession, *, connection_id: int, subject_kind: str, subject_id: str) -> ObservationSpan | None:
    result = await db.execute(
        select(ObservationSpan).where(
            ObservationSpan.mdm_connection_id == connection_id,
            ObservationSpan.subject_kind == subject_kind,
            ObservationSpan.subject_id == subject_id,
            ObservationSpan.is_current.is_(True),
        )
    )
    return result.scalar_one_or_none()


@dataclass(slots=True)
class CensusSpans:
    """One subject kind's current spans, read once for a whole census and handed out one
    subject at a time (#569).

    `take` answers the two arguments `record_observation` takes: the span this subject
    held when the census began, and whether that answer may be trusted. It may be trusted
    once. A census that names the same subject twice gets `current_loaded=False` on the
    repeat, so `record_observation` reads that one subject itself and sees the row the
    first pass has already written.

    That repeat is not hypothetical and the fallback is not politeness. The censuses read
    offset-paginated endpoints (`page`/`page-size`) over a tenant being edited underneath
    them, and a duplicate across two pages is the ordinary hazard of that read shape.
    Handing the same stale `None` out twice would take `record_observation`'s `new` branch
    twice, and the second insert would trip the partial unique index
    `uq_observation_spans_current_subject` — failing not that one object but the whole
    catalog pass, groups and definitions and departures with it, over a duplicate the
    per-object read shrugged off. This lives in the MDM-agnostic half so that a second
    MDM's catalog pass inherits the fallback instead of having to remember it.
    """

    spans: dict[str, ObservationSpan]
    _taken: set[str] = field(default_factory=set)

    def take(self, subject_id: str) -> tuple[ObservationSpan | None, bool]:
        """This subject's current span, and `True`, the first time it is asked for.
        `(None, False)` on a repeat, which reads as "not loaded — go and look"."""
        if subject_id in self._taken:
            return None, False
        self._taken.add(subject_id)
        return self.spans.get(subject_id), True


async def current_spans(db: AsyncSession, *, connection_id: int, subject_kind: str) -> CensusSpans:
    """Every current span of one subject kind, keyed by subject id: one select for a whole
    census rather than one per object (#569).

    For the catalog kinds, whose censuses are tens to hundreds of objects read whole on
    every pass — smart groups, extension-attribute definitions, and whatever a second
    MDM's catalog pass takes a census of. Not for a streamed kind, which is refused below
    rather than discouraged in prose: a fleet is read a page at a time precisely so that
    40k spans are never resident at once, and `ingest_computer` reads one span per device
    on purpose.

    A subject the map does not name has no current span, which is what a per-object miss
    meant: hand `record_observation` that `None` and it reads the subject as `new`.
    """
    if subject_kind in _STREAMED_KINDS:
        raise ValueError(
            f"current_spans is for catalog kinds counted whole; {subject_kind!r} is streamed a page at a time. "
            "Read one span per object with current_span, the way ingest_computer does."
        )
    result = await db.execute(
        select(ObservationSpan).where(
            ObservationSpan.mdm_connection_id == connection_id,
            ObservationSpan.subject_kind == subject_kind,
            ObservationSpan.is_current.is_(True),
        )
    )
    return CensusSpans({span.subject_id: span for span in result.scalars().all()})


def is_stale(current: ObservationSpan | None, observed_at: datetime) -> bool:
    """Strictly older than what the current span has already seen. Equal is allowed —
    the same reportDate through a different aperture is a legitimate new head."""
    return current is not None and observed_at < current.last_observed_at


async def _write_sections(db: AsyncSession, sections: Iterable[SectionContent]) -> None:
    now = _utcnow()
    section_rows = []
    entry_rows: dict[str, dict] = {}
    for content in sections:
        section_rows.append(
            {
                "digest": content.digest,
                "section": content.name,
                "body": content.body,
                "entry_digests": content.entry_digests if content.is_list else None,
                "entry_count": len(content.entries),
                "first_seen_at": now,
            }
        )
        for entry in content.entries:
            entry_rows.setdefault(
                entry.digest,
                {
                    "digest": entry.digest,
                    "kind": entry.kind,
                    "body": entry.body,
                    "label": entry.label,
                    "first_seen_at": now,
                },
            )

    if section_rows:
        await db.execute(
            pg_insert(ObservationSection).values(section_rows).on_conflict_do_nothing(constraint="uq_observation_section_digest")
        )

    rows = list(entry_rows.values())
    for start in range(0, len(rows), _ENTRY_BATCH):
        statement = pg_insert(ObservationEntry).values(rows[start : start + _ENTRY_BATCH])
        # Content rows are immutable except for the label, which the contract keeps
        # out of the hash precisely so it can follow a rename.
        await db.execute(
            statement.on_conflict_do_update(
                constraint="uq_observation_entry_digest",
                set_={"label": statement.excluded.label},
                where=(statement.excluded.label.isnot(None) & ObservationEntry.label.is_distinct_from(statement.excluded.label)),
            )
        )


async def record_observation(
    db: AsyncSession,
    *,
    connection_id: int,
    observation: Observation,
    aperture_digest: str,
    trigger: str,
    collected_at: datetime | None = None,
    current: ObservationSpan | None = None,
    current_loaded: bool = False,
) -> RecordResult:
    """Write one observation into the ledger and say what it meant.

    `observed_at` is the device's own time when the source has one (Jamf's reportDate)
    and our clock otherwise — groups have no device time. The monotonic guard compares
    device time, which is why the two are never conflated.

    Pass `current` (with `current_loaded=True`) when the caller already fetched the
    span to decide whether to proceed at all; otherwise it is fetched here.
    """
    collected_at = collected_at or _utcnow()
    observed_at = observation.observed_at or collected_at
    head_digest = compute_head_digest(
        observation.subject_kind, observation.subject_id, aperture_digest, observation.section_digests
    )

    if not current_loaded:
        current = await current_span(
            db,
            connection_id=connection_id,
            subject_kind=observation.subject_kind,
            subject_id=observation.subject_id,
        )

    if current is not None:
        if is_stale(current, observed_at):
            return RecordResult(outcome="stale", head_digest=head_digest, span_id=current.id)

        if current.head_digest == head_digest:
            if observed_at == current.last_observed_at:
                return RecordResult(outcome="repeat", head_digest=head_digest, span_id=current.id)
            current.last_observed_at = observed_at
            current.last_collected_at = collected_at
            current.observation_count = current.observation_count + 1
            current.last_trigger = trigger
            if observation.label and observation.label != current.label:
                current.label = observation.label
            return RecordResult(outcome="unchanged", head_digest=head_digest, span_id=current.id)

        previous_digests = current.section_digests or {}
        changed = tuple(name for name, content in observation.sections.items() if previous_digests.get(name) != content.digest)
        await _write_sections(db, (observation.sections[name] for name in changed))

        # Close the old span before the new insert so the partial unique index sees
        # one current row at a time. Explicit rather than left to flush ordering.
        await db.execute(update(ObservationSpan).where(ObservationSpan.id == current.id).values(is_current=False))
        current.is_current = False
        previous_id: uuid.UUID | None = current.id
        outcome: Outcome = "changed"
    else:
        changed = tuple(observation.sections)
        await _write_sections(db, observation.sections.values())
        previous_id = None
        outcome = "new"

    span = ObservationSpan(
        id=uuid.uuid4(),
        mdm_connection_id=connection_id,
        subject_kind=observation.subject_kind,
        subject_id=observation.subject_id,
        label=observation.label,
        udid=observation.udid,
        serial_number=observation.serial_number,
        management_id=observation.management_id,
        contract_version=CONTRACT_VERSION,
        aperture_digest=aperture_digest,
        head_digest=head_digest,
        section_digests=observation.section_digests,
        first_observed_at=observed_at,
        last_observed_at=observed_at,
        first_collected_at=collected_at,
        last_collected_at=collected_at,
        observation_count=1,
        last_trigger=trigger,
        previous_id=previous_id,
        is_current=True,
    )
    db.add(span)
    await db.flush()
    return RecordResult(
        outcome=outcome,
        head_digest=head_digest,
        span_id=span.id,
        changed_sections=changed,
        previous_span_id=previous_id,
    )
