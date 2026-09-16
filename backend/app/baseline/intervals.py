"""The interval query: the observation ledger read as one section's history (#465, #219 R5).

`observation_spans` is a temporal table and not an interval table for a rule. Four corrections — three the #219
spike verified, one the departures table imposes — each of which prints a wrong report if it is missed.

**A span's timestamps bound when we SAW a state, not how long it held.** Their difference is zero on every span
whose `observation_count` is 1 — every span in the demo data — and wrong in the direction that flatters us. An
interval runs to the *next* interval's first observation: the state is carried forward between observations,
where both ends are witnessed (R5 5.2), and outside that bracket — before the first, after the last — it is NOT
OBSERVED, printed as its own number.

**Spans are coalesced per section.** A span opens when any section's content changes, or the aperture does, so a
Mac whose `applications` churns weekly opens a span weekly while `security` sits on one digest all quarter:
printing spans as rows prints one stretch fifty times. So, gaps-and-islands over `section_digests ->> section`,
by subject, in device time (R5 5.4).

**A departure is a label on the tail, never a span.** Absence opens and closes no span (#135 rider 4): the days
are the same days and only the word is better, and the id it is labelled under is the id the row is gone under,
which for a Mac that came back under a new one is the retired id, still gone (#475, `departure_windows`).

Three prohibitions the result's shape enforces rather than discourages — never project to today, never drop a
quiet device, never ask `runs` what time it is — are each kept by one function below and documented there.

No verdicts here: an observed interval carries the **section digest** it held, the key #464's evaluator memoises
on (*cache, don't calculate*); a `None` digest is a span that did not carry the section at all, and reads
downstream as `not_reported`, never `unmet`. No display name either — `subject_id` is `devices.external_id` on
the same connection.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from itertools import groupby
from typing import Literal

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.mdm.jamf.contract import SUBJECT_COMPUTER
from app.models.schema import ObservationSpan
from app.observations.departure import departure_windows

IntervalState = Literal["observed", "not_observed", "departed"]
OBSERVED: IntervalState = "observed"
NOT_OBSERVED: IntervalState = "not_observed"
DEPARTED: IntervalState = "departed"

_ZERO = timedelta(0)
_Window = tuple[datetime, datetime | None]

# `same` is `IS NOT DISTINCT FROM` rather than `=`: a section the aperture never read is a NULL digest, and two
# adjacent NULLs are one continuous stretch, not two. The whole history below `as_of` is read rather than the
# window alone, because the span current when the window opened is what the opening state is carried forward
# *from*. The index this walk wants is `ix_observation_spans_subject`; the GIN `jsonb_path_ops` index on
# `section_digests` answers the inverse question ("every subject carrying digest X") and is not this query's.
# Tenancy is RLS, as everywhere else in the ledger.
_ISLANDS = text("""
WITH ordered AS (
    SELECT id, subject_id, first_observed_at, last_observed_at, first_collected_at, last_collected_at,
           observation_count, section_digests ->> :section AS digest, lag(last_observed_at) OVER w AS prior_last,
           (section_digests ->> :section) IS NOT DISTINCT FROM lag(section_digests ->> :section) OVER w AS same
      FROM observation_spans
     WHERE mdm_connection_id = :connection_id AND subject_kind = :subject_kind AND first_observed_at <= :as_of
    WINDOW w AS (PARTITION BY subject_id ORDER BY first_observed_at, first_collected_at, id)
), marked AS (
    -- Only a span continuing its island measures a gap inside it; the first span of one would
    -- otherwise measure the distance back to the island before it.
    SELECT *, sum(CASE WHEN same THEN 0 ELSE 1 END) OVER w AS island,
              CASE WHEN same THEN first_observed_at - prior_last END AS inner_gap
      FROM ordered WINDOW w AS (PARTITION BY subject_id ORDER BY first_observed_at, first_collected_at, id
                                ROWS UNBOUNDED PRECEDING)
)
SELECT subject_id, min(digest) AS digest, min(first_observed_at) AS starts_at, max(last_observed_at) AS last_observed_at,
       min(first_collected_at) AS first_collected_at, max(last_collected_at) AS last_collected_at,
       sum(observation_count) AS observations, max(inner_gap) AS inner_gap
  FROM marked GROUP BY subject_id, island ORDER BY subject_id, min(first_observed_at)
""")


@dataclass(frozen=True)
class Interval:
    """One closed stretch of one subject's history of one section.

    `starts_at` / `ends_at` are **device time**; the two collection timestamps are our clock beside them, R5 5.4's
    "both, always" — `None` on an unobserved stretch, never borrowed, and naming the observations themselves, so
    an interval clipped to the window's opening still cites the read it came from. `longest_gap` is the longest
    run inside it over which the state was *assumed* rather than witnessed: the widest hole between the island's
    spans, or the carry-forward to the next observation."""

    state: IntervalState
    digest: str | None
    starts_at: datetime
    ends_at: datetime
    observation_count: int = 0
    longest_gap: timedelta = _ZERO
    first_collected_at: datetime | None = None
    last_collected_at: datetime | None = None

    @property
    def duration(self) -> timedelta:
        """Zero is a real answer: "seen once, under one reporting interval" (R5 5.4)."""
        return self.ends_at - self.starts_at


@dataclass(frozen=True)
class SubjectIntervals:
    """One subject's contiguous, closed cover of the window, oldest first."""

    subject_id: str
    intervals: tuple[Interval, ...]


@dataclass(frozen=True)
class IntervalLedger:
    section: str
    subject_kind: str
    window_from: datetime
    as_of: datetime
    subjects: tuple[SubjectIntervals, ...]


async def ledger_heartbeat(db: AsyncSession, *, connection_id: int) -> datetime | None:
    """`max(observation_spans.last_collected_at)` for one connection — where `as_of` comes from when a report does
    not name one, and the only place it comes from. **Never `runs`:** runs purge at 30 days
    (`run_retention_days`) while the ledger has no retention and no purge path, so last March is answerable long
    after the run that collected it is gone, and an `as_of` taken from `runs` would silently shrink the
    answerable window to a month. A named `as_of` is never clamped down to this either — the stretch between
    heartbeat and `as_of` is the not-observed tail, and losing it is how a headline gets pretty."""
    return (
        await db.execute(
            select(func.max(ObservationSpan.last_collected_at)).where(ObservationSpan.mdm_connection_id == connection_id)
        )
    ).scalar_one_or_none()


def _gap(state: IntervalState, opens: datetime, closes: datetime) -> Interval:
    """A stretch nobody witnessed: no digest, neither collection clock, and every day of it assumed."""
    return Interval(state=state, digest=None, starts_at=opens, ends_at=closes, longest_gap=closes - opens)


def _tail(start: datetime, end: datetime, gone: tuple[_Window, ...]) -> list[Interval]:
    """The unobserved stretch after a subject's last observation, cut where a departure covers it — the same days,
    a better word. `gone` is `departure_windows`: keyed on the id the row is gone under and open-ended unless a
    census named that id again, so a Mac that came back under its own id is departed for the days it was gone
    rather than since, and an id a serial match retired is departed to `as_of`, as every other reader of that
    table already reports it."""
    pieces: list[Interval] = []
    cursor = start
    for departed_at, ended_at in gone:
        opens, closes = max(departed_at, cursor), min(ended_at or end, end)
        if closes <= opens:
            continue
        if cursor < opens:
            pieces.append(_gap(NOT_OBSERVED, cursor, opens))
        pieces.append(_gap(DEPARTED, opens, closes))
        cursor = closes
    if cursor < end:
        pieces.append(_gap(NOT_OBSERVED, cursor, end))
    return pieces


def _cover(islands: list, *, gone: tuple[_Window, ...], window_from: datetime, as_of: datetime) -> tuple[Interval, ...]:
    """One subject's islands as a contiguous cover of `[window_from, as_of]`, clipped at the window's opening:
    what closed before it is not printed, and the one straddling it starts there, with its gap held to what the
    printed stretch can contain. The head before the first observation is plainly not observed — a subject needs
    a current span to be departed at all, so nothing can have departed before it — and only the tail is relabelled."""
    out: list[Interval] = []
    if window_from < islands[0].starts_at:
        out.append(_gap(NOT_OBSERVED, window_from, islands[0].starts_at))
    for index, island in enumerate(islands):
        # Carried forward to the next island's FIRST observation — the moment the new state was witnessed,
        # which is where the old one stops being the best answer. The last island stops at its own last
        # observation: past that, nothing is witnessed at either end.
        ends_at = islands[index + 1].starts_at if index + 1 < len(islands) else island.last_observed_at
        ends_at = min(max(ends_at, island.starts_at), as_of)
        out.append(
            Interval(
                state=OBSERVED,
                digest=island.digest,
                starts_at=island.starts_at,
                ends_at=ends_at,
                observation_count=int(island.observations),
                longest_gap=max(island.inner_gap or _ZERO, ends_at - island.last_observed_at, _ZERO),
                first_collected_at=island.first_collected_at,
                last_collected_at=island.last_collected_at,
            )
        )
    out += _tail(min(islands[-1].last_observed_at, as_of), as_of, gone)

    def clip(i: Interval) -> Interval:
        if i.starts_at >= window_from:
            return i
        return replace(i, starts_at=window_from, longest_gap=min(i.longest_gap, i.ends_at - window_from))

    return tuple(clip(i) for i in out if i.ends_at > window_from or (i.ends_at == window_from == i.starts_at))


async def section_intervals(
    db: AsyncSession,
    *,
    connection_id: int,
    section: str,
    window_from: datetime,
    as_of: datetime | None = None,
    subject_kind: str = SUBJECT_COMPUTER,
) -> IntervalLedger:
    """Every subject's history of one section, as closed labelled intervals over the window. One section per call:
    ten rules across four sections is four queries, not ten. `as_of` defaults to `ledger_heartbeat`, and to
    `window_from` when the ledger is empty; nothing extends past it. Every subject the ledger holds a span for
    below `as_of` is here, observed inside the window or not — a quiet Mac cannot be dropped, only printed with
    its gap — and each one's intervals are contiguous and cover `[window_from, as_of]` exactly, because the
    identity the artefact prints (met + unmet + not observed = the window) only holds if nothing is lost here."""
    at = as_of or await ledger_heartbeat(db, connection_id=connection_id) or window_from
    bound = {"connection_id": connection_id, "subject_kind": subject_kind, "section": section, "as_of": at}
    rows = (await db.execute(_ISLANDS, bound)).all()
    gone = await departure_windows(db, connection_id=connection_id, subject_kind=subject_kind)
    subjects = tuple(
        SubjectIntervals(
            subject_id=subject_id,
            intervals=_cover(list(islands), gone=gone.get(subject_id, ()), window_from=window_from, as_of=at),
        )
        for subject_id, islands in groupby(rows, key=lambda row: row.subject_id)
    )
    return IntervalLedger(section=section, subject_kind=subject_kind, window_from=window_from, as_of=at, subjects=subjects)
