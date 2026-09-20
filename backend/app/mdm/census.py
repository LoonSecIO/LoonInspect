"""The census half of a sweep, shared by every provider (#566).

The three passes here reason over observations and runs, never over one vendor's API: the
Jamf sweep in `app.mdm.service` calls them today, and the Addigy sibling — about two weeks
out — calls the same three unchanged rather than importing them from a module named for
Jamf's primitives. Nothing here opens an HTTP client or reads a payload; by the time a
sweep arrives, all it carries is the ids it observed.

Neighbours. `app.observations.departure` derives the fact — the census, its circuit breaker,
the seven-day tail — and `app.observations.departure_events` puts it on the wire; this module
is what a sweep calls to run both inside one transaction and then say on the run what
happened. Every sentence it writes goes through `app.core.runs.log`, so it is a run-panel
line an operator reads, never a container log. The subject-kind constants still come from
`app.mdm.jamf.contract`, which is where the ledger's vocabulary lives rather than Jamf's
API; moving them is a separate job.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.alerts.service import close_departed_device_latches
from app.changes.derive import CollapsedDeparture
from app.core.findings import close_departed_device_findings
from app.core.runs import log as run_log
from app.mdm.jamf.contract import SUBJECT_COMPUTER, SUBJECT_COMPUTER_GROUP, SUBJECT_EXTENSION_ATTRIBUTE_DEFINITION
from app.models.schema import MdmConnection, Run
from app.observations.departure import DEPARTURE_TAIL_DAYS, SKIP_COLLAPSED, reconcile_census, tail_counts
from app.observations.departure_events import emit_census_events, emit_mac_notices, emit_mac_removals


async def _reconcile_departures(
    db: AsyncSession,
    connection: MdmConnection,
    run: Run | None,
    *,
    groups: Iterable[str] | None,
    definitions: Iterable[str] | None,
) -> None:
    """The departure derivation for both object kinds the catalog pass took a census of
    (#181), logged on the run, and the events it produces (#179). Commits, so a departure
    lands with the census that found it — and so does its event: `emit_census_events`
    enqueues into this session BEFORE the commit below, which is the whole reason the
    verdict carries the rows. A census that departed a group and then failed to commit has
    told no SIEM that it did."""
    at = datetime.now(UTC)
    for subject_kind, observed in ((SUBJECT_COMPUTER_GROUP, groups), (SUBJECT_EXTENSION_ATTRIBUTE_DEFINITION, definitions)):
        verdict = await reconcile_census(
            db,
            connection_id=connection.id,
            subject_kind=subject_kind,
            observed_ids=observed,
            at=at,
            census_run_id=run.id if run is not None else None,
        )
        emitted = await emit_census_events(db, connection=connection, verdict=verdict, at=at)
        if run is not None:
            level = "warning" if verdict.skipped else "info"
            await run_log(db, run, level, "departures reconciled", **verdict.as_log(), eventsEnqueued=emitted)
    await db.commit()


async def _log_collapsed_departures(db: AsyncSession, run: Run, collapsed: Mapping[tuple[str, str], CollapsedDeparture]) -> None:
    """One line per departed object, not one per device (#182).

    At the default preset this line is the echo's *whole* trace: the rows it counts are graded
    `low`, low is off, so they were never written. It names what is gone, what the deletion cost,
    whether any of it was kept, and the next check either way."""
    for entry in sorted(collapsed.values(), key=lambda e: (e.object_kind, e.object_id)):
        tail = (
            "They are on Devices › Changes under Level: Low; the page prints no sentence for this cause, so "
            "GET /api/changes?minLevel=low is where objectDeparted reads."
            if entry.recorded
            else "Level low is off under this instance's change-tracking preset, so they were not recorded; the memberships "
            "are already gone, so no later sweep derives them and nothing shows them now. Settings › Change tracking → "
            "Everything keeps the rows of the next deletion, not of this one."
        )
        await run_log(
            db,
            run,
            "info",
            f'{entry.object_kind} "{entry.label or entry.object_id}" is gone; its {entry.rows} per-device '
            f"removal {'row' if entry.rows == 1 else 'rows'} collapsed into this line at level low. {tail}",
            objectKind=entry.object_kind,
            objectId=entry.object_id,
            objectName=entry.label,
            rows=entry.rows,
            departedAt=entry.departed_at.isoformat(),
            rowLevel="low",
            rowsRecorded=entry.recorded,
        )


# The census line's last clause (#475): which keys it could match a return on. Constants because the
# drift test pins both to path 16, which quotes them.
_MATCHED_BY_ID_AND_SERIAL = "matched by Jamf id, and by serial with UDID"
_MATCHED_BY_ID_ONLY = "matched by Jamf id only: this sweep's sections carry no hardware, so no serial to match on"


def _latch_close_clause(latches_closed: int) -> str:
    """The sentence a closing latch goes quiet with — on EVERY line that closes one (#512).

    A latch closing is a row an operator was watching going quiet, and must never be something they
    infer from a number that moved. The close rides the terminal rather than the census, so a
    connection swept only by a selector reads it on the not-a-census line or nowhere. Path 16, step 5.
    """
    return (
        f"{latches_closed} open alert {'latch' if latches_closed == 1 else 'latches'} closed on Macs "
        f"that left the fleet; nothing was deleted — GET /api/alerts?open=false lists them"
    )


def _finding_close_clause(count: int) -> str:
    return (
        f"{count} open finding(s) closed on Macs that left the fleet; this does not mean fixed — "
        "last detected remains the Mac's last observation (troubleshooting §5 step 9)"
    )


async def _reconcile_device_census(
    db: AsyncSession,
    connection: MdmConnection,
    run: Run | None,
    *,
    observed_ids: list[str],
    observed_lineage: dict[tuple[str, str], str] | None,
    selector: str | None,
    devices_failed: int,
) -> None:
    """Reconcile device departures, terminal events, alerts and findings for a sweep.

    A deleted Mac leaves in seven days (#183) — and only ONE clean census may say so. Clean is
    all three, each ruling out a way of departing a Mac that is still there: the sweep reached this
    line, so it succeeded; it carried no RSQL `selector`, because a scoped sweep says nothing about
    the Macs it never asked for; and no device failed, because a device Jamf *did* return but whose
    ingest failed has a stale `last_seen_at`. A dirty night judges nobody, and the next clean one
    catches up. A sweep that is not a census says so on the run rather than going quiet: the
    operator waiting for a deleted Mac to go has to read which of the three is holding it. Commits,
    so a departure lands with its census.

    `observed_lineage` is None when this sweep's sections carry no `hardware` (#475): no serial to
    census with, so a Mac back under a new id is not recognised, and the line says which match it got
    — matching on less under the same sentence is rule 2.

    This is also where a departed Mac's open alert latches and findings are closed (#476, #607) — on BOTH paths, beside
    the terminal (#512) — because it is the only place that can be: `process_sync` runs against Macs
    a sweep returns, and a Mac that left the fleet is never swept again, so its latch would stay open
    for ever.
    """
    at = datetime.now(UTC)
    if selector is not None or devices_failed:
        # Above the gate deliberately (#179 4.5): the terminal is GUARANTEED and a tail runs out on
        # the wall clock, so a sweep too dirty to judge anybody still closes one. No census to contradict.
        # The latch close rides with it (#512): one departure, one act, one guarantee.
        removed = await emit_mac_removals(db, connection=connection, at=at)
        latches_closed = await close_departed_device_latches(
            db, connection_id=connection.id, at=at, run_id=run.id if run is not None else None
        )
        findings_closed = await close_departed_device_findings(db, connection_id=connection.id, at=at)
        await db.commit()
        if run is not None:
            line = "device census not taken; this sweep was not a clean one"
            if latches_closed:
                line += f". {_latch_close_clause(latches_closed)}"
            if findings_closed:
                line += f". {_finding_close_clause(findings_closed)}"
            await run_log(
                db,
                run,
                "info",
                line,
                reason="selector" if selector is not None else "device_failures",
                devicesFailed=devices_failed,
                macsRemoved=removed,
                latchesClosed=latches_closed,
                findingsClosed=findings_closed,
            )
        return
    verdict = await reconcile_census(
        db,
        connection_id=connection.id,
        subject_kind=SUBJECT_COMPUTER,
        observed_ids=observed_ids,
        at=at,
        census_run_id=run.id if run is not None else None,
        observed_lineage=observed_lineage,
    )
    # The wire, inside this transaction so an event and the row it describes land together (#179, built
    # by #495). Returns first: the census closes a returning Mac's row before the tail is walked.
    emitted = await emit_census_events(db, connection=connection, verdict=verdict, at=at)
    if not verdict.skipped:
        # A notice asserts "still absent" and a census the breaker refused observed nothing to assert
        # it from, so the tail pauses on a short read exactly as departing does. Returns do not.
        emitted += await emit_mac_notices(db, connection=connection, at=at)
    # BELOW the census, not above it: a Mac this census named has closed its row and left the open set,
    # so the sweep that finds one back on the day its clock runs out does not also say it was removed.
    removed = await emit_mac_removals(db, connection=connection, at=at)
    # The latch close fires with the terminal one line up, on the wall clock, unconditional on the
    # census as well as on the verdict (#512, ruled 2026-09-17): a latch crosses day seven on account
    # of a departure an EARLIER clean census recorded, so tonight's sweep being scoped or dirty has no
    # bearing on it. One departure, one act, one guarantee — which is why the branch above closes too.
    latches_closed = await close_departed_device_latches(
        db, connection_id=connection.id, at=at, run_id=run.id if run is not None else None
    )
    findings_closed = await close_departed_device_findings(db, connection_id=connection.id, at=at)
    await db.commit()
    if run is None:
        return
    in_tail, left = await tail_counts(db, connection_id=connection.id, subject_kind=SUBJECT_COMPUTER, at=at)
    # A refused census gets its OWN sentence, never a healthy one's at a louder level: "0 departed"
    # because nobody left and "0 departed" because we would not judge are the same number, and the
    # breaker's `logger.warning` is ours. So a refusal names itself and the next check (rules 1-2).
    if verdict.skipped:
        collapsed = f"only {verdict.observed} of {verdict.population} Macs came back, fewer than half the fleet"
        why = collapsed if verdict.skipped == SKIP_COLLAPSED else "the sweep returned no Macs at all"
        line = f"device census refused: {why}; departing nobody — check the API Role's privileges and this run's errors"
    else:
        line = (
            f"device census: {verdict.observed} observed, {len(verdict.departed)} departed, "
            f"{len(verdict.returned)} returned ({verdict.returned_by_serial} by serial, under a new Jamf id), "
            f"{in_tail} in their seven-day tail, {left} left the fleet; "
            f"{_MATCHED_BY_ID_AND_SERIAL if observed_lineage is not None else _MATCHED_BY_ID_ONLY}"
        )
    # On both census lines, refusal included, and on the not-a-census line above: the same words
    # wherever a latch closed, because the operator reads one of the three (`_latch_close_clause`).
    if latches_closed:
        line += f". {_latch_close_clause(latches_closed)}"
    if findings_closed:
        line += f". {_finding_close_clause(findings_closed)}"
    await run_log(
        db,
        run,
        "warning" if verdict.skipped else "info",
        line,
        **verdict.as_log(),
        inTail=in_tail,
        leftTheFleet=left,
        latchesClosed=latches_closed,
        findingsClosed=findings_closed,
        # What went on the wire, so "my SIEM saw nothing" is answerable from the run (troubleshooting §16.4).
        eventsEnqueued=emitted,
        macsRemoved=removed,
        # The sentence says "seven-day"; the machine-readable number comes from the constant.
        tailDays=DEPARTURE_TAIL_DAYS,
    )
