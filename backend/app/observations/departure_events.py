"""Departure on the wire (#179, ruled 2026-09-16): `subject.departure`, `subject.returned`.

`app.observations.departure` derives the fact and writes the `subject_departures` row; this
is the other half of that seam. Called from `mdm.service._reconcile_departures` BEFORE its
commit, which is why the census hands over the ROWS and not the counts — the outbox row and
the departure row are one transaction or neither happens.

**Two types, one sourcetype** (4.1/4.6/4.7): `subjectKind` discriminates the departing kind,
the return is its own type (#135 R3 refused one type with a `returned` state), and both are
stamped `loon:departure`. **`deviceCount` is LoonInspect's last count, never Jamf's**, which
cannot be asked once the subject is gone. **`deviceMeta` degrades by subject kind exactly as
`changes.derive._change_device_meta` does** (4.2), with **no `eventID` on a departure of
either subject**: a departure is derived from an absence, so minting one would fabricate a
correlation key for a read that never happened.

**A Mac is a tail, not an event** (4.5, built by #495), emitted from the device census. `emit_mac_notices`
sends `state: departed` with `noticeDay` 1..7 off the OPEN ROWS rather than one census's verdict, so all seven
days have one producer; `emit_mac_removals` sends the terminal `state: removed` on `left_the_fleet`.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import datetime
from typing import TypeVar

from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import get_request_id
from app.core.outbox import enqueue_event
from app.core.runs import event_time, get_run, run_meta
from app.core.wire import ENVELOPE, envelope, instance_label
from app.core.wire_vocabulary import DEPARTURE_EVENT_TYPE, RETURNED_EVENT_TYPE
from app.mdm.jamf.contract import SUBJECT_COMPUTER, SUBJECT_COMPUTER_GROUP, SUBJECT_EXTENSION_ATTRIBUTE_DEFINITION
from app.models.schema import (
    Device,
    DeviceExtensionAttribute,
    MdmConnection,
    ObservationEntry,
    ObservationSection,
    ObservationSpan,
    SubjectDeparture,
)
from app.observations.departure import DEPARTURE_TAIL_DAYS, CensusVerdict, left_the_fleet, still_gone_under_this_id
from app.schemas.payload import WIRE_SCHEMA_VERSION

# `departed` is where every subject starts; `removed` is the Mac tail's guaranteed close (4.5). An
# object departs once and is noticed once — the seven-day grace is a Mac's and an object never reaches
# `removed` — but `noticeDay` still ships on it, so `stats by noticeDay` has no null bucket that silently
# means "an object". `jamfProID` is the only key an object's return matches on; `serialNumber` with
# `priorJamfProID` is the Mac's re-enrol case (R3/3).
STATE_DEPARTED = "departed"
STATE_REMOVED = "removed"
OBJECT_NOTICE_DAY = 1
MATCHED_BY_ID = "jamfProID"

# The pass's one batching seam (#513), the size and the reason `departure._returned_by_serial` already
# batches at: asyncpg caps ONE statement at 32767 bind parameters and raises past it rather than
# degrading, and a mass deletion — a Jamf Pro purge, a connection re-pointed at a smaller instance —
# opens tens of thousands of Mac tails at once. `_open_macs` produces that set whole; `_emit_macs` and
# `_emit_mac_returns` divide it here and nowhere else, so `_devices` is only ever handed a batch and no
# id list can reach the database unbounded. A fifth caller crosses the seam by construction rather than
# by remembering to write a fifth loop, which is the whole reason there is one.
_EMIT_BATCH = 1000
_Row = TypeVar("_Row")


def _batches(rows: Sequence[_Row]) -> Iterator[Sequence[_Row]]:
    """One pass's rows in `_EMIT_BATCH`-sized pieces, last one short. Empty in, nothing out."""
    for start in range(0, len(rows), _EMIT_BATCH):
        yield rows[start : start + _EMIT_BATCH]


_MEMBERSHIPS = "group_memberships"
_MEMBERSHIP_ENTRY = "group_membership"


async def emit_census_events(db: AsyncSession, *, connection: MdmConnection, verdict: CensusVerdict, at: datetime) -> int:
    """One event per row this census moved; enqueues into the caller's session and commits nothing. A Mac's
    DEPARTURES are the exception — a tail, `emit_mac_notices`' — and a Mac's RETURNS are here."""
    if verdict.subject_kind == SUBJECT_COMPUTER:
        return await _emit_mac_returns(db, connection=connection, rows=verdict.returned, at=at)
    moved = (*verdict.departed, *verdict.returned)
    if not moved:
        return 0
    spans = await _current_spans(db, connection.id, verdict.subject_kind, [row.subject_id for row in moved])
    source = instance_label(connection.base_url)
    for row in verdict.departed:
        label, last_seen_at = spans.get(row.subject_id, (None, None))
        body = _departure_body(
            row,
            label=label,
            last_seen_at=last_seen_at,
            device_count=await _device_count(db, connection.id, row.subject_kind, row.subject_id),
            occurred_at=at,
            source=source,
            device_meta=_object_device_meta(row.subject_id),
        )
        await enqueue_event(db, DEPARTURE_EVENT_TYPE, body, request_id=get_request_id())
    for row in verdict.returned:
        label, _seen = spans.get(row.subject_id, (None, None))
        body = _returned_body(row, label=label, occurred_at=at, source=source, device_meta=_object_device_meta(row.subject_id))
        await enqueue_event(db, RETURNED_EVENT_TYPE, body, request_id=get_request_id())
    return len(moved)


async def _open_macs(db: AsyncSession, connection_id: int, *, at: datetime, expired: bool) -> list[SubjectDeparture]:
    """The Macs this connection owes an emission on: tail run out by `at` (`expired`) or still inside it —
    `removed_notified_at` takes a row out of both for good. A RETIRED HALF (back under a NEW id, so
    `prior_jamf_pro_id` holds the row open) owes its terminal but no notice: "still absent" beside that
    same sweep's own `subject.returned` is a contradiction the §7 join would read twice."""
    ran_out = left_the_fleet(SubjectDeparture.departed_at, at=at)
    rows = await db.execute(
        select(SubjectDeparture)
        .where(
            SubjectDeparture.mdm_connection_id == connection_id,
            SubjectDeparture.subject_kind == SUBJECT_COMPUTER,
            still_gone_under_this_id(),
            SubjectDeparture.removed_notified_at.is_(None),
            ran_out if expired else and_(~ran_out, SubjectDeparture.returned_at.is_(None)),
        )
        .order_by(SubjectDeparture.id)
    )
    return list(rows.scalars().all())


async def emit_mac_removals(db: AsyncSession, *, connection: MdmConnection, at: datetime) -> int:
    """The tail's guaranteed close (4.5): `state: removed` once a Mac has left the device population —
    `left_the_fleet` and nothing else, the predicate **Devices** and the Overview count drop it on. **No
    census can withhold it**: seven scoped or lossy sweeps still leave Macs whose days ran out. But none
    may be CONTRADICTED either, so the caller runs this AFTER `reconcile_census`, and above the gate."""
    rows = await _open_macs(db, connection.id, at=at, expired=True)
    for row in rows:
        row.removed_notified_at = at
    await _emit_macs(db, connection=connection, rows=rows, at=at, state=STATE_REMOVED)
    return len(rows)


async def emit_mac_notices(db: AsyncSession, *, connection: MdmConnection, at: datetime) -> int:
    """`state: departed`, `noticeDay` 1..7, one per Mac per UTC day (4.5). The census is the heartbeat
    and there is no timer: a day with no clean census emits nothing and is never backfilled, because a
    notice asserts an absence the skipped sweep did not observe — quiet to Friday resumes at 4, not 2."""
    due = []
    for row in await _open_macs(db, connection.id, at=at, expired=False):
        # UTC calendar days as ruled, not elapsed hours: 23:50 then 00:10 is the next notice day.
        day = min(DEPARTURE_TAIL_DAYS, (at.date() - row.departed_at.date()).days + 1)
        if day > row.notice_day:
            row.notice_day = day
            due.append(row)
    await _emit_macs(db, connection=connection, rows=due, at=at, state=STATE_DEPARTED)
    return len(due)


async def _emit_macs(
    db: AsyncSession, *, connection: MdmConnection, rows: list[SubjectDeparture], at: datetime, state: str
) -> None:
    """One departure event per Mac with the `Device` row's own identity: `deviceMeta` is that row's
    whole block last known (4.2), `host` is the hostname (a Mac IS a host), `deviceCount` is absent."""
    if not rows:
        return
    source = instance_label(connection.base_url)
    for batch in _batches(rows):
        # The id each row is GONE under, coalesced as `gone_for_good` does: a serial match re-keys `subject_id` to
        # the id the Mac came back as, leaving `prior_jamf_pro_id` to name and close the retired half on the wire.
        gone_ids = [row.prior_jamf_pro_id or row.subject_id for row in batch]
        devices = await _devices(db, connection.id, gone_ids)
        for row, gone in zip(batch, gone_ids, strict=True):
            device = devices.get(gone)
            hostname = device.hostname if device else None
            body = _departure_body(
                row,
                label=hostname,
                last_seen_at=device.last_seen_at if device else None,
                device_count=None,
                occurred_at=at,
                source=source,
                state=state,
                notice_day=DEPARTURE_TAIL_DAYS if state == STATE_REMOVED else row.notice_day,
                host=hostname,
                device_meta=_mac_device_meta(device, subject_id=gone, pulled=False),
            )
            await enqueue_event(db, DEPARTURE_EVENT_TYPE, body, request_id=get_request_id())


async def _emit_mac_returns(
    db: AsyncSession, *, connection: MdmConnection, rows: tuple[SubjectDeparture, ...], at: datetime
) -> int:
    """4.6 for a Mac, read off the row #475 writes: `matchedBy` is how the census recognised it, `priorJamfProID`
    joins a wipe-and-re-enrol to the departure it closes, and `deviceMeta` keeps its `eventID` — a real pull."""
    if not rows:
        return 0
    source = instance_label(connection.base_url)
    for batch in _batches(rows):
        devices = await _devices(db, connection.id, [row.subject_id for row in batch])
        for row in batch:
            device = devices.get(row.subject_id)
            hostname = device.hostname if device else None
            body = _returned_body(
                row,
                label=hostname,
                occurred_at=at,
                source=source,
                host=hostname,
                matched_by=row.matched_by or MATCHED_BY_ID,
                prior_jamf_pro_id=row.prior_jamf_pro_id,
                device_meta=_mac_device_meta(device, subject_id=row.subject_id, pulled=True),
            )
            await enqueue_event(db, RETURNED_EVENT_TYPE, body, request_id=get_request_id())
    return len(rows)


def _departure_body(
    row: SubjectDeparture,
    *,
    label: str | None,
    last_seen_at: datetime | None,
    device_count: int | None,
    occurred_at: datetime,
    source: str | None,
    device_meta: dict[str, object],
    state: str = STATE_DEPARTED,
    notice_day: int = OBJECT_NOTICE_DAY,
    host: str | None = None,
) -> dict:
    """4.3's body, which is 4.4's with a different `subjectKind`, written in the ruled order
    and delivered in it — `ordered_event_keys` keeps a family's own keys in their relative
    order, then `event` and `jobID`, then `deviceMeta`, so the order costs this family no
    table of its own. `occurredAt` is the census that derived the absence and `departedAt` the
    row's own stamp: equal on the day a subject departs, divergent on a Mac's later notice
    days, which is what makes `departedAt` the exact key a return closes on."""
    run = get_run()
    return _delivered(
        {
            "subjectKind": row.subject_kind,
            "subjectLabel": label,
            "state": state,
            "noticeDay": notice_day,
            "departedAt": row.departed_at.isoformat(),
            "occurredAt": occurred_at.isoformat(),
            "lastSeenAt": last_seen_at.isoformat() if last_seen_at else None,
            "deviceCount": device_count,
            "event": DEPARTURE_EVENT_TYPE,
            "jobID": str(run.id) if run else None,
            "deviceMeta": device_meta,
        },
        occurred_at=occurred_at,
        host=host,
        source=source,
    )


def _returned_body(
    row: SubjectDeparture,
    *,
    label: str | None,
    occurred_at: datetime,
    source: str | None,
    device_meta: dict[str, object],
    host: str | None = None,
    matched_by: str = MATCHED_BY_ID,
    prior_jamf_pro_id: str | None = None,
) -> dict:
    """4.6's body: the departure it closes, named exactly, so a subject that departs, returns,
    departs and returns again yields four events that join with no "most recent open departure"
    guesswork. `absentForDays` is whole days, floored. `device_meta`'s `eventID` is the asymmetry and
    only a Mac has one — a returning Mac was really read, so there is a pull to name, while an
    object's return coincides with a census of every object rather than a pull of that one."""
    run = get_run()
    return _delivered(
        {
            "subjectKind": row.subject_kind,
            "subjectLabel": label,
            "departedAt": row.departed_at.isoformat(),
            "occurredAt": occurred_at.isoformat(),
            "absentForDays": (occurred_at - row.departed_at).days,
            "matchedBy": matched_by,
            "priorJamfProID": prior_jamf_pro_id,
            "event": RETURNED_EVENT_TYPE,
            "jobID": str(run.id) if run else None,
            "deviceMeta": device_meta,
        },
        occurred_at=occurred_at,
        host=host,
        source=source,
    )


def _delivered(body: dict[str, object | None], *, occurred_at: datetime, host: str | None, source: str | None) -> dict:
    """Nulls dropped, then the envelope — the one rule `_event_payload` applies (#308). `host`
    is absent for an object, as it is for a `computer_group` change: "Sonoma 14.6 rollout"
    shipped as a host would invent Macs and corrupt every `dc(host)` in the index. `time` is
    `event_time(occurredAt)`, the one back-dating rule, so a sweep's departures sit at its window."""
    payload = {key: value for key, value in body.items() if value is not None}
    payload[ENVELOPE] = envelope(occurred_at=event_time(occurred_at), host=host, source=source)
    return payload


def _object_device_meta(subject_id: str) -> dict[str, object]:
    """#189's block, degrading by subject kind exactly as `_change_device_meta` degrades it:
    an object takes the run half plus `jamfProID` — its own id — plus `schemaVersion`, and no
    `hostName` or `serialNumber`, because an absent identity is recoverable where an invented
    one is not. No `eventID` on either of its two events (4.2): a census of all is not a pull of one."""
    meta = {**run_meta(), "jamfProID": subject_id, "schemaVersion": WIRE_SCHEMA_VERSION}
    return {key: value for key, value in meta.items() if value is not None}


def _mac_device_meta(device: Device | None, *, subject_id: str, pulled: bool) -> dict[str, object]:
    """A Mac's WHOLE block as the `Device` row last knew it (4.2), from the one builder the inventory family uses,
    so a departure and that Mac's last `device.inventory` cannot disagree about eleven keys. Imported at call time:
    `mdm.service` imports this module. `eventID` names a pull, so a departure drops it and a return keeps it; a Mac
    with no `Device` row takes the object block."""
    if device is None:
        return _object_device_meta(subject_id)
    from app.mdm.service import _device_meta

    meta = _device_meta(device)
    if not pulled:
        meta.pop("eventID", None)
    return meta


async def _devices(db: AsyncSession, connection_id: int, ids: Sequence[str]) -> dict[str, Device]:
    """`external_id -> Device` for the Macs about to be named — one read per BATCH, not per Mac and not
    per pass: every caller is inside `_batches`, so `ids` is at most `_EMIT_BATCH` long and this `IN (...)`
    cannot reach asyncpg's bind cap however many Macs one deletion departed (#513)."""
    rows = await db.execute(select(Device).where(Device.mdm_connection_id == connection_id, Device.external_id.in_(ids)))
    return {device.external_id: device for device in rows.scalars().all()}


async def _current_spans(db: AsyncSession, connection_id: int, kind: str, ids: list[str]) -> dict[str, tuple]:
    """`subject_id -> (label, last_observed_at)` from the subject's own current span, which is
    where its name and its last sighting are. A departed subject still has one: absence opens
    and closes no span (#135 rider 4)."""
    rows = await db.execute(
        select(ObservationSpan.subject_id, ObservationSpan.label, ObservationSpan.last_observed_at).where(
            ObservationSpan.mdm_connection_id == connection_id,
            ObservationSpan.subject_kind == kind,
            ObservationSpan.is_current.is_(True),
            ObservationSpan.subject_id.in_(ids),
        )
    )
    return {subject_id: (label, seen) for subject_id, label, seen in rows.all()}


async def _device_count(db: AsyncSession, connection_id: int, kind: str, subject_id: str) -> int | None:
    """**LoonInspect's last count of the Macs carrying this subject, not Jamf's**, which cannot
    be asked once the subject is gone. None for a kind with no such count, which drops the key
    rather than shipping a zero that would read as "no Macs"."""
    if kind == SUBJECT_COMPUTER_GROUP:
        return await _group_device_count(db, connection_id, subject_id)
    if kind == SUBJECT_EXTENSION_ATTRIBUTE_DEFINITION:
        return await _definition_device_count(db, connection_id, subject_id)
    return None


async def _group_device_count(db: AsyncSession, connection_id: int, subject_id: str) -> int:
    """Three reads through the ledger, the only place membership is held, and only the last two
    are GIN-served — said plainly because the cheapness claim is load-bearing: (1) the
    group-membership ENTRIES naming this group, which narrows on the b-tree over
    `observation_entries.kind` and then filters `body->>'groupId'` with **no index on that
    expression**, so it scans the tenant's membership entries; (2) the sections holding one of
    those digests (`ix_observation_sections_entry_digests`); (3) the current computer spans whose
    section map contains one of those section digests (`ix_observation_spans_section_digests`,
    `jsonb_path_ops`). Content addressing is what keeps the last two cheap — one section digest
    covers every Mac with the same membership set, so the OR is bounded by distinct membership
    sets carrying this group, not by the fleet — and hop (1) is bounded by distinct memberships
    too, not by devices. It has never been measured against a fleet-sized ledger; it runs once
    per departed group, which is what makes that acceptable rather than a per-device read."""
    found = await db.execute(
        select(ObservationEntry.digest).where(
            ObservationEntry.kind == _MEMBERSHIP_ENTRY, ObservationEntry.body["groupId"].astext == subject_id
        )
    )
    entries = found.scalars().all()
    if not entries:
        return 0
    found = await db.execute(
        select(ObservationSection.digest).where(
            ObservationSection.section == _MEMBERSHIPS, ObservationSection.entry_digests.has_any(array(tuple(entries)))
        )
    )
    sections = found.scalars().all()
    if not sections:
        return 0
    carries = [ObservationSpan.section_digests.op("@>")(func.jsonb_build_object(_MEMBERSHIPS, digest)) for digest in sections]
    counted = await db.execute(
        select(func.count())
        .select_from(ObservationSpan)
        .where(
            ObservationSpan.mdm_connection_id == connection_id,
            ObservationSpan.subject_kind == SUBJECT_COMPUTER,
            ObservationSpan.is_current.is_(True),
            or_(*carries),
        )
    )
    return counted.scalar_one()


async def _definition_device_count(db: AsyncSession, connection_id: int, subject_id: str) -> int:
    """One indexed COUNT over the per-device extension-attribute rows (4.4) — distinct devices,
    joined to `devices` so the count is scoped to the connection whose census departed the
    definition: two Jamf Pros number their definitions independently."""
    counted = await db.execute(
        select(func.count(func.distinct(DeviceExtensionAttribute.device_id)))
        .join(Device, Device.id == DeviceExtensionAttribute.device_id)
        .where(DeviceExtensionAttribute.definition_id == subject_id, Device.mdm_connection_id == connection_id)
    )
    return counted.scalar_one()
