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

**Only the object half is built.** The Mac's seven-day tail — `noticeDay` 1..7 and the
guaranteed terminal `state: removed` (4.5) — lands with the follow-up on #183's device
census; `_returned_body`'s `matched_by`, `prior_jamf_pro_id` and `event_id` are arguments
rather than constants so that half adds a caller, not a second shape.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, or_, select
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
from app.observations.departure import CensusVerdict
from app.schemas.payload import WIRE_SCHEMA_VERSION

# `departed` is where every subject starts; `removed` is the Mac tail's guaranteed close (4.5),
# named here so the second half invents neither spelling. An object departs once and is noticed
# once — the seven-day grace is a Mac's — but `noticeDay` still ships, so `stats by noticeDay`
# has no null bucket that silently means "an object". `jamfProID` is the only key an object's
# return can match on; `serialNumber` with `priorJamfProID` is the Mac's re-enrol case (R3/3).
STATE_DEPARTED = "departed"
STATE_REMOVED = "removed"
OBJECT_NOTICE_DAY = 1
MATCHED_BY_ID = "jamfProID"

_MEMBERSHIPS = "group_memberships"
_MEMBERSHIP_ENTRY = "group_membership"


async def emit_census_events(db: AsyncSession, *, connection: MdmConnection, verdict: CensusVerdict, at: datetime) -> int:
    """One event per row this census moved. Enqueues into the caller's session; commits nothing."""
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
        )
        await enqueue_event(db, DEPARTURE_EVENT_TYPE, body, request_id=get_request_id())
    for row in verdict.returned:
        label, _seen = spans.get(row.subject_id, (None, None))
        body = _returned_body(row, label=label, occurred_at=at, source=source)
        await enqueue_event(db, RETURNED_EVENT_TYPE, body, request_id=get_request_id())
    return len(moved)


def _departure_body(
    row: SubjectDeparture,
    *,
    label: str | None,
    last_seen_at: datetime | None,
    device_count: int | None,
    occurred_at: datetime,
    source: str | None,
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
            "deviceMeta": _departure_device_meta(row.subject_id, event_id=None),
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
    host: str | None = None,
    matched_by: str = MATCHED_BY_ID,
    prior_jamf_pro_id: str | None = None,
    event_id: str | None = None,
) -> dict:
    """4.6's body: the departure it closes, named exactly, so a subject that departs, returns,
    departs and returns again yields four events that join with no "most recent open departure"
    guesswork. `absentForDays` is whole days, floored. `event_id` is the ruled asymmetry and
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
            "deviceMeta": _departure_device_meta(row.subject_id, event_id=event_id),
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


def _departure_device_meta(subject_id: str, *, event_id: str | None) -> dict[str, object]:
    """#189's block, degrading by subject kind exactly as `_change_device_meta` degrades it:
    an object takes the run half plus `jamfProID` — its own id — plus `schemaVersion`, and no
    `hostName` or `serialNumber`, because an absent identity is recoverable where an invented
    one is not. `eventID` is None on every departure (4.2)."""
    meta = {**run_meta(), "eventID": event_id, "jamfProID": subject_id, "schemaVersion": WIRE_SCHEMA_VERSION}
    return {key: value for key, value in meta.items() if value is not None}


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
