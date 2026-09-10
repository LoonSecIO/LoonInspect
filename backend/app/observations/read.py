"""What the ledger currently holds for one Mac, by section, with the four-state absence
vocabulary made explicit (#368).

A section is one of four things, and the four must never look alike: **present** (the
current span digests it and it holds something), **empty** (the current span digests it
and the Mac reported nothing — read-and-empty still digests, #93), **not observed** (the
connection's device sweep reads the section now, but this Mac's current observation does
not carry it: no span yet, or a span taken under an older aperture), and **outside the
aperture** (the sweep never reads it — no digest, and the endpoint says why rather than
returning null). The same refusal `vuln.assessment` makes (docs/vulnerabilities.md §4a):
an absent section must never read as an empty one.

The two-hop read — `observation_spans` to `observation_sections` to `observation_entries`
— is the one `app.api.smart_groups` already proves and RLS-tests; no tenant predicate is
written here because row-level security on all three tables is the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.wire_vocabulary import SECTION_WRAPPERS
from app.mdm.jamf.contract import SUBJECT_COMPUTER, SUBJECT_COMPUTER_GROUP, V0_SECTIONS
from app.models.schema import Collection, Device, ObservationAperture, ObservationEntry, ObservationSection, ObservationSpan
from app.observations.departure import open_departures
from app.observations.ledger import current_span

SectionState = Literal["present", "empty", "not_observed", "outside_aperture"]
PRESENT: SectionState = "present"
EMPTY: SectionState = "empty"
NOT_OBSERVED: SectionState = "not_observed"
OUTSIDE_APERTURE: SectionState = "outside_aperture"

_GROUP_MEMBERSHIPS = "group_memberships"
_DEVICE_SWEEP = "device_sweep"


def classify(*, digested: bool, populated: bool, in_sweep: bool) -> SectionState:
    """The one decision, pure so it is pinned: a digest with content is present, a digest
    without is empty, no digest is either not observed (the sweep reads it) or outside
    the aperture (it does not)."""
    if digested:
        return PRESENT if populated else EMPTY
    return NOT_OBSERVED if in_sweep else OUTSIDE_APERTURE


@dataclass(frozen=True)
class ObservedEntry:
    kind: str
    label: str | None
    body: dict


@dataclass(frozen=True)
class SectionObservation:
    name: str
    wrapper: str
    state: SectionState
    body: dict | None = None
    entries: tuple[ObservedEntry, ...] = ()

    @property
    def entry_count(self) -> int:
        return len(self.entries)


@dataclass(frozen=True)
class GroupMembership:
    group_id: str
    name: str | None
    smart: bool | None
    departed_at: datetime | None


@dataclass(frozen=True)
class DeviceObservation:
    device_id: int
    subject_id: str
    observed: bool
    observed_at: datetime | None
    collected_at: datetime | None
    aperture_digest: str | None
    sections: tuple[SectionObservation, ...] = ()
    groups: tuple[GroupMembership, ...] = field(default_factory=tuple)


async def _sweep_sections(db: AsyncSession, connection_id: int) -> set[str]:
    """The sections the connection's device sweep reads now — the enabled `device_sweep`
    collection's list, or the contract's whole set when it names none or does not exist
    yet (the defaults `ensure_default_collections` creates read everything)."""
    rows = (
        (
            await db.execute(
                select(Collection.sections).where(
                    Collection.mdm_connection_id == connection_id,
                    Collection.kind == _DEVICE_SWEEP,
                    Collection.enabled.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    read: set[str] = set()
    for sections in rows:
        read |= set(sections or V0_SECTIONS)
    return read or set(V0_SECTIONS)


async def _section(db: AsyncSession, name: str, digest: str) -> tuple[dict | None, tuple[ObservedEntry, ...]]:
    row = (
        (
            await db.execute(
                select(ObservationSection).where(ObservationSection.digest == digest, ObservationSection.section == name)
            )
        )
        .scalars()
        .first()
    )
    if row is None:
        return None, ()
    if row.entry_digests is None:
        return dict(row.body or {}), ()
    digests = list(row.entry_digests or [])
    if not digests:
        return None, ()
    rows = (await db.execute(select(ObservationEntry).where(ObservationEntry.digest.in_(digests)))).scalars().all()
    by_digest = {e.digest: e for e in rows}
    entries = tuple(
        ObservedEntry(kind=by_digest[d].kind, label=by_digest[d].label, body=dict(by_digest[d].body or {}))
        for d in digests
        if d in by_digest
    )
    return None, entries


async def _groups(db: AsyncSession, connection_id: int, entries: tuple[ObservedEntry, ...]) -> tuple[GroupMembership, ...]:
    """The Mac's smart-group memberships as the ledger holds them, each named from the
    group's own current span where one exists, and marked rather than dropped when the
    group has departed (#181)."""
    ids = [str(e.body.get("groupId")) for e in entries if e.body.get("groupId") is not None]
    if not ids:
        return ()
    labels = dict(
        (
            await db.execute(
                select(ObservationSpan.subject_id, ObservationSpan.label).where(
                    ObservationSpan.mdm_connection_id == connection_id,
                    ObservationSpan.subject_kind == SUBJECT_COMPUTER_GROUP,
                    ObservationSpan.is_current.is_(True),
                    ObservationSpan.subject_id.in_(ids),
                )
            )
        ).all()
    )
    departed = await open_departures(db, subject_kind=SUBJECT_COMPUTER_GROUP)
    out = []
    for entry in entries:
        group_id = entry.body.get("groupId")
        if group_id is None:
            continue
        group_id = str(group_id)
        smart = entry.body.get("smartGroup")
        out.append(
            GroupMembership(
                group_id=group_id,
                name=labels.get(group_id) or entry.label,
                smart=bool(smart) if smart is not None else None,
                departed_at=departed.get((connection_id, group_id)),
            )
        )
    return tuple(out)


async def device_observation(db: AsyncSession, device: Device) -> DeviceObservation:
    """Every section of the wire registry, in registry order, with its state; the groups
    off the `group_memberships` section. A device with no connection or no span is
    observed=False with every readable section `not_observed`."""
    connection_id = device.mdm_connection_id
    span = (
        await current_span(db, connection_id=connection_id, subject_kind=SUBJECT_COMPUTER, subject_id=device.external_id)
        if connection_id is not None
        else None
    )
    in_sweep = await _sweep_sections(db, connection_id) if connection_id is not None else set()
    digests: dict[str, str] = dict(span.section_digests or {}) if span is not None else {}

    sections: list[SectionObservation] = []
    group_entries: tuple[ObservedEntry, ...] = ()
    for name, wrapper in SECTION_WRAPPERS.items():
        digest = digests.get(name)
        body, entries = (await _section(db, name, digest)) if digest else (None, ())
        populated = bool(body) or bool(entries)
        state = classify(digested=digest is not None, populated=populated, in_sweep=name in in_sweep)
        sections.append(
            SectionObservation(
                name=name, wrapper=wrapper, state=state, body=body if state == PRESENT and body else None, entries=entries
            )
        )
        if name == _GROUP_MEMBERSHIPS:
            group_entries = entries

    return DeviceObservation(
        device_id=device.id,
        subject_id=device.external_id,
        observed=span is not None,
        observed_at=span.last_observed_at if span else None,
        collected_at=span.last_collected_at if span else None,
        aperture_digest=span.aperture_digest if span else None,
        sections=tuple(sections),
        groups=await _groups(db, connection_id, group_entries) if connection_id is not None else (),
    )


async def aperture_sections(db: AsyncSession, digest: str) -> list[str]:
    """The sections a recorded aperture read, for a caller that wants the historical
    answer beside the current one."""
    row = (await db.execute(select(ObservationAperture).where(ObservationAperture.digest == digest))).scalars().first()
    return list((row.document or {}).get("sections", [])) if row is not None else []
