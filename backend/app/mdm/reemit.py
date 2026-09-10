"""The re-emit (#356): an operator-triggered run that emits the current `device.inventory`
snapshot for every device on a connection regardless of delta — the baseline's emission
with the ledger's current state, and no Jamf pull.

The redrive (#91) re-sends events that still exist. It does nothing for the second half
of an outage: an event that dead-lettered, got purged, and whose device has not changed
since will never be produced again, because `Run.comparison` is `delta` forever after
the baseline and an unchanged device never re-emits. For a stable fleet that is never.
This is the path that closes it.

What one is, per the ruling of 2026-09-10:

- Its own lock class (`LOCK_RE_EMIT`). It reads committed ledger state and never touches
  Jamf, so it runs beside sweeps instead of holding them off for hours at the 40k target.
- `run.completed` carries `comparison: "re-emit"`, an additive value under the #229
  procedure (docs/runs.md §4).
- Reachable without a redrive first: after a purge there may be nothing left to redrive.
- Scoped to a connection (the operator's unit), optionally to one destination
  (`EventOutbox.only_destination_id`), so a re-emit for the destination that was down
  does not re-send to the ones that were not.
- Honest about volume: one snapshot per device, ~30 KB each; the button says so, and
  #213's tick ceiling paces delivery.

The events carry the re-emit run's own `jobID` and a fresh `deviceMeta.eventID`, so in
SPL they are not duplicates of the lost ones — they are a newer observation, which is
correct and is why the dedup story is the redrive's (docs/splunk-setup.md §7).

Each device's snapshot is rebuilt from what the ledger holds: the current span's section
digests, the sections' stored bodies and entries, the current installed-app rows (for the
Jamf Patch answer and the content keys), and the extension-attribute projection. A device
with no current observation is skipped and counted, never invented.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import get_request_id
from app.core.outbox import enqueue_event
from app.core.runs import RunReclaimed, beat, event_time
from app.core.runs import log as run_log
from app.core.vuln import loaded_corpus
from app.core.wire import ENVELOPE, envelope, instance_label
from app.mdm.jamf.contract import SECTIONS, SUBJECT_COMPUTER, Entry, Observation, SectionContent
from app.mdm.patch.matching import cached_title_names
from app.mdm.service import _device_meta
from app.mdm.snapshot import build_inventory_snapshot
from app.models.schema import (
    Device,
    DeviceExtensionAttribute,
    InstalledApp,
    MdmConnection,
    ObservationEntry,
    ObservationSection,
    Run,
)
from app.observations.ledger import current_span
from app.schemas.payload import NormalizedExtensionAttribute

logger = logging.getLogger(__name__)

# Commit, heartbeat and log every this many devices: the log is what someone watching
# run-now reads, and a heartbeat per device would be a write per device for nothing.
_BATCH = 200
_EXTENSION_ATTRIBUTES = "extension_attributes"


@dataclass(frozen=True)
class ReEmitResult:
    device_count: int
    devices_processed: int
    devices_skipped: int
    devices_failed: int
    destination_id: int | None


async def observation_from_ledger(db: AsyncSession, *, connection_id: int, device: Device) -> Observation | None:
    """The device's current observation, rebuilt from the ledger — or None when the ledger
    has never recorded one for it.

    Exactly the sections the current span carries ride, in the contract's own shapes, so
    the aperture carve-out holds on a re-emit as it does on a sweep: a section outside
    the read is absent, never asserted empty.
    """
    span = await current_span(db, connection_id=connection_id, subject_kind=SUBJECT_COMPUTER, subject_id=device.external_id)
    if span is None:
        return None
    sections: dict[str, SectionContent] = {}
    for name, digest in sorted((span.section_digests or {}).items()):
        spec = SECTIONS.get(name)
        if spec is None:
            continue
        row = (await db.execute(select(ObservationSection).where(ObservationSection.digest == digest))).scalars().first()
        if row is None:
            continue
        if spec.is_list:
            digests = list(row.entry_digests or [])
            entries: list[Entry] = []
            if digests:
                rows = (await db.execute(select(ObservationEntry).where(ObservationEntry.digest.in_(digests)))).scalars().all()
                entries = [Entry(kind=spec.entry_kind or name, digest=e.digest, body=e.body, label=e.label) for e in rows]
            sections[name] = SectionContent(
                name=name, digest=digest, body=None, entries=tuple(sorted(entries, key=lambda e: e.digest))
            )
        else:
            sections[name] = SectionContent(name=name, digest=digest, body=dict(row.body or {}))
    return Observation(
        subject_kind=SUBJECT_COMPUTER,
        subject_id=device.external_id,
        sections=sections,
        observed_at=span.last_observed_at,
        udid=span.udid,
        serial_number=span.serial_number,
        management_id=span.management_id,
        label=span.label,
    )


def _extension_attributes(rows: list[DeviceExtensionAttribute]) -> list[NormalizedExtensionAttribute]:
    """The `ea` items, from the projection #197 keeps: what the device page shows. The
    four definition fields a live pull carries off Jamf's object (description, multiValue,
    dataType, options) are not stored anywhere, so a re-emitted item carries what is —
    definitionId, name, values, source, enabled — and says nothing for the rest."""
    return [
        NormalizedExtensionAttribute(
            definition_id=row.definition_id,
            name=row.name,
            values=list(row.values or []),
            source=row.source,
            enabled=row.enabled,
        )
        for row in rows
    ]


async def re_emit_connection(
    db: AsyncSession,
    connection: MdmConnection,
    *,
    run: Run,
    destination_id: int | None = None,
) -> ReEmitResult:
    """Enqueue the current snapshot of every device on `connection`, under `run`.

    Commits per batch, so a re-emit of a large fleet is visible in the outbox while it is
    still enqueueing rather than landing as one transaction hours later; the run's
    heartbeat rides the same cadence, and a reclaim mid-flight stops the loop (`beat`
    raises `RunReclaimed`), which propagates — the caller closes nothing over a verdict
    the reclaim already wrote.
    """
    device_ids = [
        row[0]
        for row in (
            await db.execute(select(Device.id).where(Device.mdm_connection_id == connection.id).order_by(Device.id))
        ).all()
    ]
    await run_log(
        db, run, "info", "re-emit started", devices=len(device_ids), destinationID=destination_id, comparison=run.comparison
    )
    corpus = loaded_corpus()
    title_names = cached_title_names()
    source = instance_label(connection.base_url)
    processed = skipped = failed = 0

    for index, device_id in enumerate(device_ids, start=1):
        device = await db.get(Device, device_id)
        if device is None:
            skipped += 1
            continue
        try:
            observation = await observation_from_ledger(db, connection_id=connection.id, device=device)
            if observation is None:
                skipped += 1
                continue
            apps = (await db.execute(select(InstalledApp).where(InstalledApp.device_id == device.id))).scalars().all()
            eas = None
            if _EXTENSION_ATTRIBUTES in observation.sections:
                rows = (
                    (await db.execute(select(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id == device.id)))
                    .scalars()
                    .all()
                )
                eas = _extension_attributes(list(rows))
            # A manual run stamps now (app.core.runs.event_time): this is a re-emit, and
            # what it emits is a newer observation than the one that was lost.
            occurred_at = event_time(device.last_inventory_at)
            snapshot = build_inventory_snapshot(
                observation,
                extension_attributes=eas,
                apps=apps,
                occurred_at=occurred_at,
                device_meta=_device_meta(device),
                corpus=corpus,
                title_names=title_names,
            )
            payload = snapshot.to_payload()
            payload[ENVELOPE] = dict(envelope(occurred_at=occurred_at, host=device.hostname, source=source))
            await enqueue_event(db, snapshot.event, payload, request_id=get_request_id(), only_destination_id=destination_id)
            processed += 1
        except RunReclaimed:
            raise
        except Exception:
            failed += 1
            logger.exception("re-emit: device skipped", extra={"device_id": device_id, "run_id": str(run.id)})
        if index % _BATCH == 0:
            await db.commit()
            await beat(db, run)
            await run_log(
                db, run, "info", "re-emit progress", enqueued=processed, skipped=skipped, failed=failed, of=len(device_ids)
            )

    await db.commit()
    await run_log(db, run, "info", "re-emit finished", enqueued=processed, skipped=skipped, failed=failed, of=len(device_ids))
    return ReEmitResult(
        device_count=len(device_ids),
        devices_processed=processed,
        devices_skipped=skipped,
        devices_failed=failed,
        destination_id=destination_id,
    )
