"""Import retained source receipts into device history, with no collection or AI work (#605).

Run once after upgrading: `python -m app.observations.history_import`. The source receipt
must fit a recorded span's collection window and its device clock. Uncorrelated events are
skipped. No live corpus is consulted. The command is idempotent and commits in small batches.
"""

import asyncio
from datetime import datetime

from sqlalchemy import select, tuple_

from app.core.database import session_for_tenant
from app.core.tenant_jobs import operational_tenant_ids
from app.models.schema import Device, EventOutbox, InventorySummaryJob, InventorySummaryState, ObservationSpan
from app.observations.history_capture import capture_at, retain_summary
from app.summaries.evidence import digest


async def import_retained(db):
    cursor = None
    imported = skipped = 0
    while True:
        query = select(EventOutbox).where(EventOutbox.event_type == "device.inventory")
        if cursor:
            query = query.where(tuple_(EventOutbox.created_at, EventOutbox.id) > tuple_(*cursor))
        events = (await db.scalars(query.order_by(EventOutbox.created_at, EventOutbox.id).limit(100))).all()
        if not events:
            break
        for event in events:
            cursor = (event.created_at, event.id)
            meta = event.payload.get("deviceMeta", {})
            try:
                observed = datetime.fromisoformat(meta["lastReportDate"].replace("Z", "+00:00"))
                connection_id, subject_id = int(meta["connectionID"]), str(meta["jamfProID"])
                if observed.tzinfo is None:
                    raise ValueError("timezone")
            except (KeyError, ValueError, TypeError, AttributeError):
                skipped += 1
                continue
            device = await db.scalar(
                select(Device).where(Device.mdm_connection_id == connection_id, Device.external_id == subject_id)
            )
            span = await db.scalar(
                select(ObservationSpan)
                .where(
                    ObservationSpan.mdm_connection_id == connection_id,
                    ObservationSpan.subject_kind == "computer",
                    ObservationSpan.subject_id == subject_id,
                    ObservationSpan.first_collected_at <= event.created_at,
                )
                .order_by(ObservationSpan.first_collected_at.desc(), ObservationSpan.id.desc())
                .limit(1)
            )
            if not device or not span or not span.first_observed_at <= observed <= span.last_observed_at:
                skipped += 1
                continue
            point = await capture_at(db, device=device, event=event, span=span, observed_at=observed)
            if point is None:
                continue
            imported += 1
            job = await db.scalar(select(InventorySummaryJob).where(InventorySummaryJob.source_id == event.id))
            if job:
                await retain_summary(db, event.id, job.status, job.summary, job.provider, job.reason)
            else:
                state = await db.get(InventorySummaryState, (device.tenant_id, digest([meta["connectionID"], meta["jamfProID"]])))
                if state and state.source_id == event.id:
                    await retain_summary(db, event.id, state.summary_status, state.short_summary)
        await db.commit()
    return {"imported": imported, "uncorrelated": skipped}


async def main():
    for tenant in await operational_tenant_ids():
        async with session_for_tenant(tenant) as db:
            result = await import_retained(db)
            print(result)


if __name__ == "__main__":
    asyncio.run(main())
