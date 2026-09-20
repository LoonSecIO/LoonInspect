"""A bounded, manual Jamf read for one device, through the normal ingestion pipeline."""

import asyncio
from urllib.parse import quote

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.changes.derive import collecting_departures
from app.core.runs import LOCK_DEVICE_REFRESH, TRIGGER_MANUAL, acquire, beat, entered, finish
from app.core.vuln_library import read_tenant_tier
from app.mdm.census import _log_collapsed_departures
from app.mdm.credentials import CredentialUnusable
from app.mdm.factory import get_mdm_client
from app.mdm.service import capture_aperture, ingest_computer, webhook_scope
from app.models.schema import MdmConnection, Run
from app.observations.ledger import ensure_aperture


class DeviceRefreshError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


async def refresh_device(db: AsyncSession, connection: MdmConnection, external_id: str, *, actor_label: str) -> dict:
    """Fetch exactly one computer under the connection's targeted-read aperture.

    The refresh has its own run class, so it cannot advance the full-fleet census or
    last-sweep stamp. One refresh per connection is allowed at a time; a competing
    request is refused rather than claiming another device's refresh as its own.
    """
    acquisition = await acquire(db, connection, trigger=TRIGGER_MANUAL, lock_class=LOCK_DEVICE_REFRESH, actor_label=actor_label)
    if not acquisition.started:
        raise DeviceRefreshError(409, "Another device update is running on this connection. Try again when it finishes.")
    run = acquisition.run
    job_id = run.id
    async with entered(run), collecting_departures() as collapsed:
        try:
            async with asyncio.timeout(60):
                await read_tenant_tier(db)
                sections, quarantine = await webhook_scope(db, connection)
                client = get_mdm_client(connection)
                async with client.http() as http:
                    aperture = await capture_aperture(
                        client, http, sections=sections, quarantined_extension_attributes=quarantine
                    )
                    raw = await client.fetch_computer_detail(http, quote(external_id, safe=""))
                if str(raw.get("id", "")) != external_id:
                    raise DeviceRefreshError(502, "Jamf returned a different computer. No inventory was updated.")
                await beat(db, run)
                aperture_digest = await ensure_aperture(db, connection_id=connection.id, aperture=aperture)
                result = await ingest_computer(
                    db,
                    connection,
                    raw,
                    aperture_digest=aperture_digest,
                    trigger=TRIGGER_MANUAL,
                    sections=sections,
                    quarantined_extension_attributes=quarantine,
                )
                await _log_collapsed_departures(db, run, collapsed)
        except asyncio.CancelledError:
            await db.rollback()
            reloaded = await db.get(Run, job_id)
            if reloaded is not None:
                await finish(
                    db,
                    reloaded,
                    ok=False,
                    device_count=1,
                    devices_failed=1,
                    error="The device update was interrupted. Retry the read.",
                )
            raise
        except Exception as exc:
            if isinstance(exc, DeviceRefreshError):
                error = exc
            elif isinstance(exc, TimeoutError):
                error = DeviceRefreshError(504, "Jamf did not finish the device update within 60 seconds. Try again.")
            elif isinstance(exc, CredentialUnusable):
                error = DeviceRefreshError(409, "The Jamf connection's credentials need attention in Settings › Connections.")
            elif isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 404:
                error = DeviceRefreshError(502, "This computer was not found in Jamf. The saved inventory has been kept.")
            else:
                error = DeviceRefreshError(502, "Could not update this device from Jamf. Check the connection and try again.")
            await db.rollback()
            reloaded = await db.get(Run, job_id)
            if reloaded is not None:
                await finish(db, reloaded, ok=False, device_count=1, devices_failed=1, error=str(error))
            if error is exc:
                raise
            raise error from exc
        await finish(db, run, ok=True, device_count=1, devices_processed=1, observations={result.outcome: 1})
        return {"jobId": str(job_id), "outcome": result.outcome}
