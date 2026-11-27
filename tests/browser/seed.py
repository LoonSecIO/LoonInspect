"""Seed the disposable app container with a Mac and an installed catalog build."""

import asyncio

from app.core.tenancy import OPERATIONAL_TENANT_ID
from app.core.tenant_jobs import tenant_job
from app.mdm.jamf.contract import build_aperture
from app.mdm.service import ingest_computer, sync_state
from app.models.schema import MdmConnection
from app.observations.ledger import ensure_aperture


async def seed():
    async with tenant_job(OPERATIONAL_TENANT_ID) as db:
        connection = MdmConnection(name="Browser smoke fixture", provider="jamf", base_url="https://smoke.invalid")
        db.add(connection)
        await db.flush()
        sections = ("general", "hardware", "applications")
        aperture = build_aperture(host="smoke.invalid", jamf_version=None, sections=sections, inventory_collection=None)
        digest = await ensure_aperture(db, connection_id=connection.id, aperture=aperture)
        record = {
            "id": "17",
            "udid": "e190da39-c8a5-439e-93e4-88ab13170017",
            "general": {
                "name": "smoke-mac",
                "reportDate": "2026-08-21T07:15:42Z",
                "remoteManagement": {"managed": True},
            },
            "hardware": {"serialNumber": "SMOKEFIXTURE17"},
            "applications": [{"name": "Smoke Catalog.app", "bundleId": "com.example.smoke", "version": "4.2.1"}],
        }
        await ingest_computer(db, connection, record, aperture_digest=digest, sections=sections, trigger="manual")
        await sync_state(db, connection)
        await db.commit()


asyncio.run(seed())
