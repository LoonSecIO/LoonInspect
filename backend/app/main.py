from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import select

from app.api.connections import router as connections_router
from app.api.devices import router as devices_router
from app.api.routes import router as api_router
from app.api.webhooks import router as webhooks_router
from app.core.config import settings
from app.core.crypto import validate_encryption_key
from app.core.database import async_session_factory, init_db
from app.mdm.factory import get_mdm_client
from app.mdm.service import process_sync
from app.models.schema import MdmConnection

scheduler = AsyncIOScheduler(timezone=settings.sync_timezone)


async def nightly_sync_sweep() -> None:
    async with async_session_factory() as db:
        result = await db.execute(select(MdmConnection).where(MdmConnection.is_active.is_(True)))
        connections = result.scalars().all()

        for connection in connections:
            try:
                client = get_mdm_client(connection)
                devices = await client.fetch_devices()
            except NotImplementedError:
                continue

            for device in devices:
                await process_sync(db, device, connection)


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_encryption_key()
    await init_db()

    if settings.scheduler_enabled:
        scheduler.add_job(
            nightly_sync_sweep,
            CronTrigger(hour=settings.sync_hour, minute=settings.sync_minute),
            id="nightly_sync_sweep",
            replace_existing=True,
        )
        scheduler.start()

    yield

    if scheduler.running:
        scheduler.shutdown()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(webhooks_router)
app.include_router(connections_router)
app.include_router(devices_router)

static_dir = Path(__file__).parent / "static"

if static_dir.exists():
    # Catch-all so client-side routes (e.g. /devices) resolve to the SPA shell on a
    # direct navigation/refresh, not a 404 — real static assets are served as-is.
    # Unmatched /api or /webhooks paths still 404 instead of silently returning HTML.
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str) -> FileResponse:
        if full_path.startswith("api/") or full_path.startswith("webhooks/"):
            raise HTTPException(status_code=404, detail="Not Found")

        candidate = static_dir / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(static_dir / "index.html")
