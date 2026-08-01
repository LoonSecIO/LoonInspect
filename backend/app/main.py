from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as api_router
from app.api.webhooks import router as webhooks_router
from app.core.config import settings
from app.core.database import init_db

scheduler = AsyncIOScheduler(timezone=settings.sync_timezone)


async def nightly_sync_sweep() -> None:
    # TODO: iterate configured MDM clients and process_sync() any devices missed by webhooks.
    pass


@asynccontextmanager
async def lifespan(app: FastAPI):
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

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
