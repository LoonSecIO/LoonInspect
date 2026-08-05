from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sqlalchemy import delete, or_, select, update

from app.api.accounts import router as accounts_router
from app.api.applications import router as applications_router
from app.api.auth import router as auth_router
from app.api.connections import router as connections_router
from app.api.destinations import router as destinations_router
from app.api.devices import router as devices_router
from app.api.feature_flags import router as feature_flags_router
from app.api.jamf_patch import router as jamf_patch_router
from app.api.routes import router as api_router
from app.api.tokens import router as tokens_router
from app.api.webhooks import router as webhooks_router
from app.core.audit import configure_audit_logging
from app.core.auth import authenticate
from app.core.bootstrap import bootstrap_accounts, migrate_legacy_siem_webhook
from app.core.config import settings
from app.core.context import SYSTEM, reset_actor, set_actor
from app.core.crypto import validate_encryption_key
from app.core.database import async_session_factory, init_db
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware
from app.core.outbox import deliver_pending, fan_out_pending, purge_delivered_events
from app.mdm.patch.jamf_catalog import sync_catalog
from app.mdm.service import sync_connection
from app.models.schema import MdmConnection, MdmSyncState, UserSession
from app.schemas.payload import SyncStatus

# Before anything else in the process emits a line, so migration output and startup
# failures are formatted the same way as request logs rather than escaping as plain
# text from whatever logger got there first.
configure_logging()

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone=settings.sync_timezone)


async def nightly_sync_sweep() -> None:
    # Scheduler jobs have no requesting user, so they run as the system actor rather
    # than falling through to anonymous.
    actor_token = set_actor(SYSTEM)
    try:
        async with async_session_factory() as db:
            result = await db.execute(select(MdmConnection).where(MdmConnection.is_active.is_(True)))
            connections = result.scalars().all()

            logger.info("sync sweep started", extra={"connection_count": len(connections)})

            results = [await sync_connection(db, connection) for connection in connections]
            failed = [result for result in results if not result.ok]

            # One bad credential no longer takes the run down — sync_connection absorbs
            # per-connection failures so every remaining connection still gets swept.
            logger.info(
                "sync sweep finished",
                extra={
                    "connections": len(results),
                    "succeeded": sum(1 for r in results if r.ok and not r.skipped),
                    "skipped": sum(1 for r in results if r.skipped),
                    "failed": len(failed),
                    "devices": sum(r.device_count for r in results),
                },
            )

            if failed:
                logger.warning(
                    "some connections failed to sync",
                    extra={"connection_ids": [r.connection_id for r in failed]},
                )
    finally:
        reset_actor(actor_token)


async def hourly_jamf_patch_sync() -> None:
    actor_token = set_actor(SYSTEM)
    try:
        async with async_session_factory() as db:
            await sync_catalog(db)
        logger.info("jamf patch catalog synced")
    finally:
        reset_actor(actor_token)


async def hourly_session_cleanup() -> None:
    """Expired and revoked sessions are dead weight once they're past use — without
    this the table grows for the life of the deployment."""
    actor_token = set_actor(SYSTEM)
    try:
        # A day's grace after expiry, so a session row still exists long enough to be
        # useful when investigating "I was logged out, what happened?".
        cutoff = datetime.now(timezone.utc) - timedelta(days=1)
        async with async_session_factory() as db:
            result = await db.execute(
                delete(UserSession).where(
                    or_(
                        UserSession.expires_at < cutoff,
                        UserSession.revoked_at < cutoff,
                    )
                )
            )
            await db.commit()

        if result.rowcount:
            logger.info("stale sessions purged", extra={"count": result.rowcount})
    finally:
        reset_actor(actor_token)


async def outbox_worker_tick() -> None:
    """Fan out newly-produced events to subscribed destinations, then attempt every
    delivery that's due. Runs frequently and independently of every sync job — that
    decoupling is the entire point: a slow or dead destination here can never slow
    down a device sync, and (once it exists) can never delay an inbound webhook's ACK
    to its sender.
    """
    actor_token = set_actor(SYSTEM)
    try:
        async with async_session_factory() as db:
            await fan_out_pending(db)
            await deliver_pending(db)
    finally:
        reset_actor(actor_token)


async def outbox_cleanup() -> None:
    """Purges outbox events whose deliveries are all terminal and past retention.
    Without this the table grows without bound once events are continuous rather than
    nightly-batched."""
    actor_token = set_actor(SYSTEM)
    try:
        async with async_session_factory() as db:
            purged = await purge_delivered_events(db, settings.event_outbox_retention_days)
        if purged:
            logger.info("purged old outbox events", extra={"count": purged})
    finally:
        reset_actor(actor_token)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Deliberately called again here, not just at import. fastapi-cli imports this
    # module to resolve the app object *before* uvicorn applies its own dictConfig,
    # so the import-time call gets overwritten and uvicorn's loggers come back with
    # their own handlers and propagate=False. Re-running once uvicorn has finished
    # setting up reclaims them. Idempotent by design.
    configure_logging()
    configure_audit_logging()

    logger.info(
        "starting",
        extra={
            "app": settings.app_name,
            "debug": settings.debug,
            # Dialect only. A non-SQLite DATABASE_URL carries a password, and startup
            # banners are exactly where connection strings get copied out of.
            "database_dialect": settings.database_url.split("://", 1)[0],
            "log_format": settings.resolved_log_format,
            "scheduler_enabled": settings.scheduler_enabled,
            "siem_webhook_configured": bool(settings.siem_webhook_url),
        },
    )

    validate_encryption_key()
    await init_db()
    logger.info("database ready, migrations applied")

    async with async_session_factory() as db:
        await bootstrap_accounts(db)
        await migrate_legacy_siem_webhook(db)

        # A process that died mid-sync leaves its connection marked 'syncing', and the
        # manual trigger refuses to start while one is in flight — so without this the
        # only recovery from a crash or a restart is editing the database by hand.
        stuck = await db.execute(
            update(MdmSyncState)
            .where(MdmSyncState.status == SyncStatus.syncing.value)
            .values(status=SyncStatus.failed.value)
        )
        await db.commit()
        if stuck.rowcount:
            logger.warning(
                "reset connections left mid-sync by a previous run",
                extra={"count": stuck.rowcount},
            )

    if settings.scheduler_enabled:
        scheduler.add_job(
            nightly_sync_sweep,
            CronTrigger(hour=settings.sync_hour, minute=settings.sync_minute),
            id="nightly_sync_sweep",
            replace_existing=True,
        )
        scheduler.add_job(
            hourly_jamf_patch_sync,
            CronTrigger(minute=0),
            id="hourly_jamf_patch_sync",
            replace_existing=True,
        )
        scheduler.add_job(
            hourly_session_cleanup,
            CronTrigger(minute=30),
            id="hourly_session_cleanup",
            replace_existing=True,
        )
        scheduler.add_job(
            outbox_worker_tick,
            IntervalTrigger(seconds=30),
            id="outbox_worker_tick",
            # APScheduler's default max_instances=1 per job already prevents a tick
            # from overlapping a still-running one; nothing here relies on that as
            # anything more than "don't double-attempt the same delivery."
            replace_existing=True,
        )
        scheduler.add_job(
            outbox_cleanup,
            CronTrigger(hour=2, minute=45),
            id="outbox_cleanup",
            replace_existing=True,
        )
        scheduler.start()
        logger.info(
            "scheduler started",
            extra={
                "jobs": [job.id for job in scheduler.get_jobs()],
                "timezone": settings.sync_timezone,
            },
        )

    yield

    if scheduler.running:
        scheduler.shutdown()
        logger.info("scheduler stopped")

    logger.info("shutdown complete")


# The global dependency is what makes this default-deny: it runs for every route on
# the app, so a router added later is protected the moment it's mounted. Opening a
# route up means editing the allowlist in app.core.auth, which is a visible diff.
app = FastAPI(
    title=settings.app_name,
    lifespan=lifespan,
    dependencies=[Depends(authenticate)],
    # FastAPI mounts its built-in docs as plain Starlette routes, which route-level
    # dependencies never run for — so the default-deny above would silently not cover
    # them, leaving the full API surface readable by anyone who can reach the port.
    # Disabled here and re-registered below as real API routes instead.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registered last so it ends up outermost — Starlette prepends each added middleware,
# so this wraps CORS and sees every request, including preflights and anything an
# inner layer rejects before a route matches.
app.add_middleware(RequestContextMiddleware)

app.include_router(auth_router)
app.include_router(accounts_router)
app.include_router(tokens_router)
app.include_router(api_router)
app.include_router(webhooks_router)
app.include_router(connections_router)
app.include_router(destinations_router)
app.include_router(devices_router)
app.include_router(applications_router)
app.include_router(jamf_patch_router)
app.include_router(feature_flags_router)

@app.get("/openapi.json", include_in_schema=False)
async def openapi_schema() -> JSONResponse:
    return JSONResponse(app.openapi())


@app.get("/docs", include_in_schema=False)
async def swagger_ui() -> HTMLResponse:
    return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{settings.app_name} API")


@app.get("/redoc", include_in_schema=False)
async def redoc_ui() -> HTMLResponse:
    return get_redoc_html(openapi_url="/openapi.json", title=f"{settings.app_name} API")


static_dir = Path(__file__).parent / "static"


def _resolve_static_asset(full_path: str) -> Path | None:
    """Resolve a request path to a file inside static_dir, or None.

    The containment check is the whole point. `static_dir / full_path` happily escapes
    the directory when full_path contains `..` (or is absolute, since that discards the
    left operand entirely), which turns this route into an unauthenticated read of any
    file the process can open — including the SQLite database and the audit log. The
    path is resolved first so `..` segments and symlinks are collapsed before the
    comparison, rather than pattern-matching on the raw string.
    """
    if not full_path:
        return None

    root = static_dir.resolve()
    candidate = (root / full_path).resolve()

    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None

    return candidate


if static_dir.exists():
    # Catch-all so client-side routes (e.g. /devices) resolve to the SPA shell on a
    # direct navigation/refresh, not a 404 — real static assets are served as-is.
    # Unmatched /api or /webhooks paths still 404 instead of silently returning HTML.
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str) -> FileResponse:
        if full_path.startswith("api/") or full_path.startswith("webhooks/"):
            raise HTTPException(status_code=404, detail="Not Found")

        asset = _resolve_static_asset(full_path)
        if asset is not None:
            return FileResponse(asset)

        # Anything else is a client-side route; the SPA shell resolves it. A traversal
        # attempt lands here too, and gets the same harmless HTML as a typo.
        return FileResponse(static_dir / "index.html")
