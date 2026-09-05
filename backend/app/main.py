from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.alerts.service import purge_closed_alerts
from app.api.accounts import router as accounts_router
from app.api.ai import router as ai_router
from app.api.alerts import router as alerts_router
from app.api.applications import router as applications_router
from app.api.auth import router as auth_router
from app.api.catalog import router as catalog_router
from app.api.changes import router as changes_router
from app.api.collections import router as collections_router
from app.api.connections import router as connections_router
from app.api.destinations import router as destinations_router
from app.api.devices import router as devices_router
from app.api.feature_flags import router as feature_flags_router
from app.api.jamf_patch import router as jamf_patch_router
from app.api.routes import router as api_router
from app.api.runs import router as runs_router
from app.api.smart_groups import router as smart_groups_router
from app.api.system import router as system_router
from app.api.tokens import router as tokens_router
from app.api.webhooks import router as webhooks_router
from app.catalog.index import rebuild_index
from app.catalog.service import refresh_tenant
from app.core.audit import configure_audit_logging
from app.core.auth import authenticate
from app.core.bootstrap import bootstrap_accounts, bootstrap_tenants, migrate_legacy_siem_webhook
from app.core.config import settings
from app.core.context import SYSTEM, reset_actor, set_actor, system_actor_for
from app.core.crypto import validate_encryption_key
from app.core.database import init_db, session_for_tenant, unscoped_session
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.core.outbox import deliver_pending, fan_out_pending, purge_delivered_events
from app.core.runs import purge_runs
from app.core.sharing import exchange_due, run_exchange
from app.core.tenancy import OPERATIONAL_TENANT_ID, reset_tenant_id, set_tenant_id
from app.mdm.collections import tick_tenant
from app.mdm.patch.jamf_catalog import sync_catalog
from app.models.schema import Tenant, UserSession

# Before anything else in the process emits a line, so migration output and startup
# failures are formatted the same way as request logs rather than escaping as plain
# text from whatever logger got there first.
configure_logging()

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone=settings.sync_timezone)


async def operational_tenant_ids() -> list[uuid.UUID]:
    """Every tenant a background job has work to do for.

    Scheduler jobs have no request to inherit a tenant from, and row-level security
    gives them no way to sweep all tenants in one query — which is the point, not a
    limitation to work around. They enumerate here and then do one tenant's work per
    session, so a job that forgets to is a job that fails rather than one that
    quietly crosses a boundary.
    """
    async with unscoped_session() as db:
        result = await db.execute(
            select(Tenant.id).where(Tenant.kind == "operational").order_by(Tenant.slug)
        )
        return list(result.scalars().all())


@asynccontextmanager
async def tenant_job(tenant_id: uuid.UUID) -> AsyncGenerator[AsyncSession, None]:
    """One tenant's slice of a scheduler job.

    Establishes both halves of the job's identity: the system actor, since there is no
    requesting user to attribute the work to, and the tenant, which the session then
    pushes into the Postgres GUC that every RLS policy reads.
    """
    actor_token = set_actor(system_actor_for(tenant_id))
    tenant_token = set_tenant_id(tenant_id)
    try:
        async with session_for_tenant(tenant_id) as db:
            yield db
    finally:
        reset_tenant_id(tenant_token)
        reset_actor(actor_token)


async def collections_tick() -> None:
    """The minute tick that replaced the single nightly cron (#27, docs/ingest-scheduling.md
    §5): ask the database which collections are due, claim each with a conditional
    UPDATE, run it. Schedule changes are ordinary row writes; no live scheduler state,
    identical behaviour on one process or six. Runs sequentially within a tick, and
    APScheduler's max_instances=1 keeps ticks from overlapping, so a long sweep simply
    delays the next tick rather than doubling up.
    """
    for tenant_id in await operational_tenant_ids():
        async with tenant_job(tenant_id) as db:
            try:
                results = await tick_tenant(db)
            except Exception:
                logger.exception("collections tick failed", extra={"tenant_id": str(tenant_id)})
                continue
        if results:
            logger.info(
                "collections tick ran",
                extra={
                    "tenant_id": str(tenant_id),
                    "ran": len(results),
                    "failed": sum(1 for r in results if not r.ok),
                    "devices": sum(r.device_count for r in results),
                },
            )


async def hourly_jamf_patch_sync() -> None:
    # The one job with no tenant: the Jamf patch catalog is the global app corpus,
    # deliberately outside tenancy because it carries no customer data and no
    # per-tenant credentials. An unscoped session can reach it and nothing else.
    actor_token = set_actor(SYSTEM)
    try:
        async with unscoped_session() as db:
            await sync_catalog(db)
            await rebuild_index(db)
        logger.info("jamf patch catalog synced")
        # Then every tenant's app catalog against the catalog that just moved — rows judged
        # against an older catalog are re-judged; a sync that changed nothing costs nothing.
        for tenant_id in await operational_tenant_ids():
            async with session_for_tenant(tenant_id) as db:
                judged = await refresh_tenant(db)
                await db.commit()
            if judged:
                logger.info("app catalog refreshed", extra={"tenant_id": str(tenant_id), "rows": judged})
    finally:
        reset_actor(actor_token)


async def sharing_exchange_tick() -> None:
    """Community data-sharing exchange (docs/data-sharing.md). Runs every five
    minutes but sends at most once per tenant per day, at a minute-of-day derived
    from the tenant's submission UUID — herd prevention without operator-facing
    scheduling. A tick that isn't due touches one settings row and stops."""
    for tenant_id in await operational_tenant_ids():
        async with tenant_job(tenant_id) as db:
            try:
                if await exchange_due(db):
                    await run_exchange(db)
            except Exception:
                # A failure here must never take the scheduler down with it; the
                # share log carries the per-attempt record.
                logger.exception("sharing exchange tick failed", extra={"tenant_id": str(tenant_id)})


async def hourly_session_cleanup() -> None:
    """Expired and revoked sessions are dead weight once they're past use — without
    this the table grows for the life of the deployment."""
    # A day's grace after expiry, so a session row still exists long enough to be
    # useful when investigating "I was logged out, what happened?".
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)

    for tenant_id in await operational_tenant_ids():
        async with tenant_job(tenant_id) as db:
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
                logger.info(
                    "stale sessions purged",
                    extra={"tenant_id": str(tenant_id), "count": result.rowcount},
                )


async def outbox_worker_tick() -> None:
    """Fan out newly-produced events to subscribed destinations, then attempt every
    delivery that's due. Runs frequently and independently of every sync job — that
    decoupling is the entire point: a slow or dead destination here can never slow
    down a device sync, and can never delay an inbound webhook's ACK to its sender.
    """
    # Per tenant, and that is the load-bearing detail. fan_out_pending() is the one
    # place that knows which destinations exist, so it is also the one place a missing
    # tenant predicate would deliver tenant A's device inventory to tenant B's SIEM —
    # silently, outbound, to a third party, with no API request involved. The
    # predicate is the RLS policy on `destinations`, which only applies to a session
    # that named a tenant, which is what this loop does.
    for tenant_id in await operational_tenant_ids():
        async with tenant_job(tenant_id) as db:
            await fan_out_pending(db)
            await deliver_pending(db)


async def outbox_cleanup() -> None:
    """Purges outbox events whose deliveries are all terminal and past retention.
    Without this the table grows without bound now that events are continuous rather
    than nightly-batched."""
    for tenant_id in await operational_tenant_ids():
        async with tenant_job(tenant_id) as db:
            purged = await purge_delivered_events(db, settings.event_outbox_retention_days)
        if purged:
            logger.info(
                "purged old outbox events",
                extra={"tenant_id": str(tenant_id), "count": purged},
            )


async def run_cleanup() -> None:
    """Purges finished runs and their log lines past retention, and closed alerts with
    them.

    Follows `audit_retention_days` rather than the outbox's seven: the run log is what
    someone opens to answer "did this run last month", so a week cannot serve its own
    purpose. Runs alongside the other purges rather than at startup, so a long-lived
    process still prunes.

    Closed alerts ride the same clock and the same setting on purpose. They cannot be
    deleted the moment they close — that would silently redefine the posture key
    `alerts.opened_24h` from "alerts opened in the trailing 24h" to "…that are still
    open" — so without a purge the table would grow for the life of the pod. Giving them
    a retention setting of their own would be one more knob an operator has to have an
    opinion about, for a row that is run history in the same sense a finished run is.
    """
    for tenant_id in await operational_tenant_ids():
        async with tenant_job(tenant_id) as db:
            purged = await purge_runs(db, settings.run_retention_days)
            closed_alerts = await purge_closed_alerts(db, settings.run_retention_days)
        if purged:
            logger.info(
                "purged old runs",
                extra={"tenant_id": str(tenant_id), "count": purged},
            )
        if closed_alerts:
            logger.info(
                "purged closed alerts",
                extra={"tenant_id": str(tenant_id), "count": closed_alerts},
            )


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
            # Dialect only. The DATABASE_URL carries a password now that the
            # database is a separate service, and startup banners are exactly where
            # connection strings get copied out of.
            "database_dialect": settings.database_url.split("://", 1)[0],
            "log_format": settings.resolved_log_format,
            "scheduler_enabled": settings.scheduler_enabled,
            "siem_webhook_configured": bool(settings.siem_webhook_url),
        },
    )

    validate_encryption_key()
    await init_db()
    logger.info("database ready, migrations applied")

    # Before anything else touches the database: every other table's row-level
    # security compares against a tenant id, and these are the rows that make one
    # exist.
    async with unscoped_session() as db:
        await bootstrap_tenants(db)

    # First-run setup is a property of the deployment rather than of a tenant — there
    # is one claim token and one first administrator — so it runs against the single
    # operational tenant rather than the loop below. #30's management surface is what
    # turns this into a per-tenant action.
    async with tenant_job(OPERATIONAL_TENANT_ID) as db:
        await bootstrap_accounts(db)
        await migrate_legacy_siem_webhook(db)

    # The blanket "mark every syncing connection failed" sweep that used to live here is
    # gone (#31). It was correct for exactly one deployment shape — a single process
    # recovering from its own crash — and actively wrong for every other: with a second
    # worker or during a rolling restart, the starting instance failed a run that a
    # healthy instance was still performing, which then carried on writing under a status
    # saying it had died.
    #
    # Recovery is the run's heartbeat instead (app.core.runs). A run whose process
    # stopped beating is reclaimed by the next acquisition — which is a path exercised
    # constantly rather than only at startup, and which cannot mistake a live run on
    # another process for a dead one.

    if settings.scheduler_enabled:
        scheduler.add_job(
            collections_tick,
            IntervalTrigger(minutes=1),
            id="collections_tick",
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
            sharing_exchange_tick,
            IntervalTrigger(minutes=5),
            id="sharing_exchange_tick",
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
        scheduler.add_job(
            run_cleanup,
            CronTrigger(hour=2, minute=50),
            id="run_cleanup",
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

# Registered first so it ends up innermost, closest to the router — it only needs to
# compress what a route actually produced. #172: 964 KB of static payload (a ~500 KB JS
# bundle, ~230 KB of woff/woff2) was going out uncompressed on every load; the default
# `exclude_content_types` already leaves woff/woff2 alone (already-compressed formats),
# so this mainly buys the JS/CSS/HTML. The Vary: Accept-Encoding it adds is also what
# keeps a cache from handing a gzip'd body to a client that never asked for one — a
# free complement to the conditional-GET support added below, not a competing concern.
# Picked over precompressed assets as the smaller, safer change: one line, well-tested
# upstream, no frontend build step or new dependency, and it compresses API JSON
# responses too as a side effect.
app.add_middleware(GZipMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registered last so it ends up outermost — Starlette prepends each added middleware,
# so this wraps CORS and sees every request, including preflights and anything an
# inner layer rejects before a route matches. SecurityHeadersMiddleware is registered
# after this one for the same reason: it must end up outermost of *both*, so the four
# headers (plus a relayed HSTS, #186) land on every response this process sends,
# including a CORS preflight and a 401 from auth.py.
app.add_middleware(RequestContextMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth_router)
app.include_router(accounts_router)
app.include_router(tokens_router)
app.include_router(api_router)
app.include_router(webhooks_router)
app.include_router(connections_router)
app.include_router(collections_router)
app.include_router(runs_router)
app.include_router(changes_router)
app.include_router(alerts_router)
app.include_router(destinations_router)
app.include_router(system_router)
app.include_router(ai_router)
app.include_router(devices_router)
app.include_router(applications_router)
app.include_router(catalog_router)
app.include_router(jamf_patch_router)
app.include_router(smart_groups_router)
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

# Vite's default build.assetsDir: every JS/CSS chunk and imported asset is fingerprinted
# into assets/<name>-<hash>.<ext>, so the filename *is* the cache key — a rebuild ships
# under a new URL and the old one is simply orphaned, never requested again. Anything
# else under static_dir — index.html, and files copied verbatim from frontend/public/
# (favicon.svg, favicon-dark.svg, logos/) — keeps the same URL across a rebuild, so it
# must revalidate every time instead of being cached blindly.
_ASSETS_PREFIX = "assets/"
_IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable"
_NO_CACHE_CACHE_CONTROL = "no-cache"


def _resolve_static_asset(full_path: str) -> Path | None:
    """Resolve a request path to a file inside static_dir, or None.

    The containment check is the whole point. `static_dir / full_path` happily escapes
    the directory when full_path contains `..` (or is absolute, since that discards the
    left operand entirely), which turns this route into an unauthenticated read of any
    file the process can open — the audit log, a mounted TLS key, the container's own
    environment. The path is resolved first so `..` segments and symlinks are collapsed
    before the comparison, rather than pattern-matching on the raw string.
    """
    if not full_path:
        return None

    root = static_dir.resolve()
    candidate = (root / full_path).resolve()

    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None

    return candidate


def _not_modified(etag: str | None, last_modified: str | None, request: Request) -> bool:
    """Mirrors starlette.staticfiles.StaticFiles.is_not_modified — this app has no
    StaticFiles mount to inherit that check from (#170's finding: FileResponse stamps
    ETag/Last-Modified but never looks at the request, so a correct If-None-Match used
    to re-send the full body every time). If-None-Match wins when both are present, per
    RFC 9110 §13.1.1/§13.1.3; a `W/` weak-validator prefix is ignored on either side.
    """
    if_none_match = request.headers.get("if-none-match")
    if etag and if_none_match:
        sent = (tag.strip(" W/") for tag in if_none_match.split(","))
        return etag.strip(" W/") in sent

    if_modified_since = request.headers.get("if-modified-since")
    if last_modified and if_modified_since:
        since = parsedate(if_modified_since)
        modified = parsedate(last_modified)
        if since is not None and modified is not None:
            return since >= modified

    return False


def _static_response(request: Request, path: Path, *, cache_control: str) -> Response:
    """Serve `path` with a deliberate response policy (#172): a validator that
    actually earns a 304, and the Cache-Control the caller decided for this class of
    file. `HEAD` needs no special handling here — `FileResponse.__call__` already
    suppresses the body for a HEAD request once it is registered for the route (see
    the `methods=` on the catch-all below); it is the route registration that was
    missing, not this function.

    `stat_result` is read once, up front, and handed to `FileResponse` explicitly —
    not only to avoid a second stat when `FileResponse.__call__` runs, but because it
    is the only way to actually control the ETag/Last-Modified it stamps.
    `del response.headers["etag"]` after construction is a silent no-op: `__call__`
    re-stats and re-adds the header via `setdefault` whenever `stat_result` is None.
    """
    stat_result = path.stat()
    response = FileResponse(path, stat_result=stat_result, headers={"Cache-Control": cache_control})

    etag = response.headers.get("etag")
    last_modified = response.headers.get("last-modified")
    if _not_modified(etag, last_modified, request):
        not_modified_headers = {"Cache-Control": cache_control}
        if etag:
            not_modified_headers["ETag"] = etag
        if last_modified:
            not_modified_headers["Last-Modified"] = last_modified
        return Response(status_code=304, headers=not_modified_headers)

    return response


if static_dir.exists():
    # Accepted exposure, ruled 2026-08-30 on #170 (closed as documented): every response
    # below still carries a `Last-Modified` of the image build time, because
    # `FileResponse` stamps it from the file's mtime — the CalVer half of the version
    # #130 took off the sign-in page, readable by anyone who can reach the port. Kept,
    # knowingly; nothing in #172 touches that mtime or that trade.
    #
    # What #172 changes is the response *policy* around it, which #170 explicitly left
    # for this issue: the shell now gets `Cache-Control: no-cache`, so a returning
    # browser always revalidates instead of leaning on RFC 9111 heuristic freshness —
    # and revalidation now actually earns a 304 (`_static_response`) instead of
    # re-sending the body every time. A content-hashed asset under assets/ gets
    # `public, max-age=31536000, immutable` instead, because the filename is the cache
    # key and a stale copy is simply never requested again.
    #
    # Catch-all so client-side routes (e.g. /devices) resolve to the SPA shell on a
    # direct navigation/refresh, not a 404 — real static assets are served as-is.
    # Unmatched /api or /webhooks paths still 404. So, now, does a miss under assets/
    # specifically: a stale index.html asking for a bundle this build no longer ships
    # used to get the SPA shell back as 200 text/html, which a `<script type="module">`
    # then silently rejected on MIME grounds — the failure that would have made a bad
    # deploy invisible in an access log full of 200s. A traversal attempt anywhere
    # *else* still gets the same harmless HTML as a typo — main.py's long-standing
    # contract, unchanged outside assets/. GET and HEAD both route here (methods=);
    # FastAPI's own `@app.get` does not register HEAD the way plain Starlette routes do.
    @app.api_route("/{full_path:path}", methods=["GET", "HEAD"])
    async def serve_spa(full_path: str, request: Request) -> Response:
        if full_path.startswith("api/") or full_path.startswith("webhooks/"):
            raise HTTPException(status_code=404, detail="Not Found")

        asset = _resolve_static_asset(full_path)
        if asset is not None:
            cache_control = _IMMUTABLE_CACHE_CONTROL if full_path.startswith(_ASSETS_PREFIX) else _NO_CACHE_CACHE_CONTROL
            return _static_response(request, asset, cache_control=cache_control)

        if full_path.startswith(_ASSETS_PREFIX):
            raise HTTPException(status_code=404, detail="Not Found")

        return _static_response(request, static_dir / "index.html", cache_control=_NO_CACHE_CACHE_CONTROL)
