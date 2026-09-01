from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import AsyncGenerator
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import event, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Session as SyncSession

from app.core.config import settings
from app.core.tenancy import TENANT_GUC, get_tenant_id

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


# pool_pre_ping because the database is now a separate container with its own restart
# and upgrade lifecycle: a pooled connection can be dead while the process is fine,
# and without this the first request after a `docker compose restart db` fails rather
# than reconnecting.
engine = create_async_engine(settings.database_url, echo=settings.debug, pool_pre_ping=True)
_session_factory = async_sessionmaker(engine, expire_on_commit=False)

_BACKEND_DIR = Path(__file__).resolve().parents[2]

# How long startup waits for the database to accept connections. `depends_on` with a
# health condition already sequences compose, but nothing sequences a `docker restart`
# of the database under a running app, and an operator running the image by hand has
# no compose at all.
_DB_WAIT_TIMEOUT_SECONDS = 60.0
_DB_WAIT_INTERVAL_SECONDS = 1.0


@event.listens_for(SyncSession, "after_begin")
def _bind_tenant_to_transaction(session: SyncSession, transaction, connection) -> None:
    """Publish the session's tenant into the Postgres GUC that RLS policies read.

    On `after_begin` rather than once per session, because a session that commits and
    then keeps working starts a *new* transaction, and `set_config(..., true)` is
    scoped to the transaction that set it. Binding here means the value can never be
    missing for part of a session's life, and can never leak into the next borrower of
    a pooled connection.

    Sessions with no tenant leave the GUC unset on purpose. Every policy compares
    against `current_setting(...)` without the missing-ok flag, so an unbound session
    touching a tenant-scoped table raises rather than quietly returning no rows —
    loud, and the same failure in development as in production.
    """
    tenant_id = session.info.get("tenant_id")
    if tenant_id is None:
        return
    connection.execute(
        text("SELECT set_config(:name, :value, true)"),
        {"name": TENANT_GUC, "value": str(tenant_id)},
    )


def session_for_tenant(tenant_id: uuid.UUID) -> AsyncSession:
    """A session whose every transaction is scoped to one tenant by the database.

    The explicit entry point for background work — scheduler jobs have no request to
    inherit a tenant from, so they name the one they are acting for.
    """
    return _session_factory(info={"tenant_id": str(tenant_id)})


async def rebind_tenant(session: AsyncSession, tenant_id: uuid.UUID) -> None:
    """Move an open session onto a different tenant.

    Authentication is the reason this exists. Finding the session row is itself a read
    of a tenant-scoped table, so a tenant has to be bound *before* the acting tenant is
    known — the request opens under a resolution scope, and this narrows it to the one
    the session row actually names. Called with the same tenant it already had, which
    is the single-tenant case, it is a cheap no-op that still keeps the two in step.

    Both halves matter. `session.info` is what the after_begin listener reads, so it
    governs every transaction from here on; the immediate set_config covers the
    transaction already in flight, which began during identity resolution and would
    otherwise keep the old value until the next commit.
    """
    session.info["tenant_id"] = str(tenant_id)
    if session.in_transaction():
        await session.execute(
            text("SELECT set_config(:name, :value, true)"),
            {"name": TENANT_GUC, "value": str(tenant_id)},
        )


def unscoped_session() -> AsyncSession:
    """A session with no tenant bound.

    Only for the handful of tables that are deliberately outside tenancy: `tenants`
    itself, and the global Jamf patch corpus. Touching anything else through one of
    these raises, which is the intent — this is not an escape hatch for cross-tenant
    reads.
    """
    return _session_factory()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Request-scoped session, bound to the tenant the middleware put in context.

    The tenant is read from context rather than accepted as an argument, so no route
    or service function is in a position to choose one — which is the whole of
    "injected via context object, never inferred" as it applies to storage.
    """
    tenant_id = get_tenant_id()
    session = _session_factory(info={"tenant_id": str(tenant_id)} if tenant_id else None)
    async with session:
        yield session


async def ping() -> None:
    """One round trip that proves the database is *answering*, not merely reachable.

    `engine.connect()` rather than a session from the factory, and not `get_db`:
    a session is the tenancy-carrying object and a liveness probe has no tenant to
    carry, so borrowing one would either bind a tenant that means nothing or leave the
    GUC unset and make the probe's own behaviour depend on RLS. This still goes
    through the same pool every request uses, which is the point — a pool with no free
    connection is an outage the probe has to see, and a check that dodged the pool
    would report health while every real request queued.

    Raises rather than returning a bool so the caller decides the consequence: startup
    retries, the health endpoint answers 503.
    """
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))


def _run_migrations() -> None:
    # Alembic's command API is sync and internally does its own asyncio.run() for the
    # async engine, so this must run off the main event loop thread (see init_db()).
    config = Config(str(_BACKEND_DIR / "alembic.ini"))
    # Tells migrations/env.py to leave logging alone — see the comment there.
    config.attributes["configure_logger"] = False
    command.upgrade(config, "head")


async def _wait_for_database() -> None:
    """Block until the database answers, or give up loudly.

    Postgres accepts TCP connections a moment before it accepts queries, and refuses
    both for a while on a first boot that has to run initdb. Retrying here turns that
    race into a few seconds of startup latency instead of a crash loop whose logs
    blame the application.
    """
    deadline = time.monotonic() + _DB_WAIT_TIMEOUT_SECONDS
    attempt = 0

    while True:
        attempt += 1
        try:
            await ping()
            if attempt > 1:
                logger.info("database accepted connections", extra={"attempts": attempt})
            return
        except (OSError, SQLAlchemyError) as exc:
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"database did not accept connections within {_DB_WAIT_TIMEOUT_SECONDS:.0f}s: {exc}"
                ) from exc
            if attempt == 1:
                logger.info("waiting for the database")
            await asyncio.sleep(_DB_WAIT_INTERVAL_SECONDS)


async def init_db() -> None:
    await _wait_for_database()
    await asyncio.to_thread(_run_migrations)
