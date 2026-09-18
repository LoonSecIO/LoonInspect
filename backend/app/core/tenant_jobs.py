"""One tenant's work at a time, for a job that has no request to inherit a tenant from.

The two primitives every scheduler job in `app.main` is written with. They lived there
until #554, when the exchange — which imports a corpus for the whole box and then has one
statement to run per organization — needed them too, and `app.core.sharing` cannot import
the application module that imports it. Nothing here changed in the move.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import reset_actor, set_actor, system_actor_for
from app.core.database import session_for_tenant, unscoped_session
from app.core.tenancy import reset_tenant_id, set_tenant_id
from app.models.schema import Tenant


async def operational_tenant_ids() -> list[uuid.UUID]:
    """Every tenant a background job has work to do for.

    Scheduler jobs have no request to inherit a tenant from, and row-level security
    gives them no way to sweep all tenants in one query — which is the point, not a
    limitation to work around. They enumerate here and then do one tenant's work per
    session, so a job that forgets to is a job that fails rather than one that
    quietly crosses a boundary.
    """
    async with unscoped_session() as db:
        result = await db.execute(select(Tenant.id).where(Tenant.kind == "operational").order_by(Tenant.slug))
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
