from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require
from app.core.database import get_db, ping
from app.core.permissions import Permission
from app.mdm.credentials import CREDENTIAL_SCHEMAS, field_specs
from app.mdm.jamf.privileges import privilege_names
from app.models.schema import MdmSyncState
from app.schemas.connections import ProviderCredentialField, ProviderInfo
from app.schemas.payload import MdmProvider, MdmSyncStatusOut

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["mdm"])

# Bounded so a database that has stopped answering — rather than refusing — still
# produces a verdict. 3s sits inside both consumers of this endpoint: the container
# HEALTHCHECK's `urlopen(timeout=4)` and its own `--timeout=5s`. A probe that timed
# out client-side would also mark the container unhealthy, but it would do so with no
# response body and no log line naming the cause, which is exactly the blindness this
# endpoint had before.
_HEALTH_TIMEOUT_SECONDS = 3.0


@router.get("/health")
async def health(response: Response) -> dict[str, str]:
    """Liveness that depends on the database, because the product does.

    This returned a bare literal until it was demonstrated, against a database holding
    zero tables and every authenticated endpoint returning 500, that the endpoint
    still answered 200 and the container still reported healthy. Nothing would ever
    have restarted it and no monitor watching the documented endpoint would ever have
    fired. The same hole is open during any outage — connection exhaustion, a crashed
    Postgres, a network partition, a half-applied migration.

    The body is deliberately the same *shape* in both states so a monitor parses one
    schema, and deliberately says nothing beyond the failure class: this route is in
    `_PUBLIC_EXACT`, so anyone who can reach the port reads it, and a DSN, a host name
    or a driver traceback here is free reconnaissance. The exception goes to the log,
    which is authenticated by being the log.
    """
    try:
        async with asyncio.timeout(_HEALTH_TIMEOUT_SECONDS):
            await ping()
    # The same pair `_wait_for_database` retries on, plus the timeout above. Anything
    # else is a bug in this process rather than an outage, and is left to surface as a
    # 500 — which fails the probe just as loudly, without being mislabelled.
    except (TimeoutError, OSError, SQLAlchemyError):
        logger.warning("health check could not reach the database", exc_info=True)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unavailable", "reason": "database"}
    return {"status": "ok"}


@router.get(
    "/mdm/status",
    response_model=list[MdmSyncStatusOut],
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def mdm_status(db: AsyncSession = Depends(get_db)) -> list[MdmSyncState]:
    result = await db.execute(select(MdmSyncState))
    return list(result.scalars().all())


@router.get(
    "/mdm/providers",
    response_model=list[ProviderInfo],
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def list_providers() -> list[ProviderInfo]:
    """What the connection form needs to draw itself — including the privileges the
    credentials will need on the other side.

    The privilege list is served rather than hardcoded in the form because the form is
    the second place an operator could have read it and the first place they will. It
    is keyed off `provider` explicitly, the way `mdm.factory` refuses to pretend it
    dispatches: a sibling vertical added later brings its own list, and inheriting
    Jamf's by falling through would be worse than showing none.
    """
    return [
        ProviderInfo(
            provider=provider,
            credential_fields=[ProviderCredentialField(**spec) for spec in field_specs(schema)],
            required_privileges=privilege_names() if provider is MdmProvider.jamf else [],
        )
        for provider, schema in CREDENTIAL_SCHEMAS.items()
    ]
