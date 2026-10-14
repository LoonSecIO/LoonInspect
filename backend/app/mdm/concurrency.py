"""Serialize device writes without holding database connections across Jamf reads."""

import hashlib

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import bound_tenant_id


class IngestBusy(RuntimeError):
    """The device is still being written by another ingest transaction."""


async def lock_device(db: AsyncSession, connection_id: int, platform: str, device_id: str) -> None:
    """Lock existing and first-time devices alike, through the caller's atomic commit.

    One nonblocking query on the usual uncontended path. A contended write waits at
    most five seconds. The savepoint restores lock_timeout and the transaction after a
    refused wait, so a caller can record the failure without a poisoned transaction.
    """
    material = f"device\x00{bound_tenant_id(db)}\x00{connection_id}\x00{platform}\x00{device_id}"
    key = int.from_bytes(hashlib.blake2b(material.encode(), digest_size=8).digest(), signed=True)
    if await db.scalar(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": key}):
        return
    try:
        async with db.begin_nested():
            previous = await db.scalar(text("SELECT current_setting('lock_timeout')"))
            await db.execute(text("SELECT set_config('lock_timeout', '5s', true)"))
            await db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
            await db.execute(text("SELECT set_config('lock_timeout', :previous, true)"), {"previous": previous})
    except DBAPIError as exc:
        if getattr(exc.orig, "sqlstate", None) != "55P03":
            raise
        raise IngestBusy(
            "Another inventory read is still being saved for this Mac. Retry shortly; "
            "if this continues, check the connection's active runs."
        ) from None
