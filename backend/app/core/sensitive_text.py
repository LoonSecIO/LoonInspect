"""Tenant-scoped storage for fleet text whose body must stay off the wire."""

import hashlib

from sqlalchemy import delete, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.mdm.jamf.contract import DEFINITION_SECTION
from app.models.schema import ObservationSection, SensitiveText

# Reference held by an extension attribute definition's immutable ledger section.
SCRIPT_DIGEST = "scriptDigest"
_TENANT_LOCK = "hashtextextended('sensitive_text:' || current_setting('looninspect.tenant_id'), 0)"


async def store_text(db: AsyncSession, body: str) -> str:
    """Store a body. The caller writes the returned digest to its owner in this transaction."""
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    # Readers that create a reference share this lock. Cleanup waits for their owner
    # records to commit, including when a writer reuses an existing body.
    await db.execute(text(f"SELECT pg_advisory_xact_lock_shared({_TENANT_LOCK})"))
    await db.execute(insert(SensitiveText).values(digest=digest, body=body).on_conflict_do_nothing())
    return digest


async def read_text(db: AsyncSession, digest: str) -> str | None:
    return await db.scalar(select(SensitiveText.body).where(SensitiveText.digest == digest))


async def purge_unreferenced_text(db: AsyncSession) -> int:
    """Keep bodies referenced by any historical definition in this tenant."""
    await db.execute(text(f"SELECT pg_advisory_xact_lock({_TENANT_LOCK})"))
    referenced = select(ObservationSection.id).where(
        ObservationSection.tenant_id == SensitiveText.tenant_id,
        ObservationSection.section == DEFINITION_SECTION,
        ObservationSection.body[SCRIPT_DIGEST].astext == SensitiveText.digest,
    )
    result = await db.execute(delete(SensitiveText).where(~referenced.exists()).execution_options(synchronize_session=False))
    return result.rowcount
