"""Tenant corpus acquisition and transactional selection primitives for #621.

No shipped route or scheduler calls these yet: authorization/delivery and release-scoped
judging must be wired before serving switches from the legacy singleton. Physical corpus
possession never implies a tenant grant, and these helpers never change sharing consent.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.tenancy import get_tenant_id
from app.models.schema import Tenant, VulnCorpusAcquisition, VulnCorpusRelease, VulnCorpusSelection


class CorpusSelectionRefused(ValueError):
    """An operator-readable refusal; no fallback to another tenant's or the latest corpus."""


def _tenant(db: AsyncSession) -> uuid.UUID:
    tenant = get_tenant_id()
    if tenant is None or db.info.get("tenant_id") != str(tenant):
        raise CorpusSelectionRefused(
            "The corpus operation has no matching organization context. Retry from the intended organization; "
            "if it repeats, contact support."
        )
    return tenant


async def record_acquisition(db: AsyncSession, signature: str) -> bool:
    """Record an already-authorized delivery for the acting tenant, without committing.

    Only a trusted delivery caller may invoke this after verifying update eligibility.
    This is not entitlement verification or a public grant API. Repeating a delivery
    preserves the first acquisition clock and basis; a globally held release alone is
    never discovered as a grant by a read path.
    """
    tenant = _tenant(db)
    if await db.scalar(select(VulnCorpusRelease.signature).where(VulnCorpusRelease.signature == signature)) is None:
        raise CorpusSelectionRefused(
            "The requested corpus release has not been retained. Check corpus storage and retry the download before selecting it."
        )
    statement = (
        insert(VulnCorpusAcquisition)
        .values(tenant_id=tenant, signature=signature, basis="delivery")
        .on_conflict_do_nothing(index_elements=["tenant_id", "signature"])
        .returning(VulnCorpusAcquisition.signature)
    )
    return (await db.execute(statement)).scalar_one_or_none() is not None


async def selected_signature(db: AsyncSession) -> str | None:
    """Read only this tenant's explicit selection, with no consent or global fallback."""
    tenant = _tenant(db)
    return await db.scalar(select(VulnCorpusSelection.signature).where(VulnCorpusSelection.tenant_id == tenant))


async def select_after_assessment(
    db: AsyncSession,
    signature: str,
    *,
    assess: Callable[[AsyncSession, str], Awaitable[None]],
) -> bool:
    """Assess and select atomically inside the caller's transaction, returning whether moved.

    `assess` must evaluate this tenant against the supplied retained release and write all
    answers through this session, without committing or publishing a process cache. A
    failure rolls back its writes and the selection together. The caller commits before
    exposing any new cached answer. A tenant-row lock serializes transitions even before
    its first selection; a lock on acquisition would not serialize two different releases.
    """
    tenant = _tenant(db)
    async with db.begin_nested():
        await db.execute(select(Tenant.id).where(Tenant.id == tenant).with_for_update())
        acquired = await db.scalar(
            select(VulnCorpusAcquisition.signature).where(
                VulnCorpusAcquisition.tenant_id == tenant, VulnCorpusAcquisition.signature == signature
            )
        )
        if acquired is None:
            raise CorpusSelectionRefused(
                "This organization has not acquired the requested corpus release. Check its update access and "
                "complete delivery before selecting the release."
            )
        if await selected_signature(db) == signature:
            return False
        await assess(db, signature)
        await db.flush()
        statement = insert(VulnCorpusSelection).values(tenant_id=tenant, signature=signature, selected_at=datetime.now(UTC))
        await db.execute(
            statement.on_conflict_do_update(
                index_elements=["tenant_id"],
                set_={"signature": statement.excluded.signature, "selected_at": statement.excluded.selected_at},
            )
        )
    return True
