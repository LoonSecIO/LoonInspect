"""Tenant acquisition, assessment and selection for the opt-in #621 serving path.

Physical possession never implies a grant. Delivery records acquisition only for the
recipient; every answer writer serializes with selection and uses retained release rows.
These helpers never change sharing consent and do not verify paid entitlements.
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
        await db.execute(select(Tenant.id).where(Tenant.id == tenant).with_for_update(key_share=True))
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


async def load_selected_corpus(db: AsyncSession) -> None:
    """Bind the selected release's metadata to this task, without loading corpus rows.

    Serving uses stored assessment columns; only the signature and as-of date belong
    in memory. No fallback to global possession, consent or a previous task's state.
    """
    from app.core.vuln import NO_CORPUS, install_selected_corpus
    from app.core.vuln_library import LibraryCorpus, VulnLibrary

    tenant = _tenant(db)
    install_selected_corpus(tenant, NO_CORPUS)
    signature = await selected_signature(db)
    if signature is None:
        return
    release = await db.get(VulnCorpusRelease, signature)
    if release is None:
        raise CorpusSelectionRefused("The selected intelligence is missing. Restore the database backup and contact support.")
    install_selected_corpus(
        tenant,
        LibraryCorpus(
            VulnLibrary(
                epoch_id=release.epoch_id,
                signature=release.signature,
                as_of=release.asof.date(),
                asof_at=release.asof,
                loaded_at=release.loaded_at,
                rows={},
                titles={},
            )
        ),
    )


async def lock_assessment(db: AsyncSession) -> None:
    """Serialize a tenant's answer writers with selection, then read committed selection."""
    tenant = _tenant(db)
    # NO KEY UPDATE serializes writers without conflicting with tenant foreign-key
    # checks taken by inventory inserts earlier in the same transaction.
    await db.execute(select(Tenant.id).where(Tenant.id == tenant).with_for_update(key_share=True))
    await load_selected_corpus(db)


async def assess_and_select(db: AsyncSession, signature: str) -> bool:
    """Run the real catalog join and installed copies before advancing the pointer.

    No process cache is published. The caller owns commit; its next unit of work reads
    the committed pointer. Retained rows and acquisition are checked by the selection
    primitive, which also serializes this transaction against ordinary answer writers.
    """
    from app.catalog.service import copy_vuln_answers, judge_vuln

    async def assess(session: AsyncSession, release: str) -> None:
        await judge_vuln(session, None, now=datetime.now(UTC), release=release)
        await copy_vuln_answers(session)

    return await select_after_assessment(db, signature, assess=assess)


async def prepare_assessment(db: AsyncSession) -> None:
    """Bootstrap migration-granted intelligence on the first real assessment, under lock."""
    await lock_assessment(db)
    if await selected_signature(db) is None:
        signature = await db.scalar(
            select(VulnCorpusAcquisition.signature)
            .where(VulnCorpusAcquisition.tenant_id == _tenant(db))
            .order_by(VulnCorpusAcquisition.acquired_at.desc(), VulnCorpusAcquisition.signature)
            .limit(1)
        )
        if signature is not None:
            await assess_and_select(db, signature)
            await load_selected_corpus(db)
