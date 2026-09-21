"""Manual corpus cleanup with optional 30-day acquisition retirement (#621).

Current and previous selections survive expiry. Tenant-bound savepoints share the cleanup
transaction, so grant retirement and orphan deletion commit or roll back together.
"""

import argparse
import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import unscoped_session
from app.models.schema import (
    Tenant,
    VulnCorpusAcquisition,
    VulnCorpusRelease,
    VulnCorpusReleaseRow,
    VulnCorpusReleaseTitle,
    VulnCorpusSelection,
    VulnLibraryEpoch,
)


@asynccontextmanager
async def _scoped(db, tenant):
    """Bind RLS inside a savepoint while preserving the caller's connection context."""
    previous = await db.scalar(text("SELECT current_setting('looninspect.tenant_id', true)"))
    async with (
        AsyncSession(
            bind=await db.connection(), info={"tenant_id": str(tenant)}, join_transaction_mode="create_savepoint"
        ) as scoped,
        scoped.begin(),
    ):
        yield scoped
        await scoped.execute(text("SELECT set_config('looninspect.tenant_id', :tenant, true)"), {"tenant": previous or ""})
    # Failure rolls back the savepoint, including its RLS setting; success restores it.


async def _retire(db, *, before, active, apply):
    eligible = 0
    protected = set()
    for tenant in await db.scalars(select(Tenant.id).order_by(Tenant.id)):
        # Same lock as selection/acquisition; held until the outer cleanup commits.
        await db.execute(select(Tenant.id).where(Tenant.id == tenant).with_for_update(key_share=True))
        async with _scoped(db, tenant) as scoped:
            selection = await scoped.get(VulnCorpusSelection, tenant)
            query = select(VulnCorpusAcquisition.signature)
            if selection and selection.previous_signature is None:
                # Unknown pre-upgrade history (or just one successful selection).
                protected.update(await scoped.scalars(query))
                continue
            pins = {active}
            if selection:
                pins.update((selection.signature, selection.previous_signature))
            grants = (await scoped.execute(select(VulnCorpusAcquisition.signature, VulnCorpusAcquisition.acquired_at))).all()
            retiring = [signature for signature, acquired in grants if acquired < before and signature not in pins]
            protected.update(signature for signature, _ in grants if signature not in retiring)
            eligible += len(retiring)
            if apply and retiring:
                await scoped.execute(delete(VulnCorpusAcquisition).where(VulnCorpusAcquisition.signature.in_(retiring)))
    return eligible, protected


async def _acquired(db, signatures):
    held = set()
    for tenant in await db.scalars(select(Tenant.id)):
        async with _scoped(db, tenant) as scoped:
            held.update(
                await scoped.scalars(
                    select(VulnCorpusAcquisition.signature).where(VulnCorpusAcquisition.signature.in_(signatures))
                )
            )
    return held


async def prune_releases(db, *, before: datetime, apply: bool = False, retire_acquisitions: bool = False):
    """Inspect or remove old unacquired releases; the caller owns commit/rollback.

    The importer lock keeps the active projection stable for the whole transaction.
    A savepoint restores child rows if a concurrently acquired release refuses deletion.
    Optional retirement removes only grants older than 30 days and the supplied cutoff.
    Selection, answers, history, consent and entitlement state are never modified.
    """
    if before.tzinfo is None or before > datetime.now(UTC):
        raise ValueError("Choose a past cleanup cutoff with a timezone, for example 2026-09-01T00:00:00Z.")
    await db.execute(text("SELECT pg_advisory_xact_lock(621, 1)"))
    active = await db.scalar(select(VulnLibraryEpoch.signature))
    result = {"examined": 0, "protected": 0, "eligible": 0, "deleted": 0}
    retirement = None
    if retire_acquisitions:
        eligible, retirement = await _retire(
            db, before=min(before, datetime.now(UTC) - timedelta(days=30)), active=active, apply=apply
        )
        result.update(acquisitionsEligible=eligible, acquisitionsRetired=eligible if apply else 0)
    cursor = ""
    while True:
        signatures = list(
            await db.scalars(
                select(VulnCorpusRelease.signature)
                .where(VulnCorpusRelease.loaded_at < before, VulnCorpusRelease.signature > cursor)
                .order_by(VulnCorpusRelease.signature)
                .limit(100)
            )
        )
        if not signatures:
            return result
        cursor = signatures[-1]
        held = await _acquired(db, signatures) if retirement is None or apply else retirement
        for signature in signatures:
            result["examined"] += 1
            if signature == active or signature in held:
                result["protected"] += 1
                continue
            if not apply:
                result["eligible"] += 1
                continue
            try:
                async with db.begin_nested():
                    for model in (VulnCorpusReleaseRow, VulnCorpusReleaseTitle, VulnCorpusRelease):
                        await db.execute(delete(model).where(model.signature == signature))
            except IntegrityError as exc:
                if getattr(exc.orig, "sqlstate", None) != "23503":
                    raise
                # RESTRICT sees every tenant, even when RLS hides its acquisition.
                # A new acquisition or another reference wins; retain the whole release.
                result["protected"] += 1
            else:
                result["eligible"] += 1
                result["deleted"] += 1


def cutoff(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed > datetime.now(UTC):
            raise ValueError
        return parsed
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Use a past date with a timezone, for example 2026-09-01T00:00:00Z.") from exc


async def run(*, before, apply, retire_acquisitions=False):
    try:
        async with unscoped_session() as db:
            # Bound waits protect an operator from hanging behind an active import.
            await db.execute(text("SET LOCAL lock_timeout = '5s'"))
            result = await prune_releases(db, before=before, apply=apply, retire_acquisitions=retire_acquisitions)
            if apply:
                await db.commit()
            else:
                await db.rollback()
    except (SQLAlchemyError, OSError):
        print(
            "Corpus cleanup failed. Check database availability and permissions, "
            "wait for any active corpus import or assessment to finish, then retry the preview. "
            "See docs/troubleshooting.md §5."
        )
        return 1
    print(
        f"{'Cleanup complete' if apply else 'Preview only; nothing deleted'}: "
        f"{result['examined']} old releases examined, {result['protected']} active or acquired releases protected, "
        f"{result['eligible']} eligible, {result['deleted']} deleted. "
        "New acquisitions can change the result before cleanup. "
        "Current and previous selected releases and historical evidence are preserved."
    )
    if retire_acquisitions:
        print(
            f"{result['acquisitionsEligible']} acquisitions eligible after 30 days; "
            f"{result['acquisitionsRetired']} retired. Retired releases cannot be selected again without authorized delivery."
        )
    return 0


def main():
    parser = argparse.ArgumentParser(description="Clean up old, unacquired intelligence. Default: preview only.")
    parser.add_argument("--before", required=True, type=cutoff, help="Exclusive first-local-load cutoff, including timezone.")
    parser.add_argument("--apply", action="store_true", help="Delete eligible releases in one transaction.")
    parser.add_argument(
        "--retire-acquisitions",
        action="store_true",
        help="Also retire acquisitions older than 30 days; always protect current and previous selections.",
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(before=args.before, apply=args.apply, retire_acquisitions=args.retire_acquisitions)))


if __name__ == "__main__":
    main()
