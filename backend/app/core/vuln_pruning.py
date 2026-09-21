"""Manual cleanup of unacquired corpus releases (#621), previewing unless --apply.

Acquisition preserves rollback, including for expired tenants. Never infer a global
absence from a tenant-filtered query; inspect grants with separately bound sessions and
keep foreign-key enforcement as the final guard against concurrent acquisition.
"""

import argparse
import asyncio
from datetime import UTC, datetime

from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.core.database import session_for_tenant, unscoped_session
from app.models.schema import (
    Tenant,
    VulnCorpusAcquisition,
    VulnCorpusRelease,
    VulnCorpusReleaseRow,
    VulnCorpusReleaseTitle,
    VulnLibraryEpoch,
)


async def _acquired(db, signatures):
    held = set()
    for tenant in await db.scalars(select(Tenant.id)):
        async with session_for_tenant(tenant) as scoped:
            held.update(
                await scoped.scalars(
                    select(VulnCorpusAcquisition.signature).where(VulnCorpusAcquisition.signature.in_(signatures))
                )
            )
    return held


async def prune_releases(db, *, before: datetime, apply: bool = False):
    """Inspect or remove old unacquired releases; the caller owns commit/rollback.

    The importer lock keeps the active projection stable for the whole transaction.
    A savepoint restores child rows if a concurrently acquired release refuses deletion.
    No acquisition, selection, answer, history, consent or expiry record is modified.
    """
    if before.tzinfo is None or before > datetime.now(UTC):
        raise ValueError("Choose a past cleanup cutoff with a timezone, for example 2026-09-01T00:00:00Z.")
    await db.execute(text("SELECT pg_advisory_xact_lock(621, 1)"))
    active = await db.scalar(select(VulnLibraryEpoch.signature))
    result = {"examined": 0, "protected": 0, "eligible": 0, "deleted": 0}
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
        held = await _acquired(db, signatures)
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


async def run(*, before, apply):
    try:
        async with unscoped_session() as db:
            # Bound waits protect an operator from hanging behind an active import.
            await db.execute(text("SET LOCAL lock_timeout = '5s'"))
            result = await prune_releases(db, before=before, apply=apply)
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
        "Tenant rollback releases and historical evidence are preserved."
    )
    return 0


def main():
    parser = argparse.ArgumentParser(description="Clean up old, unacquired intelligence. Default: preview only.")
    parser.add_argument("--before", required=True, type=cutoff, help="Exclusive first-local-load cutoff, including timezone.")
    parser.add_argument("--apply", action="store_true", help="Delete eligible releases in one transaction.")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(before=args.before, apply=args.apply)))


if __name__ == "__main__":
    main()
