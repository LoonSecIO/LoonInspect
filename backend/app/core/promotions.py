"""Promoted applications (#793): the administrator's side of docs/data-sharing.md, "Promoted applications".

The service learns what an application is, its name and bundle ID rather than only its hash,
through the reveal rule: a title seen at five independent submission UUIDs. Automatic reveals
are paused, and early on most titles never reach five. A promotion is the operator's own way
past that rule for the applications they choose: an administrator promotes a title this
organization has installed, and from then on each exchange carries its name, bundle ID and
versions in plain text beside the hashes it already sent (`app.core.sharing.build_promotions`,
which is the only place a promotion becomes bytes).

This module is the choice and nothing else: what is promoted, what could be, and why a
promoted title is being held back. It sends nothing.

- The `app_promotion` flag is the area's switch. Off, nothing can be promoted and nothing
  promoted leaves; withdrawing still works, so switching the area off never strands a choice.
- The exclude list wins. A title whose bundle ID matches an exclusion cannot be promoted, and
  one excluded after it was promoted is held back, with the pattern named.
- Only a title installed here, with a bundle identifier, can be promoted: the definition is the
  name and the bundle ID, and the versions that travel with it are this fleet's.
"""

from __future__ import annotations

import re
import uuid
from fnmatch import fnmatch

from sqlalchemy import distinct, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.exclusion_candidates import _rows
from app.core.sharing import promotion_enabled
from app.models.schema import AppPromotion, DataSharingSettings, InstalledApp

KEY_TITLE = re.compile(r"v1:[0-9a-f]{64}")

# Ceilings. A promotion is a deliberate act about one application; past a couple of hundred it
# has become a second inventory upload, which is what the reveal tier's own rule is for.
MAX_PROMOTIONS = 200
# The picker is a shortlist, like the exclusion candidates: the search box reaches the rest.
MAX_CANDIDATES = 50

# Why a promoted title is not in the next exchange although promoted.
HELD_EXCLUDED = "excluded"
HELD_NOT_INSTALLED = "not_installed"

# Why nothing promoted is leaving at all, most decisive first.
PAUSED_FLAG = "flag_off"
PAUSED_ENV = "env_disabled"
PAUSED_SHARING = "sharing_off"


class PromotionRefused(Exception):
    """Promoting said no, and why, in the operator's words. The API answers 409 with the sentence."""


REFUSED_FLAG = (
    "Nothing was promoted: promoting applications is switched off for this organization. "
    "An administrator turns on Promote applications under Settings › Feature Flags."
)
REFUSED_NOT_INSTALLED = (
    "Nothing was promoted: no device in this organization has that application installed now, "
    "or it has no bundle identifier. Choose an application from the list on this page."
)
REFUSED_LIMIT = (
    f"Nothing was promoted: {MAX_PROMOTIONS} applications are promoted already, which is the limit. "
    "Withdraw one you no longer need first."
)


def refused_excluded(bundle_id: str, pattern: str) -> str:
    return (
        f"Nothing was promoted: {bundle_id} matches the excluded pattern {pattern}, and an excluded "
        "application is never sent. Remove that pattern under Excluded bundle IDs first."
    )


def excluded_by(bundle_id: str, globs: list[str]) -> str | None:
    """The first exclusion pattern that holds this bundle ID back, or None. The same `fnmatch`
    the exchange drops with, so the page and the wire cannot disagree about a pattern."""
    return next((pattern for pattern in globs if fnmatch(bundle_id, pattern)), None)


def paused_reason(*, enabled: bool, tier: str) -> str | None:
    """Why no promotion leaves at all, or None when the next exchange carries them."""
    if not enabled:
        return PAUSED_FLAG
    if not app_settings.community_sharing:
        return PAUSED_ENV
    if tier == "off":
        return PAUSED_SHARING
    return None


async def list_promotions(db: AsyncSession, settings_row: DataSharingSettings, query: str | None = None) -> dict:
    """What is promoted, whether it is leaving, and what could be promoted next.

    Candidates are the titles installed here with a bundle identifier and not yet promoted:
    the ones no public source on this container knows first (`exclusion_candidates._rows`'
    answer, so this page and the exclusion panel cannot disagree about what is unknown), then
    the most installed. Empty while the flag is off, because nothing can be promoted then."""
    enabled = await promotion_enabled(db)
    globs = list(settings_row.exclude_globs or [])
    promoted = (await db.execute(select(AppPromotion).order_by(AppPromotion.app_name, AppPromotion.bundle_id))).scalars().all()

    counts: dict[str, tuple[int, int]] = {}
    if promoted:
        found = await db.execute(
            select(
                InstalledApp.key_title,
                func.count(distinct(InstalledApp.device_id)),
                func.count(distinct(InstalledApp.key_full)),
            )
            .where(InstalledApp.key_title.in_([row.key_title for row in promoted]))
            .group_by(InstalledApp.key_title)
        )
        counts = {key_title: (devices, versions) for key_title, devices, versions in found.all()}

    items = []
    for row in promoted:
        devices, versions = counts.get(row.key_title, (0, 0))
        pattern = excluded_by(row.bundle_id, globs)
        items.append(
            {
                "id": row.id,
                "key_title": row.key_title,
                "app_name": row.app_name,
                "bundle_id": row.bundle_id,
                "promoted_at": row.promoted_at,
                "promoted_by": row.promoted_by,
                "device_count": devices,
                "version_count": versions,
                "held": HELD_EXCLUDED if pattern else (HELD_NOT_INSTALLED if devices == 0 else None),
                "excluded_by": pattern,
            }
        )

    candidates: list[dict] = []
    more = 0
    if enabled:
        taken = {row.key_title for row in promoted}
        needle = (query or "").strip().casefold()
        wanted = [
            row
            for row in await _rows(db)
            if row.key_title not in taken and (not needle or needle in row.name.casefold() or needle in row.bundle_id.casefold())
        ]
        wanted.sort(key=lambda row: (row.known, -row.device_count, row.name.casefold(), row.bundle_id))
        more = max(0, len(wanted) - MAX_CANDIDATES)
        candidates = [
            {
                "key_title": row.key_title,
                "app_name": row.name,
                "bundle_id": row.bundle_id,
                "device_count": row.device_count,
                "known": row.known,
                "excluded_by": excluded_by(row.bundle_id, globs),
            }
            for row in wanted[:MAX_CANDIDATES]
        ]

    return {
        "enabled": enabled,
        "paused": paused_reason(enabled=enabled, tier=settings_row.tier),
        "limit": MAX_PROMOTIONS,
        "items": items,
        "candidates": candidates,
        "more_candidates": more,
    }


async def promote(
    db: AsyncSession, settings_row: DataSharingSettings, key_title: str, promoted_by: str | None
) -> tuple[AppPromotion, bool]:
    """Promote one installed title. Returns the row and whether this call made it: promoting a
    title already promoted answers with the row that exists, so a second click is not an error.

    The name and bundle ID are read from inventory by the key, never taken from the request:
    what leaves in plain text is what this fleet reported, and a caller cannot have a string of
    their own sent under the organization's submission."""
    if not await promotion_enabled(db):
        raise PromotionRefused(REFUSED_FLAG)

    existing = (await db.execute(select(AppPromotion).where(AppPromotion.key_title == key_title))).scalar_one_or_none()
    if existing is not None:
        return existing, False

    installed = (
        await db.execute(
            select(InstalledApp.bundle_id, func.min(InstalledApp.name))
            .where(InstalledApp.key_title == key_title, InstalledApp.bundle_id != "")
            .group_by(InstalledApp.bundle_id)
            .limit(1)
        )
    ).first()
    if installed is None:
        raise PromotionRefused(REFUSED_NOT_INSTALLED)
    bundle_id, app_name = installed

    pattern = excluded_by(bundle_id, list(settings_row.exclude_globs or []))
    if pattern is not None:
        raise PromotionRefused(refused_excluded(bundle_id, pattern))

    if (await db.execute(select(func.count(AppPromotion.id)))).scalar_one() >= MAX_PROMOTIONS:
        raise PromotionRefused(REFUSED_LIMIT)

    row = AppPromotion(key_title=key_title, app_name=app_name, bundle_id=bundle_id, promoted_by=promoted_by)
    db.add(row)
    try:
        await db.commit()
    except IntegrityError:
        # Two administrators promoted the same title at once: the constraint kept one row, and
        # that row is the answer to both.
        await db.rollback()
        return (await db.execute(select(AppPromotion).where(AppPromotion.key_title == key_title))).scalar_one(), False
    await db.refresh(row)
    return row, True


async def withdraw(db: AsyncSession, promotion_id: uuid.UUID) -> AppPromotion | None:
    """Withdraw a promotion: the title stops leaving by name at the next exchange. Works with the
    flag off. What the service already received is the service's to keep or delete; this stops
    the sending, as turning sharing off does."""
    row = await db.get(AppPromotion, promotion_id)
    if row is None:
        return None
    await db.delete(row)
    await db.commit()
    return row
