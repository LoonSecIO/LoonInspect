"""The Jamf side of the catalog, as a local lookup: one row per title x bundle ID x listed
version, carrying the hashes LoonInspect stamps on every installed app.

Kyle's point (2026-08-22): Jamf lists the name, bundle ID and version of every release it tracks,
with the release date — "it has the values: when you get an App you can do the local MD5 lookup on
it". `app_catalog_versions` is that table. Where Jamf gives an `appName` the row carries
`app_hash = md5(appName:bundleId)`, `version_hash = md5(appName:bundleId:version)` (Jamf-style:
no short version) and the v1 content keys; every row carries `(bundle_id, version)` for the titles
Jamf names no app for (the versioned lines, "Wireshark 4.2"). Rebuilt after each catalog sync.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from datetime import datetime

from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.content_keys import app_full_key, app_title_key
from app.core.hashing import compute_app_hash, compute_version_hash
from app.mdm.patch.matching import Catalog, CatalogTitle, load_catalog
from app.mdm.patch.requirements import BUNDLE_ID, EXTENSION_ATTRIBUTE
from app.models.schema import AppCatalogVersion

logger = logging.getLogger(__name__)

_CHUNK = 2000


def title_bundle_ids(title: CatalogTitle) -> list[str]:
    """The bundle IDs a title speaks for: its own column and every `Application Bundle ID is`
    value in its requirements (1Password 4/5/6 each name the shared ID; Jamf Self Service's
    column is a prefix its `like` test widens — only exact values make rows)."""
    found: list[str] = []
    if title.bundle_id:
        found.append(title.bundle_id)
    for group in title.requirements:
        for test in group.get("tests") or []:
            if test.get("type") != EXTENSION_ATTRIBUTE and test.get("name") == BUNDLE_ID and test.get("operator") == "is":
                value = str(test.get("value") or "").strip()
                if value and value not in found:
                    found.append(value)
    return found


def build_rows(catalog: Catalog) -> list[dict]:
    rows: list[dict] = []
    for title in catalog.titles:
        bundles = title_bundle_ids(title)
        if not bundles:
            continue
        latest = (title.current_version or "").strip().casefold()
        for bundle in bundles:
            seen: set[str] = set()
            for patch in title.patches:
                version = (patch.version or "").strip()
                if not version or version.casefold() in seen:
                    continue
                seen.add(version.casefold())
                app_name = (title.app_name or "").strip() or None
                rows.append(
                    {
                        "title_id": title.id,
                        "title_name": title.name,
                        "publisher": title.publisher,
                        "app_name": app_name,
                        "bundle_id": bundle,
                        "version": version,
                        "released_at": patch.released_at,
                        "is_latest": version.casefold() == latest,
                        "app_hash": compute_app_hash(app_name, bundle) if app_name else None,
                        "version_hash": compute_version_hash(app_name, bundle, version) if app_name else None,
                        "key_title": app_title_key(app_name, bundle) if app_name else None,
                        "key_full": app_full_key(app_name, bundle, version, None) if app_name else None,
                    }
                )
    return rows


async def rebuild_index(db: AsyncSession) -> int:
    """Replace `app_catalog_versions` from the current catalog. Commits."""
    catalog = await load_catalog(db)
    rows = build_rows(catalog)
    await db.execute(delete(AppCatalogVersion))
    for start in range(0, len(rows), _CHUNK):
        await db.execute(insert(AppCatalogVersion), rows[start : start + _CHUNK])
    await db.commit()
    logger.info("app catalog index rebuilt", extra={"rows": len(rows), "titles": len(catalog.titles)})
    return len(rows)


async def lookup_versions(
    db: AsyncSession,
    *,
    version_hashes: Iterable[str] = (),
    key_fulls: Iterable[str] = (),
    app_hashes: Iterable[str] = (),
    pairs: Iterable[tuple[str, str]] = (),
) -> Sequence[AppCatalogVersion]:
    """Every Jamf-known (title, version) row behind the given keys."""
    version_hashes, key_fulls, app_hashes, pairs = list(version_hashes), list(key_fulls), list(app_hashes), list(pairs)
    conditions = []
    if version_hashes:
        conditions.append(AppCatalogVersion.version_hash.in_(version_hashes))
    if key_fulls:
        conditions.append(AppCatalogVersion.key_full.in_(key_fulls))
    if app_hashes:
        conditions.append(AppCatalogVersion.app_hash.in_(app_hashes))
    for bundle_id, version in pairs:
        conditions.append((AppCatalogVersion.bundle_id == bundle_id) & (AppCatalogVersion.version == version))
    if not conditions:
        return []
    from sqlalchemy import or_

    stmt = select(AppCatalogVersion).where(or_(*conditions)).order_by(AppCatalogVersion.title_name, AppCatalogVersion.version)
    return (await db.execute(stmt)).scalars().all()


def newest_release(rows: Iterable[AppCatalogVersion]) -> datetime | None:
    dates = [row.released_at for row in rows if row.released_at is not None]
    return max(dates) if dates else None
