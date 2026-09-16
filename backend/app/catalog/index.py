"""The Jamf side of the catalog, as a local lookup: one row per title x bundle ID x listed
version, carrying the hashes LoonInspect stamps on every installed app.

Kyle's point (2026-08-22): Jamf lists the name, bundle ID and version of every release it tracks,
with the release date — "it has the values: when you get an App you can do the local MD5 lookup on
it". `app_catalog_versions` is that table. Where the title has an app name the row carries
`app_hash = md5(appName:bundleId)`, `version_hash = md5(appName:bundleId:version)` (Jamf-style:
no short version) and the v1 content keys; every row carries `(bundle_id, version)` for the titles
nothing names an app for. Rebuilt after each catalog sync.

**The sync decides that name, not this module** (#385). Jamf leaves `appName` null on 513 of 1,553
titles — the versioned lines, "Wireshark 4.2" among them — and names the same app in every patch's
`killApps` for the same bundle ID, which is what a Jamf inventory reports. `app.mdm.patch.jamf_catalog`
reads it there before `killApps` is stripped; here a salvaged name is a name like any other.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence

from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.content_keys import app_full_key, app_title_key
from app.core.hashing import compute_app_hash, compute_version_hash
from app.mdm.patch.matching import Catalog, CatalogTitle, load_catalog
from app.mdm.patch.requirements import bundle_ids_named
from app.models.schema import AppCatalogVersion

logger = logging.getLogger(__name__)

_CHUNK = 2000


def title_bundle_ids(title: CatalogTitle) -> list[str]:
    """The bundle IDs a title speaks for, in the order the catalog sync walks them — the walk is
    `app.mdm.patch.requirements.bundle_ids_named`, shared with the sync so the bundle ID a title's
    app name is salvaged from is the one this module makes its first rows for (#385)."""
    return bundle_ids_named(title.bundle_id, title.requirements)


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
