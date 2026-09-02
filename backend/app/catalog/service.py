"""The tenant app catalog — the rows, when they are written, and when they are judged.

A row is one distinct (name, bundle ID, version[, short version]) the tenant's fleet has shown,
keyed by `version_hash` (the same md5 every installed app carries), with `first_seen_at` and
`last_seen_at` on any device. The Jamf answer on the row — which titles, is it the latest, has
Jamf seen this version, when was it released — comes from the #65 rules (`app.mdm.patch.matching`)
evaluated against the row's own facts: no device facts, so extension attributes resolve TRUE,
which is Kyle's practice for them anyway.

When rows are judged:

* **at first sight** — `record_device_apps` runs inside `process_sync`: it upserts the device's
  apps into the catalog (first/last seen), evaluates every row whose answer is missing or older
  than the current catalog (its `evaluated_signature`), and copies the answer onto the device's
  `installed_apps` columns so the device pages need no join;
* **after every Jamf catalog sync** — `refresh_tenant` re-evaluates the rows whose signature is
  stale (a new release changes "latest" for a whole title the hour it lands) and refreshes the
  copies; a sync that changed nothing costs nothing.

Devices reach their answer through `installed_apps.version_hash`; the per-device matches table
from #65 is gone.

Why it is built as cache tables at all (Kyle, 2026-08-22): the question is how to get a device
from Jamf Pro to Splunk as fast as possible — wait for as little as possible, have as much as
possible cached. Jamf patching, vulnerability and the other enrichments are *lookups*, not
things calculated per device; calculating them means touching hundreds of MB for each device
when the goal is 40k devices in ten minutes. So the per-device cost of this module is kept to
its own rows: one SELECT of the device's apps, one SELECT of their catalog rows by hash, the
inserts for triples the fleet has never shown, a `last_seen_at` write at most once per
`LAST_SEEN_GRANULARITY` per distinct app (not once per device carrying it), an in-memory rule
pass only for rows the current catalog has not judged, and copies onto app rows only when a row
is new or its answer moved. Nothing per device reads the catalog tables themselves; the title
index lives in process memory and is rebuilt only when the catalog changes.

Follow-ups: a per-device override that reads a carried extension attribute, and rows for apps
that arrive through other paths than an MDM inventory (HEC).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.mdm.patch.matching import Catalog, TitleMatch, load_catalog, match_app, summarize
from app.mdm.patch.requirements import Facts
from app.models.schema import AppCatalogEntry, AppCatalogTitleMatch, Device, InstalledApp

logger = logging.getLogger(__name__)

# "Most recently seen on a device" is answered to this granularity: a row's last_seen_at moves
# when it is older than this, so a sweep writes it about once per distinct app rather than once
# per device carrying the app (40k devices x 80 apps would otherwise be ~3M row updates a sweep).
LAST_SEEN_GRANULARITY = timedelta(minutes=15)


def catalog_signature(catalog: Catalog) -> str:
    """What a row was judged against: the catalog's row count and newest `synced_at`."""
    count, newest = (*catalog.signature, None, None)[:2]
    stamp = newest.isoformat() if isinstance(newest, datetime) else ""
    return f"{count or 0}:{stamp}"


def _released_at(matches: Sequence[TitleMatch]) -> datetime | None:
    for match in matches:
        if match.version_known and match.installed_released_at is not None:
            return match.installed_released_at
    return None


def _apply_summary(entry: AppCatalogEntry, matches: Sequence[TitleMatch], *, now: datetime, signature: str) -> None:
    summary = summarize(matches)
    entry.evaluated_at = now
    entry.evaluated_signature = signature
    if summary is None:
        entry.jamf_title_ids = None
        entry.patch_state = None
        entry.is_latest = None
        entry.patch_available = None
        entry.patch_available_since = None
        entry.releases_missed = None
        entry.this_version_seen = None
        entry.latest_version = None
        entry.latest_released_at = None
        entry.released_at = None
        return
    entry.jamf_title_ids = summary.title_ids
    entry.patch_state = summary.state
    entry.is_latest = summary.is_compliant
    entry.patch_available = summary.patch_available
    entry.patch_available_since = summary.patch_available_since
    entry.releases_missed = summary.releases_missed
    entry.this_version_seen = summary.this_version_seen
    entry.latest_version = summary.latest_version
    entry.latest_released_at = summary.latest_released_at
    entry.released_at = _released_at(matches)


async def evaluate_entries(db: AsyncSession, entries: Sequence[AppCatalogEntry], catalog: Catalog, *, now: datetime) -> int:
    """Judge these rows against the catalog: replace their title matches and the answer columns.
    The rows must be flushed (they need ids). Returns the number of rows judged."""
    if not entries:
        return 0
    signature = catalog_signature(catalog)
    await db.execute(delete(AppCatalogTitleMatch).where(AppCatalogTitleMatch.app_catalog_id.in_([entry.id for entry in entries])))
    for entry in entries:
        facts = Facts(
            app_name=entry.name,
            bundle_id=entry.bundle_id,
            versions=tuple(version for version in (entry.version, entry.short_version) if version),
        )
        matches = match_app(facts, catalog)
        _apply_summary(entry, matches, now=now, signature=signature)
        for match in matches:
            db.add(
                AppCatalogTitleMatch(
                    app_catalog_id=entry.id,
                    title_id=match.title.id,
                    basis=match.basis,
                    state=match.state,
                    version_known=match.version_known,
                    on_latest=match.on_latest,
                    installed_version=match.installed_version,
                    installed_released_at=match.installed_released_at,
                    latest_version=match.latest_version,
                    latest_released_at=match.latest_released_at,
                    first_newer_released_at=match.first_newer_released_at,
                    releases_missed=match.releases_missed,
                    evaluated_at=now,
                )
            )
    return len(entries)


def copy_answer(entry: AppCatalogEntry, app: InstalledApp, *, now: datetime) -> None:
    """The row's answer onto a device's installed-app row (the older compliance columns and the
    #65 summary columns), so device pages and the Applications overview need no join."""
    app.jamf_title_ids = entry.jamf_title_ids
    app.patch_state = entry.patch_state
    app.is_compliant = entry.is_latest
    app.patch_available = entry.patch_available
    app.patch_available_since = entry.patch_available_since
    app.releases_missed = entry.releases_missed
    app.this_version_seen = entry.this_version_seen
    app.latest_version = entry.latest_version
    app.latest_released_at = entry.latest_released_at
    app.last_patch_check_at = now


async def record_device_apps(db: AsyncSession, device: Device, *, now: datetime | None = None) -> int:
    """`process_sync`'s hook, after the device's app rows are flushed: every app the device
    reports is seen now (first_seen_at on creation; last_seen_at moved when older than the
    granularity), rows the current catalog has not judged are judged, and app rows that are new
    or whose row's answer moved get their copy. Returns the rows judged."""
    rows = (await db.execute(select(InstalledApp).where(InstalledApp.device_id == device.id))).scalars().all()
    if not rows:
        return 0
    now = now or datetime.now(timezone.utc)
    hashes = {row.version_hash for row in rows if row.version_hash}
    existing = {
        entry.version_hash: entry
        for entry in (await db.execute(select(AppCatalogEntry).where(AppCatalogEntry.version_hash.in_(hashes)))).scalars().all()
    }
    for row in rows:
        if not row.version_hash:
            continue
        entry = existing.get(row.version_hash)
        if entry is None:
            entry = AppCatalogEntry(
                name=row.name,
                bundle_id=row.bundle_id,
                version=row.version,
                short_version=row.short_version,
                app_hash=row.app_hash,
                version_hash=row.version_hash,
                key_title=row.key_title,
                key_full=row.key_full,
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(entry)
            existing[row.version_hash] = entry
        elif entry.last_seen_at is None or now - entry.last_seen_at >= LAST_SEEN_GRANULARITY:
            entry.last_seen_at = now
    await db.flush()

    catalog = await load_catalog(db)
    signature = catalog_signature(catalog)
    stale = [entry for entry in existing.values() if entry.evaluated_signature != signature]
    judged = await evaluate_entries(db, stale, catalog, now=now)
    moved = {entry.version_hash for entry in stale}
    for row in rows:
        entry = existing.get(row.version_hash)
        if entry is None:
            continue
        # A copy costs an UPDATE per app row; only when the row is new (no answer yet) or the
        # catalog row it points at was just judged. Refreshes after a catalog sync update the
        # copies in bulk (refresh_tenant).
        if row.last_patch_check_at is None or row.version_hash in moved:
            copy_answer(entry, row, now=now)
    return judged


async def refresh_tenant(db: AsyncSession, *, force: bool = False, now: datetime | None = None) -> int:
    """Re-judge the tenant's rows whose answer predates the current catalog (all of them with
    `force`), and refresh the copies on `installed_apps`. Returns the rows judged."""
    now = now or datetime.now(timezone.utc)
    catalog = await load_catalog(db)
    signature = catalog_signature(catalog)
    stmt = select(AppCatalogEntry)
    if not force:
        stmt = stmt.where((AppCatalogEntry.evaluated_signature.is_(None)) | (AppCatalogEntry.evaluated_signature != signature))
    entries = (await db.execute(stmt)).scalars().all()
    judged = await evaluate_entries(db, entries, catalog, now=now)
    for entry in entries:
        await db.execute(
            update(InstalledApp)
            .where(InstalledApp.version_hash == entry.version_hash)
            .values(
                jamf_title_ids=entry.jamf_title_ids,
                patch_state=entry.patch_state,
                is_compliant=entry.is_latest,
                patch_available=entry.patch_available,
                patch_available_since=entry.patch_available_since,
                releases_missed=entry.releases_missed,
                this_version_seen=entry.this_version_seen,
                latest_version=entry.latest_version,
                latest_released_at=entry.latest_released_at,
                last_patch_check_at=now,
            )
        )
    if judged:
        logger.info("app catalog refreshed", extra={"rows": judged, "signature": signature})
    return judged
