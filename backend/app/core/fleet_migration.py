"""Read the Jamf Mac population once per query, before grouping inventory into software identities."""

import re
from collections import defaultdict
from datetime import datetime, timedelta
from statistics import median

from sqlalchemy import String, and_, any_, bindparam, distinct, func, or_, select, tuple_
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession

from app.mdm.patch.requirements import compare_versions, version_tuple
from app.models.schema import Device, DeviceChange, FleetAppVersion, FleetMaintainedApp, InstalledApp
from app.observations.departure import gone_for_good
from app.schemas.fleet_migration import (
    Clock,
    FleetCandidate,
    InstalledBuild,
    LocalApp,
    MigrationScope,
    ObservedChanges,
    VersionImpact,
)

_NUMERIC_RELEASE = re.compile(r"[vV]?([0-9]+(?:\.[0-9]+)*)")


def release_order(installed: str, target: str) -> int | None:
    """Compare dotted marketing versions. Qualifiers need product-specific ordering."""
    if installed == target and version_tuple(installed):
        return 0
    left, right = _NUMERIC_RELEASE.fullmatch(installed.strip()), _NUMERIC_RELEASE.fullmatch(target.strip())
    if not left or not right:
        return None
    return compare_versions(left[1], right[1])


async def device_scope(db: AsyncSession, connection_id: int | None, clock: Clock, days: int | None, now: datetime):
    clock_column = Device.last_check_in if clock == "contact" else Device.last_inventory_at
    population = select(
        Device.id, Device.mdm_connection_id, Device.external_id, Device.last_check_in, Device.last_inventory_at
    ).where(
        Device.platform == "macos",
        Device.mdm_provider == "jamf",
        ~gone_for_good(Device.mdm_connection_id, Device.external_id, at=now),
    )
    if connection_id is not None:
        population = population.where(Device.mdm_connection_id == connection_id)
    eligible = population.cte("eligible_migration_macs")
    selected = select(eligible)
    totals = select(func.count()).select_from(eligible)
    if days is None:
        count = await db.scalar(totals)
        scope = MigrationScope(connection_id=connection_id, clock=clock, eligible_macs=count, active_macs=count)
    else:
        stamp = eligible.c[clock_column.key]
        since = now - timedelta(days=days)
        within_window = stamp.between(since, now)
        unusable_date = or_(stamp.is_(None), stamp > now)
        total, active, unknown = (
            await db.execute(totals.add_columns(func.count().filter(within_window), func.count().filter(unusable_date)))
        ).one()
        selected = selected.where(within_window)
        scope = MigrationScope(
            connection_id=connection_id,
            clock=clock,
            days=days,
            eligible_macs=total,
            active_macs=active,
            stale_macs=total - active - unknown,
            unknown_macs=unknown,
        )
    return scope, selected.cte("selected_migration_macs")


async def title_index(db: AsyncSession, *, bundle_id: str | None = None):
    titles = select(FleetMaintainedApp).order_by(FleetMaintainedApp.slug)
    if bundle_id is not None:
        titles = titles.where(FleetMaintainedApp.bundle_id == bundle_id)
    by_bundle = defaultdict(list)
    for title in await db.scalars(titles):
        by_bundle[title.bundle_id].append(title)
    return by_bundle


def _installs(devices, *columns):
    return select(*columns).select_from(InstalledApp).join(devices, devices.c.id == InstalledApp.device_id)


async def local_apps(db: AsyncSession, devices, titles, jamf_names, fleet_ready: bool, *, app_hash=None, bundle_id=None):
    app = InstalledApp
    query = _installs(
        devices,
        app.app_hash,
        app.name,
        app.bundle_id,
        func.count(distinct(app.device_id)).label("macs"),
        func.count(distinct(app.version_hash)).label("versions"),
        func.jsonb_agg(distinct(app.jamf_title_ids)).filter(app.jamf_title_ids.is_not(None)).label("jamf_matches"),
        func.bool_and(app.last_patch_check_at.is_not(None)).label("jamf_evaluated"),
        func.bool_or(app.ea_assumed).label("assumed"),
    ).group_by(app.app_hash, app.name, app.bundle_id)
    if app_hash is not None:
        query = query.where(app.app_hash == app_hash)
    if bundle_id is not None:
        query = query.where(app.bundle_id == bundle_id, app.bundle_id != app.name)
    rows = []
    jamf_ids = set()
    for row in (await db.execute(query.order_by(func.lower(app.name), app.app_hash))).all():
        matched = {key for group in row.jamf_matches or [] for key in group if key in jamf_names}
        jamf_ids.update(matched)
        known_id = bool(row.bundle_id.strip()) and row.bundle_id != row.name
        candidates = titles.get(row.bundle_id, []) if known_id else []
        if not known_id:
            match = "unknown"
        elif len(candidates) > 1 or (candidates and (row.assumed or len(matched) > 1)):
            match = "ambiguous"
        elif not fleet_ready:
            match = "unknown"
        elif not candidates:
            match = "none"
        else:
            match = "exact"
        rows.append(
            LocalApp(
                app_hash=row.app_hash,
                name=row.name,
                bundle_id=row.bundle_id,
                macs=row.macs,
                version_count=row.versions,
                has_jamf_match=bool(matched),
                jamf_evaluated=bool(matched or (row.jamf_evaluated and jamf_names)),
                match=match,
                fleet_candidates=[FleetCandidate.model_validate(title) for title in candidates],
            )
        )
    return rows, jamf_ids


async def catalog_device_counts(db, devices, items, titles):
    """A single local identity already counts distinct Macs. Re-count only bundles shared by multiple identities."""
    counts = {}
    overlapping = set()
    for item in items:
        if not item.fleet_candidates:
            continue
        if item.bundle_id in counts:
            overlapping.add(item.bundle_id)
        counts[item.bundle_id] = item.macs
    if overlapping:
        app = InstalledApp
        bundles = bindparam("shared_bundles", sorted(overlapping), type_=ARRAY(String()))
        counts.update(
            (
                await db.execute(
                    _installs(devices, app.bundle_id, func.count(distinct(app.device_id)))
                    .where(app.bundle_id == any_(bundles), app.bundle_id != app.name)
                    .group_by(app.bundle_id)
                )
            ).all()
        )
    return {title.slug: counts.get(bundle, 0) for bundle, group in titles.items() for title in group}


async def build_spread(db, devices, identities):
    app = InstalledApp
    hashes = [item.app_hash for item in identities]
    if not hashes:
        return [], 0
    query = _installs(
        devices, app.app_hash, app.version_hash, app.version, app.short_version, func.count(distinct(app.device_id)).label("macs")
    ).where(app.app_hash.in_(hashes))
    rows = await db.execute(
        query.group_by(app.app_hash, app.version_hash, app.version, app.short_version).order_by(
            func.count(distinct(app.device_id)).desc(), app.version, app.version_hash
        )
    )
    builds = [InstalledBuild.model_validate(row) for row in rows]
    installed = await db.scalar(_installs(devices, func.count(distinct(app.device_id))).where(app.app_hash.in_(hashes)))
    return builds, installed


async def impact_for(db, devices, identities, builds, target, installed_macs):
    """Any older copy counts a Mac once; unknown takes precedence over a known current copy."""
    if not target or not version_tuple(target) or any(item.match != "exact" for item in identities):
        return None
    if not builds:
        return VersionImpact(target_version=target, installed_macs=0, older_macs=0, at_or_above_macs=0, unknown_macs=0)
    orders = {build.version_hash: release_order(build.version, target) for build in builds}
    old = [key for key, order in orders.items() if order is not None and order < 0]
    unreadable = [key for key, order in orders.items() if order is None]
    app = InstalledApp
    per_mac = (
        _installs(
            devices,
            app.device_id,
            func.bool_or(app.version_hash.in_(old)).label("older"),
            func.bool_or(app.version_hash.in_(unreadable)).label("unreadable"),
        )
        .where(app.app_hash.in_([item.app_hash for item in identities]))
        .group_by(app.device_id)
        .subquery()
    )
    older, unknown = (
        await db.execute(
            select(
                func.count().filter(per_mac.c.older), func.count().filter(and_(~per_mac.c.older, per_mac.c.unreadable))
            ).select_from(per_mac)
        )
    ).one()
    return VersionImpact(
        target_version=target,
        installed_macs=installed_macs,
        older_macs=older,
        at_or_above_macs=installed_macs - older - unknown,
        unknown_macs=unknown,
    )


async def local_changes(db, devices, identities, now, fleet_slug: str | None = None):
    """Count inventory observations and date recorded upgrades against the matched Fleet channel."""
    if not identities:
        return ObservedChanges()
    c = DeviceChange
    since = now - timedelta(days=90)
    changes = (
        select(
            devices.c.id.label("mac"),
            c.observed_at,
            c.old_value,
            c.new_value,
        )
        .select_from(c)
        .join(devices, and_(c.mdm_connection_id == devices.c.mdm_connection_id, c.subject_id == devices.c.external_id))
        .where(
            c.subject_kind == "computer",
            c.section == "applications",
            c.change == "updated",
            c.observed_at <= now,
            tuple_(c.entry_identity["name"].astext, c.entry_identity["bundleId"].astext).in_(
                [(item.name, item.bundle_id) for item in identities]
            ),
            or_(
                *(
                    and_(
                        c.old_value[key].astext.is_not(None),
                        c.new_value[key].astext.is_not(None),
                        c.old_value[key].astext != c.new_value[key].astext,
                    )
                    for key in ("version", "cfBundleVersion", "cfBundleShortVersionString")
                )
            ),
        )
    ).cte("matching_app_changes")
    log = changes.c
    query = select(func.count(), func.count(distinct(log.mac)), func.min(log.observed_at), func.max(log.observed_at)).where(
        log.observed_at >= since
    )
    n, macs, first, last = (await db.execute(query)).one()
    result = ObservedChanges(version_changes=n, macs=macs, first_at=first, last_at=last)
    if not fleet_slug or not n:
        return result

    # Jamf's computer inventory reports the marketing version in "version". A separate
    # CFBundleVersion can be an unrelated build number; a conflicting short version or
    # irregular version format cannot establish the ordering of a marketing-version change.
    old = log.old_value["version"].astext
    new = log.new_value["version"].astext
    old_short = log.old_value["cfBundleShortVersionString"].astext
    new_short = log.new_value["cfBundleShortVersionString"].astext
    numeric_version = r"^[0-9]+(\.[0-9]+)*$"
    releases = FleetAppVersion
    dated = (
        select(log.mac, old, new, releases.seen_at, func.min(log.observed_at))
        .select_from(changes)
        .join(releases, and_(releases.slug == fleet_slug, releases.version == new))
        .where(
            releases.seen_at <= now,
            old.op("~")(numeric_version),
            new.op("~")(numeric_version),
            func.length(old) <= 64,
            or_(old_short.is_(None), old_short == old),
            or_(new_short.is_(None), new_short == new),
        )
        .group_by(log.mac, old, new, releases.seen_at)
    )
    # A second upgrade to a release after a rollback must not shift the first observation
    # forward. Include earlier recorded upgrades in the minimum, then apply the 90-day window.
    first_upgrades = {}
    for mac, previous, version, published_at, observed_at in await db.execute(dated):
        order = release_order(previous, version)
        if order is not None and order < 0:
            key = (mac, version)
            if key not in first_upgrades or observed_at < first_upgrades[key][0]:
                first_upgrades[key] = (observed_at, published_at)
    delays = [
        (observed - published).total_seconds() / 86_400
        for observed, published in first_upgrades.values()
        if observed >= since and observed >= published
    ]
    result.adoption_samples = len(delays)
    result.median_days_after_fleet_publication = round(median(delays), 2) if delays else None
    return result
