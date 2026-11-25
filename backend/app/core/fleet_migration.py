"""Installed Jamf Mac apps beside the Fleet titles carrying their bundle identifiers (#895), and observed upgrades (#900)."""

from collections import defaultdict
from datetime import datetime, timedelta
from statistics import median

from sqlalchemy import Integer, String, and_, any_, bindparam, distinct, func, or_, select, text, tuple_
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.device_scope import rule_predicate, scoped_devices
from app.core.fleet_assessment import _in_array
from app.core.patch_plans import release_order
from app.mdm.patch.requirements import version_tuple
from app.models.schema import Device, DeviceChange, FleetAppVersion, FleetMaintainedApp, InstalledApp
from app.schemas.fleet_migration import FleetCandidate, InstalledBuild, LocalApp, MigrationScope, ObservedChanges, VersionImpact
from app.schemas.patch_plans import DeviceScope, ScopeRule

OBSERVED_DAYS = 90  # The window observed upgrades cover (#900); `windowDays` repeats it.
_VERSION_KEYS = ("version", "cfBundleShortVersionString", "cfBundleVersion")
_PLAIN = r"^[0-9]+(\.[0-9]+)*$"


async def cohort(db: AsyncSession, scope: DeviceScope, now: datetime):
    """The selected Macs' CTE and its counts. Eligible: the same connection and style, no conditions. Unknown: what
    *is unknown* selects. Both CTEs are named `patch_plan_devices`, so each is read in its own statement."""
    eligible = scoped_devices(DeviceScope(connection_id=scope.connection_id, mode=scope.mode), now)
    unknown = [func.count().filter(rule_predicate(ScopeRule(field=f, operator="unknown"), now)) for f in ("contact", "inventory")]
    total, contact, inventory = (
        await db.execute(select(func.count(), *unknown).select_from(Device).join(eligible, eligible.c.id == Device.id))
    ).one()
    selected = scoped_devices(scope, now)
    counts = MigrationScope(eligible_macs=total, unknown_contact_macs=contact, unknown_inventory_macs=inventory)
    counts.selected_macs = await db.scalar(select(func.count()).select_from(selected))
    return counts, selected


async def title_index(db: AsyncSession, *, bundle_id: str | None = None) -> dict[str, list[FleetMaintainedApp]]:
    titles = select(FleetMaintainedApp).order_by(FleetMaintainedApp.slug)
    if bundle_id is not None:
        titles = titles.where(FleetMaintainedApp.bundle_id == bundle_id)
    by_bundle = defaultdict(list)
    for title in await db.scalars(titles):
        by_bundle[title.bundle_id].append(title)
    return by_bundle


def _installs(devices, *columns):
    return select(*columns).select_from(InstalledApp).join(devices, devices.c.id == InstalledApp.device_id)


def _identified(bundle_id: str, name: str) -> bool:
    # A blank bundle identifier, or one that repeats the app's name, identifies nothing to match.
    return bool(bundle_id.strip()) and bundle_id != name


def fleet_match(bundle_id: str, name: str, candidates: list, *, assumed: bool, jamf_titles: int, catalog_complete: bool) -> str:
    """Whether one Fleet title can stand for this installed identity.

    `exact` is one title in a complete snapshot, no EA-assumed build and at most one Jamf title.
    One known divergence: patch_plans.build_snapshot also withholds its Fleet target when that one
    cached Jamf title is missing from some builds or Macs; this still reads `exact` (docs/fleet-catalog.md)."""
    if not _identified(bundle_id, name):
        return "unknown"
    if len(candidates) > 1 or (candidates and (assumed or jamf_titles > 1)):
        return "ambiguous"
    if not catalog_complete:
        return "unknown"
    return "exact" if candidates else "none"


async def local_apps(
    db: AsyncSession, devices, titles, jamf_names, fleet_ready: bool, *, app_hash: str | None = None, bundle_id: str | None = None
) -> tuple[list[LocalApp], set[str]]:
    """One row per installed identity (name and bundle ID) on the selected Macs, and the cached Jamf titles they match."""
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
    rows, jamf_ids = [], set()
    for row in (await db.execute(query.order_by(func.lower(app.name), app.app_hash))).all():
        # Every Jamf title id claimed decides the match, as build_snapshot counts; only cached ids make a Jamf match.
        claimed = {key for group in row.jamf_matches or [] for key in group}
        matched = {key for key in claimed if key in jamf_names}
        jamf_ids |= matched
        candidates = titles.get(row.bundle_id, []) if _identified(row.bundle_id, row.name) else []
        match = fleet_match(
            row.bundle_id, row.name, candidates, assumed=bool(row.assumed), jamf_titles=len(claimed), catalog_complete=fleet_ready
        )
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


async def build_spread(db: AsyncSession, devices, identities) -> tuple[list[InstalledBuild], int]:
    """Each build of `identities` on the selected Macs with its distinct Macs, and the distinct Macs carrying any."""
    app, hashes = InstalledApp, [item.app_hash for item in identities]
    macs, build = func.count(distinct(app.device_id)), (app.app_hash, app.version_hash, app.version, app.short_version)
    rows = await db.execute(
        _installs(devices, *build, macs.label("macs"))
        .where(_in_array(app.app_hash, "app_hashes", hashes))
        .group_by(*build)
        .order_by(macs.desc(), app.version, app.version_hash)
    )
    installed = await db.scalar(_installs(devices, macs).where(_in_array(app.app_hash, "app_hashes", hashes)))
    return [InstalledBuild.model_validate(row) for row in rows], installed


async def impact_for(db: AsyncSession, devices, identities, builds, target: str | None, installed_macs: int):
    """Each Mac once: older when any copy is older than `target`; else unknown when a copy cannot be ordered; else at or
    above. None for a target holding no number or an identity that is not `exact`."""
    if not target or not version_tuple(target) or any(item.match != "exact" for item in identities):
        return None
    orders = {build.version_hash: release_order(build.version, target) for build in builds}
    older = [key for key, order in orders.items() if order is not None and order < 0]
    unordered = [key for key, order in orders.items() if order is None]
    app = InstalledApp
    per_mac = (
        _installs(
            devices,
            app.device_id,
            func.bool_or(_in_array(app.version_hash, "older", older)).label("older"),
            func.bool_or(_in_array(app.version_hash, "unordered", unordered)).label("unordered"),
        )
        .where(_in_array(app.app_hash, "app_hashes", [item.app_hash for item in identities]))
        .group_by(app.device_id)
        .subquery()
    )
    counts = select(func.count().filter(per_mac.c.older), func.count().filter(~per_mac.c.older, per_mac.c.unordered))
    old, unknown = (await db.execute(counts.select_from(per_mac))).one()
    macs = {"installed_macs": installed_macs, "older_macs": old, "at_or_above_macs": installed_macs - old - unknown}
    return VersionImpact(target_version=target, unknown_macs=unknown, **macs)


def _moves(identities, *columns):
    """Application `updated` rows of one of `identities` where a version moved with both sides present (a missing side
    makes `!=` null, never true). A row with no bundle ID is matched under its name, as inventory stores the app."""
    c = DeviceChange
    name = c.entry_identity["name"].astext
    bundle = func.coalesce(func.nullif(c.entry_identity["bundleId"].astext, ""), name)
    return (
        select(*columns)
        .select_from(c)
        .where(
            c.subject_kind == "computer",
            c.section == "applications",
            c.change == "updated",
            tuple_(name, bundle).in_([(item.name, item.bundle_id) for item in identities]),
            or_(*(c.old_value[key].astext != c.new_value[key].astext for key in _VERSION_KEYS)),
        )
    )


def _ordered(old_value, new_value):
    """Both `version`s, and what lets `release_order` order them: plain dotted numbers, and a short version, where Jamf
    sends one, equal to `version`, the marketing version (`cfBundleVersion` can be an unrelated build number)."""
    old, new = old_value["version"].astext, new_value["version"].astext
    short = [(value["cfBundleShortVersionString"].astext, version) for value, version in ((old_value, old), (new_value, new))]
    agree = [or_(value.is_(None), value == version) for value, version in short]
    return old, new, [old.op("~")(_PLAIN), new.op("~")(_PLAIN), func.length(old) <= 64, *agree]


def _upgrade(old: str, new: str) -> bool:
    return (release_order(old, new) or 0) < 0


def _mac(columns):
    return columns.mdm_connection_id, columns.subject_id  # The change log's key for a Mac.


async def _first_upgrades(db: AsyncSession, identities, window, slug: str, since: datetime, now: datetime) -> dict:
    """(connection, Jamf id, version) -> (first recorded upgrade in `window`, Fleet's date), for versions `slug`'s history
    dated, kept when on or after that date. A pair goes when its Mac upgraded to the version before the window too."""
    log, fleet = window.c, FleetAppVersion
    old, new, ordered = _ordered(log.old_value, log.new_value)
    dated = select(*_mac(log), old, new, fleet.seen_at, func.min(log.observed_at)).select_from(window)
    dated = dated.join(fleet, and_(fleet.slug == slug, fleet.version == new)).where(fleet.seen_at <= now, *ordered)
    first = {}
    for connection, subject, previous, version, published, seen in await db.execute(
        dated.group_by(*_mac(log), old, new, fleet.seen_at)
    ):
        key = (connection, subject, version)
        if _upgrade(previous, version) and (key not in first or seen < first[key][0]):
            first[key] = (seen, published)
    first = {key: dates for key, dates in first.items() if dates[0] >= dates[1]}  # Before Fleet's date never counts.
    if first:  # Before the window, for these Macs and versions only (ix_device_changes_subject). A rollback is no upgrade.
        c = DeviceChange
        old, new, ordered = _ordered(c.old_value, c.new_value)
        connections, subjects, versions = (sorted({key[n] for key in first}) for n in range(3))
        macs = c.mdm_connection_id == any_(bindparam("connections", connections, type_=ARRAY(Integer)))
        earlier = _moves(identities, *_mac(c), old, new).where(macs, _in_array(c.subject_id, "subjects", subjects))
        earlier = earlier.where(_in_array(new, "versions", versions), c.observed_at < since, *ordered)
        for connection, subject, previous, version in await db.execute(earlier):
            if _upgrade(previous, version):
                first.pop((connection, subject, version), None)
    return first


async def local_changes(db: AsyncSession, devices, identities, now: datetime, slug: str | None) -> ObservedChanges:
    """`identities`' version moves on the selected Macs in the last OBSERVED_DAYS (#900) and, given the one Fleet title
    they share (`slug`), the days from Fleet's date to each Mac's first recorded upgrade to a version it dated."""
    since, c = now - timedelta(days=OBSERVED_DAYS), DeviceChange
    changes, macs, last_at, first = 0, 0, None, {}
    if identities:
        # Each statement planned for this call's Macs: a cached generic plan reads a thousand paired Macs' history as it
        # reads fifty, an index scan per Mac, where one sequential read was three times quicker (#900). This transaction only.
        await db.execute(text("SELECT set_config('plan_cache_mode', 'force_custom_plan', true)"))
        # Bounded below by the window, so a time index serves it; a row dated after `now` never counts. A semi-join, not a
        # join: the JSON filters are estimated at one row, and a join planned on that compares every row with every Mac.
        scoped = tuple_(*_mac(c)).in_(select(devices.c.mdm_connection_id, devices.c.external_id))
        window = _moves(identities, *_mac(c), c.observed_at, c.old_value, c.new_value)
        window = window.where(scoped, c.observed_at >= since, c.observed_at <= now).cte("observed_moves")
        tally = select(func.count(), func.count(distinct(tuple_(*_mac(window.c)))), func.max(window.c.observed_at))
        changes, macs, last_at = (await db.execute(tally.select_from(window))).one()
        if slug and changes:
            first = await _first_upgrades(db, identities, window, slug, since, now)
    delays = [(seen - published).total_seconds() / 86_400 for seen, published in first.values()]
    return ObservedChanges(
        window_days=OBSERVED_DAYS,
        version_changes=changes,
        macs=macs,
        last_at=last_at,
        adoption_samples=len(delays) if slug else None,
        median_days_after_fleet_publication=round(median(delays), 2) if delays else None,
    )
