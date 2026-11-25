"""Installed Jamf Mac apps beside the Fleet titles that carry their bundle identifiers (#895)."""

from collections import defaultdict
from datetime import datetime

from sqlalchemy import String, any_, bindparam, distinct, func, select
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.device_scope import rule_predicate, scoped_devices
from app.models.schema import Device, FleetMaintainedApp, InstalledApp
from app.schemas.fleet_migration import FleetCandidate, LocalApp, MigrationScope
from app.schemas.patch_plans import DeviceScope, ScopeRule


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


async def title_index(db: AsyncSession) -> dict[str, list[FleetMaintainedApp]]:
    by_bundle = defaultdict(list)
    for title in await db.scalars(select(FleetMaintainedApp).order_by(FleetMaintainedApp.slug)):
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


async def local_apps(db: AsyncSession, devices, titles, jamf_names, fleet_ready: bool) -> list[LocalApp]:
    """One row per installed identity, a name and bundle identifier, on the selected Macs."""
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
    rows = []
    for row in (await db.execute(query.order_by(func.lower(app.name), app.app_hash))).all():
        # Every Jamf title id claimed decides the match, as build_snapshot counts; only cached ids make a Jamf match.
        claimed = {key for group in row.jamf_matches or [] for key in group}
        matched = {key for key in claimed if key in jamf_names}
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
    return rows


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
