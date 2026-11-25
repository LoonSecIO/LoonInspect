"""The Fleet catalog's migration report (#895): read-only, over inventory and catalogs the instance already holds."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.fleet_catalog import _SLUG, _not_held
from app.api.settings import patching_rules
from app.core import fleet_catalog
from app.core.auth import Principal, current_principal, principal_permissions, require
from app.core.device_scope import parse_scope
from app.core.device_scope_queries import get_scope_snapshot_db, prepare_scope
from app.core.fleet_assessment import app_assessments, fleet_assessments, installed_evidence
from app.core.fleet_migration import (
    build_spread,
    catalog_device_counts,
    cohort,
    impact_for,
    local_apps,
    local_changes,
    title_index,
)
from app.core.permissions import Permission
from app.core.vuln_library import earned_corpus, loaded_epoch_signature
from app.core.vuln_read import corpus_as_of
from app.models.schema import FleetAppVersion, FleetCatalogState, FleetMaintainedApp, JamfPatchTitle
from app.schemas.fleet_migration import FleetCandidate, JamfTitle, MigrationDetail, MigrationReport, MigrationScope
from app.schemas.patch_plans import DeviceScope

# The scope counts are facts about the Mac population, so device:read as well as app:read.
router = APIRouter(
    prefix="/api/fleet-catalog/migration",
    tags=["fleet-catalog"],
    dependencies=[Depends(require(Permission.APP_READ)), Depends(require(Permission.DEVICE_READ))],
)

_NOT_IN_SCOPE = (
    "No Mac the device filter selects has this app in its inventory. Widen or clear the device filter; an app removed "
    "from every Mac is no longer listed."
)
_TARGET = Query(None, alias="targetVersion", min_length=1, max_length=64)


def _not_in_history(target: str, title: FleetMaintainedApp) -> HTTPException:
    missing = f"Fleet's version history, as this instance holds it, does not list {target} for {title.name}."
    choose = f"Choose Fleet's latest version ({title.latest_version}) or a version the title's history lists"
    return HTTPException(status_code=422, detail=f"{missing} {choose}; Read history reads that history again.")


def device_filter(device_scope: str | None = Query(None, alias="deviceScope", max_length=12000)) -> DeviceScope:
    return parse_scope(device_scope)


async def _report_context(db: AsyncSession, scope: DeviceScope, now: datetime):
    await prepare_scope(db, scope)
    counts, devices = await cohort(db, scope, now)
    state = await db.get(FleetCatalogState, 1)
    jamf = dict((await db.execute(select(JamfPatchTitle.id, JamfPatchTitle.name))).all())
    context = {
        "as_of": now,
        "scope": counts,
        "fleet_catalog_ready": bool(state and state.snapshot_status == "complete"),
        "fleet_catalog_readiness": state.snapshot_status if state else "unread",
        "jamf_catalog_ready": bool(jamf),
    }
    return context, devices, jamf


async def _evidence(db: AsyncSession, devices, items):
    """The response's one corpus read, which the caller hands its assessments, and `items`' evidence (all apps if None)."""
    corpus = await earned_corpus(db)
    stamp = corpus_as_of(corpus)
    epoch = loaded_epoch_signature() if stamp is not None else None
    hashes = None if items is None else [item.app_hash for item in items]
    return await installed_evidence(db, devices, as_of=stamp, epoch=epoch, app_hashes=hashes), corpus, stamp, epoch


def _safe_apps(items, titles):
    """Each `exact` app with its one Fleet title: the only identities an assessment may speak for."""
    return {item.app_hash: titles[item.bundle_id][0] for item in items if item.match == "exact"}


@router.get("", response_model=MigrationReport)
async def migration_report(
    scope: DeviceScope = Depends(device_filter), db: AsyncSession = Depends(get_scope_snapshot_db)
) -> MigrationReport:
    """Each app on the Macs `deviceScope` selects, with the Fleet titles that carry its bundle identifier."""
    return await read_migration(scope, db)


async def read_migration(scope: DeviceScope, db: AsyncSession) -> MigrationReport:
    now = datetime.now(UTC)
    if not await fleet_catalog.enabled(db):
        return MigrationReport(enabled=False, as_of=now, scope=MigrationScope())
    context, devices, jamf = await _report_context(db, scope, now)
    evidence, corpus, _, epoch = await _evidence(db, devices, None)
    titles = await title_index(db)
    items, _ = await local_apps(db, devices, titles, jamf, context["fleet_catalog_ready"])
    return MigrationReport(
        **context,
        items=items,
        installed_evidence=evidence,
        fleet_device_counts=await catalog_device_counts(db, devices, items, titles),
        app_assessments=await app_assessments(
            db, _safe_apps(items, titles), eligible_devices=devices, corpus=corpus, epoch=epoch, rules=await patching_rules(db)
        ),
    )


def _why_no_impact(ready: bool, comparison: FleetMaintainedApp | None, items) -> str:
    if not ready:
        return "catalog_incomplete"  # snapshot partial or unread
    if comparison is None and items and items[0].match == "none":
        return "no_fleet_title"
    if comparison is None or any(item.match != "exact" for item in items):
        return "identity_review"
    return "unordered_target"  # impact_for: the target holds no number


async def _detail(
    db: AsyncSession, scope: DeviceScope, app_hash: str | None, slug: str | None, target: str | None, *, include_ids: bool
) -> MigrationDetail:
    if not await fleet_catalog.enabled(db):
        raise HTTPException(status_code=409, detail=fleet_catalog.FLAG_OFF)
    title = await db.get(FleetMaintainedApp, slug) if slug is not None else None
    if slug is not None and title is None:
        raise _not_held(slug)
    context, devices, jamf = await _report_context(db, scope, datetime.now(UTC))
    bundle = title.bundle_id if title is not None else None
    titles = await title_index(db, bundle_id=bundle)
    ready = context["fleet_catalog_ready"]
    items, matched = await local_apps(db, devices, titles, jamf, ready, app_hash=app_hash, bundle_id=bundle)
    if app_hash is not None and not items:
        raise HTTPException(status_code=404, detail=_NOT_IN_SCOPE)
    safe_apps = _safe_apps(items, titles)
    comparison = (title or safe_apps.get(app_hash)) if ready else None
    if comparison is not None:
        target = target or comparison.latest_version
        listed = select(FleetAppVersion.version).where(FleetAppVersion.slug == comparison.slug, FleetAppVersion.version == target)
        if target != comparison.latest_version and await db.scalar(listed) is None:
            raise _not_in_history(target, comparison)
    builds, installed_macs = await build_spread(db, devices, items)
    evidence, corpus, _, epoch = await _evidence(db, devices, items)
    read = {"eligible_devices": devices, "corpus": corpus, "epoch": epoch, "rules": await patching_rules(db)}
    read |= {"include_builds": True, "include_ids": include_ids, "target_version": target}
    impact = await impact_for(db, devices, items, builds, target, installed_macs) if comparison is not None else None
    timed = comparison is not None and all(item.match == "exact" for item in items)  # one Fleet title to date against
    return MigrationDetail(
        **context,
        observed_changes=await local_changes(db, devices, items, context["as_of"], comparison.slug if timed else None),
        installed_evidence=evidence,
        app_assessments=await app_assessments(db, safe_apps, **read),
        assessments=await fleet_assessments(db, [title], **read) if timed and title is not None else {},
        item=items[0] if app_hash is not None else None,
        title=FleetCandidate.model_validate(title) if title is not None else None,
        items=items,
        builds=builds,
        jamf_titles=[JamfTitle(id=key, name=jamf[key]) for key in sorted(matched)],
        installed_macs=installed_macs,
        impact=impact,
        impact_unavailable=None if impact is not None else _why_no_impact(ready, comparison, items),
    )


@router.get("/apps/{app_hash}", response_model=MigrationDetail)
async def read_app(
    app_hash: str = Path(pattern=r"^[0-9a-f]{32}$"),
    target_version: str | None = _TARGET,
    scope: DeviceScope = Depends(device_filter),
    db: AsyncSession = Depends(get_scope_snapshot_db),
    principal: Principal = Depends(current_principal),
) -> MigrationDetail:
    """One installed app on the Macs `deviceScope` selects: its builds, Jamf Patch titles and a Fleet target's impact."""
    include_ids = Permission.VULN_READ in principal_permissions(principal)
    return await _detail(db, scope, app_hash, None, target_version, include_ids=include_ids)


@router.get("/titles/{slug}", response_model=MigrationDetail)
async def read_title(
    slug: str = _SLUG,
    target_version: str | None = _TARGET,
    scope: DeviceScope = Depends(device_filter),
    db: AsyncSession = Depends(get_scope_snapshot_db),
    principal: Principal = Depends(current_principal),
) -> MigrationDetail:
    """One Fleet title and every app with its bundle ID, as `/apps` answers one. Finding IDs need `vuln:read` on both."""
    include_ids = Permission.VULN_READ in principal_permissions(principal)
    return await _detail(db, scope, None, slug, target_version, include_ids=include_ids)
