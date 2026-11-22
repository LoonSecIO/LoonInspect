"""Read-only software migration review using scoped Jamf inventory and locally cached catalogs."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import fleet_catalog
from app.core.auth import Principal, current_principal, principal_permissions, require
from app.core.database import get_snapshot_db
from app.core.fleet_assessment import app_assessments, fleet_assessments, installed_evidence
from app.core.fleet_migration import (
    build_spread,
    catalog_device_counts,
    device_scope,
    impact_for,
    local_apps,
    local_changes,
    title_index,
)
from app.core.permissions import Permission
from app.models.schema import FleetAppVersion, FleetCatalogState, FleetMaintainedApp, JamfPatchTitle, MdmConnection
from app.schemas.fleet_migration import (
    Clock,
    FleetCandidate,
    JamfTitle,
    MigrationDetail,
    MigrationReport,
    MigrationScope,
    SourceConnection,
)

router = APIRouter(
    prefix="/api/fleet-catalog/migration", tags=["fleet-catalog"], dependencies=[Depends(require(Permission.APP_READ))]
)


class Cohort:
    def __init__(
        self,
        connection_id: int | None = Query(None, alias="connectionId", ge=1),
        clock: Clock = "contact",
        days: int | None = Query(None, ge=1, le=3650),
    ):
        self.connection_id, self.clock, self.days = connection_id, clock, days


async def _report_context(db, cohort, now):
    scope, devices = await device_scope(db, cohort.connection_id, cohort.clock, cohort.days, now)
    state = await db.get(FleetCatalogState, 1)
    jamf = dict((await db.execute(select(JamfPatchTitle.id, JamfPatchTitle.name))).all())
    context = {
        "as_of": now,
        "scope": scope,
        "fleet_catalog_ready": bool(state and state.snapshot_status == "complete"),
        "fleet_catalog_readiness": state.snapshot_status if state else "unread",
        "jamf_catalog_ready": bool(jamf),
    }
    return context, devices, jamf


def _safe_apps(items, titles):
    return {item.app_hash: titles[item.bundle_id][0] for item in items if item.match == "exact"}


@router.get("", response_model=MigrationReport)
async def migration_report(
    cohort: Cohort = Depends(), db: AsyncSession = Depends(get_snapshot_db), principal: Principal = Depends(current_principal)
) -> MigrationReport:
    """Current Jamf Mac inventory for the selected connection and activity window. Omit days to include all timestamps."""
    return await read_migration(cohort, db, show_connections=Permission.CONNECTION_READ in principal_permissions(principal))


async def read_migration(cohort: Cohort, db: AsyncSession, *, show_connections: bool = False) -> MigrationReport:
    """The cohort includes current Jamf Mac records in this organization. Omit days to include every timestamp."""
    now = datetime.now(UTC)
    if not await fleet_catalog.enabled(db):
        return MigrationReport(enabled=False, as_of=now, scope=MigrationScope())
    context, devices, jamf = await _report_context(db, cohort, now)
    titles = await title_index(db)
    items, _ = await local_apps(db, devices, titles, jamf, context["fleet_catalog_ready"])
    connections = []
    if show_connections:
        connections = (
            await db.execute(
                select(MdmConnection.id, MdmConnection.name)
                .where(MdmConnection.provider == "jamf")
                .order_by(MdmConnection.name, MdmConnection.id)
            )
        ).all()
    return MigrationReport(
        **context,
        installed_evidence=await installed_evidence(db, devices, items),
        items=items,
        connections=[SourceConnection.model_validate(row) for row in connections],
        fleet_device_counts=await catalog_device_counts(db, devices, items, titles),
        app_assessments=await app_assessments(db, _safe_apps(items, titles), eligible_devices=devices),
    )


async def _detail(db, cohort, app_hash, slug, target, *, include_ids: bool):
    now = datetime.now(UTC)
    if not await fleet_catalog.enabled(db):
        raise HTTPException(409, fleet_catalog.FLAG_OFF)
    title = None
    if slug is not None:
        title = await db.get(FleetMaintainedApp, slug)
        if title is None:
            raise HTTPException(
                404, "This Fleet title is absent from the cached catalog. Reopen the catalog and check its last refresh."
            )
    context, devices, jamf = await _report_context(db, cohort, now)
    bundle = title.bundle_id if title is not None else None
    titles = await title_index(db, bundle_id=bundle)
    items, matches = await local_apps(
        db, devices, titles, jamf, context["fleet_catalog_ready"], app_hash=app_hash, bundle_id=bundle
    )
    if app_hash is not None and not items:
        raise HTTPException(
            404,
            "No selected Mac has this Jamf app in inventory. Check the connection and activity window.",
        )
    safe_apps = _safe_apps(items, titles)
    comparison = (title or safe_apps.get(app_hash)) if context["fleet_catalog_ready"] else None
    if target is None and comparison is not None:
        target = comparison.latest_version
    if target is not None and comparison is not None and target != comparison.latest_version:
        held = await db.scalar(
            select(FleetAppVersion.version).where(FleetAppVersion.slug == comparison.slug, FleetAppVersion.version == target)
        )
        if held is None:
            raise HTTPException(
                422,
                "This version is absent from the cached Fleet history. Choose the current version or a listed version.",
            )
    builds, installed_macs = await build_spread(db, devices, items)
    safe_title = comparison is not None and title is not None and all(item.match == "exact" for item in items)
    by_title = (
        await fleet_assessments(
            db, [title], eligible_devices=devices, include_builds=True, include_ids=include_ids, target_version=target
        )
        if safe_title
        else {}
    )
    return MigrationDetail(
        **context,
        installed_evidence=await installed_evidence(db, devices, items),
        title=FleetCandidate.model_validate(title) if title else None,
        item=items[0] if app_hash is not None else None,
        items=items,
        builds=builds,
        jamf_titles=[JamfTitle(id=key, name=jamf[key]) for key in sorted(matches)],
        installed_macs=installed_macs,
        observed_changes=await local_changes(
            db, devices, items, now, comparison.slug if comparison and all(item.match == "exact" for item in items) else None
        ),
        impact=await impact_for(db, devices, items, builds, target, installed_macs) if comparison is not None else None,
        app_assessments=await app_assessments(
            db, safe_apps, eligible_devices=devices, include_builds=True, include_ids=include_ids, target_version=target
        ),
        assessments=by_title,
    )


@router.get("/apps/{app_hash}", response_model=MigrationDetail)
async def read_app(
    app_hash: str = Path(pattern=r"^[0-9a-f]{32}$"),
    target_version: str | None = Query(None, alias="targetVersion", min_length=1, max_length=64),
    cohort: Cohort = Depends(),
    db: AsyncSession = Depends(get_snapshot_db),
    principal: Principal = Depends(current_principal),
) -> MigrationDetail:
    return await _detail(
        db, cohort, app_hash, None, target_version, include_ids=Permission.VULN_READ in principal_permissions(principal)
    )


@router.get("/titles/{slug}", response_model=MigrationDetail)
async def read_title(
    slug: str = Path(pattern=rf"^{fleet_catalog.SLUG_PATTERN}$"),
    target_version: str | None = Query(None, alias="targetVersion", min_length=1, max_length=64),
    cohort: Cohort = Depends(),
    db: AsyncSession = Depends(get_snapshot_db),
    principal: Principal = Depends(current_principal),
) -> MigrationDetail:
    return await _detail(
        db, cohort, None, slug, target_version, include_ids=Permission.VULN_READ in principal_permissions(principal)
    )
