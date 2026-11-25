"""The Fleet catalog's migration report (#895): read-only, over inventory and catalogs the instance already holds."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.settings import patching_rules
from app.core import fleet_catalog
from app.core.auth import require
from app.core.device_scope import parse_scope
from app.core.device_scope_queries import get_scope_snapshot_db, prepare_scope
from app.core.fleet_assessment import app_assessments, installed_evidence
from app.core.fleet_migration import catalog_device_counts, cohort, local_apps, title_index
from app.core.permissions import Permission
from app.core.vuln_library import earned_corpus, loaded_epoch_signature
from app.core.vuln_read import corpus_as_of
from app.models.schema import FleetCatalogState, JamfPatchTitle
from app.schemas.fleet_migration import MigrationReport, MigrationScope
from app.schemas.patch_plans import DeviceScope

# The scope counts are facts about the Mac population, so device:read as well as app:read.
router = APIRouter(
    prefix="/api/fleet-catalog/migration",
    tags=["fleet-catalog"],
    dependencies=[Depends(require(Permission.APP_READ)), Depends(require(Permission.DEVICE_READ))],
)


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
    corpus = await earned_corpus(db)
    stamp = corpus_as_of(corpus)
    epoch = loaded_epoch_signature() if stamp is not None else None
    context, devices, jamf = await _report_context(db, scope, now)
    titles = await title_index(db)
    items = await local_apps(db, devices, titles, jamf, context["fleet_catalog_ready"])
    return MigrationReport(
        **context,
        items=items,
        installed_evidence=await installed_evidence(db, devices, as_of=stamp, epoch=epoch),
        fleet_device_counts=await catalog_device_counts(db, devices, items, titles),
        app_assessments=await app_assessments(
            db, _safe_apps(items, titles), eligible_devices=devices, corpus=corpus, epoch=epoch, rules=await patching_rules(db)
        ),
    )
