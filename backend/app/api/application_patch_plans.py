"""Installed-application patch proposals, background evidence, and exact-revision PDF exports."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.providers import Provider
from app.api.changes_prompt import prompt_status
from app.core.audit import audit
from app.core.auth import Principal, current_principal, require
from app.core.database import bound_tenant_id, get_db
from app.core.device_scope import parse_scope, scoped_devices
from app.core.device_scope_proposal import propose_scope
from app.core.device_scope_queries import get_scope_db, get_scope_snapshot_db, prepare_scope
from app.core.patch_plan_pdf import render_pdf
from app.core.patch_plan_research import run_research
from app.core.patch_plans import build_snapshot, plan_output
from app.core.permissions import Permission
from app.models.schema import ApplicationPatchPlan, Device, DeviceExtensionAttribute, MdmConnection, ObservationSpan, Tenant
from app.schemas.patch_plans import BuildPlan, ProposeScope, ResearchPlan, ReviewPlan

router = APIRouter(
    prefix="/api/application-patch-plans",
    tags=["application-patch-plans"],
    dependencies=[Depends(require(Permission.APP_READ)), Depends(require(Permission.DEVICE_READ))],
)


@router.get("/scope-options")
async def scope_options(
    device_scope: str | None = Query(None, alias="deviceScope", max_length=12000),
    db: AsyncSession = Depends(get_scope_snapshot_db),
) -> dict:
    scope = parse_scope(device_scope)
    await prepare_scope(db, scope)
    population = scoped_devices(scope)
    sources = (
        await db.execute(
            select(MdmConnection.id, MdmConnection.name).where(MdmConnection.provider == "jamf").order_by(MdmConnection.name)
        )
    ).all()
    groups = (
        await db.execute(
            select(ObservationSpan.mdm_connection_id, ObservationSpan.subject_id, ObservationSpan.label)
            .where(ObservationSpan.subject_kind == "computer_group", ObservationSpan.is_current.is_(True))
            .order_by(ObservationSpan.label)
            .limit(1500)
        )
    ).all()
    attribute_query = (
        select(DeviceExtensionAttribute.definition_id, DeviceExtensionAttribute.name)
        .join(Device, Device.id == DeviceExtensionAttribute.device_id)
        .where(Device.mdm_provider == "jamf", Device.platform == "macos")
        .distinct()
        .order_by(DeviceExtensionAttribute.name)
        .limit(1500)
    )
    if scope.connection_id is not None:
        attribute_query = attribute_query.where(Device.mdm_connection_id == scope.connection_id)
    attributes = (await db.execute(attribute_query)).all()
    return {
        "devices": await db.scalar(select(func.count()).select_from(population)),
        "connections": [{"id": row.id, "name": row.name} for row in sources],
        "groups": [{"connectionId": row[0], "id": row[1], "name": row[2] or row[1]} for row in groups],
        "attributes": [{"id": row[0], "name": row[1] or row[0]} for row in attributes],
    }


@router.get("/ai-status")
async def ai_status(db: AsyncSession = Depends(get_db)):
    return await prompt_status(db)


@router.post("/propose-scope")
async def propose_group(payload: ProposeScope, db: AsyncSession = Depends(get_scope_db)) -> dict:
    options = await scope_options(payload.scope.model_dump_json(by_alias=True), db)
    return await propose_scope(db, payload, options)


@router.get("")
async def list_plans(db: AsyncSession = Depends(get_db)) -> list[dict]:
    rows = await db.scalars(select(ApplicationPatchPlan).order_by(ApplicationPatchPlan.created_at.desc()).limit(100))
    return [
        {
            "id": str(row.id),
            "title": row.title,
            "createdAt": row.created_at.isoformat(),
            "applications": [{"appHash": a["appHash"], "name": a["name"]} for a in row.snapshot["applications"]],
            "revision": row.revision,
            "researchStatus": row.research_status,
        }
        for row in rows
    ]


@router.post("", status_code=201, dependencies=[Depends(require(Permission.PATCH_PLAN_WRITE))])
async def build_plan(
    payload: BuildPlan, db: AsyncSession = Depends(get_scope_snapshot_db), principal: Principal = Depends(current_principal)
) -> dict:
    organization = await db.get(Tenant, bound_tenant_id(db))
    snapshot = await build_snapshot(db, payload, organization.name if organization else "Organization")
    plan = ApplicationPatchPlan(title=payload.title, created_by=principal.account.email, snapshot=snapshot)
    db.add(plan)
    await db.commit()
    result = plan_output(plan)
    audit(
        "patch-plan.created",
        target_type="patch_plan",
        target_id=str(plan.id),
        applications=len(payload.app_hashes),
        revision=plan.revision,
        sha256=result["sha256"],
    )
    return result


async def load_plan(db, plan_id):
    plan = await db.get(ApplicationPatchPlan, plan_id)
    if plan is None:
        raise HTTPException(404, "This patch plan is not available in this organization. Open a saved plan or build a new one.")
    if plan.research_status == "running" and plan.research_started_at < datetime.now(UTC) - timedelta(minutes=6):
        await db.execute(
            update(ApplicationPatchPlan)
            .where(
                ApplicationPatchPlan.id == plan_id,
                ApplicationPatchPlan.research_status == "running",
                ApplicationPatchPlan.research_started_at == plan.research_started_at,
            )
            .values(
                research_status="interrupted",
                revision=ApplicationPatchPlan.revision + 1,
                research={"detail": "The investigation stopped before completion. Check service availability and retry."},
            )
        )
        await db.commit()
        await db.refresh(plan)
    return plan


@router.get("/{plan_id}")
async def read_plan(plan_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> dict:
    return plan_output(await load_plan(db, plan_id))


@router.get("/{plan_id}/pdf")
async def export_plan(plan_id: uuid.UUID, revision: int = Query(ge=1), db: AsyncSession = Depends(get_db)):
    plan = await load_plan(db, plan_id)
    if plan.revision != revision:
        raise HTTPException(
            409, "This plan has new investigation results. Refresh the plan, review the changes, then export again."
        )
    result = plan_output(plan)
    content = await run_in_threadpool(render_pdf, result)
    audit(
        "patch-plan.exported", target_type="patch_plan", target_id=str(plan.id), revision=plan.revision, sha256=result["sha256"]
    )
    return Response(
        content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="patch-plan-{plan.id}-r{plan.revision}.pdf"',
            "Cache-Control": "no-store",
        },
    )


@router.patch("/{plan_id}", dependencies=[Depends(require(Permission.PATCH_PLAN_WRITE))])
async def record_review(
    plan_id: uuid.UUID, payload: ReviewPlan, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)
) -> dict:
    plan = await load_plan(db, plan_id)
    review = {
        **payload.model_dump(exclude={"revision"}),
        "recordedBy": principal.account.email,
        "recordedAt": datetime.now(UTC).isoformat(),
    }
    changed = await db.execute(
        update(ApplicationPatchPlan)
        .where(
            ApplicationPatchPlan.id == plan_id,
            ApplicationPatchPlan.revision == payload.revision,
            ApplicationPatchPlan.research_status != "running",
        )
        .values(snapshot={**plan.snapshot, "operatorReview": review}, revision=ApplicationPatchPlan.revision + 1)
    )
    if not changed.rowcount:
        raise HTTPException(409, "The plan changed or investigation is running. Refresh the plan and retry your review notes.")
    await db.commit()
    await db.refresh(plan)
    result = plan_output(plan)
    audit(
        "patch-plan.review.updated",
        target_type="patch_plan",
        target_id=str(plan_id),
        revision=plan.revision,
        sha256=result["sha256"],
    )
    return result


@router.post("/{plan_id}/research", status_code=202, dependencies=[Depends(require(Permission.PATCH_PLAN_WRITE))])
async def investigate(
    plan_id: uuid.UUID, payload: ResearchPlan, tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)
) -> dict:
    plan = await load_plan(db, plan_id)
    if payload.provider is not None:
        try:
            Provider(payload.provider)
        except ValueError as exc:
            raise HTTPException(422, "Select a saved provider in Settings > AI.") from exc
        status = await prompt_status(db)
        if not status.available:
            raise HTTPException(
                409, "AI assistance is unavailable. Check the AI feature, inference consent and saved provider in Settings > AI."
            )
    if not payload.installomator and not payload.provider:
        raise HTTPException(422, "Select Installomator investigation or an AI provider.")
    tenant = bound_tenant_id(db)
    await db.execute(select(func.pg_advisory_xact_lock(int.from_bytes(tenant.bytes[:8], "big", signed=True))))
    recent = datetime.now(UTC) - timedelta(minutes=6)
    running = await db.scalar(
        select(func.count())
        .select_from(ApplicationPatchPlan)
        .where(ApplicationPatchPlan.research_status == "running", ApplicationPatchPlan.research_started_at > recent)
    )
    if running >= 2:
        raise HTTPException(429, "Two patch-plan investigations are running. Wait for one to finish, then retry.")
    now = datetime.now(UTC)
    changed = await db.execute(
        update(ApplicationPatchPlan)
        .where(ApplicationPatchPlan.id == plan_id, ApplicationPatchPlan.research_status != "running")
        .values(research_status="running", research_started_at=now, research=None, revision=ApplicationPatchPlan.revision + 1)
    )
    if not changed.rowcount:
        raise HTTPException(409, "This plan is already being investigated. Its progress will appear here.")
    await db.commit()
    await db.refresh(plan)
    tasks.add_task(run_research, tenant, plan_id, now, payload.provider, payload.installomator)
    audit("patch-plan.investigation.started", target_type="patch_plan", target_id=str(plan_id), provider=payload.provider)
    return plan_output(plan)
