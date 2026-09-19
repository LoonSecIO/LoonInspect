"""Explicit inventory provider selection and operational summary metrics (#594)."""

from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.providers import Provider
from app.core.ai import ai_features_enabled
from app.core.ai_configs import saved_config
from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.sharing import get_or_create_settings
from app.models.schema import InventorySummaryJob as Job
from app.models.schema import InventorySummaryMetric as Metric
from app.models.schema import InventorySummarySettings as Settings
from app.summaries.diagnostics import REASONS
from app.summaries.service import bucket, now

router = APIRouter(prefix="/api/inventory-summaries", tags=["inventory summaries"])


class Options(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)
    enabled: bool = False
    provider: Literal["apple_fm", "openai_compatible"] = "apple_fm"
    preprompt: str = Field(default="", max_length=500)
    interval_seconds: int = Field(default=2, ge=1, le=60)


@router.get("/settings", dependencies=[Depends(require(Permission.SYSTEM_READ))], response_model=Options)
async def options(db: AsyncSession = Depends(get_db)):
    row = await db.scalar(select(Settings))
    return Options(**{k: getattr(row, k) for k in Options.model_fields}) if row else Options()


@router.put("/settings", dependencies=[Depends(require(Permission.SYSTEM_WRITE))], response_model=Options)
async def save(payload: Options, db: AsyncSession = Depends(get_db)):
    if payload.enabled:
        consent = await get_or_create_settings(db)
        if not await ai_features_enabled(db) or not consent.ai_inference:
            raise HTTPException(409, "Enable AI features and inference consent before enabling inventory summaries.")
        if not await saved_config(db, Provider(payload.provider)):
            raise HTTPException(409, "Save this provider's endpoint first.")
    row = await db.scalar(select(Settings).with_for_update())
    if row is None:
        row = Settings(enabled_at=now())
        db.add(row)
    elif payload.enabled and not row.enabled:
        row.enabled_at = now()
    for key, value in payload.model_dump().items():
        setattr(row, key, value)
    await db.commit()
    audit(
        AuditAction.AI_CONFIG_SAVED, target_type="inventory_summary_settings", enabled=payload.enabled, provider=payload.provider
    )
    return payload


@router.get("/metrics", dependencies=[Depends(require(Permission.SYSTEM_READ))])
async def metrics(db: AsyncSession = Depends(get_db)):
    settings = await db.scalar(select(Settings))
    cutoff = bucket(now() - timedelta(hours=24))
    provider = settings.provider if settings else "apple_fm"
    scope = [Job.created_at >= cutoff, Job.provider == provider]
    counters = [Metric.bucket_at >= cutoff, Metric.provider == provider]
    counts = dict(
        (await db.execute(select(Metric.status, func.sum(Metric.count)).where(*counters).group_by(Metric.status))).all()
    )
    for status, count in (
        await db.execute(
            select(Job.status, func.count()).where(*scope, Job.status.in_(("pending", "processing"))).group_by(Job.status)
        )
    ).all():
        counts[status] = count
    reasons = dict(
        (
            await db.execute(
                select(Metric.reason, func.sum(Metric.count)).where(*counters, Metric.reason != "none").group_by(Metric.reason)
            )
        ).all()
    )
    attempts, average = (
        await db.execute(select(func.coalesce(func.sum(Job.attempts), 0), func.avg(Job.latency_ms)).where(*scope))
    ).one()
    overloads = await db.scalar(select(func.coalesce(func.sum(Job.overloads), 0)).where(*scope))
    oldest = await db.scalar(
        select(func.min(Job.created_at)).where(
            Job.status.in_(("pending", "processing")), Job.provider == (settings.provider if settings else "")
        )
    )
    drops = counts.get("dropped", 0) + counts.get("failed", 0)
    total = sum(counts.values())
    return {
        "reasons": [
            {"reason": reason, "count": count, "nextCheck": REASONS.get(reason, REASONS["internal_error"])}
            for reason, count in reasons.items()
        ],
        "enabled": bool(settings and settings.enabled),
        "provider": settings.provider if settings else None,
        "windowHours": 24,
        "counts": counts,
        "attempts": attempts,
        "overloadJobs": overloads,
        "averageLatencyMs": round(average) if average else None,
        "dropRate": drops / total if total else None,
        "successRate": counts.get("completed", 0) / attempts if attempts else None,
        "oldestQueuedAt": oldest,
        "asOf": now(),
    }
