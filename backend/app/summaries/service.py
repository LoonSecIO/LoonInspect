"""Consume committed inventory snapshots and deliver independently timed summaries (#594)."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, exists, func, select

from app.ai.adapters import AdapterError, CompletionRequest, complete
from app.ai.providers import HostReach, Provider
from app.api.ai import judged_endpoint
from app.core.ai import AIRefused, ai_features_enabled, require_ai
from app.core.ai_configs import get_config, saved_config
from app.core.auth import as_utc
from app.core.outbox import enqueue_event
from app.core.tenant_jobs import operational_tenant_ids, tenant_job
from app.core.wire import ENVELOPE
from app.models.schema import EventOutbox
from app.models.schema import InventorySummaryJob as Job
from app.models.schema import InventorySummarySettings as Settings
from app.models.schema import InventorySummaryState as State
from app.summaries.evidence import PROMPT_VERSION, SYSTEM, checked_reply, compact, compare, digest, prompt

logger = logging.getLogger(__name__)
EVENT = "device.inventory.summary"
TTL = timedelta(hours=1)
MAX_PENDING = 1000
TERMINAL = ("completed", "cached", "no_updates", "baseline", "incomplete", "dropped", "failed")


def now():
    return datetime.now(UTC)


def config_key(settings, config):
    return digest([settings.provider, settings.preprompt, str(config.updated_at) if config else None, PROMPT_VERSION])


async def finish(db, job, status, summary=None, reason=None):
    """Persist the result and its separate SIEM event atomically, without touching source delivery."""
    job.status, job.summary, job.reason, job.finished_at = status, summary, reason, now()
    if status in ("dropped", "failed"):
        logger.warning(
            "inventory summary dropped",
            extra={
                "summary_id": str(job.id),
                "source_event_id": job.source_id,
                "reason": reason,
                "age_seconds": (now() - as_utc(job.created_at)).total_seconds(),
            },
        )
    body = {
        "event": EVENT,
        "summaryID": str(job.id),
        "sourceEventID": job.source_id,
        "occurredAt": job.source_at.isoformat(),
        "generatedAt": job.finished_at.isoformat(),
        "queuedAt": job.created_at.isoformat(),
        "expiresAt": job.expires_at.isoformat(),
        "deviceMeta": job.correlation["deviceMeta"],
        "summaryStatus": status,
        "summaryProvider": job.provider,
        "promptVersion": PROMPT_VERSION,
        "shortSummary": summary,
        "reason": reason,
        "evidence": job.evidence,
        "advisory": True,
        "corpusAsOf": job.correlation.get("corpusAsOf", []),
        "evidenceScope": ["applications", "os_version_build", "selected_security_fields"],
        ENVELOPE: job.correlation.get(ENVELOPE, {}),
    }
    # Reuse source HEC time, never generation time. Arrival remains Splunk _indextime.
    body[ENVELOPE] = {**body[ENVELOPE], "time": job.source_at.timestamp()}
    await enqueue_event(db, EVENT, body)
    await db.commit()


async def collect(db):
    settings = await db.scalar(select(Settings).with_for_update(skip_locked=True))
    if not settings:
        return
    # Retain receipts beyond the intake lookback, including while inference is disabled.
    # retention-clock: summary-jobs — README.md and KNOWN_ISSUES.md name this clock.
    await db.execute(delete(Job).where(Job.created_at < now() - timedelta(days=8), Job.status.in_(TERMINAL)))
    if not settings.enabled or not await ai_features_enabled(db):
        await db.commit()
        return
    config = await saved_config(db, Provider(settings.provider))
    key = config_key(settings, config)
    events = (
        await db.scalars(
            select(EventOutbox)
            .where(
                EventOutbox.event_type == "device.inventory",
                EventOutbox.created_at >= settings.enabled_at,
                EventOutbox.created_at >= now() - timedelta(days=7),
                ~exists(select(Job.id).where(Job.source_id == EventOutbox.id)),
            )
            .order_by(EventOutbox.id)
            .limit(500)
        )
    ).all()
    pending = await db.scalar(select(func.count()).select_from(Job).where(Job.status.in_(("pending", "processing"))))
    for event in events:
        payload = event.payload
        meta = payload.get("deviceMeta", {})
        # Without stable source identity, don't accidentally compare two devices.
        if not meta.get("connectionID") or not meta.get("jamfProID"):
            continue
        device_key = digest([meta["connectionID"], meta["jamfProID"]])
        source_at = datetime.fromisoformat(payload["occurredAt"].replace("Z", "+00:00"))
        state = await db.get(State, (event.tenant_id, device_key))
        current = compact(payload)
        evidence = compare(state.facts if state else None, current)
        job = Job(
            source_id=event.id,
            created_at=event.created_at,
            expires_at=as_utc(event.created_at) + TTL,
            source_at=source_at,
            provider=settings.provider,
            config_key=key,
            cache_key=digest([key, evidence]),
            evidence=evidence,
            correlation={
                "deviceMeta": meta,
                ENVELOPE: payload.get(ENVELOPE, {}),
                "corpusAsOf": sorted(
                    {
                        item.get("vuln", {}).get("corpusAsOf")
                        for item in (payload.get("app") or [])
                        if item.get("vuln", {}).get("corpusAsOf")
                    }
                ),
            },
            status="pending",
        )
        db.add(job)
        await db.flush()
        if state and source_at < as_utc(state.source_at):
            await finish(db, job, "dropped", reason="stale_observation")
            await db.refresh(settings, with_for_update=True)
            if not settings.enabled:
                break
            continue
        if state:
            state.facts = {**state.facts, **current}
            state.source_at = source_at
        else:
            db.add(State(device_key=device_key, facts=current, source_at=source_at))
        # Commit the state and receipt together before another intake can see this event.
        if job.expires_at <= now():
            await finish(db, job, "dropped", reason="expired")
        elif evidence["kind"] == "unchanged":
            await finish(db, job, "no_updates", "No updates")
        elif evidence["kind"] in ("baseline", "incomplete"):
            await finish(
                db, job, evidence["kind"], "Baseline recorded" if evidence["kind"] == "baseline" else "Incomplete observation"
            )
        elif pending >= MAX_PENDING:
            await finish(db, job, "dropped", reason="capacity")
        else:
            pending += 1
            await db.commit()
        # finish commits; reacquire the settings lock before continuing intake.
        await db.refresh(settings, with_for_update=True)
        if not settings.enabled:
            break
    await db.commit()


async def work_one(tenant_id, *, transport=None):
    async with tenant_job(tenant_id) as db:
        clock = now()
        settings = await db.scalar(select(Settings).with_for_update())
        if not settings:
            return
        # An abandoned lease can be retried after two minutes; its original TTL stands.
        job = await db.scalar(
            select(Job)
            .where(Job.status.in_(("pending", "processing")), Job.next_attempt_at <= clock)
            .order_by(Job.created_at)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if not job:
            return
        if as_utc(job.expires_at) <= clock:
            await finish(db, job, "dropped", reason="expired")
            return
        if not settings.enabled or not await ai_features_enabled(db):
            await finish(db, job, "dropped", reason="disabled")
            return
        config = await get_config(db, Provider(settings.provider))
        if not config or config_key(settings, config) != job.config_key:
            await finish(db, job, "dropped", reason="configuration_changed")
            return
        cached = await db.scalar(select(Job.summary).where(Job.cache_key == job.cache_key, Job.status == "completed").limit(1))
        if cached:
            await finish(db, job, "cached", cached)
            return
        competing = await db.scalar(
            select(Job.id)
            .where(Job.id != job.id, Job.cache_key == job.cache_key, Job.status == "processing", Job.next_attempt_at > clock)
            .limit(1)
        )
        if competing:
            return
        job.status = "processing"
        job.attempts += 1
        job.next_attempt_at = clock + timedelta(minutes=2)
        await db.commit()
        job_id = job.id
        start = time.monotonic()
        try:
            provider = Provider(job.provider)
            wire, base, destination, host = await judged_endpoint(
                provider,
                HostReach(config.host_reach) if config.host_reach else None,
                config.base_url,
                carries_key=bool(config.api_key_encrypted),
            )
            await require_ai(
                db,
                feature="inventory_summary",
                destination=destination,
                fields=["app_names", "app_versions", "finding_counts", "posture_changes", "customer_preprompt"],
            )
            text = prompt(job.evidence, settings.preprompt)
            request = CompletionRequest(
                base_url=base,
                model=config.model,
                prompt=text,
                system=SYSTEM,
                api_key=config.api_key_encrypted,
                host_header=host,
                max_tokens=180,
                temperature=0,
                reasoning_effort=None if provider is Provider.apple_fm else config.reasoning_effort,
                serial=provider is Provider.apple_fm,
                minimum_interval=settings.interval_seconds if provider is Provider.apple_fm else 0,
            )
            result = await complete(
                wire, request, transport=transport, timeout_seconds=min(60, (as_utc(job.expires_at) - now()).total_seconds())
            )
            answer = checked_reply(result.content, job.evidence["facts"])
            job.latency_ms = int((time.monotonic() - start) * 1000)
            # Recheck consent/config after the network hop; never publish a stale setting's result.
            await db.refresh(settings)
            latest = await saved_config(db, Provider(settings.provider))
            from app.core.sharing import get_or_create_settings

            consent = await get_or_create_settings(db)
            if (
                not consent.ai_inference
                or not settings.enabled
                or config_key(settings, latest) != job.config_key
                or not await ai_features_enabled(db)
            ):
                await finish(db, job, "dropped", reason="configuration_changed")
            elif now() >= as_utc(job.expires_at):
                await finish(db, job, "dropped", reason="expired")
            else:
                await finish(db, job, "completed", answer)
        except AIRefused:
            await finish(db, job, "dropped", reason="consent_missing")
        except AdapterError as exc:
            reason = "overload" if exc.status == 429 else exc.kind
            job.reason = reason
            job.overloads += int(reason == "overload")
            job.latency_ms = int((time.monotonic() - start) * 1000)
            logger.warning("inventory summary attempt failed", extra={"summary_id": str(job.id), "reason": reason})
            if job.attempts < 3 and (exc.status == 429 or exc.kind in ("timeout", "unreachable")):
                job.status = "pending"
                job.next_attempt_at = now() + timedelta(seconds=30 * job.attempts)
                await db.commit()
            else:
                await finish(db, job, "failed", reason=reason)
        except Exception:
            # Never expose upstream content/keys through an error string or exception log.
            await db.rollback()
            job = await db.get(Job, job_id)
            if job:
                await finish(db, job, "failed", reason="invalid_or_unavailable")


async def tick():
    for tenant in await operational_tenant_ids():
        try:
            async with tenant_job(tenant) as db:
                await collect(db)
            await asyncio.gather(work_one(tenant), work_one(tenant))
        except Exception:
            logger.error("inventory summary worker failed; inventory delivery is independent", extra={"tenant_id": str(tenant)})
