"""Consume committed inventory snapshots and deliver independently timed summaries (#594)."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import delete, exists, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import aliased

from app.ai.adapters import AdapterError, CompletionRequest, complete
from app.ai.providers import HostReach, Provider
from app.api.ai import judged_endpoint
from app.core.ai import AIFeaturesDisabled, AIRefused, ai_features_enabled, require_ai
from app.core.ai_configs import get_config, saved_config
from app.core.auth import as_utc
from app.core.outbox import enqueue_event
from app.core.tenant_jobs import operational_tenant_ids, tenant_job
from app.core.wire import ENVELOPE
from app.core.wire_vocabulary import INVENTORY_SUMMARY_EVENT_TYPE
from app.models.schema import EventOutbox, FeatureFlag
from app.models.schema import InventorySummaryJob as Job
from app.models.schema import InventorySummaryMetric as Metric
from app.models.schema import InventorySummarySettings as Settings
from app.models.schema import InventorySummaryState as State
from app.observations.history_capture import retain_summary
from app.summaries.diagnostics import REASONS, safe_exception
from app.summaries.evidence import PROMPT_VERSION, SYSTEM, InvalidSummary, checked_reply, compact, compare, digest, prompt

logger = logging.getLogger(__name__)
EVENT = INVENTORY_SUMMARY_EVENT_TYPE
TTL = timedelta(hours=1)
MAX_PENDING = 1000
TERMINAL = ("completed", "cached", "no_updates", "baseline", "incomplete", "dropped", "failed")


def now():
    return datetime.now(UTC)


def config_key(settings, config):
    return digest([settings.provider, settings.preprompt, str(config.updated_at) if config else None, PROMPT_VERSION])


def bucket(moment):
    return as_utc(moment).replace(second=0, microsecond=0)


async def count_outcome(db, provider, status, *, reason=None, at=None):
    statement = insert(Metric).values(
        provider=provider, bucket_at=bucket(at or now()), status=status, reason=reason or "none", count=1
    )
    await db.execute(
        statement.on_conflict_do_update(
            index_elements=["tenant_id", "provider", "bucket_at", "status", "reason"],
            set_={"count": Metric.count + 1},
        )
    )


def log_drop(source_id, reason, **extra):
    logger.warning(
        "inventory summary not produced; " + REASONS[reason], extra={"source_event_id": source_id, "reason": reason, **extra}
    )


async def finish(db, job, status, summary=None, reason=None):
    """Persist outcome; emit only successful briefings of meaningful changes."""
    job.status, job.summary, job.reason, job.finished_at = status, summary, reason, now()
    meta = job.correlation["deviceMeta"]
    state = await db.get(State, (job.tenant_id, digest([meta["connectionID"], meta["jamfProID"]])))
    if state and state.source_id == job.source_id:
        state.summary_status, state.short_summary = status, summary
    await retain_summary(db, job.source_id, status, summary, job.provider, reason)
    await count_outcome(db, job.provider, status, reason=reason, at=job.created_at)
    if status in ("dropped", "failed"):
        log_drop(job.source_id, reason, summary_id=str(job.id), age_seconds=(now() - as_utc(job.created_at)).total_seconds())
    if status in ("completed", "cached") and job.evidence["kind"] == "changed":
        body = {
            "event": EVENT,
            "summaryID": str(job.id),
            "sourceEventID": job.source_id,
            "occurredAt": job.source_at.isoformat(),
            "sourceEnqueuedAt": job.correlation["sourceEnqueuedAt"],
            "generatedAt": job.finished_at.isoformat(),
            "queuedAt": job.created_at.isoformat(),
            "expiresAt": job.expires_at.isoformat(),
            "deviceMeta": job.correlation["deviceMeta"],
            "summaryStatus": status,
            "summaryProvider": job.provider,
            "promptVersion": PROMPT_VERSION,
            "shortSummary": summary,
            "evidence": job.evidence,
            "advisory": True,
            "corpusAsOf": job.correlation.get("corpusAsOf", []),
            "evidenceScope": ["applications", "os_version_build", "disk_encryption", "selected_security_fields"],
            ENVELOPE: {**job.correlation.get(ENVELOPE, {}), "time": job.source_at.timestamp()},
        }

        # Optional values are absent, recursively, under the frozen wire convention.
        def present(value):
            if isinstance(value, dict):
                return {k: present(v) for k, v in value.items() if v is not None}
            if isinstance(value, list):
                return [present(v) for v in value]
            return value

        await enqueue_event(db, EVENT, present(body))
    await db.commit()


async def collect(db):
    settings = await db.scalar(select(Settings).with_for_update(skip_locked=True))
    if not settings:
        return
    # retention-clock: summary-jobs — receipts/cache expire even while AI is disabled.
    await db.execute(delete(Job).where(Job.created_at < now() - timedelta(days=8), Job.status.in_(TERMINAL)))
    # retention-clock: summary-metrics — minute counters cover the 24-hour dashboard.
    await db.execute(delete(Metric).where(Metric.bucket_at < now() - timedelta(hours=25)))
    if not settings.enabled or not await ai_features_enabled(db):
        await db.commit()
        return
    # A per-event receipt marker survives out-of-order transaction commits. An integer
    # high-water mark would silently skip a lower ID committed after a higher one.
    events = (
        await db.scalars(
            select(EventOutbox)
            .where(
                EventOutbox.event_type == "device.inventory",
                EventOutbox.created_at >= settings.enabled_at,
                EventOutbox.created_at >= now() - timedelta(days=7),
                EventOutbox.summary_collected_at.is_(None),
            )
            .order_by(EventOutbox.created_at, EventOutbox.id)
            .limit(500)
        )
    ).all()
    for event in events:
        await db.refresh(event, with_for_update=True)
        if event.summary_collected_at is not None:
            continue
        clock = now()
        event.summary_collected_at = clock
        state = None
        payload = event.payload
        meta = payload.get("deviceMeta") or {}
        try:
            if not meta.get("connectionID") or not meta.get("jamfProID"):
                raise ValueError("identity")
            source_at = datetime.fromisoformat(payload["occurredAt"].replace("Z", "+00:00"))
            if source_at.tzinfo is None:
                raise ValueError("timezone")
            current = compact(payload)
        except (ValueError, KeyError, TypeError, AttributeError):
            log_drop(event.id, "invalid_observation")
            await count_outcome(db, settings.provider, "dropped", reason="invalid_observation")
        else:
            device_key = digest([meta["connectionID"], meta["jamfProID"]])
            state = await db.get(State, (event.tenant_id, device_key))
            if state and source_at < as_utc(state.source_at):
                log_drop(event.id, "stale_observation")
                await count_outcome(db, settings.provider, "dropped", reason="stale_observation")
            else:
                evidence = compare(state.facts if state else None, current)
                if state:
                    state.facts = {
                        **state.facts,
                        **{
                            section: values if section == "apps" else {**state.facts.get(section, {}), **values}
                            for section, values in current.items()
                        },
                    }
                    state.source_at = source_at
                else:
                    state = State(device_key=device_key, facts=current, source_at=source_at)
                    db.add(state)
                state.source_id = event.id
                kind = evidence["kind"]
                if kind != "changed":
                    status = "no_updates" if kind == "unchanged" else kind
                    state.summary_status = status
                    state.short_summary = "No updates" if status == "no_updates" else None
                    await count_outcome(db, settings.provider, status)
                elif as_utc(event.created_at) + TTL <= clock:
                    state.summary_status, state.short_summary = "dropped", None
                    log_drop(event.id, "expired")
                    await count_outcome(db, settings.provider, "dropped", reason="expired")
                else:
                    config = await saved_config(db, Provider(settings.provider))
                    key = config_key(settings, config)
                    cache_key = digest([key, evidence])
                    cached = await db.scalar(
                        select(Job.summary).where(Job.cache_key == cache_key, Job.status == "completed").limit(1)
                    )
                    pending = await db.scalar(
                        select(func.count()).select_from(Job).where(Job.status.in_(("pending", "processing")))
                    )
                    if not cached and pending >= MAX_PENDING:
                        state.summary_status, state.short_summary = "dropped", None
                        log_drop(event.id, "capacity")
                        await count_outcome(db, settings.provider, "dropped", reason="capacity")
                    else:
                        job = Job(
                            source_id=event.id,
                            created_at=clock,
                            expires_at=as_utc(event.created_at) + TTL,
                            source_at=source_at,
                            provider=settings.provider,
                            config_key=key,
                            cache_key=cache_key,
                            evidence=evidence,
                            correlation={
                                "deviceMeta": meta,
                                "sourceEnqueuedAt": as_utc(event.created_at).isoformat(),
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
                        state.summary_status, state.short_summary = "pending", None
                        if cached:
                            await db.flush()
                            await finish(db, job, "cached", cached)
        if state and state.source_id == event.id:
            await retain_summary(db, event.id, state.summary_status, state.short_summary, settings.provider)
        await db.commit()
        await db.refresh(settings, with_for_update=True)
        if not settings.enabled:
            break
    await db.commit()


async def work_one(tenant_id, *, transport=None):
    async with tenant_job(tenant_id) as db:
        clock = now()
        settings = await db.scalar(select(Settings).with_for_update())
        if not settings:
            return False
        # An abandoned lease can be retried after two minutes; its original TTL stands.
        twin = aliased(Job)
        competing = exists(
            select(twin.id).where(
                twin.id != Job.id, twin.cache_key == Job.cache_key, twin.status == "processing", twin.next_attempt_at > clock
            )
        )
        job = await db.scalar(
            select(Job)
            .where(Job.status.in_(("pending", "processing")), Job.next_attempt_at <= clock, ~competing)
            .order_by(Job.created_at)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if not job:
            return False
        if as_utc(job.expires_at) <= clock:
            await finish(db, job, "dropped", reason="expired")
            return True
        if not settings.enabled or not await ai_features_enabled(db):
            await finish(db, job, "dropped", reason="disabled")
            return True
        config = await get_config(db, Provider(settings.provider))
        if not config or config_key(settings, config) != job.config_key:
            await finish(db, job, "dropped", reason="configuration_changed")
            return True
        cached = await db.scalar(select(Job.summary).where(Job.cache_key == job.cache_key, Job.status == "completed").limit(1))
        if cached:
            await finish(db, job, "cached", cached)
            return True
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
                background=True,
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
            await db.refresh(consent)
            flag_on = await db.scalar(select(FeatureFlag.enabled).where(FeatureFlag.key == "ai_features"))
            if not consent.ai_inference:
                await finish(db, job, "dropped", reason="consent_missing")
            elif not settings.enabled or not flag_on:
                await finish(db, job, "dropped", reason="disabled")
            elif config_key(settings, latest) != job.config_key:
                await finish(db, job, "dropped", reason="configuration_changed")
            elif now() >= as_utc(job.expires_at):
                await finish(db, job, "dropped", reason="expired")
            else:
                await finish(db, job, "completed", answer)
        except InvalidSummary as exc:
            await finish(db, job, "failed", reason=str(exc))
        except HTTPException as exc:
            logger.warning(
                "inventory summary endpoint refused; " + REASONS["endpoint_refused"],
                extra={"summary_id": str(job_id), "http_status": exc.status_code},
            )
            await finish(db, job, "failed", reason="endpoint_refused")
        except AIRefused as exc:
            await finish(db, job, "dropped", reason="disabled" if isinstance(exc, AIFeaturesDisabled) else "consent_missing")
        except AdapterError as exc:
            reason = "overload" if exc.status == 429 else exc.kind
            job.reason = reason
            job.overloads += int(reason == "overload")
            job.latency_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "inventory summary attempt failed; " + REASONS[reason], extra={"summary_id": str(job.id), "reason": reason}
            )
            if job.attempts < 3 and (exc.status == 429 or exc.kind in ("timeout", "unreachable")):
                job.status = "pending"
                job.next_attempt_at = now() + timedelta(seconds=30 * job.attempts)
                await db.commit()
            else:
                await finish(db, job, "failed", reason=reason)
        except Exception as exc:
            # Never expose upstream content/keys through an error string or exception log.
            logger.error(
                "inventory summary failed; " + REASONS["internal_error"], extra={"summary_id": str(job_id), **safe_exception(exc)}
            )
            await db.rollback()
            job = await db.get(Job, job_id)
            if job:
                await finish(db, job, "failed", reason="internal_error")

        return True


async def drain(tenant, *, transport=None, max_jobs=1000):
    """Drain local completions without spending a five-second slot on each cache hit."""
    deadline = time.monotonic() + 30
    for _ in range(max_jobs):
        if time.monotonic() >= deadline or not await work_one(tenant, transport=transport):
            break


async def tick():
    for tenant in await operational_tenant_ids():
        try:
            async with tenant_job(tenant) as db:
                await collect(db)
            await asyncio.gather(drain(tenant), drain(tenant))
        except Exception as exc:
            logger.error(
                "inventory summary worker failed; " + REASONS["internal_error"],
                extra={"tenant_id": str(tenant), **safe_exception(exc)},
            )


async def run_worker():
    """Wait after completion, so slow inference cannot produce scheduler overlap warnings."""
    while True:
        try:
            await tick()
        except Exception as exc:
            logger.error("inventory summary scheduling failed; " + REASONS["internal_error"], extra=safe_exception(exc))
        await asyncio.sleep(5)
