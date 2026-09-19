"""Summary isolation, expiry, corpus transitions and delivery over real Postgres (#594)."""

import os
import uuid
from datetime import timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from tests.test_inventory_summary import snapshot

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres"),
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest_asyncio.fixture(loop_scope="session")
async def summary_db(tenant_ready):
    from app.core.database import session_for_tenant, unscoped_session
    from app.core.sharing import get_or_create_settings
    from app.models.schema import (
        AIProviderConfig,
        DataSharingSettings,
        EventOutbox,
        FeatureFlag,
        InventorySummaryJob,
        InventorySummarySettings,
        InventorySummaryState,
        ShareLog,
        Tenant,
    )
    from app.summaries.service import now

    tenant = uuid.uuid4()
    async with unscoped_session() as global_db:
        global_db.add(Tenant(id=tenant, slug=f"summary-{tenant.hex}", name="Synthetic summaries", kind="operational"))
        await global_db.commit()
    async with session_for_tenant(tenant) as db:
        db.add(FeatureFlag(key="ai_features", enabled=True))
        db.add(InventorySummarySettings(enabled=True, provider="apple_fm", enabled_at=now() - timedelta(hours=2)))
        db.add(
            AIProviderConfig(
                provider="apple_fm", base_url="http://127.0.0.1:1976/v1", model="system", host_reach="custom", updated_at=now()
            )
        )
        consent = await get_or_create_settings(db)
        consent.ai_inference = True
        await db.commit()
        try:
            yield db, tenant
        finally:
            await db.rollback()
            for model in (
                InventorySummaryJob,
                InventorySummaryState,
                InventorySummarySettings,
                EventOutbox,
                ShareLog,
                DataSharingSettings,
                AIProviderConfig,
                FeatureFlag,
            ):
                await db.execute(delete(model))
            await db.commit()
    async with unscoped_session() as global_db:
        await global_db.execute(delete(Tenant).where(Tenant.id == tenant))
        await global_db.commit()


async def emit(db, data, device="1", age=0):
    from app.core.outbox import enqueue_event
    from app.summaries.service import now

    instant = now() - timedelta(seconds=age)
    payload = {
        **data,
        "event": "device.inventory",
        "occurredAt": instant.isoformat(),
        "deviceMeta": {"connectionID": 1, "jamfProID": device, "eventID": str(uuid.uuid4())},
    }
    event = await enqueue_event(db, "device.inventory", payload)
    event.created_at = instant
    await db.commit()
    return event.id


async def test_corpus_only_change_delivers_a_separate_correlated_summary(summary_db):
    from app.core.outbox import hec_events
    from app.models.schema import EventOutbox, ShareLog
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(["CVE-2025-1001", "CVE-2025-1002"], total=2))
    await collect(db)
    original = await db.get(EventOutbox, source)
    source_time = original.payload["occurredAt"]
    assert original.fanned_out is False, "summary must not wait for any SIEM delivery"
    calls = []

    async def respond(request):
        calls.append(request)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "Chrome now has 2 findings."}, "finish_reason": "stop"}]}
        )

    await work_one(tenant, transport=httpx.MockTransport(respond))
    await db.rollback()
    job = await db.scalar(select(Job).where(Job.source_id == source))
    assert job.status == "completed"
    assert len(calls) == 1
    assert "CVE-2025" not in calls[0].content.decode()
    assert await db.scalar(select(ShareLog.id).where(ShareLog.tier == "ai"))
    events = (await db.scalars(select(EventOutbox).where(EventOutbox.event_type == "device.inventory.summary"))).all()
    answer = next(e.payload for e in events if e.payload["sourceEventID"] == source)
    assert answer["occurredAt"] == source_time
    assert answer["generatedAt"] >= source_time
    assert hec_events(answer)[0]["time"] == job.source_at.timestamp()


async def test_unchanged_skips_model_and_receipt_is_not_reprocessed(summary_db):
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot())
    await collect(db)
    await collect(db)
    await work_one(tenant, transport=httpx.MockTransport(lambda r: pytest.fail("no-change inference")))
    job = await db.scalar(select(Job).where(Job.source_id == source))
    assert (job.status, job.summary, job.attempts) == ("no_updates", "No updates", 0)


async def test_expiry_is_logged_and_does_not_delete_source(summary_db, caplog):
    from app.models.schema import EventOutbox
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect

    db, _ = summary_db
    source = await emit(db, snapshot(), age=3700)
    await collect(db)
    job = await db.scalar(select(Job).where(Job.source_id == source))
    assert (job.status, job.reason) == ("dropped", "expired")
    assert await db.get(EventOutbox, source)
    assert "inventory summary dropped" in caplog.text


async def test_tenant_cannot_read_or_change_another_tenants_jobs(summary_db, db):
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect

    own, _ = summary_db
    source = await emit(own, snapshot())
    await collect(own)
    assert await db.scalar(select(Job.id).where(Job.source_id == source)) is None
    result = await db.execute(delete(Job).where(Job.source_id == source))
    assert result.rowcount == 0
    await db.rollback()


async def test_revoked_consent_drops_without_a_network_call(summary_db):
    from app.core.sharing import get_or_create_settings
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(version="2"))
    await collect(db)
    consent = await get_or_create_settings(db)
    consent.ai_inference = False
    await db.commit()
    await work_one(tenant, transport=httpx.MockTransport(lambda r: pytest.fail("consent bypass")))
    await db.rollback()
    job = await db.scalar(select(Job).where(Job.source_id == source))
    assert job.reason == "consent_missing"


async def test_cache_reuses_identical_changes_for_a_second_device(summary_db):
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    for device in ("1", "2"):
        await emit(db, snapshot(), device=device)
    await collect(db)
    for device in ("1", "2"):
        await emit(db, snapshot(version="2"), device=device)
    await collect(db)
    calls = []

    def response(request):
        calls.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "Chrome updated to version 2."}}]})

    for _ in range(2):
        await work_one(tenant, transport=httpx.MockTransport(response))
    await db.rollback()
    statuses = (await db.scalars(select(Job.status))).all()
    assert statuses.count("cached") == 1 and statuses.count("completed") == 1
    assert len(calls) == 1


async def test_overload_retries_preserve_expiry_and_are_counted(summary_db):
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(version="2"))
    await collect(db)
    before = await db.scalar(select(Job.expires_at).where(Job.source_id == source))
    await work_one(tenant, transport=httpx.MockTransport(lambda request: httpx.Response(429, json={"error": "busy"})))
    await db.rollback()
    job = await db.scalar(select(Job).where(Job.source_id == source))
    assert job.status == "pending" and job.overloads == 1 and job.attempts == 1
    assert job.expires_at == before


async def test_configuration_change_invalidates_a_pending_job(summary_db):
    from app.models.schema import InventorySummaryJob as Job
    from app.models.schema import InventorySummarySettings as Settings
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(version="2"))
    await collect(db)
    settings = await db.scalar(select(Settings))
    settings.preprompt = "A changed preference"
    await db.commit()
    await work_one(tenant, transport=httpx.MockTransport(lambda r: pytest.fail("stale configuration")))
    await db.rollback()
    job = await db.scalar(select(Job).where(Job.source_id == source))
    assert job.reason == "configuration_changed"


async def test_abandoned_lease_recovers_with_original_expiry(summary_db):
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, now, work_one

    db, tenant = summary_db
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(version="2"))
    await collect(db)
    job = await db.scalar(select(Job).where(Job.source_id == source))
    expiry = job.expires_at
    job.status = "processing"
    job.next_attempt_at = now() - timedelta(seconds=1)
    await db.commit()
    await work_one(
        tenant,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "Chrome updated to version 2."}}]})
        ),
    )
    await db.refresh(job)
    assert job.status == "completed" and job.expires_at == expiry


async def test_capacity_drop_is_visible_and_keeps_inventory(summary_db, monkeypatch):
    from app.models.schema import EventOutbox
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect

    db, _ = summary_db
    await emit(db, snapshot())
    await collect(db)
    monkeypatch.setattr("app.summaries.service.MAX_PENDING", 0)
    source = await emit(db, snapshot(version="2"))
    await collect(db)
    job = await db.scalar(select(Job).where(Job.source_id == source))
    assert job.reason == "capacity"
    assert await db.get(EventOutbox, source)


async def test_metrics_include_overload_and_drop_without_claiming_success(summary_db):
    from app.api.inventory_summaries import metrics
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    await emit(db, snapshot())
    await collect(db)
    await emit(db, snapshot(version="2"))
    await collect(db)
    await work_one(tenant, transport=httpx.MockTransport(lambda r: httpx.Response(429)))
    await db.rollback()
    result = await metrics(db)
    assert result["overloadJobs"] == 1 and result["attempts"] == 1
    assert result["successRate"] == 0 and result["counts"]["pending"] == 1


async def test_openai_compatible_uses_the_same_compact_evidence(summary_db):
    from app.models.schema import AIProviderConfig, InventorySummarySettings
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    settings = await db.scalar(select(InventorySummarySettings))
    settings.provider = "openai_compatible"
    db.add(AIProviderConfig(provider="openai_compatible", base_url="http://127.0.0.1:11434/v1", model="synthetic"))
    await db.commit()
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(version="2"))
    await collect(db)
    calls = []

    def response(request):
        calls.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "Chrome updated to version 2."}}]})

    await work_one(tenant, transport=httpx.MockTransport(response))
    await db.rollback()
    job = await db.scalar(select(Job).where(Job.source_id == source))
    assert job.status == "completed" and len(calls) == 1
    assert len(calls[0].content) < 4000
    assert "deviceMeta" not in calls[0].content.decode()
