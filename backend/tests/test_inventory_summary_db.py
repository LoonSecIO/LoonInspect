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
        InventorySummaryMetric,
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
                InventorySummaryMetric,
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
    await emit(db, snapshot())
    await collect(db)
    await collect(db)
    await work_one(tenant, transport=httpx.MockTransport(lambda r: pytest.fail("no-change inference")))
    from app.models.schema import EventOutbox, InventorySummaryMetric, InventorySummaryState

    assert await db.scalar(select(Job.id)) is None
    state = await db.scalar(select(InventorySummaryState))
    assert (state.summary_status, state.short_summary) == ("no_updates", "No updates")
    assert await db.scalar(select(InventorySummaryMetric.count).where(InventorySummaryMetric.status == "no_updates")) == 1
    assert await db.scalar(select(EventOutbox.id).where(EventOutbox.event_type == "device.inventory.summary")) is None


async def test_expiry_is_logged_and_does_not_delete_source(summary_db, caplog):
    from app.models.schema import EventOutbox
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect

    db, _ = summary_db
    from app.models.schema import InventorySummaryMetric

    await emit(db, snapshot(), age=4000)
    await collect(db)
    source = await emit(db, snapshot(version="2"), age=3700)
    await collect(db)
    assert await db.scalar(select(Job.id).where(Job.source_id == source)) is None
    assert await db.scalar(select(InventorySummaryMetric.count).where(InventorySummaryMetric.reason == "expired")) == 1
    assert await db.get(EventOutbox, source)
    assert "one-hour deadline elapsed" in caplog.text


async def test_tenant_cannot_read_or_change_another_tenants_jobs(summary_db, db):
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect

    own, _ = summary_db
    await emit(own, snapshot())
    await collect(own)
    source = await emit(own, snapshot(version="2"))
    await collect(own)
    assert await own.scalar(select(Job.id).where(Job.source_id == source)) is not None
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
    from app.models.schema import InventorySummaryMetric

    assert await db.scalar(select(Job.id).where(Job.source_id == source)) is None
    assert await db.scalar(select(InventorySummaryMetric.count).where(InventorySummaryMetric.reason == "capacity")) == 1
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


async def test_receipt_retention_runs_while_summaries_are_disabled(summary_db):
    from app.models.schema import EventOutbox, InventorySummarySettings
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, finish, now

    db, _ = summary_db
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(version="2"))
    await collect(db)
    job = await db.scalar(select(Job).where(Job.source_id == source))
    await finish(db, job, "failed", reason="invalid_summary")
    job.created_at = now() - timedelta(days=9)
    settings = await db.scalar(select(InventorySummarySettings))
    settings.enabled = False
    await db.commit()
    await collect(db)
    assert await db.scalar(select(Job.id).where(Job.source_id == source)) is None
    assert await db.get(EventOutbox, source), "summary retention must not delete source inventory"


async def test_drain_resolves_a_cohort_without_one_scheduler_slot_per_cache_hit(summary_db):
    from sqlalchemy import func

    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, drain

    db, tenant = summary_db
    for device in range(40):
        await emit(db, snapshot(), device=str(device + 1))
    await collect(db)
    for device in range(40):
        await emit(db, snapshot(version="2"), device=str(device + 1))
    await collect(db)
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "Chrome updated to version 2."}}]})

    await drain(tenant, transport=httpx.MockTransport(respond))
    await db.rollback()
    assert len(calls) == 1
    assert await db.scalar(select(func.count()).select_from(Job).where(Job.status == "cached")) == 39
    assert await db.scalar(select(func.count()).select_from(Job).where(Job.status == "pending")) == 0


async def test_busy_twin_does_not_block_unrelated_work(summary_db):
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, now, work_one

    db, tenant = summary_db
    for device in ("1", "2", "3"):
        await emit(db, snapshot(), device=device)
    await collect(db)
    first = await emit(db, snapshot(version="2"), device="1")
    twin = await emit(db, snapshot(version="2"), device="2")
    other = await emit(db, snapshot(version="3"), device="3")
    await collect(db)
    job = await db.scalar(select(Job).where(Job.source_id == first))
    job.status, job.next_attempt_at = "processing", now() + timedelta(minutes=2)
    await db.commit()
    await work_one(
        tenant,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "Chrome updated to version 3."}}]})
        ),
    )
    await db.rollback()
    assert await db.scalar(select(Job.status).where(Job.source_id == other)) == "completed"
    assert await db.scalar(select(Job.status).where(Job.source_id == twin)) == "pending"


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        ("Chrome moved to 128.", "unsupported_number"),
        ("No updates", "unsupported_no_change"),
        ("<b>Chrome</b>", "invalid_summary"),
    ],
)
async def test_invalid_reply_names_the_reason_without_publishing_a_null_summary(summary_db, reply, reason, caplog):
    from app.models.schema import EventOutbox
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(version="128.0.1"))
    await collect(db)
    await work_one(
        tenant, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"choices": [{"message": {"content": reply}}]}))
    )
    await db.rollback()
    job = await db.scalar(select(Job).where(Job.source_id == source))
    assert job.reason == reason
    assert "Check model choice" in caplog.text
    assert await db.scalar(select(EventOutbox.id).where(EventOutbox.event_type == "device.inventory.summary")) is None


async def test_endpoint_refusal_and_unexpected_failures_are_diagnosable_without_secrets(summary_db, monkeypatch, caplog):
    from fastapi import HTTPException

    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    await emit(db, snapshot())
    await collect(db)
    for version, error, reason in [
        ("2", HTTPException(422, "private-key-sentinel"), "endpoint_refused"),
        ("3", RuntimeError("private-key-sentinel"), "internal_error"),
    ]:
        source = await emit(db, snapshot(version=version))
        await collect(db)

        async def refuse(*args, failure=error, **kwargs):
            raise failure

        monkeypatch.setattr("app.summaries.service.judged_endpoint", refuse)
        await work_one(tenant)
        await db.rollback()
        assert await db.scalar(select(Job.reason).where(Job.source_id == source)) == reason
    assert "private-key-sentinel" not in caplog.text
    assert any(getattr(record, "error_type", None) == "RuntimeError" and record.stack for record in caplog.records)


async def test_lower_source_id_committed_later_is_not_skipped(summary_db):
    from app.core.database import session_for_tenant
    from app.models.schema import EventOutbox, InventorySummaryState
    from app.summaries.service import collect, now

    db, tenant = summary_db
    async with session_for_tenant(tenant) as late:
        source = EventOutbox(
            event_type="device.inventory",
            payload={**snapshot(), "occurredAt": now().isoformat(), "deviceMeta": {"connectionID": 1, "jamfProID": "late"}},
        )
        late.add(source)
        await late.flush()
        await emit(db, snapshot(), device="early")
        await collect(db)
        await late.commit()
    await collect(db)
    from sqlalchemy import func

    assert await db.scalar(select(func.count()).select_from(InventorySummaryState)) == 2


async def test_counter_rls_and_wire_null_absence(summary_db, db):
    from app.core.outbox import hec_events
    from app.core.wire_vocabulary import INVENTORY_SUMMARY_SOURCETYPE
    from app.models.schema import EventOutbox, InventorySummaryMetric
    from app.summaries.service import collect, work_one

    own, tenant = summary_db
    await emit(own, snapshot(), age=10)
    await collect(own)
    assert await own.scalar(select(InventorySummaryMetric.count)) == 1
    assert await db.scalar(select(InventorySummaryMetric.count)) is None
    source = await emit(own, snapshot(version="2"), age=5)
    await collect(own)
    await work_one(
        tenant,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "Chrome updated to version 2."}}]})
        ),
    )
    await own.rollback()
    payload = await own.scalar(select(EventOutbox.payload).where(EventOutbox.event_type == "device.inventory.summary"))
    assert payload["sourceEventID"] == source
    assert payload["queuedAt"] > payload["sourceEnqueuedAt"]
    assert hec_events(payload)[0]["sourcetype"] == INVENTORY_SUMMARY_SOURCETYPE

    def no_null(value):
        assert value is not None
        if isinstance(value, dict):
            assert "ids" not in value
            for item in value.values():
                no_null(item)
        if isinstance(value, list):
            for item in value:
                no_null(item)

    no_null(payload)


@pytest.mark.parametrize("revoke", ["consent", "flag"])
async def test_revocation_during_inference_prevents_publication(summary_db, revoke):
    from app.core.database import session_for_tenant
    from app.core.sharing import get_or_create_settings
    from app.models.schema import EventOutbox, FeatureFlag
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(version="2"))
    await collect(db)

    async def answer(request):
        async with session_for_tenant(tenant) as other:
            if revoke == "consent":
                row = await get_or_create_settings(other)
                row.ai_inference = False
            else:
                row = await other.scalar(select(FeatureFlag).where(FeatureFlag.key == "ai_features"))
                row.enabled = False
            await other.commit()
        return httpx.Response(200, json={"choices": [{"message": {"content": "Chrome updated to version 2."}}]})

    await work_one(tenant, transport=httpx.MockTransport(answer))
    await db.rollback()
    job = await db.scalar(select(Job).where(Job.source_id == source))
    assert job.reason == ("consent_missing" if revoke == "consent" else "disabled")
    assert await db.scalar(select(EventOutbox.id).where(EventOutbox.event_type == "device.inventory.summary")) is None
