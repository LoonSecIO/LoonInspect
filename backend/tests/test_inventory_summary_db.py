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
        AIUsageAttempt,
        AIUsageCoverage,
        AIUsageDaily,
        AIUsageWork,
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
                AIUsageDaily,
                AIUsageAttempt,
                AIUsageWork,
                AIUsageCoverage,
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
    from app.models.schema import AIUsageDaily

    assert (await db.scalar(select(AIUsageDaily.events).where(AIUsageDaily.kind == "call"))) == 1
    events = (await db.execute(select(AIUsageDaily.outcome, AIUsageDaily.events).where(AIUsageDaily.kind == "queue"))).all()
    assert dict(events) == {"received": 2, "started": 1, "completed": 1, "cached": 1}


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


async def test_an_apple_card_saved_naming_another_model_is_never_dialled(summary_db, caplog):
    """A row an older build saved naming `pcc`, Private Cloud Compute, on Apple's servers (#738):
    the job fails with its own reason, whose next check is the Save's sentence, before the gate."""
    from sqlalchemy import update

    from app.api.ai import APPLE_FM_SYSTEM_ONLY
    from app.models.schema import AIProviderConfig, ShareLog
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, work_one

    db, tenant = summary_db
    await db.execute(update(AIProviderConfig).values(model="pcc"))
    await db.commit()
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(version="2"))
    await collect(db)
    await work_one(tenant, transport=httpx.MockTransport(lambda r: pytest.fail("pcc was dialled")))
    await db.rollback()
    job = (await db.execute(select(Job.status, Job.reason).where(Job.source_id == source))).one()
    assert tuple(job) == ("failed", "apple_model_refused")
    assert await db.scalar(select(ShareLog.id).where(ShareLog.tier == "ai")) is None
    assert APPLE_FM_SYSTEM_ONLY in caplog.text


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


async def test_extension_attribute_change_is_briefed_and_follows_the_change_log_policy(summary_db):
    """#644: a value change is evidence; a definition the Change Log mutes is not."""
    from app.models.schema import ChangePolicy, EventOutbox, InventorySummaryMetric, InventorySummaryState, ShareLog
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, work_one
    from tests.test_inventory_summary import with_ea

    db, tenant = summary_db
    try:
        await emit(db, with_ea(snapshot(), ("1", "Device Security EA", [])))
        await collect(db)
        state = await db.scalar(select(InventorySummaryState))
        assert state.summary_status == "baseline"
        source = await emit(db, with_ea(snapshot(), ("1", "Device Security EA", ["SomeValue"])))
        await collect(db)
        job = await db.scalar(select(Job).where(Job.source_id == source))
        assert job is not None and job.status == "pending"
        assert job.evidence["changes"] == [
            {"section": "extensionAttributes", "field": "1", "name": "Device Security EA", "before": [], "after": ["SomeValue"]}
        ]
        calls = []

        async def respond(request):
            calls.append(request.content.decode())
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": "Device Security EA changed from empty to SomeValue."}, "finish_reason": "stop"}
                    ]
                },
            )

        await work_one(tenant, transport=httpx.MockTransport(respond))
        await db.rollback()
        await db.refresh(job)
        assert job.status == "completed"
        assert len(calls) == 1 and "Extension attribute Device Security EA: (empty) -> SomeValue." in calls[0]
        disclosed = await db.scalar(select(ShareLog.payload).where(ShareLog.tier == "ai"))
        assert "extension_attribute_values" in disclosed["fields"]
        assert disclosed["model"] == "system"  # the saved card's, as sent (#739)
        briefing = await db.scalar(select(EventOutbox.payload).where(EventOutbox.event_type == "device.inventory.summary"))
        assert briefing["shortSummary"] == "Device Security EA changed from empty to SomeValue."
        assert "extension_attributes" in briefing["evidenceScope"]
        assert briefing["evidence"]["changes"][0]["section"] == "extensionAttributes"

        # Muted in the Change Log: the next value change is not evidence — no job, no call.
        db.add(ChangePolicy(version="v0", overrides={"mutedExtensionAttributes": ["1"]}))
        await db.commit()
        muted = await emit(db, with_ea(snapshot(), ("1", "Device Security EA", ["Another"])))
        await collect(db)
        assert await db.scalar(select(Job.id).where(Job.source_id == muted)) is None
        await db.refresh(state)
        assert (state.summary_status, state.short_summary, state.source_id) == ("no_updates", "No updates", muted)
        assert state.facts["extensionAttributes"] == {}
        assert await db.scalar(select(InventorySummaryMetric.count).where(InventorySummaryMetric.status == "no_updates")) == 1
    finally:
        await db.rollback()
        await db.execute(delete(ChangePolicy))
        await db.commit()


async def test_loaded_model_change_partitions_the_summary_cache(summary_db):
    import json

    from app.models.schema import AIProviderConfig, AIUsageDaily, InventorySummaryJob, InventorySummarySettings
    from app.summaries.service import collect, now, work_one

    db, tenant = summary_db
    settings = await db.scalar(select(InventorySummarySettings))
    settings.provider = "openai_compatible"
    db.add(
        AIProviderConfig(
            provider=settings.provider,
            base_url="http://127.0.0.1:11434/v1",
            model="qwen",
            ollama_policy={"preferences": ["gemma", "qwen"], "fallback": None},
            updated_at=now(),
        )
    )
    await db.commit()
    for device in ("1", "2", "3"):
        await emit(db, snapshot(), device=device)
    await collect(db)
    for device in ("1", "2", "3"):
        await emit(db, snapshot(version="2"), device=device)
    await collect(db)
    sent = []
    loaded = "gemma"

    def reply(req):
        if req.url.path == "/api/ps":
            return httpx.Response(200, json={"models": [{"name": loaded, "digest": "digest-" + loaded}]})
        if req.url.path == "/api/show":
            return httpx.Response(200, json={"capabilities": ["completion"]})
        assert req.url.path == "/v1/chat/completions"
        name = json.loads(req.content)["model"]
        sent.append(name)
        return httpx.Response(
            200, json={"model": name + "-reported", "choices": [{"message": {"content": "Chrome updated to version 2."}}]}
        )

    for next_model in ("gemma", "qwen", "gemma"):
        loaded = next_model
        assert await work_one(tenant, transport=httpx.MockTransport(reply))
    await db.rollback()
    assert sent == ["gemma", "qwen"]
    jobs = (await db.scalars(select(InventorySummaryJob).order_by(InventorySummaryJob.created_at))).all()
    assert [(j.status, j.requested_model, j.reported_model) for j in jobs] == [
        ("completed", "gemma", "gemma-reported"),
        ("completed", "qwen", "qwen-reported"),
        ("cached", "gemma", "gemma-reported"),
    ]
    calls = (await db.execute(select(AIUsageDaily.requested, AIUsageDaily.reported).where(AIUsageDaily.kind == "call"))).all()
    assert set(calls) == {("gemma", "gemma-reported"), ("qwen", "qwen-reported")}


async def seed_abandoned_summary_attempt(db, *, dispatched):
    from app.ai.providers import Provider
    from app.core.ai_configs import get_config
    from app.core.ai_usage import recorder
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, now

    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(version="2"))
    await collect(db)
    job = await db.scalar(select(Job).where(Job.source_id == source))
    job.status, job.attempts = "processing", 1
    job.next_attempt_at = now() - timedelta(seconds=1)
    job.requested_model = "system"
    config = await get_config(db, Provider.apple_fm)
    await db.commit()
    meter = recorder(db, "inventory_summary", "apple_fm", "system", config=config, work_id=job.id)
    await meter.start(60)
    if dispatched:
        meter.dispatch()
        await meter.dispatch_task
    return job, meter


@pytest.mark.parametrize("dispatched", [False, True])
async def test_reclaimed_summary_lease_accounts_for_old_attempt_and_current_dispatch(summary_db, dispatched):
    from app.core.ai_activity import activity_report, live_report
    from app.core.database import session_for_tenant
    from app.models.schema import AIUsageAttempt as Attempt
    from app.summaries.service import now, work_one

    db, tenant = summary_db
    job, old = await seed_abandoned_summary_attempt(db, dispatched=dispatched)
    expiry = job.expires_at
    observed = []

    async def response(request):
        # Dispatch progress is an asynchronous metadata write, so let it settle before
        # reading live status. The request itself remains in flight in this handler.
        import asyncio

        for _ in range(40):
            async with session_for_tenant(tenant) as reading:
                live = await live_report(reading)
            if live["inventory"]["running"] == 1:
                observed.append(live)
                break
            await asyncio.sleep(0.01)
        assert (live["inventory"]["waiting"], live["inventory"]["running"]) == (0, 1)
        return httpx.Response(200, json={"choices": [{"message": {"content": "Chrome updated to version 2."}}]})

    await work_one(tenant, transport=httpx.MockTransport(response))
    await db.refresh(job)
    assert job.status == "completed" and job.expires_at == expiry and job.attempts == 2
    assert observed
    previous = await db.get(Attempt, old.id, populate_existing=True)
    assert previous.outcome == "interrupted" and previous.finished_at is not None
    assert (previous.dispatched_at is not None) is dispatched
    assert previous.request_ms is None and previous.total_ms is None
    report = await activity_report(db, now().date(), now().date())
    assert report["totals"]["attempts"] == 2
    assert report["totals"]["dispatches"] == 1 + int(dispatched)
    assert report["totals"]["dispatchReports"] == 1 + int(dispatched)
    assert report["totals"]["retries"] == report["totals"]["usefulResults"] == 1
    assert report["coverage"]["legacyAttempts"] == 0
    assert (report["work"]["arrivals"], report["work"]["completed"]) == (1, 1)
    assert not await work_one(tenant, transport=httpx.MockTransport(lambda r: pytest.fail("completed job retried")))
    await old.finish_attempt("timeout", None)
    assert (await activity_report(db, now().date(), now().date()))["totals"]["attempts"] == 2


@pytest.mark.parametrize("stop", ["expired", "configuration_changed", "consent_missing"])
async def test_reclaimed_summary_terminal_refusal_closes_unfinished_attempt_without_dispatch(summary_db, stop):
    from app.core.ai_activity import activity_report
    from app.core.sharing import get_or_create_settings
    from app.models.schema import AIUsageAttempt as Attempt
    from app.models.schema import InventorySummarySettings as Settings
    from app.summaries.service import now, work_one

    db, tenant = summary_db
    job, old = await seed_abandoned_summary_attempt(db, dispatched=True)
    if stop == "expired":
        job.expires_at = now() - timedelta(seconds=1)
    elif stop == "configuration_changed":
        (await db.scalar(select(Settings))).preprompt = "Synthetic changed preference"
    else:
        (await get_or_create_settings(db)).ai_inference = False
    await db.commit()
    await work_one(tenant, transport=httpx.MockTransport(lambda r: pytest.fail("refused job dialled a provider")))
    await db.refresh(job)
    assert job.reason == stop and job.status == "dropped"
    previous = await db.get(Attempt, old.id, populate_existing=True)
    assert previous.outcome == "interrupted" and previous.finished_at is not None
    assert previous.dispatched_at is not None and previous.request_ms is None
    report = await activity_report(db, now().date(), now().date())
    assert report["totals"]["attempts"] == report["totals"]["dispatches"] == 1
    assert report["totals"]["usefulResults"] == 0 and report["totals"]["retries"] == 0
    assert report["work"]["expired" if stop == "expired" else "skipped"] == 1


async def test_web_only_process_reports_not_running_only_when_nothing_drains_inventory(summary_db, monkeypatch):
    """SCHEDULER_ENABLED describes the process answering; another container can drain the queue."""
    from sqlalchemy import update

    from app.core.ai_activity import live_report
    from app.core.ai_usage import recorder
    from app.core.config import settings
    from app.models.schema import AIUsageAttempt as Attempt
    from app.models.schema import InventorySummaryJob as Job
    from app.summaries.service import collect, now

    db, _ = summary_db
    monkeypatch.setattr(settings, "scheduler_enabled", False)
    await emit(db, snapshot())
    await collect(db)
    source = await emit(db, snapshot(version="2"))
    await collect(db)
    job = await db.scalar(select(Job).where(Job.source_id == source))
    assert job.status == "pending"
    # Just queued: a scheduler elsewhere has had no chance to pick it up yet.
    assert (await live_report(db))["state"] != "not_running"
    job.created_at = now() - timedelta(minutes=10)
    await db.commit()
    # A scheduler in another container started an inventory attempt a minute ago.
    meter = recorder(db, "inventory_summary", "apple_fm", "system", work_id=uuid.uuid4())
    await meter.start(60)
    await meter.finish_attempt("answered", None)
    await db.execute(update(Attempt).where(Attempt.id == meter.id).values(started_at=now() - timedelta(minutes=1)))
    await db.commit()
    assert (await live_report(db))["state"] != "not_running"
    # Nothing has started an inventory attempt for ten minutes: nothing drains the queue.
    await db.execute(update(Attempt).where(Attempt.id == meter.id).values(started_at=now() - timedelta(minutes=10)))
    await db.commit()
    live = await live_report(db)
    assert live["state"] == "not_running" and "scheduler_enabled" in live["nextCheck"]
    monkeypatch.setattr(settings, "scheduler_enabled", True)
    assert (await live_report(db))["state"] != "not_running"
