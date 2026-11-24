"""AI Activity accounting with synthetic metadata, real RLS and mocked inference only."""

import asyncio
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from fastapi.encoders import jsonable_encoder
from sqlalchemy import delete, text, update

from app.ai.adapters import AdapterError, CompletionRequest, complete
from app.ai.providers import Provider, Wire
from app.core.ai_activity import activity_report, live_report
from app.core.ai_configs import save_config
from app.core.ai_usage import (
    _last_recording_failures,
    _recording_failures,
    accepted,
    add,
    recorder,
    service_identity,
    work_event,
)
from app.core.database import session_for_tenant, unscoped_session
from app.models.schema import (
    AIProviderConfig,
    DataSharingSettings,
    FeatureFlag,
    Tenant,
)
from app.models.schema import (
    AIUsageAttempt as Attempt,
)
from app.models.schema import (
    AIUsageCoverage as Coverage,
)
from app.models.schema import (
    AIUsageDaily as Daily,
)
from app.models.schema import (
    AIUsageWork as Work,
)

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="requires PostgreSQL"),
    pytest.mark.asyncio(loop_scope="session"),
]
TENANT = uuid.UUID("641fd3f5-f264-4efe-bab8-6537b56be872")


@pytest_asyncio.fixture(loop_scope="session")
async def activity_db(tenant_ready):
    async with unscoped_session() as db:
        if not await db.get(Tenant, TENANT):
            db.add(Tenant(id=TENANT, slug="test-ai-activity", name="Synthetic AI Activity"))
            await db.commit()
    async with session_for_tenant(TENANT) as db:
        for model in (Attempt, Work, Coverage, Daily, AIProviderConfig, DataSharingSettings, FeatureFlag):
            await db.execute(delete(model))
        db.add(FeatureFlag(key="ai_features", enabled=True))
        db.add(DataSharingSettings(ai_inference=True))
        await db.commit()
        _recording_failures.pop(TENANT, None)
        _last_recording_failures.pop(TENANT, None)
        try:
            yield db
        finally:
            await db.rollback()
            _recording_failures.pop(TENANT, None)
            _last_recording_failures.pop(TENANT, None)


async def configure(db, provider="openai_compatible", *, base="https://api.openai.com/v1", label=None, kind=None, model="alias"):
    return await save_config(
        db,
        Provider(provider),
        host_reach=None,
        base_url=base,
        model=model,
        reasoning_effort=None,
        api_key=None,
        clear_key=False,
        updated_by=None,
        service_label=label,
        service_kind=kind,
    )


def reply(*, model="actual", tokens=None):
    return SimpleNamespace(
        model=model,
        input_tokens=tokens,
        completion_tokens=None,
        cached_tokens=None,
        provider_ms=None,
        content="SYNTHETIC_RESPONSE_MUST_NOT_BE_RECORDED",
        reasoning="SYNTHETIC_REASONING_MUST_NOT_BE_RECORDED",
    )


async def attempt(
    db,
    config,
    *,
    feature="ai_test_box",
    outcome="answered",
    use="completed",
    dispatched=True,
    work_id=None,
    number=1,
    fallback=False,
    tokens=None,
    model="actual",
    status=None,
):
    meter = recorder(
        db, feature, config.provider, "alias", config=config, work_id=work_id, attempt_number=number, fallback=fallback
    )
    await meter.start(60)
    if dispatched:
        meter.dispatch()
    await meter.finish_attempt(outcome, reply(tokens=tokens, model=model), status=status)
    if use:
        await meter.accepted(use)
    return meter


async def test_service_attribution_composed_filters_reconcile_with_legacy_and_logical_work(activity_db):
    db = activity_db
    fm = await configure(db, "apple_fm", base="http://127.0.0.1:1976/v1")
    cloud = await configure(db, label="Cloud A")
    await attempt(db, fm, tokens=0)
    job = uuid.uuid4()
    now = datetime.now(UTC)
    await work_event(db, job, "inventory_summary", cloud.provider, "waiting", now, config=cloud)
    await db.commit()
    await attempt(db, cloud, feature="inventory_summary", work_id=job, outcome="http_status", status=429, use=None)
    await attempt(db, cloud, feature="inventory_summary", work_id=job, number=2, fallback=True, tokens=12)
    await work_event(db, job, "inventory_summary", cloud.provider, "completed", now, config=cloud)
    await work_event(db, uuid.uuid4(), "inventory_summary", cloud.provider, "cached", now, config=cloud)
    await db.commit()
    local = await configure(db, base="http://127.0.0.1:11434/v1", label="Local A", kind="ollama")
    await attempt(db, local, feature="changes_prompt", use="unusable")
    await attempt(db, fm, outcome="timeout", dispatched=False, use=None)
    await add(
        db,
        feature="changes_prompt",
        provider="openai_compatible",
        requested="alias",
        reported="actual",
        kind="call",
        outcome="answered",
        request_ms=100,
        input_tokens=7,
        input_reports=1,
    )
    await db.commit()
    today = now.date()
    report = await activity_report(db, today - timedelta(days=1), today)
    totals = report["totals"]
    assert totals["attempts"] == 6
    assert (totals["dispatches"], totals["dispatchReports"], totals["usefulResults"], totals["usefulReports"]) == (4, 5, 2, 5)
    assert (totals["retries"], totals["fallbacks"], totals["waitingTimeouts"], totals["unusable"]) == (1, 1, 1, 1)
    assert (totals["inputTokens"], totals["inputReports"], totals["outputTokens"], totals["outputReports"]) == (19, 3, None, 0)
    assert report["coverage"]["legacyAttempts"] == 1
    assert report["work"] == {
        "arrivals": 5,
        "completed": 2,
        "failed": 2,
        "cached": 1,
        "skipped": 0,
        "expired": 0,
        "retries": 1,
        "fallbacks": 1,
    }
    assert {r["serviceKind"] for r in report["services"]} == {"apple_fm", "openai", "ollama", "legacy"}
    assert {r["serviceLabel"] for r in report["services"]} >= {"Cloud A", "Local A", "Legacy / unknown compatible service"}
    assert report["configuredServices"][-1]["serviceLabel"] == "Local A"
    for collection in ("services", "purposes", "groups", "trend"):
        assert sum(r["attempts"] for r in report[collection]) == totals["attempts"]
    filtered = await activity_report(
        db,
        today,
        today,
        service=str(cloud.service_id),
        provider=cloud.provider,
        purpose="inventory_summary",
        model="actual",
        outcome="completed",
    )
    assert filtered["totals"]["attempts"] == filtered["totals"]["usefulResults"] == 1
    assert filtered["work"]["arrivals"] == filtered["work"]["completed"] == 1
    assert sum(r["attempts"] for r in filtered["trend"]) == 1
    assert (await activity_report(db, today, today, model="missing"))["state"] == "no_matches"
    # New configuration does not rewrite the snapshot labels on old attempts.
    await configure(db, base="https://example.invalid/v1", label="Renamed service", kind="compatible")
    assert "Cloud A" in {r["serviceLabel"] for r in (await activity_report(db, today, today))["services"]}
    serialized = json.dumps(jsonable_encoder(report))
    assert all(
        marker not in serialized for marker in ("127.0.0.1", "api.openai.com", "SYNTHETIC_RESPONSE", "SYNTHETIC_REASONING")
    )


async def test_config_identity_changes_for_service_changes_only(activity_db):
    db = activity_db
    original = await configure(db, label="Cloud A")
    same = await configure(db, model="new-model")
    assert same.service_id == original.service_id and same.service_label == "Cloud A"
    changed = await configure(db, label="Cloud B")
    assert changed.service_id != original.service_id
    restored = await configure(db, label="")
    assert restored.service_id != changed.service_id and restored.service_label is None
    assert service_identity(restored.provider, restored)["service_label"] == "OpenAI"


async def test_unknown_tokens_and_metadata_only_storage_and_tenant_isolation(activity_db, db):
    config = await configure(activity_db, base="http://localhost:11434/v1")
    assert service_identity(config.provider, config)["service_kind"] == "compatible"
    meter = await attempt(activity_db, config, model="https://synthetic-secret.invalid/model?token=DO_NOT_RECORD")
    report = await activity_report(activity_db, datetime.now(UTC).date(), datetime.now(UTC).date())
    assert report["totals"]["inputTokens"] is None and report["totals"]["inputReports"] == 0
    facts = (await activity_db.get(Attempt, meter.id)).__dict__
    assert facts["reported"] == ""
    assert not {"prompt", "content", "response", "reasoning", "api_key", "base_url"} & facts.keys()
    assert await db.get(Attempt, meter.id) is None
    assert await db.get(Work, meter.work_id) is None
    assert await db.get(Coverage, TENANT) is None
    with pytest.raises(Exception, match="row-level security"):
        await db.execute(update(Work).where(Work.id == uuid.uuid4()).values(tenant_id=TENANT))
        # INSERT is the write-side isolation proof; zero-row UPDATE alone proves nothing.
        db.add(
            Work(
                id=uuid.uuid4(),
                tenant_id=TENANT,
                feature="test",
                provider="apple_fm",
                **service_identity("apple_fm"),
                arrived_at=datetime.now(UTC),
                deadline_at=datetime.now(UTC),
            )
        )
        await db.flush()
    await db.rollback()


async def test_utc_history_boundary_and_no_duplicate_daily_contribution(activity_db):
    db = activity_db
    config = await configure(db)
    meter = await attempt(db, config, tokens=4)
    stamp = datetime.now(UTC).replace(hour=0, minute=5)
    await db.execute(update(Attempt).where(Attempt.id == meter.id).values(finished_at=stamp))
    await db.execute(text("SET LOCAL TIME ZONE 'America/Los_Angeles'"))
    report = await activity_report(db, stamp.date(), stamp.date())
    assert report["totals"]["attempts"] == 1
    assert report["totals"]["inputTokens"] == 4
    assert report["coverage"]["legacyAttempts"] == 0


async def test_recording_failure_never_looks_like_empty_success_and_recovers_window(activity_db, monkeypatch):
    from app.core import ai_usage

    db = activity_db
    config = await configure(db)
    real = ai_usage.session_for_tenant

    def unavailable(_tenant):
        raise RuntimeError("SYNTHETIC_UNSAFE_DATABASE_DETAIL")

    monkeypatch.setattr(ai_usage, "session_for_tenant", unavailable)
    meter = recorder(db, "ai_test_box", config.provider, "m", config=config)
    await meter.start(1)
    today = datetime.now(UTC).date()
    assert (await activity_report(db, today, today))["state"] == "unavailable"
    assert (await live_report(db))["state"] == "unavailable"
    monkeypatch.setattr(ai_usage, "session_for_tenant", real)
    await attempt(db, config)
    row = await db.get(Coverage, TENANT, populate_existing=True)
    assert row.degraded_since is not None and row.last_gap_at is not None
    # Recovery does not invent lost history. Only the later live interval can recover.
    old = datetime.now(UTC) - timedelta(hours=1)
    await db.execute(update(Coverage).values(first_measured_at=old, degraded_since=old, last_gap_at=old))
    await db.commit()
    _recording_failures.pop(TENANT)
    _last_recording_failures.pop(TENANT)
    assert (await live_report(db))["state"] == "keeping_up"
    assert (await activity_report(db, today, today))["state"] == "unavailable"


async def test_fm_wait_is_visible_and_timeout_does_not_count_as_provider_dispatch(activity_db):
    db = activity_db
    config = await configure(db, "apple_fm", base="http://127.0.0.1:1976/v1")
    entered, release = asyncio.Event(), asyncio.Event()

    async def handler(request):
        entered.set()
        await release.wait()
        return httpx.Response(200, json={"choices": [{"message": {"content": "synthetic answer"}}]})

    transport = httpx.MockTransport(handler)

    def request():
        return CompletionRequest(
            base_url=config.base_url,
            model="system",
            prompt="SYNTHETIC_PRIVATE_PROMPT",
            serial=True,
            record_usage=recorder(db, "ai_test_box", config.provider, "system", config=config),
        )

    first = asyncio.create_task(complete(Wire.openai_chat, request(), transport=transport))
    await asyncio.wait_for(entered.wait(), 5)
    second_request = request()
    second = asyncio.create_task(complete(Wire.openai_chat, second_request, transport=transport, timeout_seconds=0.3))
    try:
        for _ in range(40):
            live = await live_report(db)
            if live["interactive"]["waiting"] == 1 and live["interactive"]["running"] == 1:
                break
            await asyncio.sleep(0.01)
        assert (live["interactive"]["waiting"], live["interactive"]["running"]) == (1, 1)
        assert live["oldestWaitingSeconds"] is not None
        with pytest.raises(AdapterError, match="complete reply"):
            await second
    finally:
        release.set()
        result = await first
        await accepted(result)
        if not second.done():
            second.cancel()
    row = await db.get(Attempt, second_request.record_usage.id)
    assert row.outcome == "waiting_timeout" and row.dispatched_at is None
    assert row.wait_ms >= 200 and row.request_ms is None
    report = await activity_report(db, datetime.now(UTC).date(), datetime.now(UTC).date())
    assert (report["totals"]["attempts"], report["totals"]["dispatches"], report["totals"]["waitingTimeouts"]) == (2, 1, 1)


async def test_live_burst_drain_disabled_and_empty_states(activity_db):
    db = activity_db
    config = await configure(db)
    now = datetime.now(UTC)
    db.add(Coverage(first_measured_at=now - timedelta(hours=1), last_recorded_at=now))
    await db.commit()
    assert (await live_report(db))["state"] == "idle"
    assert (await activity_report(db, now.date(), now.date()))["state"] == "no_calls"
    ids = [uuid.uuid4() for _ in range(4)]
    for work_id in ids:
        await work_event(db, work_id, "changes_prompt", config.provider, "waiting", now, config=config)
    await db.commit()
    burst = await live_report(db)
    assert (burst["state"], burst["waiting"], burst["arrivals"], burst["usefulCompletions"]) == ("backlog_growing", 4, 4, 0)
    for work_id in ids:
        await work_event(db, work_id, "changes_prompt", config.provider, "completed", now, config=config)
    await db.commit()
    drained = await live_report(db)
    assert (drained["state"], drained["waiting"], drained["usefulCompletions"]) == ("keeping_up", 0, 4)
    await db.execute(update(FeatureFlag).where(FeatureFlag.key == "ai_features").values(enabled=False))
    await db.commit()
    assert (await live_report(db))["state"] == "disabled"
    history = await activity_report(db, now.date(), now.date())
    assert history["aiEnabled"] is False and history["usageEnabled"] is True


async def test_retention_keeps_finished_day_and_work_counts_use_event_times(activity_db):
    from app.core.ai_usage import RETENTION_DAYS, prune

    db = activity_db
    config = await configure(db)
    meter = await attempt(db, config)
    today = datetime.now(UTC).date()
    cutoff_day = today - timedelta(days=RETENTION_DAYS - 1)
    cutoff = datetime.combine(cutoff_day, datetime.min.time(), UTC)
    arrived, finished = cutoff - timedelta(minutes=1), cutoff + timedelta(minutes=1)
    await db.execute(update(Attempt).where(Attempt.id == meter.id).values(started_at=arrived, finished_at=finished))
    await db.execute(update(Work).where(Work.id == meter.work_id).values(arrived_at=arrived, finished_at=finished))
    await db.execute(delete(Daily))
    await add(
        db,
        feature="ai_test_box",
        provider=config.provider,
        requested="alias",
        reported="actual",
        kind="call",
        outcome="answered",
        at=finished,
    )
    await db.commit()
    # Terminal work belongs to its completion day, independently of arrivals.
    previous = await activity_report(db, arrived.date(), arrived.date())
    terminal = await activity_report(db, cutoff_day, cutoff_day)
    assert (previous["work"]["arrivals"], previous["work"]["completed"]) == (1, 0)
    assert (terminal["work"]["arrivals"], terminal["work"]["completed"]) == (0, 1)
    await prune(db, today)
    await db.commit()
    kept = await activity_report(db, cutoff_day, cutoff_day)
    assert kept["totals"]["attempts"] == kept["coverage"]["detailedAttempts"] == 1
    assert kept["coverage"]["legacyAttempts"] == 0
    assert kept["work"]["completed"] == 1
    # Once the finish itself falls out of retention, both detailed facts expire.
    await prune(db, today + timedelta(days=1))
    await db.commit()
    assert await db.get(Attempt, meter.id, populate_existing=True) is None
    assert await db.get(Work, meter.work_id, populate_existing=True) is None


async def test_abandoned_interactive_work_stalls_then_maintenance_expires_once(activity_db):
    from app.core.ai_usage import expire_abandoned

    db = activity_db
    config = await configure(db)
    meter = recorder(db, "changes_prompt", config.provider, "m", config=config)
    await meter.start(10)
    now = datetime.now(UTC)
    await db.execute(update(Coverage).values(first_measured_at=now - timedelta(hours=1)))
    await db.execute(update(Work).where(Work.id == meter.work_id).values(deadline_at=now - timedelta(seconds=30)))
    await db.commit()
    assert (await live_report(db))["state"] == "stalled"
    await expire_abandoned(db, now)
    await db.commit()
    assert (await db.get(Work, meter.work_id, populate_existing=True)).outcome == "waiting"
    await db.execute(update(Work).where(Work.id == meter.work_id).values(deadline_at=now - timedelta(seconds=121)))
    await expire_abandoned(db, now)
    await db.commit()
    live = await live_report(db)
    assert (live["state"], live["waiting"], live["running"], live["expired"]) == ("expired", 0, 0, 1)
    facts = await db.get(Attempt, meter.id, populate_existing=True)
    assert facts.outcome == "interrupted" and facts.total_ms is None and facts.request_ms is None
    report = await activity_report(db, now.date(), now.date())
    assert report["totals"]["attempts"] == 1
    assert report["totals"]["dispatches"] is None and report["totals"]["dispatchReports"] == 0
    await expire_abandoned(db, now)
    await db.commit()
    await meter.finish_attempt("timeout", None)
    assert (await activity_report(db, now.date(), now.date()))["totals"]["attempts"] == 1


async def test_legacy_callback_preserves_elapsed_without_inventing_boundaries(activity_db):
    from app.core.ai_usage import usage_report

    db = activity_db
    config = await configure(db)
    await recorder(db, "ai_test_box", config.provider, "alias", config=config)("answered", reply(tokens=3), 245)
    today = datetime.now(UTC).date()
    assert (await usage_report(db, today, today))["calls"][0]["request_ms"] == 245
    report = await activity_report(db, today, today)
    assert report["coverage"]["legacyAttempts"] == 1 and report["detailedSince"] is None
    assert report["totals"]["dispatches"] is None and report["totals"]["avgRequestMs"] is None


async def test_automatic_service_identity_rotates_across_json_null_ollama_policy(activity_db):
    db = activity_db

    async def save(policy):
        return await save_config(
            db,
            Provider.openai_compatible,
            host_reach=None,
            base_url="http://127.0.0.1:11434/v1",
            model="m",
            reasoning_effort=None,
            api_key=None,
            clear_key=False,
            updated_by=None,
            ollama_policy=policy,
        )

    automatic = await save(None)
    ollama = await save({"preferences": ["m"], "fallback": None})
    assert service_identity(automatic.provider, automatic)["service_kind"] == "compatible"
    assert service_identity(ollama.provider, ollama)["service_kind"] == "ollama"
    assert automatic.service_id != ollama.service_id
    edited_models = await save({"preferences": ["m2"], "fallback": "m3"})
    assert edited_models.service_id == ollama.service_id
    automatic_again = await save(None)
    assert automatic_again.service_id != ollama.service_id
