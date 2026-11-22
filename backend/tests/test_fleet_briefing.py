"""Synthetic Fleet briefing with a stand-in provider. Only aggregate counts cross the adapter."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.ai.adapters import AdapterError
from app.ai.providers import Provider, Wire
from app.api import fleet_briefing as briefing
from app.core.ai import AIConsentMissing
from app.schemas.changes_prompt import PromptStatusOut
from app.schemas.fleet_assessment import FleetAssessmentOut
from app.schemas.fleet_migration import LocalApp, MigrationReport, MigrationScope, SourceConnection


def example():
    return MigrationReport(
        as_of=datetime.now(UTC),
        scope=MigrationScope(active_macs=2),
        connections=[SourceConnection(id=7, name="Sensitive customer")],
        items=[
            LocalApp(
                app_hash="private-app-id",
                name="Secret.app",
                bundle_id="private.bundle",
                macs=2,
                version_count=1,
                match="exact",
                has_jamf_match=True,
                jamf_evaluated=True,
                fleet_candidates=[],
            )
        ],
        app_assessments={
            "private-app-id": FleetAssessmentOut(
                target_version="3.0-private",
                reason="sensitive detail",
                management_reason="internal rule",
                out_of_policy_builds=1,
                kev_builds=1,
                unknown_builds=1,
            )
        },
    )


@pytest.fixture
def mocks(monkeypatch):
    config = SimpleNamespace(
        provider=Provider.openai_compatible,
        model="saved",
        api_key_encrypted=None,
        host_reach=None,
        base_url="http://127.0.0.1:8181/v1",
        ollama_policy=None,
        reasoning_effort=None,
    )
    patched = {
        "read_migration": AsyncMock(return_value=example()),
        "prompt_status": AsyncMock(return_value=PromptStatusOut(available=True, providers=[], reason=None)),
        "chosen_config": AsyncMock(return_value=config),
        "judged_endpoint": AsyncMock(return_value=(Wire.openai_chat, config.base_url, "127.0.0.1:8181", None)),
        "select_model": AsyncMock(return_value={"model": "actual"}),
        "require_ai": AsyncMock(),
        "complete": AsyncMock(return_value=SimpleNamespace(outcome="answered", content='["apps_with_kev","apps_overdue"]')),
    }
    for name, stub in patched.items():
        monkeypatch.setattr(briefing, name, stub)
    monkeypatch.setattr(briefing, "audit", lambda *args, **kwargs: None)
    return patched


@pytest.mark.asyncio
async def test_outbound_prompt_only_contains_disclosed_server_counters(mocks):
    db = object()
    result = await briefing.briefing(briefing.BriefingIn(), object(), db)
    assert result.outcome == "selected" and result.model == "actual"
    assert [(line.code, line.count) for line in result.highlights] == [("apps_with_kev", 1), ("apps_overdue", 1)]
    request = mocks["complete"].await_args.args[1]
    counts = json.loads(request.prompt)
    assert counts == {"apps_overdue": 1, "apps_with_kev": 1, "incomplete_comparisons": 1, "exact_candidates": 1, "scoped_macs": 2}
    assert set(mocks["require_ai"].await_args.kwargs["fields"]) == set(counts)
    assert mocks["require_ai"].await_args.kwargs["model"] == "actual"
    assert request.model == "actual" and request.record_usage is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad", ['["CVE-2026-9999"]', '{"command":"run"}', '["scoped_macs","scoped_macs"]', '["apps_with_kev",{}]']
)
async def test_untrusted_model_result_never_becomes_report_text(bad, mocks):
    mocks["complete"].return_value = SimpleNamespace(outcome="answered", content=bad)
    result = await briefing.briefing(briefing.BriefingIn(), object(), object())
    assert result.outcome == "fallback" and bad not in result.model_dump_json()
    assert [h.code for h in result.highlights] == ["apps_overdue", "apps_with_kev", "incomplete_comparisons"]


@pytest.mark.asyncio
async def test_no_consent_no_dial_including_revocation_after_status(mocks):
    mocks["prompt_status"].return_value = PromptStatusOut(available=False, reason="consent_off", providers=[])
    with pytest.raises(HTTPException, match="consent"):
        await briefing.briefing(briefing.BriefingIn(), object(), object())
    mocks["chosen_config"].assert_not_awaited()
    mocks["prompt_status"].return_value = PromptStatusOut(available=True, reason=None, providers=[])
    mocks["require_ai"].side_effect = AIConsentMissing("AI inference consent was revoked")
    with pytest.raises(HTTPException, match="revoked"):
        await briefing.briefing(briefing.BriefingIn(), object(), object())
    mocks["complete"].assert_not_awaited()


@pytest.mark.asyncio
async def test_unreachable_provider_falls_back_to_scoped_facts(mocks):
    mocks["complete"].side_effect = AdapterError("timeout", "not for output")
    result = await briefing.briefing(briefing.BriefingIn(), object(), object())
    assert result.outcome == "fallback" and "timeout" in result.detail
    assert "not for output" not in result.model_dump_json()


def test_request_cannot_supply_prompt_or_report_data():
    with pytest.raises(ValidationError):
        briefing.BriefingIn.model_validate({"prompt": "private facts", "apps_overdue": 999})
