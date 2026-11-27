"""The migration briefing (#910) through its routes, on Postgres and #895's inventory, with a stand-in provider."""

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.api import fleet_briefing
from app.core.ai import AI_SHARE_TIER
from app.main import app
from app.models import schema as s
from tests.test_changes_prompt_db import Recorder, _ai_rows, _reply, _reset, _saved, _switches, audit_records  # noqa: F401
from tests.test_fleet_assessment import A
from tests.test_fleet_assessment_db import EPOCH, behind, catalog_row
from tests.test_fleet_catalog_db import ALPHA
from tests.test_fleet_migration_db import _filter, accounts, admin, flag_off, flag_on, github, inventory, unstated  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

BRIEFING, FEATURE, MODEL = "/api/fleet-catalog/briefing", fleet_briefing.FEATURE, "qwen3.5:2b-mlx"  # `_saved`'s card


async def _clear(db) -> None:
    await _reset(db)
    for model in (s.AIUsageAttempt, s.AIUsageWork, s.AIUsageDaily):
        await db.execute(delete(model).where(model.feature == FEATURE))
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def endpoint(db, monkeypatch: pytest.MonkeyPatch):
    """A stand-in provider, with AI on, consent given and an OpenAI-compatible card saved; none of its usage left."""
    recorder = Recorder()
    monkeypatch.setattr(fleet_briefing, "transport_override", httpx.MockTransport(recorder))
    await _clear(db)
    await _switches(db, flag=True, consent=True)
    await _saved(db, "openai_compatible")
    yield recorder
    await _clear(db)


async def test_the_fleet_flag_and_the_reports_permissions_come_first(db, admin, flag_off, endpoint) -> None:  # noqa: F811
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://policy.example.com") as client:
        for scopes, status in ((["app:read"], 403), (["device:read"], 403), (["app:read", "device:read"], 409)):
            minted = await admin.post("/api/auth/tokens", json={"name": "fleet briefing", "scopes": scopes, "expiresInDays": 1})
            client.headers["Authorization"] = f"Bearer {minted.json()['token']}"
            for response in (await client.get(BRIEFING), await client.post(BRIEFING, json={})):
                assert response.status_code == status, (scopes, response.text)
                assert status == 403 or response.json()["detail"] == fleet_briefing.fleet_catalog.FLAG_OFF
    assert endpoint.requests == [] and await _ai_rows(db) == []


@pytest.mark.usefixtures("flag_on", "unstated")
async def test_only_the_codes_leave_and_the_work_closes(db, inventory, admin, endpoint, audit_records) -> None:  # noqa: F811
    source, alpha, _ = inventory
    # Alpha 1.0, 30 days behind its Jamf title under a confirmed 14-day rule: one app out of policy.
    entry, title_id = catalog_row("Alpha", ALPHA, "1.0", [A], EPOCH), uuid.uuid4().hex
    db.add(entry)
    await behind(db, entry, title_id, days=30)
    await db.commit()
    try:
        assert (await admin.put(f"/api/settings/patching-policy/overrides/{title_id}", json={"maxDaysBehind": 14})).is_success
        endpoint.body = _reply('["apps_overdue"]')
        chosen = await admin.post(BRIEFING, params=_filter(source), json={})
        endpoint.body = _reply('["invented"]')
        refused = await admin.post(BRIEFING, params=_filter(source), json={})
    finally:
        await db.rollback()
        await db.execute(delete(s.JamfPatchTitle).where(s.JamfPatchTitle.id == title_id))  # Its match goes with it.
        await db.execute(delete(s.AppCatalogEntry).where(s.AppCatalogEntry.app_hash == alpha))
        await db.commit()
    assert chosen.json() == {
        "outcome": "selected", "reason": None, "highlights": [{"code": "apps_overdue", "count": 1}],
        "provider": "openai_compatible", "model": MODEL, "error": None,
    }  # fmt: skip
    assert (refused.json()["outcome"], refused.json()["reason"], "invented" in refused.text) == ("fallback", "unusable", False)
    counts = {"apps_overdue": 1, "ambiguous_apps": 1, "incomplete_comparisons": 1, "exact_candidates": 2, "scoped_macs": 3}
    assert [line["code"] for line in refused.json()["highlights"]] == list(counts)[:3]
    private = ("Alpha", ALPHA, alpha, "1.0", "2.0", "migration-test-", "serial-", "host-")  # App, version, connection, Mac
    for sent in (json.loads(request.content) for request in endpoint.requests):
        assert ([m["content"] for m in sent["messages"]], sent["model"]) == ([fleet_briefing.SYSTEM, json.dumps(counts)], MODEL)
        assert not [name for name in private if name in json.dumps(sent)]
    rows = await _ai_rows(db)
    assert [row.payload for row in rows] == [{"feature": FEATURE, "fields": sorted(counts), "model": MODEL}] * 2
    config = await db.scalar(select(s.AIProviderConfig).where(s.AIProviderConfig.provider == "openai_compatible"))
    work = (await db.scalars(select(s.AIUsageWork).filter_by(feature=FEATURE).order_by(s.AIUsageWork.arrived_at))).all()
    assert [(w.outcome, w.service_id, w.service_kind != "legacy", w.finished_at is not None) for w in work] == [
        ("completed", str(config.service_id), True, True), ("unusable", str(config.service_id), True, True),
    ]  # fmt: skip
    activity = (await admin.get("/api/system/ai/activity", params={"purpose": FEATURE})).json()
    assert [purpose["label"] for purpose in activity["purposes"]] == ["Fleet migration briefings"]
    audited = [r for r in audit_records if r["action"] == "ai.fleet-catalog-briefing.sent"]
    assert [(r["outcome"], r["metadata"].get("highlights"), r["metadata"].get("error_kind")) for r in audited] == [
        ("selected", 1, None), ("unparseable", None, "malformed"),
    ]  # fmt: skip
    assert {key for r in audited for key in r["metadata"]} == {"provider", "latency_ms", "highlights", "error_kind"}


async def test_the_gate_runs_after_the_reports_snapshot(db, inventory, admin, flag_on, endpoint, monkeypatch) -> None:  # noqa: F811
    """Another AI caller prunes an expired share-log row mid-report: in READ COMMITTED the gate's prune finds it gone."""
    expired = datetime.now(UTC) - timedelta(days=91)
    stale = s.ShareLog(occurred_at=expired, tier=AI_SHARE_TIER, endpoint="x", outcome="sent", payload={})
    db.add(stale)
    await db.commit()
    read = fleet_briefing.read_migration

    async def read_then_prune(scope, session):
        report = await read(scope, session)
        await db.execute(delete(s.ShareLog).where(s.ShareLog.id == stale.id))
        await db.commit()
        return report

    monkeypatch.setattr(fleet_briefing, "read_migration", read_then_prune)
    endpoint.body = _reply('```json\n["exact_candidates"]\n```')
    response = await admin.post(BRIEFING, params=_filter(inventory[0]), json={})
    assert (response.status_code, response.json()["outcome"]) == (200, "selected"), response.text


async def test_a_provider_failure_falls_back_with_the_adapters_sentence(db, inventory, admin, flag_on, endpoint) -> None:  # noqa: F811
    endpoint.status, endpoint.body = 401, {"error": {"message": "upstream-private-detail"}}
    response = await admin.post(BRIEFING, params=_filter(inventory[0]), json={})
    body, error = response.json(), response.json()["error"]
    assert (body["outcome"], body["reason"], len(body["highlights"]), error["kind"], error["status"]) == (
        "fallback", "error", 3, "http_status", 401,
    )  # fmt: skip
    assert "HTTP 401: The endpoint rejected authentication" in error["message"] and "upstream" not in response.text


async def test_a_reply_that_is_not_an_answer_closes_unusable(db, inventory, admin, flag_on, endpoint, audit_records) -> None:  # noqa: F811
    """Empty, or its budget spent thinking: the report's counts, the work closed `unusable`, the adapter's outcome audited."""
    thinking = {"model": "system", "choices": [{"message": {"content": "", "reasoning": "Weighing."}, "finish_reason": "length"}]}
    for body in (_reply(""), thinking):
        endpoint.body = body
        reply = (await admin.post(BRIEFING, params=_filter(inventory[0]), json={})).json()
        assert (reply["outcome"], reply["reason"], len(reply["highlights"])) == ("fallback", "unusable", 3)
    assert json.loads(endpoint.requests[0].content)["max_tokens"] == 200  # The Changes Prompt's budget, room to think in.
    work = (await db.scalars(select(s.AIUsageWork).filter_by(feature=FEATURE).order_by(s.AIUsageWork.arrived_at))).all()
    assert [(w.outcome, w.reason) for w in work] == [("unusable", "empty"), ("unusable", "budget_exhausted_thinking")]
    audited = [r for r in audit_records if r["action"] == "ai.fleet-catalog-briefing.sent"]
    assert [(r["outcome"], r["metadata"]["error_kind"]) for r in audited] == [("unparseable", w.reason) for w in work]


async def test_main_refuses_with_the_gates_sentence_and_sends_nothing(db, inventory, admin, flag_on, endpoint) -> None:  # noqa: F811
    await _switches(db, flag=True, consent=False)
    withdrawn, status = await admin.post(BRIEFING, params=_filter(inventory[0]), json={}), (await admin.get(BRIEFING)).json()
    await _reset(db)  # AI off and no card saved: the Mac count alone reads neither.
    nothing = await admin.post(BRIEFING, params={"deviceScope": json.dumps({"connectionId": 2147483647})}, json={})
    await _saved(db, "openai_compatible")
    off = await admin.post(BRIEFING, params=_filter(inventory[0]), json={})
    assert (withdrawn.status_code, off.status_code, status["reason"]) == (409, 409, "consent_off")
    assert off.json()["detail"] == f"AI features are off; {FEATURE} may not run"
    assert withdrawn.json()["detail"].startswith(f"AI-inference consent is off; {FEATURE} may not send bytes to ")
    assert nothing.json() == {
        "outcome": "fallback", "reason": "nothing_to_rank", "highlights": [{"code": "scoped_macs", "count": 0}],
        "provider": None, "model": None, "error": None,
    }  # fmt: skip
    assert endpoint.requests == [] and await _ai_rows(db) == []
