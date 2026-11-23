"""Proposals use the AI gate, local inventory counts, and never write a saved scope or plan."""

import json

import httpx
from sqlalchemy import func, select

from app.core import device_scope_proposal as proposals
from app.models.schema import ApplicationPatchPlan
from tests.patch_plan_fixtures import accounts, admin, flag_off, github, inventory  # noqa: F401
from tests.test_application_patch_plans_db import pytestmark as pytestmark
from tests.test_changes_prompt_db import _ai_rows, _reset, _saved, _switches


async def test_proposal_consent_disclosure_count_and_no_plan_write(db, admin, inventory, monkeypatch):  # noqa: F811
    source, _, _ = inventory
    scope = {
        "connectionId": source,
        "match": "all",
        "rules": [
            {"field": "contact", "operator": "within", "value": "14"},
            {"match": "any", "rules": [{"field": "managed", "operator": "unknown"}, {"field": "site", "value": "HQ"}]},
        ],
    }
    sent = []
    answer = {"scope": scope, "unsupported": []}

    def endpoint(request):
        sent.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": "qwen3.8:27b-mlx",
                "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(answer)}}],
                "usage": {"prompt_tokens": 30, "completion_tokens": 60},
            },
        )

    monkeypatch.setattr(proposals, "transport_override", httpx.MockTransport(endpoint))
    await _reset(db)
    try:
        await _switches(db, flag=True, consent=False)
        await _saved(db, "openai_compatible", "qwen3.8:27b-mlx")
        payload = {
            "question": "Contact within 14 days AND (managed unknown OR site HQ)",
            "scope": {"connectionId": source},
            "provider": "openai_compatible",
        }
        response = await admin.post("/api/application-patch-plans/propose-scope", json=payload)
        assert response.status_code == 409 and not sent
        await _switches(db, flag=True, consent=True)
        before = await db.scalar(select(func.count()).select_from(ApplicationPatchPlan))
        response = await admin.post("/api/application-patch-plans/propose-scope", json=payload)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["outcome"] == "proposed" and body["matchedDevices"] == 1
        assert body["scope"]["rules"][1]["match"] == "any"
        logs = await _ai_rows(db)
        assert any(row.payload.get("feature") == "device_scope_proposal" for row in logs)
        assert await db.scalar(select(func.count()).select_from(ApplicationPatchPlan)) == before
        assert "serial-" not in json.dumps(sent) and "host-" not in json.dumps(sent)
        answer["unsupported"] = ["Cannot scope FileVault here"]
        body = (await admin.post("/api/application-patch-plans/propose-scope", json=payload)).json()
        assert body["outcome"] == "unsupported" and body["scope"] is None
    finally:
        await _reset(db)
