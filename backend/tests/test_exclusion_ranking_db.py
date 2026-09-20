"""Real candidate query, consent/disclosure, and operator-owned saves for #409."""

# Imported pytest fixtures are deliberately shadowed by fixture arguments.
# ruff: noqa: F811
import json
import os

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.api import exclusion_ranking as api
from app.core.sharing import get_or_create_settings
from app.models.schema import ShareLog
from tests.test_ai_configs_db import (  # noqa: F401
    VIEWER,
    _flag_on,
    _signed_in,
    accounts,
    clean,
    client,
    db,
)
from tests.test_exclusion_candidates_db import fleet  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres"),
    pytest.mark.asyncio(loop_scope="session"),
]
URL = "/api/system/data-sharing/exclusion-ranking"


@pytest_asyncio.fixture(loop_scope="session")
async def enabled(db, clean):
    row = await get_or_create_settings(db)
    old = row.ai_inference
    row.ai_inference = True
    await db.commit()
    await _flag_on(db)
    yield
    await db.rollback()
    row = await get_or_create_settings(db)
    row.ai_inference = old
    await db.execute(delete(ShareLog).where(ShareLog.payload["feature"].astext == "exclusion_ranking"))
    await db.commit()


async def test_rank_discloses_before_sending_and_never_saves_exclusions(client, db, enabled, fleet, monkeypatch):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    saved = await client.put(
        "/api/system/ai/configs/openai_compatible", json={"baseUrl": "http://127.0.0.1:11434/v1", "model": "local"}
    )
    assert saved.status_code == 200
    original = list((await get_or_create_settings(db)).exclude_globs or [])
    requests = []

    async def answer(request):
        async with session_for_tenant(OPERATIONAL_TENANT_ID) as other:
            disclosure = (
                (await other.execute(select(ShareLog).where(ShareLog.payload["feature"].astext == "exclusion_ranking")))
                .scalars()
                .one()
            )
            assert "app_names" in disclosure.payload["fields"]
            assert "Acme" not in json.dumps(disclosure.payload)
        body = json.loads(request.content)
        groups = json.loads(body["messages"][1]["content"])["candidates"]
        assert all(len(group["apps"]) <= 3 for group in groups)
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "classifications": [
                                        {"index": group["index"], "classification": "likely_in_house"} for group in groups
                                    ]
                                }
                            )
                        }
                    }
                ]
            },
        )

    monkeypatch.setattr(api, "transport_override", httpx.MockTransport(answer))
    status = (await client.get(URL)).json()
    assert status["available"] and len(status["providers"]) == 1
    result = await client.post(URL, json={"provider": "openai_compatible", "globs": original})
    assert result.status_code == 200, result.text
    data = result.json()
    assert requests and data["assessments"][0]["classification"] == "likely_in_house"
    assert data["candidates"]["groups"][0]["suggestion"] is not None
    await db.refresh(await get_or_create_settings(db))
    assert list((await get_or_create_settings(db)).exclude_globs or []) == original


@pytest.mark.parametrize("case", ["flag_off", "consent_off", "public", "hosted_provider"])
async def test_refusals_send_no_inventory(client, db, enabled, monkeypatch, case):
    from sqlalchemy import update

    from app.models.schema import FeatureFlag

    if case == "flag_off":
        await db.execute(update(FeatureFlag).where(FeatureFlag.key == "ai_features").values(enabled=False))
    if case == "consent_off":
        (await get_or_create_settings(db)).ai_inference = False
    await db.commit()
    if case == "public":
        assert (
            await client.put(
                "/api/system/ai/configs/openai_compatible", json={"baseUrl": "https://8.8.8.8/v1", "model": "hosted"}
            )
        ).status_code == 200

    def forbidden(request):
        pytest.fail("a refused request dialled a model")

    monkeypatch.setattr(api, "transport_override", httpx.MockTransport(forbidden))
    result = await client.post(
        URL, json={"provider": "anthropic" if case == "hosted_provider" else "openai_compatible", "globs": []}
    )
    assert result.status_code == 409, result.text
    assert (
        await db.execute(select(ShareLog).where(ShareLog.payload["feature"].astext == "exclusion_ranking"))
    ).scalars().all() == []


async def test_viewer_cannot_send_inventory_for_ranking(accounts):
    viewer = await _signed_in(*VIEWER)
    try:
        assert (await viewer.post(URL, json={"provider": "openai_compatible", "globs": []})).status_code == 403
    finally:
        await viewer.aclose()


@pytest.mark.parametrize("reply", ["not JSON", '{"classifications":[{"index":0,"classification":"uncertain","glob":"*"}]}'])
async def test_bad_model_answers_leave_saved_exclusions_unchanged(client, db, enabled, fleet, monkeypatch, reply):
    await client.put("/api/system/ai/configs/openai_compatible", json={"baseUrl": "http://127.0.0.1:11434/v1", "model": "local"})
    settings = await get_or_create_settings(db)
    original = list(settings.exclude_globs or [])
    monkeypatch.setattr(
        api,
        "transport_override",
        httpx.MockTransport(lambda request: httpx.Response(200, json={"choices": [{"message": {"content": reply}}]})),
    )
    response = await client.post(URL, json={"provider": "openai_compatible", "globs": []})
    assert response.status_code == 502
    assert "no exclusions were changed" in response.json()["detail"]
    await db.refresh(settings)
    assert list(settings.exclude_globs or []) == original
