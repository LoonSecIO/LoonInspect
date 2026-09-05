"""POST /api/system/ai/test through the whole door (#319): the URL rule, the reach
table, the gate, the disclosure row, the wire, and what comes back.

The endpoint is stood in for by an `httpx.MockTransport` installed on
`app.api.ai.transport_override`; the recorder notes when it was called so the
disclosure row's timestamp can be shown to precede the first byte. Needs a real
Postgres for the gate's rows, so it is gated on RUN_DB_TESTS like its siblings.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("ai-test-box-admin@example.com", "ai-test-box-admin-password")
AUDITOR = ("ai-test-box-auditor@example.com", "ai-test-box-auditor-password")
KEY = "sk-test-box-key-never-shown"

REPLY = {
    "model": "qwen3.5:2b-mlx",
    "choices": [{"message": {"content": "Because they don't have the guts.", "reasoning": "skeletons"}, "finish_reason": "stop"}],
    "usage": {"completion_tokens": 57},
}


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts() -> None:
    from app.core.bootstrap import bootstrap_tenants, create_account
    from app.core.database import init_db, session_for_tenant, unscoped_session
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account

    await init_db()
    async with unscoped_session() as db:
        await bootstrap_tenants(db)
    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        for (email, password), role in ((ADMIN, "admin"), (AUDITOR, "auditor")):
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=role, password=password, roles=(role,))
        await db.commit()


async def _signed_in(email: str, password: str) -> httpx.AsyncClient:
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://ai.example.com")
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return client


@pytest_asyncio.fixture(loop_scope="session")
async def client(accounts):
    signed_in = await _signed_in(*ADMIN)
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


@pytest_asyncio.fixture(loop_scope="session")
async def db(accounts):
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        yield session


async def _reset(db) -> None:
    from app.core.ai import AI_SHARE_TIER
    from app.core.feature_flags import AI_FEATURES_FLAG
    from app.models.schema import DataSharingSettings, FeatureFlag, ShareLog

    await db.rollback()
    await db.execute(delete(FeatureFlag).where(FeatureFlag.key == AI_FEATURES_FLAG))
    await db.execute(delete(ShareLog).where(ShareLog.tier == AI_SHARE_TIER))
    row = (await db.execute(select(DataSharingSettings))).scalar_one_or_none()
    if row is not None:
        row.ai_inference = False
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def clean(db):
    await _reset(db)
    yield
    await _reset(db)


async def _switches(db, *, flag: bool, consent: bool) -> None:
    from app.api.feature_flags import update_feature_flag
    from app.api.system import update_data_sharing
    from app.core.feature_flags import AI_FEATURES_FLAG
    from app.schemas.feature_flags import FeatureFlagUpdate
    from app.schemas.system import DataSharingUpdate

    if flag:
        await update_feature_flag(AI_FEATURES_FLAG, FeatureFlagUpdate(enabled=True), db)
    await update_data_sharing(DataSharingUpdate(ai_inference=consent), db)


async def _ai_rows(db) -> list:
    from app.core.ai import AI_SHARE_TIER
    from app.models.schema import ShareLog

    await db.rollback()
    return (await db.execute(select(ShareLog).where(ShareLog.tier == AI_SHARE_TIER))).scalars().all()


class Recorder:
    def __init__(self, status: int = 200, body: dict | None = None) -> None:
        self.status = status
        self.body = body if body is not None else REPLY
        self.requests: list[httpx.Request] = []
        self.called_at: datetime | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.called_at = datetime.now(timezone.utc)
        return httpx.Response(self.status, json=self.body)


@pytest.fixture
def endpoint(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    recorder = Recorder()
    monkeypatch.setattr("app.api.ai.transport_override", httpx.MockTransport(recorder))
    return recorder


def _body(**overrides):
    body = {
        "provider": "openai_compatible",
        "baseUrl": "http://host.docker.internal:11434/v1",
        "model": "qwen3.5:2b-mlx",
        "prompt": "Tell me a joke.",
        "reasoningEffort": "none",
    }
    body.update(overrides)
    return body


async def test_flag_off_refuses_before_anything_is_dialled(client, db, clean, endpoint):
    response = await client.post("/api/system/ai/test", json=_body())
    assert response.status_code == 409
    assert "AI features are off" in response.json()["detail"]
    assert endpoint.requests == []
    assert await _ai_rows(db) == []


async def test_consent_off_refuses_the_off_pod_call(client, db, clean, endpoint):
    await _switches(db, flag=True, consent=False)
    response = await client.post("/api/system/ai/test", json=_body())
    assert response.status_code == 409
    assert "consent is off" in response.json()["detail"]
    assert endpoint.requests == []
    assert await _ai_rows(db) == []


async def test_a_permitted_send_writes_the_row_first_and_returns_the_reply(client, db, clean, endpoint):
    await _switches(db, flag=True, consent=True)
    response = await client.post("/api/system/ai/test", json=_body())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["outcome"] == "answered"
    assert body["content"] == "Because they don't have the guts."
    assert body["reasoning"] == "skeletons"
    assert body["destination"] == "http://host.docker.internal:11434"
    assert body["completionTokens"] == 57
    assert body["error"] is None

    # The wire carried exactly the documented shape, to the documented path.
    assert len(endpoint.requests) == 1
    request = endpoint.requests[0]
    assert str(request.url) == "http://host.docker.internal:11434/v1/chat/completions"
    assert "authorization" not in request.headers

    # One disclosure row, naming the destination and the one field that left, and
    # committed before the endpoint saw the first byte.
    rows = await _ai_rows(db)
    assert len(rows) == 1
    assert rows[0].endpoint == "http://host.docker.internal:11434"
    assert rows[0].payload == {"feature": "ai_test_box", "fields": ["prompt_text"]}
    assert rows[0].occurred_at <= endpoint.called_at


async def test_the_key_reaches_the_wire_and_nothing_else(client, db, clean, endpoint, caplog):
    await _switches(db, flag=True, consent=True)
    with caplog.at_level(logging.DEBUG):
        response = await client.post("/api/system/ai/test", json=_body(apiKey=KEY))
    assert response.status_code == 200, response.text
    assert endpoint.requests[0].headers["authorization"] == f"Bearer {KEY}"
    assert KEY not in response.text
    assert KEY not in caplog.text
    rows = await _ai_rows(db)
    assert KEY not in repr(rows[0].payload)


async def test_anthropic_needs_a_key_and_speaks_its_own_wire(client, db, clean, endpoint):
    await _switches(db, flag=True, consent=True)
    anthropic = {"provider": "anthropic", "baseUrl": "https://api.anthropic.com", "model": "claude-fable-5-1"}
    refused = await client.post("/api/system/ai/test", json=_body(**anthropic))
    assert refused.status_code == 422
    assert "needs an API key" in refused.json()["detail"]
    assert endpoint.requests == []

    endpoint.body = {
        "model": "claude-fable-5-1",
        "content": [{"type": "text", "text": "A joke."}],
        "stop_reason": "end_turn",
        "usage": {"output_tokens": 3},
    }
    response = await client.post("/api/system/ai/test", json=_body(**anthropic, apiKey=KEY, reasoningEffort=None))
    assert response.status_code == 200, response.text
    assert response.json()["wire"] == "anthropic_messages"
    assert response.json()["content"] == "A joke."
    request = endpoint.requests[-1]
    assert str(request.url) == "https://api.anthropic.com/v1/messages"
    assert request.headers["x-api-key"] == KEY
    assert request.headers["anthropic-version"] == "2023-06-01"


async def test_a_reserved_reach_is_refused_by_name_before_the_gate(client, db, clean, endpoint):
    await _switches(db, flag=True, consent=True)
    response = await client.post("/api/system/ai/test", json=_body(hostReach="orbstack"))
    assert response.status_code == 400
    assert "orbstack" in response.json()["detail"]
    assert endpoint.requests == []
    assert await _ai_rows(db) == []


async def test_a_blocked_url_is_refused_before_the_gate(client, db, clean, endpoint):
    await _switches(db, flag=True, consent=True)
    response = await client.post("/api/system/ai/test", json=_body(baseUrl="http://169.254.169.254/v1"))
    assert response.status_code == 422
    assert "link-local" in response.json()["detail"]
    assert endpoint.requests == []
    assert await _ai_rows(db) == []


async def test_an_upstream_failure_is_reported_in_the_reply_and_the_attempt_is_on_record(client, db, clean, endpoint):
    await _switches(db, flag=True, consent=True)
    endpoint.status = 500
    endpoint.body = {"error": {"message": "boom"}}
    response = await client.post("/api/system/ai/test", json=_body())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["outcome"] == "error"
    assert body["error"]["kind"] == "http_status"
    assert body["error"]["status"] == 500
    assert "boom" in body["error"]["message"]
    assert len(await _ai_rows(db)) == 1


async def test_an_auditor_may_read_the_table_but_not_send(accounts, clean):
    auditor = await _signed_in(*AUDITOR)
    try:
        listing = await auditor.get("/api/system/ai/providers")
        assert listing.status_code == 200
        refused = await auditor.post("/api/system/ai/test", json=_body())
        assert refused.status_code == 403
    finally:
        await auditor.aclose()


async def test_the_table_and_the_detection_are_served(client):
    providers = (await client.get("/api/system/ai/providers")).json()
    assert [e["provider"] for e in providers["entries"]] == ["apple_fm", "openai_compatible", "anthropic"]
    reaches = {r["reach"]: r for r in providers["reaches"]}
    assert reaches["docker_desktop"] == {"reach": "docker_desktop", "hostname": "host.docker.internal", "implemented": True}
    assert reaches["orbstack"]["implemented"] is False
    assert providers["reasoningEfforts"][0] == "none"

    host = (await client.get("/api/system/ai/host")).json()
    assert set(host) >= {"runtime", "hostOs", "appleSilicon", "aliasResolves", "dockerDesktopOnMacos", "evidence"}
