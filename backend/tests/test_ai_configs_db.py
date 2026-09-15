"""Saved AI provider configs through the running routes (/api/system/ai/configs): a card's
Save kept server-side, the key encrypted at rest and never returned, the test box's URL
and key rules applied to what the row will hold, and the flag and the roles in front.

The key is read back from the column as Postgres holds it, through raw SQL the type
decorator never touches, so "encrypted at rest" is asserted of the stored bytes and not
of the ORM's view of them. Gated on RUN_DB_TESTS like the other database suites.
"""

from __future__ import annotations

import json
import logging
import os

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("ai-configs-admin@example.com", "ai-configs-admin-password")
VIEWER = ("ai-configs-viewer@example.com", "ai-configs-viewer-password")
AUDITOR = ("ai-configs-auditor@example.com", "ai-configs-auditor-password")
# Long and distinctive, so an absence assertion cannot pass by colliding with base64.
KEY = "sk-ant-saved-config-key-vvq-5c81e2d7f0"
OTHER_KEY = "sk-ant-replacement-key-vvq-9a04b6c3e1"

APPLE_FM = {"baseUrl": "http://host.docker.internal:1976/v1", "model": "system"}
OLLAMA = {"baseUrl": "http://host.docker.internal:11434/v1", "model": "qwen3.5:2b-mlx", "reasoningEffort": "none"}
ANTHROPIC = {"baseUrl": "https://api.anthropic.com", "model": "claude-fable-5-1"}


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
        for (email, password), role in ((ADMIN, "admin"), (VIEWER, "viewer"), (AUDITOR, "auditor")):
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=role, password=password, roles=(role,))
        await db.commit()


async def _signed_in(email: str, password: str) -> httpx.AsyncClient:
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://ai-configs.example.com")
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
    """The flag off and no saved configs. Other suites share the tenant, so only what
    this suite touches is cleared."""
    from app.core.feature_flags import AI_FEATURES_FLAG
    from app.models.schema import AIProviderConfig, FeatureFlag

    await db.rollback()
    await db.execute(delete(FeatureFlag).where(FeatureFlag.key == AI_FEATURES_FLAG))
    await db.execute(delete(AIProviderConfig))
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def clean(db):
    await _reset(db)
    yield
    await _reset(db)


async def _flag_on(db) -> None:
    from app.api.feature_flags import update_feature_flag
    from app.core.feature_flags import AI_FEATURES_FLAG
    from app.schemas.feature_flags import FeatureFlagUpdate

    await update_feature_flag(AI_FEATURES_FLAG, FeatureFlagUpdate(enabled=True), db)


async def _stored_key(provider: str) -> str | None:
    """The key column as Postgres holds it. `text()` carries no type decorator, so
    nothing on this path decrypts."""
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        result = await db.execute(
            text("SELECT api_key_encrypted FROM ai_provider_configs WHERE provider = :provider"), {"provider": provider}
        )
        return result.scalar_one()


def _decrypted(token: str) -> str:
    from cryptography.fernet import Fernet

    from app.core.crypto import get_encryption_key

    return Fernet(get_encryption_key()).decrypt(token.encode()).decode()


@pytest.fixture
def audit_records() -> list[dict]:
    """The tenant's audit events, read off the logger rather than the rotated file."""
    from app.core.audit import _audit_logger
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    captured: list[dict] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(json.loads(record.getMessage()))

    # Built first, then appended to: _build_audit_logger replaces the handler list.
    tenant_logger = _audit_logger(str(OPERATIONAL_TENANT_ID))
    handler = _Capture()
    tenant_logger.addHandler(handler)
    try:
        yield captured
    finally:
        tenant_logger.removeHandler(handler)


# --- a Save, kept -----------------------------------------------------------------------------


async def test_a_save_keeps_the_config_and_the_key_only_as_ciphertext(client, db, clean, audit_records, caplog):
    await _flag_on(db)
    with caplog.at_level(logging.DEBUG):
        response = await client.put("/api/system/ai/configs/anthropic", json={**ANTHROPIC, "apiKey": KEY})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provider"] == "anthropic"
    assert body["baseUrl"] == "https://api.anthropic.com"
    assert body["model"] == "claude-fable-5-1"
    assert body["hasKey"] is True
    assert body["updatedBy"] == ADMIN[0]
    assert body["updatedAt"] is not None
    assert "apiKey" not in body and KEY not in response.text

    # At rest: a Fernet token this deployment's key opens, never the plaintext.
    stored = await _stored_key("anthropic")
    assert stored is not None and stored != KEY and KEY not in stored
    assert stored.startswith("gAAAAA"), "not a Fernet token: the column is storing something else"
    assert _decrypted(stored) == KEY

    # On the trail, the save and whether a key is stored; never the key, in the audit or the log.
    saved = [r for r in audit_records if r["action"] == "ai.config.saved"]
    assert len(saved) == 1
    assert saved[0]["metadata"] == {
        "provider": "anthropic",
        "destination": "https://api.anthropic.com",
        "model": "claude-fable-5-1",
        "has_key": True,
    }
    assert KEY not in json.dumps(audit_records)
    assert KEY not in caplog.text


async def test_the_listing_never_returns_the_key(client, db, clean):
    await _flag_on(db)
    assert (await client.put("/api/system/ai/configs/anthropic", json={**ANTHROPIC, "apiKey": KEY})).status_code == 200
    assert (await client.put("/api/system/ai/configs/apple_fm", json=APPLE_FM)).status_code == 200

    response = await client.get("/api/system/ai/configs")
    assert response.status_code == 200, response.text
    assert KEY not in response.text
    configs = {c["provider"]: c for c in response.json()["configs"]}
    assert configs["anthropic"]["hasKey"] is True
    assert configs["apple_fm"]["hasKey"] is False
    assert all("apiKey" not in c for c in configs.values())


async def test_the_configs_come_back_in_the_cards_order(client, db, clean):
    await _flag_on(db)
    for provider, body in (("anthropic", {**ANTHROPIC, "apiKey": KEY}), ("openai_compatible", OLLAMA), ("apple_fm", APPLE_FM)):
        assert (await client.put(f"/api/system/ai/configs/{provider}", json=body)).status_code == 200
    listing = (await client.get("/api/system/ai/configs")).json()["configs"]
    assert [c["provider"] for c in listing] == ["apple_fm", "openai_compatible", "anthropic"]


async def test_a_second_save_replaces_the_first_and_there_is_one_row(client, db, clean):
    from app.models.schema import AIProviderConfig

    await _flag_on(db)
    assert (await client.put("/api/system/ai/configs/openai_compatible", json=OLLAMA)).status_code == 200
    again = await client.put("/api/system/ai/configs/openai_compatible", json={**OLLAMA, "model": "gemma4:26b"})
    assert again.status_code == 200, again.text
    assert again.json()["model"] == "gemma4:26b"
    await db.rollback()
    rows = (await db.execute(select(AIProviderConfig).where(AIProviderConfig.provider == "openai_compatible"))).scalars().all()
    assert [r.model for r in rows] == ["gemma4:26b"]


# --- the key rules, judged against the key the row will hold ------------------------------------


async def test_anthropic_without_a_key_is_refused_and_nothing_is_saved(client, db, clean):
    await _flag_on(db)
    refused = await client.put("/api/system/ai/configs/anthropic", json=ANTHROPIC)
    assert refused.status_code == 422
    assert "needs an API key" in refused.json()["detail"]
    assert (await client.get("/api/system/ai/configs")).json()["configs"] == []


async def test_a_save_without_a_key_keeps_the_stored_one(client, db, clean):
    """The browser never holds the stored key, so a Save that sends none must keep it —
    and the required-key rule must count it, or every edit of an Anthropic card would be
    refused until the key was typed again."""
    await _flag_on(db)
    assert (await client.put("/api/system/ai/configs/anthropic", json={**ANTHROPIC, "apiKey": KEY})).status_code == 200
    edited = await client.put("/api/system/ai/configs/anthropic", json={**ANTHROPIC, "model": "claude-opus-5"})
    assert edited.status_code == 200, edited.text
    assert edited.json()["model"] == "claude-opus-5"
    assert edited.json()["hasKey"] is True
    assert _decrypted(await _stored_key("anthropic")) == KEY


async def test_a_new_key_replaces_the_stored_one(client, db, clean):
    await _flag_on(db)
    assert (await client.put("/api/system/ai/configs/anthropic", json={**ANTHROPIC, "apiKey": KEY})).status_code == 200
    replaced = await client.put("/api/system/ai/configs/anthropic", json={**ANTHROPIC, "apiKey": OTHER_KEY})
    assert replaced.status_code == 200, replaced.text
    assert _decrypted(await _stored_key("anthropic")) == OTHER_KEY


async def test_clear_key_removes_the_stored_key(client, db, clean):
    await _flag_on(db)
    assert (await client.put("/api/system/ai/configs/openai_compatible", json={**OLLAMA, "apiKey": KEY})).status_code == 200
    assert await _stored_key("openai_compatible") is not None

    cleared = await client.put("/api/system/ai/configs/openai_compatible", json={**OLLAMA, "clearKey": True})
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["hasKey"] is False
    assert await _stored_key("openai_compatible") is None


async def test_clearing_a_required_key_is_refused_and_the_key_stays(client, db, clean):
    await _flag_on(db)
    assert (await client.put("/api/system/ai/configs/anthropic", json={**ANTHROPIC, "apiKey": KEY})).status_code == 200
    refused = await client.put("/api/system/ai/configs/anthropic", json={**ANTHROPIC, "clearKey": True})
    assert refused.status_code == 422
    assert "needs an API key" in refused.json()["detail"]
    assert _decrypted(await _stored_key("anthropic")) == KEY


async def test_a_stored_key_counts_for_the_plain_http_rule(client, db, clean):
    """A key kept by omission still travels with every call, so moving the URL to plain
    http off the local network is refused as if the key had been typed."""
    await _flag_on(db)
    saved = await client.put(
        "/api/system/ai/configs/openai_compatible", json={**OLLAMA, "baseUrl": "https://inference.example.com/v1", "apiKey": KEY}
    )
    assert saved.status_code == 200, saved.text
    moved = await client.put(
        "/api/system/ai/configs/openai_compatible", json={**OLLAMA, "baseUrl": "http://inference.example.com/v1"}
    )
    assert moved.status_code == 422, moved.text
    listing = (await client.get("/api/system/ai/configs")).json()["configs"]
    assert listing[0]["baseUrl"] == "https://inference.example.com/v1"


async def test_the_url_and_reach_rules_are_the_test_boxs(client, db, clean):
    await _flag_on(db)
    blocked = await client.put(
        "/api/system/ai/configs/openai_compatible", json={**OLLAMA, "baseUrl": "http://169.254.169.254/v1"}
    )
    assert blocked.status_code == 422
    assert "link-local" in blocked.json()["detail"]
    reserved = await client.put("/api/system/ai/configs/apple_fm", json={**APPLE_FM, "hostReach": "orbstack"})
    assert reserved.status_code == 400
    assert "orbstack" in reserved.json()["detail"]
    assert (await client.get("/api/system/ai/configs")).json()["configs"] == []


async def test_an_over_long_key_is_refused_without_being_echoed(client, db, clean):
    """Bounded in the route, not the schema: the route's refusal says what to check,
    where the schema's would only count characters. A key is never echoed either way."""
    await _flag_on(db)
    refused = await client.put("/api/system/ai/configs/anthropic", json={**ANTHROPIC, "apiKey": KEY + "x" * 512})
    assert refused.status_code == 422
    assert refused.json()["detail"] == (
        "The API key is longer than the 512 characters Settings › AI accepts. "
        "Check that only the key was pasted, with nothing before or after it."
    )
    assert KEY not in refused.text
    assert (await client.get("/api/system/ai/configs")).json()["configs"] == []

    # The bound itself is unchanged: 512 characters is still a key.
    at_bound = await client.put("/api/system/ai/configs/anthropic", json={**ANTHROPIC, "apiKey": "k" * 512})
    assert at_bound.status_code == 200, at_bound.text


@pytest.mark.parametrize(
    ("method", "path", "body", "missing"),
    [
        ("PUT", "/api/system/ai/configs/anthropic", {"baseUrl": ANTHROPIC["baseUrl"], "apiKey": KEY}, "model"),
        ("POST", "/api/system/ai/test", {"provider": "anthropic", **ANTHROPIC, "apiKey": KEY}, "prompt"),
        ("POST", "/api/system/ai/models", {"provider": "anthropic", "apiKey": KEY}, "baseUrl"),
    ],
    ids=["save", "test-box", "model-list"],
)
async def test_a_body_refused_by_validation_never_sends_the_key_back(client, db, clean, caplog, method, path, body, missing):
    """Refused before the route runs, so the route's own care with the key gets no say.
    FastAPI's 422 returned the body as each error's `input`, key and all; app.main's
    handler answers the same shape without it (tests/test_validation_errors.py)."""
    await _flag_on(db)
    with caplog.at_level(logging.DEBUG):
        refused = await client.request(method, path, json=body)
    assert refused.status_code == 422
    assert KEY not in refused.text
    assert refused.json()["detail"] == [{"type": "missing", "loc": ["body", missing], "msg": "Field required"}]
    assert KEY not in caplog.text
    assert (await client.get("/api/system/ai/configs")).json()["configs"] == []


async def test_apple_takes_no_reasoning_effort_and_the_saved_card_is_left_as_it_was(client, db, clean, audit_records):
    """`fm serve` answers 400 to any reasoning effort on its system model, "none" included,
    so an Apple card saved with one would fail every Prompt bar question. The Save is
    refused with the way out and the card already saved stands; the rule is Apple's alone."""
    await _flag_on(db)
    assert (await client.put("/api/system/ai/configs/apple_fm", json={**APPLE_FM, "reasoningEffort": None})).status_code == 200
    for effort in ("none", "low"):
        refused = await client.put("/api/system/ai/configs/apple_fm", json={**APPLE_FM, "reasoningEffort": effort})
        assert refused.status_code == 422, effort
        assert refused.json()["detail"] == (
            "Apple's on-device model takes no reasoning effort — fm serve refuses it on the system model. "
            "Save the Apple Foundation Models via Docker Desktop card again from Settings › AI; the page sends none."
        )
    listing = (await client.get("/api/system/ai/configs")).json()["configs"]
    assert [(c["provider"], c["reasoningEffort"]) for c in listing] == [("apple_fm", None)]
    assert [r["metadata"]["provider"] for r in audit_records if r["action"] == "ai.config.saved"] == ["apple_fm"]

    # An OpenAI-compatible card keeps its own: a local thinking model needs `none`.
    ollama = await client.put("/api/system/ai/configs/openai_compatible", json=OLLAMA)
    assert ollama.status_code == 200, ollama.text
    assert ollama.json()["reasoningEffort"] == "none"


async def test_the_url_is_stored_as_judged(client, db, clean):
    await _flag_on(db)
    saved = await client.put(
        "/api/system/ai/configs/apple_fm", json={**APPLE_FM, "baseUrl": "  http://host.docker.internal:1976/v1/ "}
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["baseUrl"] == "http://host.docker.internal:1976/v1"


# --- removal ------------------------------------------------------------------------------------


async def test_delete_answers_204_then_404(client, db, clean, audit_records):
    await _flag_on(db)
    assert (await client.put("/api/system/ai/configs/anthropic", json={**ANTHROPIC, "apiKey": KEY})).status_code == 200

    removed = await client.delete("/api/system/ai/configs/anthropic")
    assert removed.status_code == 204
    assert (await client.get("/api/system/ai/configs")).json()["configs"] == []
    assert [r["metadata"] for r in audit_records if r["action"] == "ai.config.removed"] == [{"provider": "anthropic"}]

    again = await client.delete("/api/system/ai/configs/anthropic")
    assert again.status_code == 404
    assert again.json()["detail"] == "No saved config for anthropic."


# --- the switches and the roles in front --------------------------------------------------------


async def test_a_save_is_refused_while_the_flag_is_off(client, db, clean):
    refused = await client.put("/api/system/ai/configs/apple_fm", json=APPLE_FM)
    assert refused.status_code == 409
    assert "AI features are off" in refused.json()["detail"]
    assert (await client.get("/api/system/ai/configs")).json()["configs"] == []


async def test_a_viewer_can_neither_save_nor_list(accounts, db, clean):
    await _flag_on(db)
    viewer = await _signed_in(*VIEWER)
    try:
        assert (await viewer.put("/api/system/ai/configs/apple_fm", json=APPLE_FM)).status_code == 403
        assert (await viewer.get("/api/system/ai/configs")).status_code == 403
        assert (await viewer.delete("/api/system/ai/configs/apple_fm")).status_code == 403
    finally:
        await viewer.aclose()


async def test_an_auditor_may_list_but_not_save(accounts, db, clean):
    await _flag_on(db)
    auditor = await _signed_in(*AUDITOR)
    try:
        assert (await auditor.get("/api/system/ai/configs")).status_code == 200
        assert (await auditor.put("/api/system/ai/configs/apple_fm", json=APPLE_FM)).status_code == 403
    finally:
        await auditor.aclose()
