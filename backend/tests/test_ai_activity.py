"""Pure AI Activity status rules and safe configured-service attribution."""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.core.ai_activity import PURPOSES, health
from app.core.ai_usage import failure_category, service_identity
from app.schemas.ai import AIConfigIn


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({"enabled": False}, "disabled"),
        ({"consent": False}, "disabled"),
        ({"configured": False}, "no_provider"),
        ({"degraded": True}, "unavailable"),
        ({"inventory_undrained": True}, "not_running"),
        ({"stalled": 1}, "stalled"),
        ({"limited": 1}, "rate_limited"),
        ({"oldest": 121}, "waiting_too_long"),
        ({"since": None}, "observing"),
        ({"waiting": 2, "arrivals": 4, "completed": 2}, "backlog_growing"),
        ({"expired": 1}, "expired"),
        ({"failures": 1}, "failures"),
        ({}, "idle"),
        ({"arrivals": 2, "completed": 2}, "keeping_up"),
    ],
)
def test_health_explains_rule_and_next_check(changes, expected):
    now = datetime.now(UTC)
    data = {
        "enabled": True,
        "consent": True,
        "configured": True,
        "degraded": False,
        "since": now - timedelta(hours=1),
        "now": now,
        "waiting": 0,
        "running": 0,
        "oldest": None,
        "arrivals": 0,
        "completed": 0,
        "expired": 0,
        "failures": 0,
        "limited": 0,
        "stalled": 0,
    }
    verdict = health(**(data | changes))
    assert verdict[0] == expected
    assert all(isinstance(value, str) and value for value in verdict)


@pytest.mark.parametrize(
    "base,kind",
    [
        ("https://api.openai.com/v1", "openai"),
        ("https://api.openai.com.example.invalid/v1", "compatible"),
        ("http://localhost:11434/v1", "compatible"),
        ("https://example.invalid/v1", "compatible"),
    ],
)
def test_wire_family_and_model_name_never_prove_service(base, kind):
    config = SimpleNamespace(base_url=base, model="gpt-test", service_id="opaque-id")
    identity = service_identity("openai_compatible", config)
    assert identity["service_kind"] == kind and identity["service_id"] == "opaque-id"
    assert base not in str(identity)


@pytest.mark.parametrize("value", ["https://secret.invalid/key", "admin@example.invalid", "Bearer: synthetic", "line\nnext"])
def test_service_label_cannot_accept_addresses_or_header_shaped_text(value):
    with pytest.raises(ValidationError):
        AIConfigIn(baseUrl="https://api.openai.com/v1", model="m", serviceLabel=value)


@pytest.mark.parametrize(
    "outcome,status,sent,expected",
    [
        ("timeout", None, False, "waiting_timeout"),
        ("timeout", None, True, "timeout"),
        ("http_status", 429, True, "rate_limited"),
        ("http_status", 401, True, "authentication"),
        ("http_status", 403, True, "forbidden"),
        ("http_status", 503, True, "unavailable"),
        ("unreachable", None, True, "unavailable"),
    ],
)
def test_safe_failure_categories(outcome, status, sent, expected):
    assert failure_category(outcome, status, sent) == expected


def test_unsaved_tests_and_missing_legacy_configuration_are_explicit():
    from app.schemas.ai import AITestIn

    payload = AITestIn(provider="openai_compatible", baseUrl="https://api.openai.com/v1", model="m", prompt="synthetic")
    first = service_identity(payload.provider, payload)
    assert first["service_label"] == "OpenAI (test endpoint)"
    assert first["service_id"].startswith("test-")
    assert first == service_identity(payload.provider, payload)
    missing = service_identity("openai_compatible")
    assert missing["service_kind"] == "legacy" and missing["service_id"] == "legacy-openai_compatible"


def test_unsaved_service_identity_keeps_attribution_versions_distinct():
    from app.schemas.ai import AITestIn

    payload = AITestIn(provider="openai_compatible", baseUrl="http://localhost:11434/v1", model="m", prompt="synthetic")
    unknown = service_identity(payload.provider, payload)
    ollama = service_identity(payload.provider, payload.model_copy(update={"ollama_policy": {"preferences": ["m"]}}))
    assert unknown["service_kind"] == "compatible" and ollama["service_kind"] == "ollama"
    assert unknown["service_id"] != ollama["service_id"]


async def test_recording_failure_names_its_cause_and_never_its_message(caplog, monkeypatch):
    from app.core import ai_usage

    def broken(_tenant):
        raise RuntimeError("SYNTHETIC_UNSAFE_DATABASE_DETAIL")

    class Slow:
        # What asyncio.timeout raises once the recorder's two-second budget runs out.
        async def __aenter__(self):
            raise TimeoutError

        async def __aexit__(self, *exc):
            return False

    async def write(_session):
        pytest.fail("the write ran without a session")

    tenant = uuid.uuid4()
    meter = ai_usage.recorder(None, "ai_test_box", "apple_fm", "m")
    meter.tenant = tenant
    try:
        with caplog.at_level(logging.WARNING, logger="app.core.ai_usage"):
            monkeypatch.setattr(ai_usage, "session_for_tenant", broken)
            await meter._save(write)
            monkeypatch.setattr(ai_usage, "session_for_tenant", lambda _tenant: Slow())
            await meter._save(write)
    finally:
        ai_usage._recording_failures.pop(tenant, None)
        ai_usage._last_recording_failures.pop(tenant, None)
    fault, slow = [r for r in caplog.records if r.getMessage().startswith("AI usage could not be saved")]
    assert "(RuntimeError)" in fault.getMessage() and "migrations" in fault.getMessage()
    assert fault.error_type == "RuntimeError" and fault.stack
    assert "2 seconds" in slow.getMessage() and "database load" in slow.getMessage()
    assert slow.error_type == "TimeoutError"
    assert "SYNTHETIC_UNSAFE_DATABASE_DETAIL" not in caplog.text


def test_every_purpose_is_worded_and_explain_is_one_of_them():
    # The page prints a purpose as the server words it (`activityCopy.ts`), so a label
    # that is its own code reaches the reader as a code (#984).
    assert PURPOSES["explain"] == "Explanations"
    assert all(label[:1].isupper() and label != code for code, label in PURPOSES.items())
