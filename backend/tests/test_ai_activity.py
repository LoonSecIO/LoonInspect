"""Pure AI Activity status rules and safe configured-service attribution."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.core.ai_activity import health
from app.core.ai_usage import failure_category, service_identity
from app.schemas.ai import AIConfigIn


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({"enabled": False}, "disabled"),
        ({"consent": False}, "disabled"),
        ({"configured": False}, "no_provider"),
        ({"degraded": True}, "unavailable"),
        ({"scheduler_enabled": False, "inventory_waiting": 1}, "not_running"),
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
