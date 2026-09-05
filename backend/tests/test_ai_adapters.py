"""The AI test box's pure half (#319): request shapes, reply parsing, the four
failures, the URL rule, and the provider table. No database, no network — the
endpoint is an `httpx.MockTransport` where one is needed at all.

Two of these pin findings from a real endpoint on 2026-09-05 rather than a reading
of a spec: Ollama's reply carries `message.reasoning` beside `content`, and a small
thinking model can spend its whole `max_tokens` thinking and answer with empty
content. That second case is an outcome of its own, never "the model said nothing".
"""

from __future__ import annotations

import ipaddress
import logging

import httpx
import pytest

from app.ai.adapters import (
    OUTCOME_ANSWERED,
    OUTCOME_BUDGET_EXHAUSTED_THINKING,
    OUTCOME_EMPTY,
    AdapterError,
    CompletionRequest,
    build_request,
    complete,
    parse_response,
)
from app.ai.providers import (
    DEFAULTS,
    IMPLEMENTED_REACH,
    WIRE_FOR,
    HostReach,
    Provider,
    ReachNotImplemented,
    Wire,
    default_base_url,
    hostname_for,
)
from app.core.egress import (
    BlockedBaseUrl,
    destination_for_log,
    inference_blocked_reason,
    validate_inference_base_url,
)

KEY = "sk-never-to-be-seen-again"
REQ = CompletionRequest(
    base_url="http://host.docker.internal:11434/v1", model="qwen3.5:2b-mlx", prompt="Tell me a joke."
)

# --- request shapes -----------------------------------------------------------------------


def test_openai_request_is_the_documented_shape_and_carries_nothing_extra():
    url, headers, body = build_request(Wire.openai_chat, REQ)
    assert url == "http://host.docker.internal:11434/v1/chat/completions"
    assert "Authorization" not in headers
    assert body == {
        "model": "qwen3.5:2b-mlx",
        "messages": [{"role": "user", "content": "Tell me a joke."}],
        "temperature": 0.7,
        "max_tokens": 1024,
    }


def test_openai_request_adds_bearer_and_reasoning_effort_only_when_given():
    req = CompletionRequest(
        base_url="https://api.openai.com/v1/", model="m", prompt="p", api_key=KEY, reasoning_effort="none"
    )
    url, headers, body = build_request(Wire.openai_chat, req)
    assert url == "https://api.openai.com/v1/chat/completions"
    assert headers["Authorization"] == f"Bearer {KEY}"
    assert body["reasoning_effort"] == "none"


def test_anthropic_request_is_the_messages_api_shape():
    req = CompletionRequest(
        base_url="https://api.anthropic.com", model="claude-fable-5-1", prompt="p", api_key=KEY, max_tokens=64
    )
    url, headers, body = build_request(Wire.anthropic_messages, req)
    assert url == "https://api.anthropic.com/v1/messages"
    assert headers["x-api-key"] == KEY
    assert headers["anthropic-version"] == "2023-06-01"
    assert "Authorization" not in headers
    assert body == {
        "model": "claude-fable-5-1",
        "max_tokens": 64,
        "temperature": 0.7,
        "messages": [{"role": "user", "content": "p"}],
    }


# --- reply parsing ------------------------------------------------------------------------

OLLAMA_REPLY = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "model": "qwen3.8:27b-mlx",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "She looked surprised.", "reasoning": "The user wants a joke."},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 15, "completion_tokens": 232, "total_tokens": 247},
}


def test_openai_reply_keeps_reasoning_beside_content():
    result = parse_response(Wire.openai_chat, OLLAMA_REPLY)
    assert result.outcome == OUTCOME_ANSWERED
    assert result.content == "She looked surprised."
    assert result.reasoning == "The user wants a joke."
    assert result.model == "qwen3.8:27b-mlx"
    assert result.finish_reason == "stop"
    assert result.completion_tokens == 232


def test_openai_reply_that_spent_its_budget_thinking_is_its_own_outcome():
    reply = {
        "choices": [{"message": {"content": "", "reasoning": "Let me think of a good one..."}, "finish_reason": "length"}],
        "usage": {"completion_tokens": 1024},
    }
    result = parse_response(Wire.openai_chat, reply)
    assert result.outcome == OUTCOME_BUDGET_EXHAUSTED_THINKING
    assert result.content == ""
    assert result.reasoning.startswith("Let me think")


def test_openai_reply_with_nothing_at_all_is_empty_not_an_error():
    reply = {"choices": [{"message": {"content": None}, "finish_reason": "stop"}]}
    assert parse_response(Wire.openai_chat, reply).outcome == OUTCOME_EMPTY


def test_openai_reply_content_parts_are_joined():
    parts = [{"type": "text", "text": "a"}, {"type": "image", "url": "x"}, {"type": "text", "text": "b"}]
    reply = {"choices": [{"message": {"content": parts}}]}
    assert parse_response(Wire.openai_chat, reply).content == "ab"


def test_openai_reply_reasoning_content_alias_is_read():
    reply = {"choices": [{"message": {"content": "ok", "reasoning_content": "thought"}}]}
    assert parse_response(Wire.openai_chat, reply).reasoning == "thought"


@pytest.mark.parametrize("payload", [[], "text", {}, {"choices": []}, {"choices": [{}]}, {"choices": [{"message": "x"}]}])
def test_openai_reply_without_a_message_is_malformed(payload):
    with pytest.raises(AdapterError) as excinfo:
        parse_response(Wire.openai_chat, payload)
    assert excinfo.value.kind == "malformed"


def test_anthropic_reply_joins_text_blocks_and_maps_stop_reason():
    reply = {
        "model": "claude-fable-5-1",
        "content": [
            {"type": "thinking", "thinking": "hmm"},
            {"type": "text", "text": "Why did the"},
            {"type": "text", "text": " chicken cross?"},
        ],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 10, "output_tokens": 12},
    }
    result = parse_response(Wire.anthropic_messages, reply)
    assert result.outcome == OUTCOME_ANSWERED
    assert result.content == "Why did the chicken cross?"
    assert result.reasoning == "hmm"
    assert result.finish_reason == "stop"
    assert result.completion_tokens == 12


def test_anthropic_max_tokens_reads_as_length_so_the_outcome_rule_is_shared():
    reply = {
        "content": [{"type": "thinking", "thinking": "..."}],
        "stop_reason": "max_tokens",
        "usage": {"output_tokens": 64},
    }
    assert parse_response(Wire.anthropic_messages, reply).outcome == OUTCOME_BUDGET_EXHAUSTED_THINKING


def test_anthropic_reply_without_content_blocks_is_malformed():
    with pytest.raises(AdapterError) as excinfo:
        parse_response(Wire.anthropic_messages, {"stop_reason": "end_turn"})
    assert excinfo.value.kind == "malformed"


# --- the wire, through a stand-in server ------------------------------------------------


def _server(handler):
    return httpx.MockTransport(handler)


async def test_key_goes_on_the_wire_and_nowhere_else(caplog):
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("authorization", "")
        seen["body"] = request.content.decode()
        return httpx.Response(200, json=OLLAMA_REPLY)

    req = CompletionRequest(base_url="http://127.0.0.1:11434/v1", model="m", prompt="p", api_key=KEY)
    with caplog.at_level(logging.DEBUG):
        result = await complete(Wire.openai_chat, req, transport=_server(handler))

    assert seen["authorization"] == f"Bearer {KEY}"
    assert KEY not in seen["body"]
    assert KEY not in caplog.text
    assert KEY not in repr(result)
    assert result.outcome == OUTCOME_ANSWERED


async def test_timeout_is_its_own_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(AdapterError) as excinfo:
        await complete(Wire.openai_chat, REQ, transport=_server(handler), timeout_seconds=3)
    assert excinfo.value.kind == "timeout"
    assert "3 s" in excinfo.value.message


async def test_unreachable_is_its_own_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(AdapterError) as excinfo:
        await complete(Wire.openai_chat, REQ, transport=_server(handler))
    assert excinfo.value.kind == "unreachable"


@pytest.mark.parametrize(
    ("status", "hint"),
    [(401, "rejected the key"), (404, "no such route or model"), (429, "rate-limiting"), (500, "HTTP 500"), (529, "overloaded")],
)
async def test_rejections_carry_the_status_a_hint_and_a_bounded_message(status, hint):
    def handler(request: httpx.Request) -> httpx.Response:
        message = "model 'nope' not found " + "x" * 1000
        return httpx.Response(status, json={"error": {"message": message, "type": "invalid_request_error"}})

    req = CompletionRequest(base_url="http://127.0.0.1:11434/v1", model="nope", prompt="p", api_key=KEY)
    with pytest.raises(AdapterError) as excinfo:
        await complete(Wire.openai_chat, req, transport=_server(handler))
    err = excinfo.value
    assert err.kind == "http_status"
    assert err.status == status
    assert hint in err.message
    assert "model 'nope' not found" in err.message
    assert len(err.message) < 420
    assert KEY not in err.message


async def test_a_non_json_rejection_shows_its_size_and_type_but_never_its_body():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            502, text="<html><title>nginx/1.25 banner</title></html>", headers={"content-type": "text/html"}
        )

    with pytest.raises(AdapterError) as excinfo:
        await complete(Wire.openai_chat, REQ, transport=_server(handler))
    assert "HTTP 502" in excinfo.value.message
    assert "text/html" in excinfo.value.message
    assert "nginx" not in excinfo.value.message


async def test_a_200_that_is_not_json_is_malformed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="captive portal", headers={"content-type": "text/html"})

    with pytest.raises(AdapterError) as excinfo:
        await complete(Wire.openai_chat, REQ, transport=_server(handler))
    assert excinfo.value.kind == "malformed"
    assert "captive" not in excinfo.value.message


# --- the URL rule ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "carries_key"),
    [
        ("http://host.docker.internal:11434/v1", False),
        ("http://host.docker.internal:11535/v1/", False),
        ("http://127.0.0.1:11434/v1", True),
        ("http://192.168.1.10:11434/v1", True),
        ("http://localhost:11434/v1", True),
        ("http://mini.local:11434/v1", False),
        ("https://api.anthropic.com", True),
        ("https://api.openai.com/v1", True),
    ],
)
def test_accepted_inference_urls(url, carries_key):
    assert validate_inference_base_url(url, carries_key=carries_key) == url.rstrip("/")


@pytest.mark.parametrize(
    ("url", "carries_key", "because"),
    [
        ("", False, "required"),
        ("http://" + "a" * 300 + ".example", False, "at most 255"),
        ("ftp://host/v1", False, "http:// or https://"),
        ("host.docker.internal:11434", False, "http:// or https://"),
        ("http://user:pw@host/v1", False, "credentials in the URL"),
        ("http://host/v1?x=1", False, "no query string"),
        ("http://host:notaport/v1", False, "parse"),
        ("http://169.254.169.254/v1", False, "link-local"),
        ("http://[::ffff:169.254.169.254]/v1", False, "link-local"),
        ("http://0.0.0.0/v1", False, "unspecified"),
        # The one place this rule is stricter than the MDM rule: a key in clear to a
        # host that is not local.
        ("http://mini.local:11434/v1", True, "in clear"),
        ("http://api.example.com/v1", True, "in clear"),
    ],
)
def test_refused_inference_urls_say_why(url, carries_key, because):
    with pytest.raises(BlockedBaseUrl) as excinfo:
        validate_inference_base_url(url, carries_key=carries_key)
    assert because in str(excinfo.value)


def test_loopback_is_allowed_for_inference_and_still_refused_for_mdm():
    from app.core.egress import blocked_address_reason

    loopback = ipaddress.ip_address("127.0.0.1")
    assert inference_blocked_reason(loopback) is None
    assert blocked_address_reason(loopback) == "a loopback address"
    metadata = ipaddress.ip_address("169.254.169.254")
    assert inference_blocked_reason(metadata) is not None


def test_the_log_records_the_origin_only():
    assert destination_for_log("http://host.docker.internal:11434/v1") == "http://host.docker.internal:11434"
    assert destination_for_log("https://api.anthropic.com") == "https://api.anthropic.com"


# --- the provider table ---------------------------------------------------------------------


def test_every_entry_has_a_wire_and_defaults():
    for provider in Provider:
        assert provider in WIRE_FOR
        assert DEFAULTS[provider].wire is WIRE_FOR[provider]


def test_the_docker_desktop_card_fills_the_alias():
    assert default_base_url(Provider.apple_fm) == "http://host.docker.internal:11535/v1"
    assert default_base_url(Provider.openai_compatible) == "http://host.docker.internal:11434/v1"
    assert default_base_url(Provider.anthropic) == "https://api.anthropic.com"


@pytest.mark.parametrize("reach", [HostReach.orbstack, HostReach.colima, HostReach.podman, HostReach.remote_mac])
def test_reserved_reaches_are_refused_by_name(reach):
    assert reach not in IMPLEMENTED_REACH
    with pytest.raises(ReachNotImplemented) as excinfo:
        hostname_for(reach)
    assert reach.value in str(excinfo.value)
    assert "Docker Desktop" in str(excinfo.value)


def test_custom_reach_has_no_host_name_to_resolve():
    with pytest.raises(ValueError):
        hostname_for(HostReach.custom)
