"""Two wire adapters, one normalised result, and nothing clever in between (#319).

``openai_chat`` speaks ``POST {base}/chat/completions`` — Ollama, OpenAI itself, a
gateway, LM Studio, vLLM, and the Apple Foundation Models shim all answer it.
``anthropic_messages`` speaks ``POST {base}/v1/messages``. Both take the same
``CompletionRequest`` and return the same ``CompletionResult`` so the endpoint and the
page never branch on the wire.

Three things this module is strict about, each learned on 2026-09-05 against a real
endpoint rather than assumed:

- **Thinking is a separate field, and it can eat the whole budget.** Ollama returns
  ``message.reasoning`` beside ``content`` (other servers say ``reasoning_content``);
  a small thinking model given 1024 tokens spent every one of them thinking and
  answered with empty content. That is reported as its own outcome,
  ``budget_exhausted_thinking``, with the reasoning attached, never as "the model
  said nothing". Sending OpenAI's ``reasoning_effort`` is what actually stops it
  (``think: false`` was ignored), so the request carries that field when asked.
- **The key never appears anywhere but the wire.** Not in an exception, not in a log
  line, not in the reply. Errors describe the response, never the request.
- **What a caller-chosen server says back is bounded**, the way
  ``app.api.connections._upstream_detail`` bounds a Jamf test: a JSON error message
  truncated to ``_DETAIL_MAX_CHARS``; for anything else the status, the content type
  and the size only. The first 500 characters of an HTML error page are the part with
  the server banner in them.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from app.ai.providers import Wire

logger = logging.getLogger(__name__)

ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_TIMEOUT_SECONDS = 120.0
_CONNECT_TIMEOUT_SECONDS = 10.0
_DETAIL_MAX_CHARS = 300

OUTCOME_ANSWERED = "answered"
OUTCOME_EMPTY = "empty"
OUTCOME_BUDGET_EXHAUSTED_THINKING = "budget_exhausted_thinking"


@dataclass(frozen=True)
class CompletionRequest:
    base_url: str
    model: str
    prompt: str
    api_key: str | None = None
    # OpenAI's ``reasoning_effort``; sent only when set, because a server that does
    # not know the field may refuse the whole request rather than ignore it.
    reasoning_effort: str | None = None
    max_tokens: int = 1024
    temperature: float = 0.7


@dataclass(frozen=True)
class CompletionResult:
    outcome: str
    content: str
    reasoning: str | None
    model: str | None
    finish_reason: str | None
    completion_tokens: int | None


class AdapterError(Exception):
    """The call did not produce a usable answer, and which way it failed.

    ``kind`` is one of ``unreachable`` | ``timeout`` | ``http_status`` | ``malformed``;
    ``status`` is set for ``http_status``. The message is safe to show verbatim.
    """

    def __init__(self, kind: str, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.status = status


def _joined_base(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + path


def build_request(wire: Wire, req: CompletionRequest) -> tuple[str, dict[str, str], dict[str, Any]]:
    """The URL, headers and JSON body that would go on the wire. Pure, and the one
    place either request shape is written down."""
    if wire is Wire.openai_chat:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if req.api_key:
            headers["Authorization"] = f"Bearer {req.api_key}"
        body: dict[str, Any] = {
            "model": req.model,
            "messages": [{"role": "user", "content": req.prompt}],
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
        }
        if req.reasoning_effort:
            body["reasoning_effort"] = req.reasoning_effort
        return _joined_base(req.base_url, "/chat/completions"), headers, body

    if wire is Wire.anthropic_messages:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "anthropic-version": ANTHROPIC_VERSION,
        }
        if req.api_key:
            headers["x-api-key"] = req.api_key
        body = {
            "model": req.model,
            "max_tokens": req.max_tokens,
            "temperature": req.temperature,
            "messages": [{"role": "user", "content": req.prompt}],
        }
        return _joined_base(req.base_url, "/v1/messages"), headers, body

    raise ValueError(f"unknown wire {wire!r}")


def _text_of(content: Any) -> str:
    """OpenAI ``content`` is a string, null, or a list of parts; only the text parts
    are an answer."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            part.get("text", "") for part in content if isinstance(part, dict) and part.get("type") == "text"
        )
    raise AdapterError("malformed", "the reply's content was neither text nor a list of parts")


def _outcome(content: str, reasoning: str | None, finish_reason: str | None) -> str:
    if content.strip():
        return OUTCOME_ANSWERED
    if reasoning and finish_reason == "length":
        return OUTCOME_BUDGET_EXHAUSTED_THINKING
    return OUTCOME_EMPTY


def parse_response(wire: Wire, payload: Any) -> CompletionResult:
    """A 2xx JSON body into the normalised result, or ``AdapterError('malformed')``
    naming what was missing. Pure."""
    if not isinstance(payload, dict):
        raise AdapterError("malformed", "the reply was JSON but not an object")

    if wire is Wire.openai_chat:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise AdapterError("malformed", "the reply carried no choices")
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message")
        if not isinstance(message, dict):
            raise AdapterError("malformed", "the reply's first choice carried no message")
        content = _text_of(message.get("content"))
        reasoning = message.get("reasoning") or message.get("reasoning_content") or None
        if reasoning is not None and not isinstance(reasoning, str):
            reasoning = None
        finish_reason = first.get("finish_reason")
        usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
        tokens = usage.get("completion_tokens")
        return CompletionResult(
            outcome=_outcome(content, reasoning, finish_reason),
            content=content,
            reasoning=reasoning,
            model=payload.get("model") if isinstance(payload.get("model"), str) else None,
            finish_reason=finish_reason if isinstance(finish_reason, str) else None,
            completion_tokens=tokens if isinstance(tokens, int) else None,
        )

    if wire is Wire.anthropic_messages:
        blocks = payload.get("content")
        if not isinstance(blocks, list):
            raise AdapterError("malformed", "the reply carried no content blocks")
        content = "".join(
            b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"
        )
        thinking = "\n".join(
            b.get("thinking", "") for b in blocks if isinstance(b, dict) and b.get("type") == "thinking"
        )
        stop_reason = payload.get("stop_reason")
        # Anthropic's vocabulary into OpenAI's, so the outcome rule above is the same
        # rule for both wires.
        finish_reason = {"max_tokens": "length", "end_turn": "stop", "stop_sequence": "stop"}.get(
            stop_reason, stop_reason if isinstance(stop_reason, str) else None
        )
        usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
        tokens = usage.get("output_tokens")
        reasoning = thinking or None
        return CompletionResult(
            outcome=_outcome(content, reasoning, finish_reason),
            content=content,
            reasoning=reasoning,
            model=payload.get("model") if isinstance(payload.get("model"), str) else None,
            finish_reason=finish_reason,
            completion_tokens=tokens if isinstance(tokens, int) else None,
        )

    raise ValueError(f"unknown wire {wire!r}")


def _status_message(response: httpx.Response) -> str:
    """What of a rejection may be shown: a JSON error message, truncated; otherwise the
    status, the declared type and the size."""
    content_type = response.headers.get("content-type", "")
    status_line = f"HTTP {response.status_code}"
    hint = {
        401: "the endpoint rejected the key",
        403: "the endpoint refused this key for that model or route",
        404: "no such route or model at this URL",
        429: "the endpoint is rate-limiting this key",
        529: "the endpoint is overloaded",
    }.get(response.status_code)
    prefix = f"{status_line}: {hint}" if hint else status_line
    if "json" in content_type.split(";")[0].lower():
        try:
            body = response.json()
        except ValueError:
            body = None
        message: Any = None
        if isinstance(body, dict):
            error = body.get("error")
            message = error.get("message") if isinstance(error, dict) else error
        if isinstance(message, str) and message.strip():
            return f"{prefix} — {message.strip()[:_DETAIL_MAX_CHARS]}"
        return prefix
    return f"{prefix}. The response was {content_type or 'of no declared type'}, {len(response.content)} bytes; not shown."


async def complete(
    wire: Wire,
    req: CompletionRequest,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> CompletionResult:
    """One request, one reply, one of four failures. ``transport`` exists so a test can
    stand in for the server, the way ``app.core.sharing.post_exchange`` allows."""
    url, headers, body = build_request(wire, req)
    limits = httpx.Timeout(timeout_seconds, connect=_CONNECT_TIMEOUT_SECONDS)
    try:
        async with httpx.AsyncClient(timeout=limits, transport=transport) as client:
            response = await client.post(url, headers=headers, json=body)
    except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
        raise AdapterError("timeout", f"no reply within {timeout_seconds:.0f} s ({type(exc).__name__})") from exc
    except httpx.HTTPError as exc:
        # ConnectError, RemoteProtocolError, UnsupportedProtocol… — the endpoint was
        # never reached or hung up. The exception text names the host, never a header.
        raise AdapterError("unreachable", f"could not reach the endpoint: {exc}") from exc

    logger.info("ai test box: %s %s -> %s", wire.value, httpx.URL(url).host, response.status_code)
    if response.status_code < 200 or response.status_code >= 300:
        raise AdapterError("http_status", _status_message(response), status=response.status_code)
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        content_type = response.headers.get("content-type", "") or "of no declared type"
        raise AdapterError(
            "malformed",
            f"HTTP {response.status_code} but the body was not JSON ({content_type}, {len(response.content)} bytes)",
        ) from exc
    return parse_response(wire, payload)
