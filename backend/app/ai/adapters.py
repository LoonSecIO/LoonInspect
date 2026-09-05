"""Two wire adapters, one bounded wire, one normalised result (#319, #322).

``openai_chat`` speaks ``POST {base}/chat/completions`` and ``GET {base}/models`` —
Ollama, OpenAI itself, a gateway, LM Studio, vLLM, and the Apple Foundation Models shim
all answer them. ``anthropic_messages`` speaks ``POST {base}/v1/messages`` and
``GET {base}/v1/models``. Both take the same request shapes and return the same result
shapes so the endpoint and the page never branch on the wire.

Things this module is strict about, each learned against a real endpoint on 2026-09-05
or named in the attack-surface review (``docs/ai-threat-model.md``) rather than assumed:

- **The endpoint is hostile on the way back.** Every call goes through one door,
  ``_request``: a wall-clock bound on the whole exchange (``asyncio.timeout``, because
  httpx's read timeout is per chunk and a one-byte-per-minute drip would otherwise hold
  a worker for as long as it liked), a size cap read while streaming (a reply to "tell
  me a joke" is bytes, and a gigabyte is an attack), redirects never followed (a 302 to
  ``169.254.169.254`` would turn the URL rule into a bypass), and at most two calls in
  flight per process (never a fan-out, by mechanism).
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
  and the size only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import weakref
from dataclasses import dataclass
from typing import Any

import httpx

from app.ai.providers import Wire

logger = logging.getLogger(__name__)

ANTHROPIC_VERSION = "2023-06-01"
# Wall clock for one whole exchange, including waiting for a slot.
DEFAULT_TIMEOUT_SECONDS = 120.0
_CONNECT_TIMEOUT_SECONDS = 10.0
# Per chunk. The total above is the real bound; this only stops a stalled socket sooner.
_READ_TIMEOUT_SECONDS = 60.0
MAX_RESPONSE_BYTES = 1_048_576
MAX_CONCURRENT_CALLS = 2
MAX_MODELS_LISTED = 500
MAX_MODEL_ID_CHARS = 200
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


@dataclass(frozen=True)
class ModelInfo:
    id: str
    label: str | None


class AdapterError(Exception):
    """The call did not produce a usable answer, and which way it failed.

    ``kind`` is one of ``unreachable`` | ``timeout`` | ``http_status`` | ``malformed`` |
    ``too_large``; ``status`` is set for ``http_status``. The message is safe to show
    verbatim.
    """

    def __init__(self, kind: str, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.status = status


# --- request shapes ---------------------------------------------------------------------------


def _joined_base(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + path


def _headers(wire: Wire, api_key: str | None) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if wire is Wire.anthropic_messages:
        headers["anthropic-version"] = ANTHROPIC_VERSION
        if api_key:
            headers["x-api-key"] = api_key
    elif api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def build_request(wire: Wire, req: CompletionRequest) -> tuple[str, dict[str, str], dict[str, Any]]:
    """The URL, headers and JSON body of a completion. Pure, and the one place either
    request shape is written down."""
    headers = {"Content-Type": "application/json", **_headers(wire, req.api_key)}
    if wire is Wire.openai_chat:
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
        body = {
            "model": req.model,
            "max_tokens": req.max_tokens,
            "temperature": req.temperature,
            "messages": [{"role": "user", "content": req.prompt}],
        }
        return _joined_base(req.base_url, "/v1/messages"), headers, body

    raise ValueError(f"unknown wire {wire!r}")


def build_models_request(wire: Wire, base_url: str, api_key: str | None) -> tuple[str, dict[str, str]]:
    """The URL and headers of a model listing. OpenAI-style servers list at
    ``{base}/models``; Anthropic pages at ``{base}/v1/models`` and takes ``limit``."""
    if wire is Wire.openai_chat:
        return _joined_base(base_url, "/models"), _headers(wire, api_key)
    if wire is Wire.anthropic_messages:
        return _joined_base(base_url, f"/v1/models?limit={MAX_MODELS_LISTED}"), _headers(wire, api_key)
    raise ValueError(f"unknown wire {wire!r}")


# --- reply parsing ----------------------------------------------------------------------------


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


def parse_models_response(wire: Wire, payload: Any) -> list[ModelInfo]:
    """``{"data": [{"id": ...}]}`` on both wires (Anthropic adds ``display_name``) into
    a bounded, de-duplicated, sorted list. Pure."""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise AdapterError("malformed", "the reply carried no model list")
    seen: dict[str, ModelInfo] = {}
    for item in payload["data"]:
        if not isinstance(item, dict):
            continue
        model_id = item.get("id")
        if not isinstance(model_id, str) or not model_id.strip() or len(model_id) > MAX_MODEL_ID_CHARS:
            continue
        label = item.get("display_name") if wire is Wire.anthropic_messages else None
        seen.setdefault(model_id, ModelInfo(id=model_id, label=label if isinstance(label, str) else None))
        if len(seen) >= MAX_MODELS_LISTED:
            break
    return sorted(seen.values(), key=lambda m: m.id)


# --- the wire, one door -----------------------------------------------------------------------


@dataclass(frozen=True)
class _Reply:
    status: int
    content_type: str
    body: bytes


# Per event loop rather than per module: a semaphore binds to the loop that first
# waits on it, and the test lanes run more than one loop per process.
_slots: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = weakref.WeakKeyDictionary()


def _wire_slots() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    slots = _slots.get(loop)
    if slots is None:
        slots = _slots[loop] = asyncio.Semaphore(MAX_CONCURRENT_CALLS)
    return slots


async def _request(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: dict[str, Any] | None = None,
    transport: httpx.AsyncBaseTransport | None,
    timeout_seconds: float,
) -> _Reply:
    """One exchange with a caller-chosen server, bounded four ways (module docstring)."""
    limits = httpx.Timeout(_READ_TIMEOUT_SECONDS, connect=_CONNECT_TIMEOUT_SECONDS)
    try:
        async with asyncio.timeout(timeout_seconds):
            async with _wire_slots():
                async with httpx.AsyncClient(timeout=limits, transport=transport, follow_redirects=False) as client:
                    async with client.stream(method, url, headers=headers, json=json_body) as response:
                        chunks: list[bytes] = []
                        size = 0
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > MAX_RESPONSE_BYTES:
                                raise AdapterError(
                                    "too_large",
                                    f"the reply exceeded {MAX_RESPONSE_BYTES // 1024} KiB and was cut off",
                                )
                            chunks.append(chunk)
                        return _Reply(
                            status=response.status_code,
                            content_type=response.headers.get("content-type", ""),
                            body=b"".join(chunks),
                        )
    except TimeoutError as exc:
        raise AdapterError("timeout", f"no complete reply within {timeout_seconds:g} s") from exc
    except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
        raise AdapterError("timeout", f"the endpoint stalled ({type(exc).__name__})") from exc
    except httpx.HTTPError as exc:
        # ConnectError, RemoteProtocolError, UnsupportedProtocol… — the endpoint was
        # never reached or hung up. The exception text names the host, never a header.
        raise AdapterError("unreachable", f"could not reach the endpoint: {exc}") from exc


def _status_message(reply: _Reply) -> str:
    """What of a rejection may be shown: a JSON error message, truncated; otherwise the
    status, the declared type and the size."""
    status_line = f"HTTP {reply.status}"
    hint = {
        401: "the endpoint rejected the key",
        403: "the endpoint refused this key for that model or route",
        404: "no such route or model at this URL",
        429: "the endpoint is rate-limiting this key",
        529: "the endpoint is overloaded",
    }.get(reply.status)
    if hint is None and 300 <= reply.status < 400:
        hint = "the endpoint redirected, and redirects are not followed"
    prefix = f"{status_line}: {hint}" if hint else status_line
    if "json" in reply.content_type.split(";")[0].lower():
        try:
            body = json.loads(reply.body)
        except ValueError:
            body = None
        message: Any = None
        if isinstance(body, dict):
            error = body.get("error")
            message = error.get("message") if isinstance(error, dict) else error
        if isinstance(message, str) and message.strip():
            return f"{prefix} — {message.strip()[:_DETAIL_MAX_CHARS]}"
        return prefix
    declared = reply.content_type or "of no declared type"
    return f"{prefix}. The response was {declared}, {len(reply.body)} bytes; not shown."


def _json_or_raise(reply: _Reply) -> Any:
    if reply.status < 200 or reply.status >= 300:
        raise AdapterError("http_status", _status_message(reply), status=reply.status)
    try:
        return json.loads(reply.body)
    except ValueError as exc:
        declared = reply.content_type or "of no declared type"
        raise AdapterError(
            "malformed", f"HTTP {reply.status} but the body was not JSON ({declared}, {len(reply.body)} bytes)"
        ) from exc


async def complete(
    wire: Wire,
    req: CompletionRequest,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> CompletionResult:
    """One prompt, one reply, one of five failures. ``transport`` exists so a test can
    stand in for the server, the way ``app.core.sharing.post_exchange`` allows."""
    url, headers, body = build_request(wire, req)
    reply = await _request("POST", url, headers=headers, json_body=body, transport=transport, timeout_seconds=timeout_seconds)
    logger.info("ai wire: %s POST %s -> %s", wire.value, httpx.URL(url).host, reply.status)
    return parse_response(wire, _json_or_raise(reply))


async def list_models(
    wire: Wire,
    base_url: str,
    api_key: str | None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[ModelInfo]:
    """What the endpoint says it serves. Same door, same bounds, nothing of the fleet on
    the wire — the key is the only thing sent."""
    url, headers = build_models_request(wire, base_url, api_key)
    reply = await _request("GET", url, headers=headers, transport=transport, timeout_seconds=timeout_seconds)
    logger.info("ai wire: %s GET %s -> %s", wire.value, httpx.URL(url).host, reply.status)
    return parse_models_response(wire, _json_or_raise(reply))
