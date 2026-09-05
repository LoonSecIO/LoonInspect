"""Settings > AI: the test box (#319), the first caller of the AI gate.

One prompt to an endpoint the admin names, the reply shown as it came back. The
order inside ``test`` is the whole security story and is not to be reshuffled:

1. the URL is judged (``validate_inference_base_url`` and a resolution check —
   loopback and private hosts allowed, link-local and the rest refused);
2. the gate is asked (``require_ai``: the master flag, the AI-inference consent,
   and one share-log row naming the destination and the single field that leaves,
   committed *before* the first byte moves);
3. the adapter dials, bounded by a timeout, and whatever it says is bounded in turn.

The key travels browser → this process → the endpoint and nowhere else: it is not
stored, not logged, not audited, not echoed. Every model call in this product is made
here in Python, never by the browser (Kyle, 2026-09-05).
"""

from __future__ import annotations

import time

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.adapters import AdapterError, CompletionRequest, complete
from app.ai.host_detect import read_host_detection
from app.ai.providers import (
    ANTHROPIC_MODELS,
    DEFAULTS,
    IMPLEMENTED_REACH,
    WIRE_FOR,
    HostReach,
    Provider,
    ReachNotImplemented,
    default_base_url,
    hostname_for,
)
from app.core.ai import AIConsentMissing, AIFeaturesDisabled, require_ai
from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.database import get_db
from app.core.egress import (
    BlockedBaseUrl,
    destination_for_log,
    inference_blocked_reason,
    refuse_blocked_resolution,
    validate_inference_base_url,
)
from app.core.permissions import Permission
from app.schemas.ai import (
    AIErrorOut,
    AITestIn,
    AITestOut,
    HostDetectionOut,
    HostReachOut,
    ProviderEntryOut,
    ProvidersOut,
)

router = APIRouter(prefix="/api/system/ai", tags=["ai"])

AI_TEST_BOX_FEATURE = "ai_test_box"
DISCLOSED_FIELDS = ("prompt_text",)
REASONING_EFFORTS = ("none", "minimal", "low", "medium", "high")

# A test stands in for the endpoint by setting this; production leaves it None.
transport_override: httpx.AsyncBaseTransport | None = None


def _reach_hostname(reach: HostReach) -> str | None:
    try:
        return hostname_for(reach)
    except (ReachNotImplemented, ValueError):
        return None


@router.get(
    "/providers",
    response_model=ProvidersOut,
    dependencies=[Depends(require(Permission.SYSTEM_READ))],
)
async def list_providers() -> ProvidersOut:
    """What the cards fill in, served rather than duplicated in the SPA so there is
    one table (``app.ai.providers``)."""
    return ProvidersOut(
        entries=[
            ProviderEntryOut(
                provider=d.provider,
                wire=d.wire,
                base_url=default_base_url(d.provider),
                model=d.model,
                key=d.key,
                reasoning_effort=d.reasoning_effort,
                uses_host_reach=d.uses_host_reach,
                models=list(ANTHROPIC_MODELS) if d.provider is Provider.anthropic else [d.model],
            )
            for d in DEFAULTS.values()
        ],
        reaches=[
            HostReachOut(reach=reach, hostname=_reach_hostname(reach), implemented=reach in IMPLEMENTED_REACH)
            for reach in HostReach
        ],
        reasoning_efforts=list(REASONING_EFFORTS),
    )


@router.get(
    "/host",
    response_model=HostDetectionOut,
    dependencies=[Depends(require(Permission.SYSTEM_READ))],
)
async def host() -> HostDetectionOut:
    """A hint with its evidence, never a gate (``app.ai.host_detect``)."""
    d = await read_host_detection()
    return HostDetectionOut(
        runtime=d.runtime,
        host_os=d.host_os,
        apple_silicon=d.apple_silicon,
        alias=d.alias,
        alias_resolves=d.alias_resolves,
        docker_desktop_on_macos=d.docker_desktop_on_macos,
        evidence=d.evidence,
    )


@router.post(
    "/test",
    response_model=AITestOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def test_endpoint(payload: AITestIn, db: AsyncSession = Depends(get_db)) -> AITestOut:
    defaults = DEFAULTS[payload.provider]
    wire = WIRE_FOR[payload.provider]
    if defaults.key == "required" and not payload.api_key:
        raise HTTPException(status_code=422, detail=f"{payload.provider.value} needs an API key")

    reach = payload.host_reach or (HostReach.docker_desktop if defaults.uses_host_reach else HostReach.custom)
    if reach not in IMPLEMENTED_REACH:
        try:
            hostname_for(reach)
        except ReachNotImplemented as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        base_url = validate_inference_base_url(payload.base_url, carries_key=bool(payload.api_key))
        await refuse_blocked_resolution(base_url, reason_for=inference_blocked_reason)
    except BlockedBaseUrl as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    destination = destination_for_log(base_url)

    # The gate, before anything is dialled. Refusals are the operator's switches, so
    # they answer 409 with the gate's own sentence rather than a generic error.
    try:
        await require_ai(db, feature=AI_TEST_BOX_FEATURE, destination=destination, fields=DISCLOSED_FIELDS)
    except (AIFeaturesDisabled, AIConsentMissing) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    request = CompletionRequest(
        base_url=base_url,
        model=payload.model,
        prompt=payload.prompt,
        api_key=payload.api_key,
        reasoning_effort=payload.reasoning_effort,
        max_tokens=payload.max_tokens,
    )
    started = time.monotonic()
    try:
        result = await complete(wire, request, transport=transport_override)
    except AdapterError as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        audit(
            AuditAction.AI_TEST_SENT,
            target_type="ai_endpoint",
            target_id=destination,
            provider=payload.provider.value,
            outcome="error",
            error_kind=exc.kind,
            latency_ms=latency_ms,
        )
        return AITestOut(
            provider=payload.provider,
            wire=wire,
            destination=destination,
            model=None,
            outcome="error",
            content="",
            reasoning=None,
            finish_reason=None,
            completion_tokens=None,
            latency_ms=latency_ms,
            error=AIErrorOut(kind=exc.kind, message=exc.message, status=exc.status),
        )

    latency_ms = int((time.monotonic() - started) * 1000)
    audit(
        AuditAction.AI_TEST_SENT,
        target_type="ai_endpoint",
        target_id=destination,
        provider=payload.provider.value,
        outcome=result.outcome,
        latency_ms=latency_ms,
    )
    return AITestOut(
        provider=payload.provider,
        wire=wire,
        destination=destination,
        model=result.model or payload.model,
        outcome=result.outcome,
        content=result.content,
        reasoning=result.reasoning,
        finish_reason=result.finish_reason,
        completion_tokens=result.completion_tokens,
        latency_ms=latency_ms,
    )
