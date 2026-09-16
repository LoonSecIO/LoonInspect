"""Settings > AI: the test box (#319) and the model listing (#322), the first callers
of the AI gate.

One prompt to an endpoint the admin names, the reply shown as it came back; and one
question to that endpoint, "what do you serve?", answered as a list. The order inside
both is the whole security story and is not to be reshuffled:

1. the URL is judged (``validate_inference_base_url`` and a resolution check —
   loopback and private hosts allowed, link-local and the rest refused);
2. the gate is asked (``require_ai``: the master flag, the AI-inference consent,
   and one share-log row naming the destination and what leaves — ``prompt_text`` for
   a send, nothing of the fleet for a listing — committed *before* the first byte);
3. the adapter dials through its one bounded door, and whatever it says is bounded
   in turn.

The key travels browser → this process → the endpoint and nowhere else: it is not
logged, not audited, not echoed. Every model call in this product is made here in
Python, never by the browser (Kyle, 2026-09-05).

Since 2026-09-14 a card's Save also keeps what it holds (``/configs``, app.core.ai_configs):
the key encrypted at rest like a Jamf client secret, and write-only — a config comes back
saying whether a key is stored, never what it is. A Save is judged exactly as a test is
(step 1) and asks only the flag of the gate, because saving sends nothing anywhere; the
feature that later dials the saved URL judges it again and asks the whole gate.
"""

from __future__ import annotations

import time

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.adapters import MAX_MODEL_ID_CHARS, AdapterError, CompletionRequest, complete, list_models
from app.ai.host_detect import read_host_detection
from app.ai.providers import (
    ANTHROPIC_MODELS,
    APPLE_FM_MODELS,
    DEFAULTS,
    IMPLEMENTED_REACH,
    WIRE_FOR,
    HostReach,
    Provider,
    ReachNotImplemented,
    Wire,
    default_base_url,
    hostname_for,
    presented_host,
)
from app.core.ai import AIConsentMissing, AIFeaturesDisabled, require_ai
from app.core.ai_configs import SavedConfig, delete_config, keeps_key, list_configs, save_config, saved_config
from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
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
    API_KEY_MAX_LENGTH,
    AIConfigIn,
    AIConfigOut,
    AIConfigsOut,
    AIErrorOut,
    AIModelOut,
    AIModelsIn,
    AIModelsOut,
    AITestIn,
    AITestOut,
    HostDetectionOut,
    HostReachOut,
    ProviderEntryOut,
    ProvidersOut,
)

router = APIRouter(prefix="/api/system/ai", tags=["ai"])

AI_TEST_BOX_FEATURE = "ai_test_box"
AI_MODEL_LISTING_FEATURE = "ai_model_listing"
# Saving a config is on-pod work: the gate is asked for the flag only, and logs nothing.
AI_CONFIG_FEATURE = "ai_config"
# The two reads Settings > AI opens with: on-pod work like a Save, gated the same way (#402).
AI_PROVIDER_TABLE_FEATURE = "ai_provider_table"
AI_HOST_DETECTION_FEATURE = "ai_host_detection"
DISCLOSED_FIELDS = ("prompt_text",)
REASONING_EFFORTS = ("none", "minimal", "low", "medium", "high")

# A test stands in for the endpoint by setting this; production leaves it None.
transport_override: httpx.AsyncBaseTransport | None = None

# The names on the Settings > AI cards. An operator reads these; the wire values
# (apple_fm, openai_compatible) are nobody's vocabulary (docs/diagnosability.md §3).
CARD_LABELS: dict[Provider, str] = {
    Provider.apple_fm: "Apple Foundation Models via Docker Desktop",
    Provider.openai_compatible: "OpenAI-compatible",
    Provider.anthropic: "Anthropic",
}

# What failed, why, and what to check (docs/diagnosability.md rule 3) — and never the key.
API_KEY_TOO_LONG = (
    f"The API key is longer than the {API_KEY_MAX_LENGTH} characters Settings › AI accepts. "
    "Check that only the key was pasted, with nothing before or after it."
)
# `fm serve` answers 400 to any `reasoning_effort` on its on-device model, "none" included
# (docs/ai-layer.md, measured 2026-09-05; again 2026-09-15 on macOS 27.0), so an Apple card
# carrying one fails every call made with it. Kyle's ruling: refused where it is set, a
# test or a Save, and never sent where a saved card is dialled (app.api.changes_prompt).
APPLE_FM_TAKES_NO_EFFORT = (
    "Apple's on-device model takes no reasoning effort — fm serve refuses it on the system model. "
    f"Save the {CARD_LABELS[Provider.apple_fm]} card again from Settings › AI; the page sends none."
)


def _bounded_key(api_key: str | None) -> None:
    """The key's length, refused here rather than by the schema, for the sentence: it
    says what to check, where the schema's refusal would only count characters
    (``API_KEY_MAX_LENGTH``). First in every route that takes one, where the schema's
    check used to run."""
    if api_key is not None and len(api_key) > API_KEY_MAX_LENGTH:
        raise HTTPException(status_code=422, detail=API_KEY_TOO_LONG)


def _effort_accepted(provider: Provider, reasoning_effort: str | None) -> None:
    """Apple's card takes no reasoning effort (``APPLE_FM_TAKES_NO_EFFORT``). A rule
    about the body, like the key's bound, so it runs beside it: before the URL is judged
    or the gate is asked, and so before anything is dialled or disclosed."""
    if provider is Provider.apple_fm and reasoning_effort is not None:
        raise HTTPException(status_code=422, detail=APPLE_FM_TAKES_NO_EFFORT)


async def _flag_or_409(db: AsyncSession, feature: str) -> None:
    """The master flag alone, for on-pod work that sends nothing anywhere (#402).

    The flag switches the whole AI area, in both directions: with it off, Settings > AI is
    neither listed nor reachable, and the two reads that page opens with — and a Save —
    answer the gate's sentence. ``destination=None`` for every caller, so nothing leaves,
    nothing is logged, and ``AIConsentMissing``, the gate's other half, cannot be raised.
    """
    try:
        await require_ai(db, feature=feature)
    except AIFeaturesDisabled as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _reach_hostname(reach: HostReach) -> str | None:
    try:
        return hostname_for(reach)
    except (ReachNotImplemented, ValueError):
        return None


async def judged_endpoint(
    provider: Provider, host_reach: HostReach | None, base_url: str, *, carries_key: bool
) -> tuple[Wire, str, str, str | None]:
    """Step 1 of the module docstring, shared by every route that names an endpoint —
    the test box, the listing, a config's Save, and the Changes Prompt bar's call: the
    wire, the URL as it may be dialled, the origin the share log will record, and the
    `Host` the reach presents (``presented_host``). Raises the HTTP refusal itself.

    ``carries_key`` is whether a key will travel with the request, sent or stored: the
    required-key rule and the plain-http rule are both about that, never its value."""
    defaults = DEFAULTS[provider]
    if defaults.key == "required" and not carries_key:
        raise HTTPException(status_code=422, detail=f"{provider.value} needs an API key")

    reach = host_reach or (HostReach.docker_desktop if defaults.uses_host_reach else HostReach.custom)
    if reach not in IMPLEMENTED_REACH:
        try:
            hostname_for(reach)
        except ReachNotImplemented as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        judged = validate_inference_base_url(base_url, carries_key=carries_key)
        await refuse_blocked_resolution(judged, reason_for=inference_blocked_reason)
    except BlockedBaseUrl as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return WIRE_FOR[provider], judged, destination_for_log(judged), presented_host(reach, judged)


@router.get(
    "/providers",
    response_model=ProvidersOut,
    dependencies=[Depends(require(Permission.SYSTEM_READ))],
)
async def list_providers(db: AsyncSession = Depends(get_db)) -> ProvidersOut:
    """What the cards fill in, served rather than duplicated in the SPA so there is
    one table (``app.ai.providers``). Behind the flag, like everything else in the area."""
    await _flag_or_409(db, AI_PROVIDER_TABLE_FEATURE)
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
                models=(
                    list(ANTHROPIC_MODELS)
                    if d.provider is Provider.anthropic
                    else list(APPLE_FM_MODELS)
                    if d.provider is Provider.apple_fm
                    else [d.model]
                ),
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
async def host(db: AsyncSession = Depends(get_db)) -> HostDetectionOut:
    """A hint with its evidence; a gate on one card, and on nothing here (#404,
    ``app.ai.host_detect``). Behind the flag all the same: with the area off, nothing
    reads this container's `/proc` or asks DNS about the Docker Desktop alias on a page
    nobody may open."""
    await _flag_or_409(db, AI_HOST_DETECTION_FEATURE)
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
    "/models",
    response_model=AIModelsOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def list_endpoint_models(payload: AIModelsIn, db: AsyncSession = Depends(get_db)) -> AIModelsOut:
    """What the endpoint says it serves, to fill the model field's suggestions. A POST
    because the body carries the key; nothing is stored."""
    _bounded_key(payload.api_key)
    wire, base_url, destination, host_header = await judged_endpoint(
        payload.provider, payload.host_reach, payload.base_url, carries_key=bool(payload.api_key)
    )

    # The gate, declared honestly: nothing of the fleet leaves, and the row says so.
    try:
        await require_ai(db, feature=AI_MODEL_LISTING_FEATURE, destination=destination, carries_no_fleet_data=True)
    except (AIFeaturesDisabled, AIConsentMissing) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    started = time.monotonic()
    try:
        models = await list_models(wire, base_url, payload.api_key, host_header=host_header, transport=transport_override)
    except AdapterError as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        audit(
            AuditAction.AI_MODELS_LISTED,
            target_type="ai_endpoint",
            target_id=destination,
            provider=payload.provider.value,
            outcome="error",
            error_kind=exc.kind,
            latency_ms=latency_ms,
        )
        return AIModelsOut(
            provider=payload.provider,
            wire=wire,
            destination=destination,
            models=[],
            latency_ms=latency_ms,
            error=AIErrorOut(kind=exc.kind, message=exc.message, status=exc.status),
        )

    latency_ms = int((time.monotonic() - started) * 1000)
    audit(
        AuditAction.AI_MODELS_LISTED,
        target_type="ai_endpoint",
        target_id=destination,
        provider=payload.provider.value,
        outcome="listed",
        count=len(models),
        latency_ms=latency_ms,
    )
    return AIModelsOut(
        provider=payload.provider,
        wire=wire,
        destination=destination,
        models=[AIModelOut(id=m.id, label=m.label) for m in models],
        latency_ms=latency_ms,
    )


@router.post(
    "/test",
    response_model=AITestOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def test_endpoint(payload: AITestIn, db: AsyncSession = Depends(get_db)) -> AITestOut:
    _bounded_key(payload.api_key)
    _effort_accepted(payload.provider, payload.reasoning_effort)
    wire, base_url, destination, host_header = await judged_endpoint(
        payload.provider, payload.host_reach, payload.base_url, carries_key=bool(payload.api_key)
    )

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
        host_header=host_header,
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
        # Bounded: the endpoint chose this string.
        model=(result.model or payload.model)[:MAX_MODEL_ID_CHARS],
        outcome=result.outcome,
        content=result.content,
        reasoning=result.reasoning,
        finish_reason=result.finish_reason,
        completion_tokens=result.completion_tokens,
        latency_ms=latency_ms,
    )


# --- saved configs (2026-09-14) ----------------------------------------------------------


def config_out(config: SavedConfig) -> AIConfigOut:
    return AIConfigOut(
        provider=config.provider,
        host_reach=config.host_reach,
        base_url=config.base_url,
        model=config.model,
        reasoning_effort=config.reasoning_effort,
        has_key=config.has_key,
        updated_at=config.updated_at,
        updated_by=config.updated_by,
    )


@router.get(
    "/configs",
    response_model=AIConfigsOut,
    dependencies=[Depends(require(Permission.SYSTEM_READ))],
)
async def list_saved_configs(db: AsyncSession = Depends(get_db)) -> AIConfigsOut:
    """What each card last saved, in card order. ``hasKey`` in place of the key."""
    return AIConfigsOut(configs=[config_out(c) for c in await list_configs(db)])


@router.put(
    "/configs/{provider}",
    response_model=AIConfigOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def save_provider_config(
    provider: Provider,
    payload: AIConfigIn,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> AIConfigOut:
    """Keep what the card holds, judged as a test is. Refused while the flag is off: a
    saved endpoint is standing permission for a feature to dial it, and the flag is what
    says the AI area is on at all. ``apiKey`` omitted keeps the stored key, so the key
    rules are judged against the key the row will hold, not only the one sent."""
    _bounded_key(payload.api_key)
    _effort_accepted(provider, payload.reasoning_effort)
    await _flag_or_409(db, AI_CONFIG_FEATURE)

    stored = await saved_config(db, provider)
    has_key = keeps_key(stored is not None and stored.has_key, payload.api_key, payload.clear_key)
    _, base_url, destination, _ = await judged_endpoint(provider, payload.host_reach, payload.base_url, carries_key=has_key)

    config = await save_config(
        db,
        provider,
        host_reach=payload.host_reach.value if payload.host_reach else None,
        base_url=base_url,
        model=payload.model,
        reasoning_effort=payload.reasoning_effort,
        api_key=payload.api_key,
        clear_key=payload.clear_key,
        updated_by=principal.account.email,
    )
    audit(
        AuditAction.AI_CONFIG_SAVED,
        target_type="ai_provider_config",
        target_id=provider.value,
        provider=provider.value,
        destination=destination,
        model=config.model,
        has_key=config.has_key,
    )
    return config_out(config)


@router.delete(
    "/configs/{provider}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def delete_provider_config(provider: Provider, db: AsyncSession = Depends(get_db)) -> None:
    """Forget what the card saved, key included. Not flag-gated: turning the AI area off
    must not strand a stored key where nobody can remove it."""
    if not await delete_config(db, provider):
        raise HTTPException(status_code=404, detail=f"No saved config for {provider.value}.")
    audit(AuditAction.AI_CONFIG_REMOVED, target_type="ai_provider_config", target_id=provider.value, provider=provider.value)
