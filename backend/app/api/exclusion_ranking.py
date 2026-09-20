"""Optional local AI ranking on Data Sharing; selecting and saving exclusions stays operator-owned (#409)."""

import time
from typing import Annotated, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.adapters import OUTCOME_ANSWERED, AdapterError, CompletionRequest, complete
from app.ai.exclusion_ranking import CLASSES, DISCLOSED_FIELDS, FEATURE, SYSTEM, Classification, build_prompt, interpret
from app.ai.providers import HostReach, Provider
from app.api.ai import judged_endpoint
from app.api.changes_prompt import chosen_config
from app.core.ai import AIRefused, ai_features_enabled, require_ai
from app.core.ai_configs import list_configs
from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.database import get_db
from app.core.egress import BlockedBaseUrl, destination_for_log
from app.core.exclusion_candidates import build_candidates
from app.core.local_inference import LOCAL_ONLY, pinned_address
from app.core.permissions import Permission
from app.core.sharing import get_or_create_settings
from app.schemas.system import ExclusionCandidatesOut

router = APIRouter(prefix="/api/system/data-sharing/exclusion-ranking", tags=["system"])
transport_override: httpx.AsyncBaseTransport | None = None
LOCAL_PROVIDERS = {Provider.apple_fm, Provider.openai_compatible}


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class RankingProvider(_Base):
    provider: Provider
    model: str
    destination: str


class RankingStatus(_Base):
    available: bool
    reason: Literal["flag_off", "consent_off", "local_endpoint_required"] | None
    providers: list[RankingProvider] = Field(default_factory=list)


class RankingIn(_Base):
    provider: Provider
    globs: list[Annotated[str, Field(max_length=512)]] = Field(default_factory=list, max_length=40)


class RankedGroup(_Base):
    prefix: str
    classification: Classification


class RankingOut(_Base):
    candidates: ExclusionCandidatesOut
    assessments: list[RankedGroup]
    destination: str
    model: str


@router.get("", response_model=RankingStatus, dependencies=[Depends(require(Permission.SYSTEM_READ))])
async def status(db: AsyncSession = Depends(get_db)) -> RankingStatus:
    if not await ai_features_enabled(db):
        return RankingStatus(available=False, reason="flag_off")
    if not (await get_or_create_settings(db)).ai_inference:
        return RankingStatus(available=False, reason="consent_off")
    providers = []
    for config in await list_configs(db):
        if Provider(config.provider) not in LOCAL_PROVIDERS:
            continue
        try:
            await pinned_address(config.base_url)
        except BlockedBaseUrl:
            continue
        # The URL's origin is the same disclosure the gate records; no path or credential.
        providers.append(
            RankingProvider(provider=config.provider, model=config.model, destination=destination_for_log(config.base_url))
        )
    return RankingStatus(available=bool(providers), reason=None if providers else "local_endpoint_required", providers=providers)


@router.post("", response_model=RankingOut, dependencies=[Depends(require(Permission.SYSTEM_WRITE))])
async def rank(payload: RankingIn, db: AsyncSession = Depends(get_db)) -> RankingOut:
    # Check both switches before inventory work, DNS or any model request.
    if not await ai_features_enabled(db) or not (await get_or_create_settings(db)).ai_inference:
        raise HTTPException(status_code=409, detail="Turn on AI features and AI-inference consent before ranking candidates.")
    if payload.provider not in LOCAL_PROVIDERS:
        raise HTTPException(status_code=409, detail=LOCAL_ONLY)
    config = await chosen_config(db, payload.provider)
    wire, base_url, destination, host_header = await judged_endpoint(
        payload.provider,
        HostReach(config.host_reach) if config.host_reach else None,
        config.base_url,
        carries_key=bool(config.api_key_encrypted),
    )
    try:
        address = await pinned_address(base_url)
    except BlockedBaseUrl as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    candidates = await build_candidates(db, payload.globs)
    if not candidates.groups:
        raise HTTPException(status_code=409, detail="There are no exclusion candidates to rank. Nothing was sent.")
    try:
        prompt = build_prompt([group.model_dump() for group in candidates.groups])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        await require_ai(db, feature=FEATURE, destination=destination, fields=DISCLOSED_FIELDS)
    except AIRefused as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    started = time.monotonic()
    try:
        result = await complete(
            wire,
            CompletionRequest(
                base_url=base_url,
                model=config.model,
                prompt=prompt,
                system=SYSTEM,
                serial=payload.provider is Provider.apple_fm,
                api_key=config.api_key_encrypted,
                reasoning_effort=None if payload.provider is Provider.apple_fm else config.reasoning_effort,
                temperature=0,
                max_tokens=768,
                host_header=host_header,
                connect_ip=address,
            ),
            transport=transport_override,
            timeout_seconds=30,
        )
    except AdapterError as exc:
        audit(
            AuditAction.AI_EXCLUSION_RANKING,
            outcome="error",
            target_type="ai_endpoint",
            target_id=destination,
            error_kind=exc.kind,
            latency_ms=int((time.monotonic() - started) * 1000),
        )
        raise HTTPException(
            status_code=502,
            detail=(
                "The local model could not rank these candidates. Check its connection in Settings › AI and retry; "
                "the candidate list and saved exclusions are unchanged."
            ),
        ) from exc
    labels = interpret(result.content, len(candidates.groups)) if result.outcome == OUTCOME_ANSWERED else None
    audit(
        AuditAction.AI_EXCLUSION_RANKING,
        outcome="ranked" if labels else "unparseable",
        target_type="ai_endpoint",
        target_id=destination,
        latency_ms=int((time.monotonic() - started) * 1000),
    )
    if labels is None:
        raise HTTPException(
            status_code=502,
            detail=(
                "The local model did not return a valid classification for each candidate. Retry or use the existing "
                "candidate list; no exclusions were changed."
            ),
        )
    pairs = sorted(zip(candidates.groups, labels, strict=True), key=lambda pair: CLASSES.index(pair[1]))
    return RankingOut(
        candidates=candidates.model_copy(update={"groups": [group for group, _ in pairs]}),
        assessments=[RankedGroup(prefix=group.prefix, classification=label) for group, label in pairs],
        destination=destination,
        model=config.model,
    )
