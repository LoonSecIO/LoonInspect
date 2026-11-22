"""Optional Fleet briefing: a saved provider ranks server-computed facts for the selected cohort."""

import json
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.adapters import OUTCOME_ANSWERED, AdapterError, CompletionRequest, complete
from app.ai.providers import HostReach, Provider
from app.api.ai import judged_endpoint
from app.api.changes_prompt import chosen_config, prompt_status
from app.api.fleet_migration import Cohort, read_migration
from app.core import fleet_catalog
from app.core.ai import AIRefused, require_ai
from app.core.ai_usage import recorder
from app.core.audit import audit
from app.core.auth import require
from app.core.database import get_db, get_snapshot_db
from app.core.ollama import select_model, selected
from app.core.permissions import Permission
from app.schemas.changes_prompt import PromptStatusOut
from app.schemas.fleet_migration import MigrationReport

router = APIRouter(
    prefix="/api/fleet-catalog/briefing", tags=["fleet-catalog"], dependencies=[Depends(require(Permission.APP_READ))]
)
FEATURE = "fleet_catalog_briefing"
transport_override: httpx.AsyncBaseTransport | None = None
SYSTEM = (
    "Choose up to three migration or patch-review highlights from the supplied aggregate counts. "
    "Return a JSON array containing only distinct keys present in the input. "
    "Prefer evidence of overdue policy, known exploited findings on installed builds, or uncertainty worth resolving."
)


class BriefingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Provider | None = None


class Highlight(BaseModel):
    code: str
    count: int
    text: str


class BriefingOut(BaseModel):
    outcome: Literal["selected", "fallback"]
    highlights: list[Highlight]
    provider: Provider | None = None
    model: str | None = None
    detail: str | None = None


def _facts(report: MigrationReport) -> list[Highlight]:
    assessments = report.app_assessments.values()
    facts = [
        (
            "apps_overdue",
            sum(row.out_of_policy_builds > 0 for row in assessments),
            "with an installed build outside the confirmed Jamf patch rule",
        ),
        (
            "apps_with_kev",
            sum(bool(row.kev_builds) for row in assessments),
            "with an older installed build carrying a KEV-listed finding",
        ),
        ("ambiguous_apps", sum(item.match == "ambiguous" for item in report.items), "with an identity needing review"),
        (
            "incomplete_comparisons",
            sum(row.unknown_builds > 0 or row.net_only_builds > 0 for row in assessments),
            "with an older build lacking an exact finding comparison",
        ),
        (
            "recurring_review",
            sum(row.management == "recurring" for row in assessments),
            "with an observed gap and repeated Fleet catalog updates",
        ),
        ("exact_candidates", sum(item.match == "exact" for item in report.items), "with an exact Fleet catalog candidate"),
    ]
    highlights = [Highlight(code=code, count=n, text=f"{n} app{'s' if n != 1 else ''} {label}.") for code, n, label in facts if n]
    macs = report.scope.active_macs
    highlights.append(
        Highlight(code="scoped_macs", count=macs, text=f"{macs} Mac{'s' if macs != 1 else ''} in the selected scope.")
    )
    return highlights


def _pick(raw: str, facts: list[Highlight]) -> list[Highlight]:
    """Resolve only the small, closed set of requested codes to original local facts."""
    if len(raw) > 512:
        return []
    try:
        codes = json.loads(raw)
    except (ValueError, RecursionError):
        return []
    by_code = {fact.code: fact for fact in facts}
    if not isinstance(codes, list) or not 1 <= len(codes) <= 3:
        return []
    if not all(isinstance(code, str) and code in by_code for code in codes) or len(set(codes)) != len(codes):
        return []
    return [by_code[code] for code in codes]


@router.get("", response_model=PromptStatusOut)
async def briefing_status(db: AsyncSession = Depends(get_db)) -> PromptStatusOut:
    if not await fleet_catalog.enabled(db):
        raise HTTPException(409, fleet_catalog.FLAG_OFF)
    return await prompt_status(db)


@router.post("", response_model=BriefingOut)
async def briefing(payload: BriefingIn, cohort: Cohort = Depends(), db: AsyncSession = Depends(get_snapshot_db)) -> BriefingOut:
    report = await read_migration(cohort, db)
    if not report.enabled:
        raise HTTPException(409, fleet_catalog.FLAG_OFF)
    status = await prompt_status(db)
    if not status.available:
        raise HTTPException(
            409,
            {
                "flag_off": "Enable AI features in Settings to request a briefing.",
                "consent_off": "Grant AI inference consent in Settings to share aggregate report counts.",
                "no_provider": "Save a provider in Settings → AI to request a briefing.",
            }.get(status.reason, "Check AI availability in Settings."),
        )
    facts = _facts(report)
    if len(facts) <= 1:
        return BriefingOut(
            outcome="fallback", highlights=facts, detail="No additional report highlights are available in this scope."
        )
    config = await chosen_config(db, payload.provider)
    provider = Provider(config.provider)
    key = config.api_key_encrypted
    wire, base, destination, host = await judged_endpoint(
        provider, HostReach(config.host_reach) if config.host_reach else None, config.base_url, carries_key=bool(key)
    )
    model = selected(
        await select_model(
            db,
            provider=provider,
            pinned=config.model,
            policy=config.ollama_policy,
            base=base,
            destination=destination,
            host=host,
            key=key,
            transport=transport_override,
        )
    )
    counts = {fact.code: fact.count for fact in facts}
    try:
        await require_ai(db, feature=FEATURE, destination=destination, fields=list(counts), model=model)
    except AIRefused as exc:
        raise HTTPException(409, detail=str(exc)) from exc
    request = CompletionRequest(
        base_url=base,
        model=model,
        prompt=json.dumps(counts),
        system=SYSTEM,
        max_tokens=100,
        temperature=0,
        api_key=key,
        host_header=host,
        serial=provider is Provider.apple_fm,
        reasoning_effort=None if provider is Provider.apple_fm else config.reasoning_effort,
        record_usage=recorder(db, FEATURE, provider.value, model),
    )
    try:
        result = await complete(wire, request, timeout_seconds=20, transport=transport_override)
        selected_facts = _pick(result.content, facts) if result.outcome == OUTCOME_ANSWERED else []
        detail = None if selected_facts else "The model returned no usable selection. Showing highlights from the report."
    except AdapterError as exc:
        selected_facts = []
        detail = f"The provider call failed ({exc.kind}). Showing report highlights. Check the provider in Settings → AI."
    outcome = "selected" if selected_facts else "fallback"
    audit(
        "ai.fleet-catalog-briefing.sent",
        outcome=outcome,
        target_type="ai_endpoint",
        target_id=destination,
        provider=provider.value,
        highlights=len(selected_facts),
    )
    return BriefingOut(outcome=outcome, provider=provider, model=model, highlights=selected_facts or facts[:3], detail=detail)
