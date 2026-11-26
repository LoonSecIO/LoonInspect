"""The migration briefing (#910): a saved provider picks which of the migration report's own counts lead.

Only the report's counts leave, keyed by code (`_facts`), once its snapshot has ended and in the order of
``app.api.patch_policy_rules``; only codes the request carried come back (`_pick`). The page words every code.
"""

import json
import re
import time
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.adapters import OUTCOME_ANSWERED, AdapterError, CompletionRequest, complete
from app.ai.changes_prompt import CALL_TIMEOUT_SECONDS, MAX_REPLY_TOKENS
from app.ai.providers import HostReach, Provider
from app.api.ai import judged_endpoint
from app.api.changes_prompt import chosen_config, prompt_status
from app.api.fleet_migration import device_filter, read_migration
from app.core import fleet_catalog
from app.core.ai import AIRefused, require_ai
from app.core.ai_usage import accepted, recorder
from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.database import get_db
from app.core.device_scope_queries import get_scope_snapshot_db
from app.core.ollama import select_model, selected
from app.core.permissions import Permission
from app.schemas.ai import AIErrorOut
from app.schemas.changes_prompt import PromptStatusOut
from app.schemas.fleet_migration import MigrationReport
from app.schemas.patch_plans import DeviceScope, ReportModel

router = APIRouter(
    prefix="/api/fleet-catalog/briefing",
    tags=["fleet-catalog"],
    dependencies=[Depends(require(Permission.APP_READ)), Depends(require(Permission.DEVICE_READ))],
)

FEATURE = "fleet_catalog_briefing"
# A test stands in for the endpoint by setting this; production leaves it None.
transport_override: httpx.AsyncBaseTransport | None = None
SYSTEM = (
    "Choose up to three migration or patch-review highlights from the supplied aggregate counts. "
    "Return a JSON array containing only distinct keys present in the input. "
    "Prefer evidence of overdue policy, known exploited findings on installed builds, or uncertainty worth resolving."
)
Code = Literal["apps_overdue", "apps_with_kev", "ambiguous_apps", "incomplete_comparisons", "recurring_review",
               "exact_candidates", "scoped_macs"]  # fmt: skip


class BriefingIn(ReportModel):
    model_config = ConfigDict(extra="forbid")  # The report is read here, never taken from the request.
    # None asks the first saved config, in the Settings > AI cards' order.
    provider: Provider | None = None


class Highlight(ReportModel):
    code: Code
    count: int


class BriefingOut(ReportModel):
    # selected: the model's choice, in its order. fallback: the report's first three; `reason` says why: nothing_to_rank
    # (only the Mac count, so nothing asked), unusable (no choice in the reply) or error (`error` has the adapter's sentence).
    outcome: Literal["selected", "fallback"]
    reason: Literal["nothing_to_rank", "unusable", "error"] | None = None
    highlights: list[Highlight]
    provider: Provider | None = None
    model: str | None = None
    error: AIErrorOut | None = None


def _facts(report: MigrationReport) -> list[Highlight]:
    """The report's non-zero app counts, then its Macs, read off #898's assessments and #895's items: never a name."""
    assessed = report.app_assessments.values()
    counts = {
        "apps_overdue": sum(row.out_of_policy_builds > 0 for row in assessed),
        "apps_with_kev": sum(bool(row.kev_builds) for row in assessed),
        "ambiguous_apps": sum(item.match == "ambiguous" for item in report.items),
        "incomplete_comparisons": sum(row.unknown_builds > 0 or row.net_only_builds > 0 for row in assessed),
        "recurring_review": sum(row.management == "recurring" for row in assessed),
        "exact_candidates": sum(item.match == "exact" for item in report.items),
    }
    facts = [Highlight(code=code, count=count) for code, count in counts.items() if count]
    return [*facts, Highlight(code="scoped_macs", count=report.scope.selected_macs)]


def _pick(raw: str, facts: list[Highlight]) -> list[Highlight]:
    """One to three distinct codes the request carried, in the model's order, as the report's facts; else no choice."""
    if len(raw) > 512:
        return []
    fenced = re.fullmatch(r"```(?:json)?\s*\n(.*?)\n```", raw.strip(), flags=re.DOTALL)  # read_proposal's one fence
    try:
        codes = json.loads(fenced[1] if fenced else raw)
    except (ValueError, RecursionError):
        return []
    by_code = {fact.code: fact for fact in facts}
    if not isinstance(codes, list) or not 1 <= len(codes) <= 3 or not all(isinstance(c, str) and c in by_code for c in codes):
        return []
    return [by_code[code] for code in codes] if len(set(codes)) == len(codes) else []


@router.get("", response_model=PromptStatusOut)
async def briefing_status(db: AsyncSession = Depends(get_db)) -> PromptStatusOut:
    """Whether a briefing can be asked for: the Fleet catalog flag, then the AI switches as every AI surface reads them."""
    if not await fleet_catalog.enabled(db):
        raise HTTPException(status_code=409, detail=fleet_catalog.FLAG_OFF)
    return await prompt_status(db)


def _audited(outcome: str, provider: Provider, destination: str, latency_ms: int, **metadata: object) -> None:
    """Who asked which provider, how it went and how long, with the highlight count or error kind; never counts or reply."""
    audit(
        AuditAction.AI_FLEET_CATALOG_BRIEFING, outcome=outcome, target_type="ai_endpoint",
        target_id=destination, provider=provider.value, latency_ms=latency_ms, **metadata,
    )  # fmt: skip


@router.post("", response_model=BriefingOut)
async def briefing(
    payload: BriefingIn, scope: DeviceScope = Depends(device_filter), db: AsyncSession = Depends(get_scope_snapshot_db)
) -> BriefingOut:
    """Which of the report's counts for the Macs `deviceScope` selects lead, as a saved provider ranks them."""
    report = await read_migration(scope, db)
    if not report.enabled:
        raise HTTPException(status_code=409, detail=fleet_catalog.FLAG_OFF)
    facts = _facts(report)
    # The snapshot ends here: inside REPEATABLE READ, the gate's share-log prune fails to serialize when another AI
    # caller pruned the same row first. The commit returns the pooled connection, which resets its isolation level,
    # so the rest runs in READ COMMITTED like every other AI caller's, and nothing after it reads the report.
    await db.commit()
    if len(facts) <= 1:
        return BriefingOut(outcome="fallback", reason="nothing_to_rank", highlights=facts)
    config = await chosen_config(db, payload.provider)
    provider, api_key = Provider(config.provider), config.api_key_encrypted
    reach = HostReach(config.host_reach) if config.host_reach else None
    wire, base_url, destination, host_header = await judged_endpoint(provider, reach, config.base_url, carries_key=bool(api_key))
    selection = await select_model(
        db, provider=provider, pinned=config.model, policy=config.ollama_policy, base=base_url,
        destination=destination, host=host_header, key=api_key, transport=transport_override,
    )  # fmt: skip
    model = selected(selection)
    counts = {fact.code: fact.count for fact in facts}
    try:
        await require_ai(db, feature=FEATURE, destination=destination, fields=list(counts), model=model)
    except AIRefused as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    request = CompletionRequest(
        record_usage=recorder(db, FEATURE, provider.value, model, config=config,
                              fallback="fallback" in selection.get("reason", "")),
        serial=provider is Provider.apple_fm,
        base_url=base_url, model=model, prompt=json.dumps(counts), system=SYSTEM, api_key=api_key,
        reasoning_effort=None if provider is Provider.apple_fm else config.reasoning_effort,
        max_tokens=MAX_REPLY_TOKENS, temperature=0, host_header=host_header,
    )  # fmt: skip
    asked = {"provider": provider, "model": model}
    started = time.monotonic()
    try:
        result = await complete(wire, request, transport=transport_override, timeout_seconds=CALL_TIMEOUT_SECONDS)
    except AdapterError as exc:
        _audited("error", provider, destination, int((time.monotonic() - started) * 1000), error_kind=exc.kind)
        error = AIErrorOut(kind=exc.kind, message=exc.message, status=exc.status)
        return BriefingOut(outcome="fallback", reason="error", highlights=facts[:3], error=error, **asked)
    latency_ms = int((time.monotonic() - started) * 1000)
    picked = _pick(result.content, facts) if result.outcome == OUTCOME_ANSWERED else []
    if not picked:
        await accepted(result, "unusable")
        kind = "malformed" if result.outcome == OUTCOME_ANSWERED else result.outcome
        _audited("unparseable", provider, destination, latency_ms, error_kind=kind)
        return BriefingOut(outcome="fallback", reason="unusable", highlights=facts[:3], **asked)
    await accepted(result, "completed")
    _audited("selected", provider, destination, latency_ms, highlights=len(picked))
    return BriefingOut(outcome="selected", highlights=picked, **asked)
