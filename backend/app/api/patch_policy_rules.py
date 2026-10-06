"""Drafting the organization's patching rule from its stated policy: the statement in, the
rule editor's boxes out. Nothing here saves a rule.

The order is slot 1's (``app.api.changes_prompt``) and is not to be reshuffled: read the
stated policy and refuse where there is none, since no bytes should leave for a draft of
nothing; sanitise it (``sanitize_statement``); choose a saved config (``chosen_config``) and
judge its URL again; ask the gate (``require_ai``: the flag, the consent, one share-log row
naming the destination and ``policy_statement``, before the first byte); send the static
instructions and the statement and nothing else — never a device, never an app — and force
the reply into the rule vocabulary (``interpret``), where a number the statement's own words
do not state is dropped.

The answer is a draft and stays one. The page puts it in the editor's boxes; a rule exists
only when a person presses Confirm there, which is ``PUT /api/settings/patching-policy/rule``
and its audit line. Both routes ask for ``system:write``: the statement is sent off the pod
only by someone who could confirm what comes back.

The statement and the reply are never logged, audited or returned.
"""

from __future__ import annotations

import time
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.adapters import OUTCOME_ANSWERED, AdapterError, CompletionRequest, complete
from app.ai.changes_prompt import CALL_TIMEOUT_SECONDS
from app.ai.patch_policy_rules import (
    DISCLOSED_FIELDS,
    FEATURE,
    MAX_REPLY_TOKENS,
    NOT_A_PATCHING_POLICY,
    SYSTEM_INSTRUCTION,
    interpret,
    sanitize_statement,
)
from app.ai.providers import HostReach, Provider
from app.api.ai import judged_endpoint
from app.api.changes_prompt import chosen_config, prompt_status
from app.core.ai import AIRefused, require_ai
from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.models.schema import PatchingPolicy
from app.schemas.ai import AIErrorOut
from app.schemas.changes_prompt import PromptStatusOut
from app.schemas.settings import PatchRule

router = APIRouter(prefix="/api/settings/patching-policy/rule/draft", tags=["settings"])

# A test stands in for the endpoint by setting this; production leaves it None.
transport_override: httpx.AsyncBaseTransport | None = None

NO_STATEMENT = (
    "No patching policy is stated, so there is nothing to draft a rule from. State the policy on Devices › Applications › "
    "Jamf Patch first, or type the rule's limits yourself — a rule does not need a statement."
)
UNPARSEABLE = (
    "The model's answer was not a rule draft, so nothing was filled in. Type the rule's limits yourself, or draft again "
    "with another saved provider."
)
# One sentence for both ways a statement is found not to be a patching policy: the model's
# refusal, and the code's own check that the statement speaks of patching at all, in English.
NOT_A_POLICY = (
    "The stated policy does not read as being about keeping software up to date, so nothing was drafted. The draft reads "
    "English statements only. Check the statement on this page, or type the rule's limits yourself."
)


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class RuleDraftIn(_Base):
    # None asks the first saved config, in the Settings > AI cards' order.
    provider: Provider | None = None


class RuleDraftOut(_Base):
    # drafted (the boxes are filled, or left empty with the reason in `unsupported` and
    # `repairs`) | invalid (the statement is not a patching policy; `error` carries the
    # sentence) | error (the endpoint failed) | unparseable (it answered, but not with a draft)
    outcome: Literal["drafted", "invalid", "error", "unparseable"]
    # The draft, for the editor's boxes. Never saved here. A limit is null where the
    # statement states none — or where the model proposed a number the statement does not
    # state, which `repairs` then says.
    rule: PatchRule | None = None
    # What the limits cannot express about this statement, as codes the page words itself:
    # `hardware`, `os`, `apps`, `process` (the model's, each kept only where the statement
    # bears it out), and `severity` and `no_number` (code's own). No model-written text
    # reaches the page.
    cannot: list[Literal["severity", "hardware", "os", "apps", "process", "no_number"]] = Field(default_factory=list)
    repairs: list[str] = Field(default_factory=list)
    # Whether the statement was longer than what is sent, so the draft read only its start.
    truncated: bool = False
    provider: Provider
    model: str
    destination: str
    latency_ms: int
    error: AIErrorOut | None = None


@router.get("", response_model=PromptStatusOut, dependencies=[Depends(require(Permission.SYSTEM_WRITE))])
async def draft_status(db: AsyncSession = Depends(get_db)) -> PromptStatusOut:
    """Whether the Draft button is drawn: the flag, the consent, a saved config, in that
    order — slot 1's own reader, so no two AI surfaces disagree about which switch is off."""
    return await prompt_status(db)


def _audited(outcome: str, provider: Provider, destination: str, latency_ms: int, **metadata: object) -> None:
    """Who asked which provider, how it went and how long it took. Kinds and counts only:
    never the statement, never the reply, never a repair's words."""
    audit(
        AuditAction.AI_PATCH_POLICY_RULES, outcome=outcome, target_type="ai_endpoint",
        target_id=destination, provider=provider.value, latency_ms=latency_ms, **metadata,
    )  # fmt: skip


@router.post("", response_model=RuleDraftOut, dependencies=[Depends(require(Permission.SYSTEM_WRITE))])
async def draft(payload: RuleDraftIn, db: AsyncSession = Depends(get_db)) -> RuleDraftOut:
    stored = (await db.execute(select(PatchingPolicy.statement))).scalar_one_or_none()
    statement, truncated = sanitize_statement(stored or "")
    if not statement:
        raise HTTPException(status_code=409, detail=NO_STATEMENT)

    config = await chosen_config(db, payload.provider)
    provider, model, api_key = Provider(config.provider), config.model, config.api_key_encrypted
    reach = HostReach(config.host_reach) if config.host_reach else None
    wire, base_url, destination, host_header = await judged_endpoint(provider, reach, config.base_url, carries_key=bool(api_key))
    try:
        await require_ai(db, feature=FEATURE, destination=destination, fields=DISCLOSED_FIELDS, model=model)
    except AIRefused as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    request = CompletionRequest(
        serial=provider is Provider.apple_fm,
        base_url=base_url, model=model, prompt=statement, system=SYSTEM_INSTRUCTION, api_key=api_key,
        # Never for Apple, whatever the row holds: `fm serve` answers 400 to any effort on its
        # system model (slot 2's note, and its reason).
        reasoning_effort=None if provider is Provider.apple_fm else config.reasoning_effort,
        max_tokens=MAX_REPLY_TOKENS,
        # The same statement, the same draft.
        temperature=0, host_header=host_header,
    )  # fmt: skip
    answer = {"provider": provider, "model": model, "destination": destination, "truncated": truncated}
    started = time.monotonic()
    try:
        result = await complete(wire, request, transport=transport_override, timeout_seconds=CALL_TIMEOUT_SECONDS)
    except AdapterError as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        _audited("error", provider, destination, latency_ms, error_kind=exc.kind)
        error = AIErrorOut(kind=exc.kind, message=exc.message, status=exc.status)
        return RuleDraftOut(outcome="error", latency_ms=latency_ms, error=error, **answer)
    latency_ms = int((time.monotonic() - started) * 1000)

    reading = interpret(result.content, statement) if result.outcome == OUTCOME_ANSWERED else None
    if reading is None or not reading.parsed:
        kind = result.outcome if reading is None else "malformed"
        _audited("unparseable", provider, destination, latency_ms, error_kind=kind)
        error = AIErrorOut(kind=kind, message=UNPARSEABLE, status=None)
        return RuleDraftOut(outcome="unparseable", latency_ms=latency_ms, error=error, **answer)

    if reading.invalid:
        _audited("invalid", provider, destination, latency_ms, reason=reading.invalid)
        error = AIErrorOut(kind=NOT_A_PATCHING_POLICY, message=NOT_A_POLICY, status=None)
        return RuleDraftOut(outcome="invalid", latency_ms=latency_ms, error=error, **answer)

    _audited("drafted", provider, destination, latency_ms, repairs=len(reading.repairs), empty=reading.empty)
    return RuleDraftOut(
        outcome="drafted",
        rule=PatchRule(
            max_days_behind=reading.max_days_behind,
            max_releases_behind=reading.max_releases_behind,
            max_days_behind_severe=reading.max_days_behind_severe,
        ),
        cannot=reading.cannot,
        repairs=reading.repairs,
        latency_ms=latency_ms,
        **answer,
    )
