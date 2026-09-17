"""The Vulnerabilities page's AI lever (#534): a question in; that page's own filters out,
with the count `GET /api/catalog` will answer with when they run.

Slot 2. The order is slot 1's (``app.api.changes_prompt``) and is not to be reshuffled:
sanitise the question (``sanitize_question``, shared) and refuse an empty one; refuse before
dialling where no corpus answers for this organization, since the list itself answers 409 and
no bytes should leave for a question that has no answer to reach; choose a saved config
(``chosen_config``) and judge its URL again; ask the gate (``require_ai``: the flag, the
consent, one share-log row naming the destination and ``query_text``, before the first byte);
send the static instructions and the question and nothing else — never a build, never a
finding — and force the reply into this page's vocabulary (``interpret``); then count by
calling ``list_catalog`` itself, so the number the box states is the number the list then
shows: not the same WHERE clause, the same code.

The three dispositions carry over unchanged. ``applied`` runs on Enter (ruling 2).
``proposed`` is one a repair widened: the same filters and count, shown beside *Apply these
filters*, running nothing until it is pressed (ruling 9). ``invalid`` is text the model judged
not a question about this list — a question about Macs, departments or sites among it, which
the device list answers and this page cannot (``NOT_ABOUT_VULNERABILITIES``).

The question and the reply are never logged, audited or returned. Viewers hold ``vuln:read``
and the lever is theirs, so both routes ask for exactly that; every role holding it holds
``app:read`` too (``_INVENTORY_READ``), which is what the count below reads under.
"""

from __future__ import annotations

import time
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.adapters import OUTCOME_ANSWERED, AdapterError, CompletionRequest, complete
from app.ai.changes_prompt import CALL_TIMEOUT_SECONDS, MAX_REPLY_TOKENS, sanitize_question
from app.ai.providers import HostReach, Provider
from app.ai.vulnerabilities_prompt import (
    DISCLOSED_FIELDS,
    FEATURE,
    NOT_ABOUT_VULNERABILITIES,
    SYSTEM_INSTRUCTION,
    interpret,
)
from app.api.ai import judged_endpoint
from app.api.catalog import list_catalog
from app.api.changes_prompt import EMPTY_QUESTION, ONLY_REMOVED, QUESTION_TOO_LONG, UNPARSEABLE, chosen_config, prompt_status
from app.core.ai import AIRefused, require_ai
from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.vuln_library import earned_corpus
from app.core.vuln_read import NO_ANSWER
from app.schemas.ai import AIErrorOut
from app.schemas.changes_prompt import QUESTION_MAX_LENGTH, PromptIn, PromptStatusOut

router = APIRouter(prefix="/api/vulnerabilities/prompt", tags=["vulnerabilities"])


class _Base(BaseModel):
    """The answer's shape, beside the route as the sibling module `app.api.vulnerabilities`
    keeps its own (#533). Slot 1's request and status shapes are reused as they stand
    (`app.schemas.changes_prompt`): only the answer is this page's."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class VulnPromptFiltersOut(_Base):
    """The page's own URL keys. `vuln` and `order` are always set — the page has no *all*
    state and no unordered list — and `band` is None for every severity."""

    q: str | None
    vuln: Literal["findings", "kev", "unknown_app", "clean", "patchable"]
    band: Literal["critical", "high", "medium", "low"] | None
    order: Literal["exposure", "age", "payoff"]


class VulnPromptSummaryOut(_Base):
    """What the page will show, counted by `GET /api/catalog` itself: the one number in the
    answer, and never the model's."""

    total: int


class VulnPromptOut(_Base):
    # applied (the page runs the filters) | proposed (a repair widened the answer, so a person
    # applies it; ruling 9) | invalid (not a question these filters answer, so nothing runs;
    # `error` carries the reason and the page's sentence) | error (the endpoint failed) |
    # unparseable (it answered, but not with filters)
    outcome: Literal["applied", "proposed", "invalid", "error", "unparseable"]
    filters: VulnPromptFiltersOut | None
    # The model's own note on what the filters cannot express: the only model-written text
    # that reaches the page, which renders it as text.
    unsupported: str | None
    repairs: list[str]
    # The repairs, of those above, that widened the answer: non-empty exactly when the outcome
    # is `proposed`, and the page's reason for not running the filters.
    widening: list[str] = Field(default_factory=list)
    summary: VulnPromptSummaryOut | None
    provider: Provider
    model: str
    destination: str
    latency_ms: int
    error: AIErrorOut | None = None


# A test stands in for the endpoint by setting this; production leaves it None.
transport_override: httpx.AsyncBaseTransport | None = None

# The model judged the text not a question about this list. The sentence names the page that
# does answer a question about Macs, because that is the near miss worth naming: the lever
# sits on a list of builds, and *which Macs have Chrome* is a real question elsewhere.
NOT_A_VULN_QUESTION = (
    "The model judged this not a question about the builds on this page, so nothing was run: the AI lever only sets "
    "this page's filters. Ask which apps carry findings, which are on CISA KEV, which are outside the corpus, or what "
    "to patch first. A question about Macs, departments or sites is answered by the device list under Devices, not "
    "here — this page answers per build, never per Mac."
)


@router.get("", response_model=PromptStatusOut, dependencies=[Depends(require(Permission.VULN_READ))])
async def lever_status(db: AsyncSession = Depends(get_db)) -> PromptStatusOut:
    """Whether the lever is drawn: the flag, the consent, a saved config, in that order —
    slot 1's own reader, called rather than copied, so the two bars can never disagree about
    which switch is off. Absent means no lever at all and a plain search box."""
    return await prompt_status(db)


def _answer(outcome: str, provider: Provider, model: str, destination: str, latency_ms: int, **rest: object) -> VulnPromptOut:
    """Every outcome answers with the same shape: which endpoint was asked and how long it
    took, stated even where there are no filters, since the page names it either way."""
    fields: dict[str, object] = {
        "filters": None, "unsupported": None, "repairs": [], "widening": [], "summary": None, "error": None,
    }  # fmt: skip
    return VulnPromptOut(
        outcome=outcome, provider=provider, model=model, destination=destination, latency_ms=latency_ms, **(fields | rest)
    )


def _audited(outcome: str, provider: Provider, destination: str, latency_ms: int, **metadata: object) -> None:
    """Who asked which provider, how it went and how long it took. Counts and kinds only:
    never the question, never the reply, never a repair's words."""
    audit(
        AuditAction.AI_VULNERABILITIES_PROMPT, outcome=outcome, target_type="ai_endpoint",
        target_id=destination, provider=provider.value, latency_ms=latency_ms, **metadata,
    )  # fmt: skip


@router.post("", response_model=VulnPromptOut, dependencies=[Depends(require(Permission.VULN_READ))])
async def ask(payload: PromptIn, db: AsyncSession = Depends(get_db)) -> VulnPromptOut:
    if len(payload.question) > QUESTION_MAX_LENGTH:
        raise HTTPException(status_code=422, detail=QUESTION_TOO_LONG)
    question = sanitize_question(payload.question)
    if not question:
        raise HTTPException(status_code=422, detail=ONLY_REMOVED if payload.question.strip() else EMPTY_QUESTION)
    # Before the gate and before the dial: with no corpus answering here there is no list to
    # filter, the count below would raise, and a question would have left the pod for nothing.
    if (await earned_corpus(db)).as_of is None:
        raise HTTPException(status_code=409, detail=NO_ANSWER)

    config = await chosen_config(db, payload.provider)
    provider, model, api_key = Provider(config.provider), config.model, config.api_key_encrypted
    reach = HostReach(config.host_reach) if config.host_reach else None
    wire, base_url, destination, host_header = await judged_endpoint(provider, reach, config.base_url, carries_key=bool(api_key))
    try:
        await require_ai(db, feature=FEATURE, destination=destination, fields=DISCLOSED_FIELDS)
    except AIRefused as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    request = CompletionRequest(
        base_url=base_url, model=model, prompt=question, system=SYSTEM_INSTRUCTION, api_key=api_key,
        # Never for Apple, whatever the row holds: `fm serve` answers 400 to any effort on its
        # system model, and a row saved before Save refused one would fail every question.
        reasoning_effort=None if provider is Provider.apple_fm else config.reasoning_effort,
        max_tokens=MAX_REPLY_TOKENS,
        # The same question, the same filters: an answer that moved between two asks would
        # make the lever a slot machine.
        temperature=0, host_header=host_header,
    )  # fmt: skip
    started = time.monotonic()
    try:
        result = await complete(wire, request, transport=transport_override, timeout_seconds=CALL_TIMEOUT_SECONDS)
    except AdapterError as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        _audited("error", provider, destination, latency_ms, error_kind=exc.kind)
        error = AIErrorOut(kind=exc.kind, message=exc.message, status=exc.status)
        return _answer("error", provider, model, destination, latency_ms, error=error)
    latency_ms = int((time.monotonic() - started) * 1000)

    reading = interpret(result.content) if result.outcome == OUTCOME_ANSWERED else None
    if reading is None or not reading.parsed:
        kind = result.outcome if reading is None else "malformed"
        _audited("unparseable", provider, destination, latency_ms, error_kind=kind)
        error = AIErrorOut(kind=kind, message=UNPARSEABLE, status=None)
        return _answer("unparseable", provider, model, destination, latency_ms, error=error)

    if reading.invalid:
        # No filters and no count: there is nothing to count for, and nothing will run.
        _audited("invalid", provider, destination, latency_ms, reason=reading.invalid)
        error = AIErrorOut(kind=NOT_ABOUT_VULNERABILITIES, message=NOT_A_VULN_QUESTION, status=None)
        return _answer("invalid", provider, model, destination, latency_ms, error=error)

    outcome = "proposed" if reading.widened else "applied"
    filters = reading.filters
    # The list's own function, not a second copy of its WHERE, one row deep. Every argument by
    # name, none left to default: those defaults are FastAPI `Query` objects, which only a
    # request resolves — `app_hash` left out would reach the WHERE as one.
    listed = await list_catalog(
        db, q=filters["q"], jamf="all", installed_only=True, app_hash=None,
        vuln=filters["vuln"], band=filters["band"], order=filters["order"], page=1, page_size=1,
    )  # fmt: skip
    repairs = [str(repair) for repair in reading.repairs]
    _audited(outcome, provider, destination, latency_ms, repairs=len(repairs))
    return _answer(
        outcome, provider, model, destination, latency_ms,
        filters=VulnPromptFiltersOut(**filters), unsupported=reading.unsupported,
        repairs=repairs, widening=reading.widening, summary=VulnPromptSummaryOut(total=listed.total),
    )  # fmt: skip
