"""The Changes page's Prompt bar (2026-09-14): a question in; the page's own filters out,
with a summary of what they match, counted by Postgres.

The order is the test box's (app.api.ai), and is not to be reshuffled:

1. the question is sanitised (``sanitize_question``), and an empty one is refused;
2. a saved config is chosen — the one asked for, or the first in the Settings > AI
   cards' order — and its URL is judged again (``judged_endpoint``), because what a
   name resolves to can change after it was saved;
3. the gate is asked (``require_ai``: the flag, the consent, and one share-log row
   naming the destination and ``query_text``, committed before the first byte);
4. the static instructions and the question go to the endpoint — nothing else, never a
   device row — and the reply is forced into the page's vocabulary (``interpret``);
5. the summary is counted with the page's own WHERE clause (``change_conditions``), so
   the numbers the response box states are the numbers the page then shows.

An answer the page may run is ``applied``. One that a repair widened (a name dropped, an
unknown section, level or change read as any, an unknown key with a value ignored) is
``proposed``: the same filters and summary, which the page shows beside an Apply button
instead of running (Kyle, 2026-09-15, ruling 1C on #436). Text the model judged not a
question about device changes is ``invalid``: no filters, no summary, and the page's own
sentence for why (``INVALID_SENTENCES``), so nothing runs (Kyle, 2026-09-15: "What model
are you?" had listed every device).

The question and the reply are never logged, audited or returned: the audit row says
which provider was asked, how it went, how long it took and how many repairs were made.
The only model-written text in the response is ``unsupported``, and the page renders it
as text. Viewers hold ``device:read`` and nothing else, and the bar is theirs too, so
both routes ask for exactly that.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.ai.adapters import OUTCOME_ANSWERED, AdapterError, CompletionRequest, complete
from app.ai.changes_prompt import (
    CALL_TIMEOUT_SECONDS,
    DISCLOSED_FIELDS,
    FEATURE,
    MAX_REPLY_TOKENS,
    NOT_ABOUT_CHANGES,
    SYSTEM_INSTRUCTION,
    interpret,
    sanitize_question,
)
from app.ai.providers import HostReach, Provider
from app.api.ai import CARD_LABELS, judged_endpoint
from app.api.changes import CHANGE_KINDS, change_conditions
from app.core.ai import AIRefused, ai_features_enabled, require_ai
from app.core.ai_configs import get_config, list_configs
from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.crypto import StoredValueUnreadable
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.sharing import get_or_create_settings
from app.models.schema import AIProviderConfig, DeviceChange, ObservationSpan
from app.schemas.ai import AIErrorOut
from app.schemas.changes_prompt import (
    QUESTION_MAX_LENGTH,
    PromptDeviceOut,
    PromptFiltersOut,
    PromptIn,
    PromptOut,
    PromptProviderOut,
    PromptStatusOut,
    PromptSummaryOut,
    PromptWhenOut,
)

router = APIRouter(prefix="/api/changes/prompt", tags=["changes"])
logger = logging.getLogger(__name__)

# A test stands in for the endpoint by setting this; production leaves it None.
transport_override: httpx.AsyncBaseTransport | None = None

# The response box lists the newest devices, and says how many more there are.
SUMMARY_DEVICES = 25

# What failed, why, and what to check (docs/diagnosability.md rule 3).
EMPTY_QUESTION = "Type a question first."
# Visible text that sanitising removed entirely: say why, or the operator sees their typing
# called empty.
ONLY_REMOVED = (
    "The question held only what the Prompt bar removes before sending: model control tokens such "
    "as <|im_start|> or [INST], or invisible characters. Type the question in words."
)
QUESTION_TOO_LONG = f"The question is longer than the {QUESTION_MAX_LENGTH:,} characters the Prompt bar reads. Shorten it."
NO_PROVIDER_SAVED = "No AI provider is saved. An admin saves one in Settings › AI; then the Prompt bar can use it."
UNPARSEABLE = (
    "The model's answer was not the filter settings the Prompt bar needs. Rephrase the question, or use the filters directly."
)
# The model judged the text not a question about device changes: a greeting, a question
# about the model, general knowledge, writing, or an order to do something. What the bar
# can do instead, in words an operator acts on; never the question's words.
NOT_A_CHANGES_QUESTION = (
    "The model judged this not a question about what changed on your devices, so nothing was run: the Prompt bar "
    "only reads the change log. Ask which Macs installed, removed or updated something, or what changed on one Mac. "
    "If it was such a question, word it around the change, or set the filters by hand."
)
INVALID_SENTENCES = {NOT_ABOUT_CHANGES: NOT_A_CHANGES_QUESTION}


def key_unreadable(provider: Provider) -> str:
    # Whoever asked may be a viewer, so the sentence names who acts, not "you".
    return (
        f"The API key saved on the {CARD_LABELS[provider]} card cannot be read: this server's ENCRYPTION_KEY is not "
        "the one it was saved under. An admin re-enters the key on that card in Settings › AI and saves it, or "
        "restores the original ENCRYPTION_KEY (docs/operations.md §1)."
    )


def not_saved(provider: Provider) -> str:
    return f"The {CARD_LABELS[provider]} card is not saved in Settings › AI. An admin saves it there."


@router.get(
    "",
    response_model=PromptStatusOut,
    dependencies=[Depends(require(Permission.DEVICE_READ))],
)
async def prompt_status(db: AsyncSession = Depends(get_db)) -> PromptStatusOut:
    """Whether the bar is shown: the flag, the consent, a saved config, in that order.
    Asked here rather than pieced together by the page, because a viewer can read the
    consent and the configs nowhere else."""
    configs = await list_configs(db)
    reason = None
    if not await ai_features_enabled(db):
        reason = "flag_off"
    elif not (await get_or_create_settings(db)).ai_inference:
        reason = "consent_off"
    elif not configs:
        reason = "no_provider"
    return PromptStatusOut(
        available=reason is None,
        reason=reason,
        providers=[PromptProviderOut(provider=c.provider, model=c.model) for c in configs],
    )


async def _chosen(db: AsyncSession, requested: Provider | None) -> AIProviderConfig:
    """The saved config to ask: the one named, or the first in the cards' order.

    The provider is settled from the listing, which never opens a key, before its row is
    loaded with the key decrypted. So a key this instance cannot read (a restore that
    brought the database and not its ENCRYPTION_KEY) is refused naming the card to
    re-enter it on, rather than as the generic 503 about every stored credential."""
    provider = requested
    if provider is None:
        saved = await list_configs(db)
        if not saved:
            raise HTTPException(status_code=409, detail=NO_PROVIDER_SAVED)
        provider = Provider(saved[0].provider)
    try:
        config = await get_config(db, provider)
    except StoredValueUnreadable as exc:
        # Caught here, so main.py's handler never logs it: the container log is where a
        # wrong ENCRYPTION_KEY is announced (docs/diagnosability.md §4), so say it here.
        logger.warning(
            "the saved %s API key cannot be read with this ENCRYPTION_KEY; an admin re-enters it on "
            "Settings › AI, or the original ENCRYPTION_KEY is restored (docs/operations.md §1)",
            CARD_LABELS[provider],
        )
        raise HTTPException(status_code=503, detail=key_unreadable(provider)) from exc
    if config is None:
        raise HTTPException(status_code=409, detail=not_saved(provider))
    return config


async def _when(db: AsyncSession, conditions: list, oldest: datetime) -> PromptWhenOut:
    """The newest matching change's own times, and the ones of the observation it moved away
    from: the window it happened in (ruling R1 on #443). One indexed row — the same
    `observed_at desc, id desc` the feed's first row is — and a join to the earlier span.

    The span may be gone (``ON DELETE SET NULL``), and then there is no lower bound to state
    rather than a guessed one."""
    previous = aliased(ObservationSpan)
    row = (
        await db.execute(
            select(
                DeviceChange.observed_at,
                DeviceChange.collected_at,
                previous.last_observed_at,
                previous.last_collected_at,
            )
            .outerjoin(previous, previous.id == DeviceChange.previous_span_id)
            .where(*conditions)
            .order_by(DeviceChange.observed_at.desc(), DeviceChange.id.desc())
            .limit(1)
        )
    ).one()
    observed_at, collected_at, previous_observed_at, previous_collected_at = row
    return PromptWhenOut(
        observed_at=observed_at,
        oldest_observed_at=oldest,
        collected_at=collected_at,
        previous_observed_at=previous_observed_at,
        previous_collected_at=previous_collected_at,
        device_time_moved=previous_observed_at is not None and previous_observed_at < observed_at,
    )


async def _summary(db: AsyncSession, filters: dict[str, str | None]) -> PromptSummaryOut:
    """What the page will show for ``filters``: the rows, the computers among them, newest
    first, and when they were observed. Three scans, whatever the fleet's size."""
    conditions = change_conditions(
        q=filters["q"],
        artifact=filters["artifact"],
        level=filters["level"],
        section=filters["section"],
        change=filters["change"],
    )
    is_computer = DeviceChange.subject_kind == "computer"

    total, other_subjects, oldest = (
        await db.execute(
            select(func.count(), func.count().filter(~is_computer), func.min(DeviceChange.observed_at))
            .select_from(DeviceChange)
            .where(*conditions)
        )
    ).one()

    # Grouped by the Jamf id per connection, not by name: a renamed Mac is one device
    # with two labels. `count(*) OVER ()` is evaluated before the LIMIT, so it is every
    # matching computer, not the 25 listed.
    rows = (
        await db.execute(
            select(
                DeviceChange.mdm_connection_id,
                DeviceChange.subject_id,
                func.max(DeviceChange.subject_label),
                func.max(DeviceChange.serial_number),
                # The ordering column, kept: the line says when this Mac's newest one was seen.
                func.max(DeviceChange.observed_at),
                *(func.count().filter(DeviceChange.change == kind) for kind in CHANGE_KINDS),
                func.count().over(),
            )
            .where(*conditions, is_computer)
            .group_by(DeviceChange.mdm_connection_id, DeviceChange.subject_id)
            .order_by(func.max(DeviceChange.observed_at).desc(), DeviceChange.mdm_connection_id, DeviceChange.subject_id)
            .limit(SUMMARY_DEVICES)
        )
    ).all()
    devices_total = rows[0][-1] if rows else 0
    return PromptSummaryOut(
        total=total,
        devices_total=devices_total,
        truncated=devices_total > len(rows),
        other_subjects=other_subjects,
        devices=[
            PromptDeviceOut(
                connection_id=connection_id,
                subject_id=subject_id,
                label=label,
                serial=serial,
                last_observed_at=last_observed_at,
                added=added,
                removed=removed,
                updated=updated,
                changed=changed,
            )
            for connection_id, subject_id, label, serial, last_observed_at, added, removed, updated, changed, _ in rows
        ],
        # Nothing matched, nothing was observed: the box says "No changes match." and no time.
        when=await _when(db, conditions, oldest) if total else None,
    )


@router.post(
    "",
    response_model=PromptOut,
    dependencies=[Depends(require(Permission.DEVICE_READ))],
)
async def ask(payload: PromptIn, db: AsyncSession = Depends(get_db)) -> PromptOut:
    # Bounded here rather than by the schema, for the sentences (PromptIn).
    if len(payload.question) > QUESTION_MAX_LENGTH:
        raise HTTPException(status_code=422, detail=QUESTION_TOO_LONG)
    question = sanitize_question(payload.question)
    if not question:
        raise HTTPException(status_code=422, detail=ONLY_REMOVED if payload.question.strip() else EMPTY_QUESTION)

    config = await _chosen(db, payload.provider)
    provider = Provider(config.provider)
    model = config.model
    api_key = config.api_key_encrypted
    wire, base_url, destination, host_header = await judged_endpoint(
        provider,
        HostReach(config.host_reach) if config.host_reach else None,
        config.base_url,
        carries_key=bool(api_key),
    )

    # The gate, before anything is dialled. Its refusals are the operator's switches, so
    # they answer 409 with the gate's own sentence.
    try:
        await require_ai(db, feature=FEATURE, destination=destination, fields=DISCLOSED_FIELDS)
    except AIRefused as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    request = CompletionRequest(
        base_url=base_url,
        model=model,
        prompt=question,
        system=SYSTEM_INSTRUCTION,
        api_key=api_key,
        # Never for Apple, whatever the row holds. `fm serve` answers 400 to any
        # reasoning effort on its system model, and a Save now refuses one
        # (app.api.ai.APPLE_FM_TAKES_NO_EFFORT); but a row saved before it did would
        # otherwise fail every question here until an admin opened the card and saved again.
        reasoning_effort=None if provider is Provider.apple_fm else config.reasoning_effort,
        max_tokens=MAX_REPLY_TOKENS,
        # The same question, the same filters: an answer that moves between two asks
        # would make the bar a slot machine.
        temperature=0,
        host_header=host_header,
    )

    started = time.monotonic()
    try:
        result = await complete(wire, request, transport=transport_override, timeout_seconds=CALL_TIMEOUT_SECONDS)
    except AdapterError as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        _audited("error", provider, destination, latency_ms, error_kind=exc.kind)
        return PromptOut(
            outcome="error",
            filters=None,
            unsupported=None,
            repairs=[],
            summary=None,
            provider=provider,
            model=model,
            destination=destination,
            latency_ms=latency_ms,
            error=AIErrorOut(kind=exc.kind, message=exc.message, status=exc.status),
        )
    latency_ms = int((time.monotonic() - started) * 1000)

    interpretation = interpret(question, result.content) if result.outcome == OUTCOME_ANSWERED else None
    if interpretation is None or not interpretation.parsed:
        # empty | budget_exhausted_thinking from the adapter, or an answer holding no
        # filter object: either way nothing is applied, and the page keeps its filters.
        kind = result.outcome if interpretation is None else "malformed"
        _audited("unparseable", provider, destination, latency_ms, error_kind=kind)
        return PromptOut(
            outcome="unparseable",
            filters=None,
            unsupported=None,
            repairs=[],
            summary=None,
            provider=provider,
            model=model,
            destination=destination,
            latency_ms=latency_ms,
            error=AIErrorOut(kind=kind, message=UNPARSEABLE, status=None),
        )

    # Not a question the filters can answer. Before this, "What model are you?" came back
    # as every control unset, which is the whole log, and the page listed every device. No
    # summary is counted: there are no filters to count for, and nothing will run.
    if interpretation.invalid:
        _audited("invalid", provider, destination, latency_ms, reason=interpretation.invalid)
        return PromptOut(
            outcome="invalid",
            filters=None,
            unsupported=None,
            repairs=[],
            summary=None,
            provider=provider,
            model=model,
            destination=destination,
            latency_ms=latency_ms,
            error=AIErrorOut(kind=interpretation.invalid, message=INVALID_SENTENCES[interpretation.invalid], status=None),
        )

    # A widened answer searches for more than the model's did, so a person applies it: the
    # page gets the same filters and summary as an applied one, and runs nothing until then.
    outcome = "proposed" if interpretation.widened else "applied"
    summary = await _summary(db, interpretation.filters)
    _audited(outcome, provider, destination, latency_ms, repairs=len(interpretation.repairs))
    return PromptOut(
        outcome=outcome,
        filters=PromptFiltersOut(**interpretation.filters),
        unsupported=interpretation.unsupported,
        # Plain strings on the wire: each repair is a `Repair`, a str carrying its direction.
        repairs=[str(repair) for repair in interpretation.repairs],
        widening=interpretation.widening,
        summary=summary,
        provider=provider,
        model=model,
        destination=destination,
        latency_ms=latency_ms,
    )


def _audited(outcome: str, provider: Provider, destination: str, latency_ms: int, **metadata: object) -> None:
    """Who asked which provider, how it went and how long it took. Counts and kinds
    only: never the question, never the reply, never a repair's words."""
    audit(
        AuditAction.AI_CHANGES_PROMPT,
        outcome=outcome,
        target_type="ai_endpoint",
        target_id=destination,
        provider=provider.value,
        latency_ms=latency_ms,
        **metadata,
    )
