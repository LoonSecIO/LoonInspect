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
   device row — and the reply is forced into the page's vocabulary (``interpret``), which also
   reads a start out of the question's own words against this server's clock and the viewer's
   zone (#444); the model is never asked for one;
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
import re
import time
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.ai.adapters import OUTCOME_ANSWERED, AdapterError, CompletionRequest, complete
from app.ai.changes_prompt import (
    CALL_TIMEOUT_SECONDS,
    DISCLOSED_FIELDS,
    FEATURE,
    MAX_REPLY_TOKENS,
    NOT_ABOUT_CHANGES,
    SECTIONS,
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
from app.core.crypto import StoredValueUnknownKeyId, StoredValueUnreadable
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.sharing import get_or_create_settings
from app.mdm.org_units import DEPARTMENT, ids_for_name
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


async def chosen_config(db: AsyncSession, requested: Provider | None) -> AIProviderConfig:
    """The saved config to ask: the one named, or the first in the cards' order.

    The provider is settled from the listing, which never opens a key, before its row is
    loaded with the key decrypted. So a key this instance cannot read (a restore that
    brought the database and not its ENCRYPTION_KEY) is refused naming the card to
    re-enter it on, rather than as the generic 503 about every stored credential. A value
    carrying a key id this build does not know is a different failure with a different fix
    and keeps its own sentence (#480)."""
    provider = requested
    if provider is None:
        saved = await list_configs(db)
        if not saved:
            raise HTTPException(status_code=409, detail=NO_PROVIDER_SAVED)
        provider = Provider(saved[0].provider)
    try:
        config = await get_config(db, provider)
    except StoredValueUnknownKeyId:
        # Not a wrong key, so not this surface's sentence (#480): the row was written by a
        # newer build, and re-entering the key on the card would neither fix it nor be
        # needed. Left to `main.py`'s handler, which answers every surface the same way —
        # 503, the sentence naming the image, one log line.
        raise
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


# The dimensions the bar can set, and the page's words for them — the chips' labels, since
# none of them is a control on the page (#447).
PROMPT_DIMENSIONS: tuple[str, ...] = ("model", "os_version", "department", "managed")
_MODEL = "Model"
_OS_VERSION = "OS version"
_DEPARTMENT = "Department"
# A version an operator would type: digits and dots, so "26" and "26.6.2" are one, and
# "Sequoia" is not (the ledger stores numbers).
_VERSIONISH = re.compile(r"\d+(?:\.\d+)*")
# Two words for management state, and no list of synonyms: #442's lesson is that a word list
# over the *question* refuses real questions. This reads a value the model already chose.
_MANAGEMENT_WORDS = {"unmanaged": "false", "not managed": "false", "unenrolled": "false"}


# The words a question uses for a section. For one decision only: when a Filter-to-one-thing value
# is re-read as a department, the section the model chose beside it stays if the question named
# that section ("which apps changed in Finance") and goes if the model only guessed it from the
# misread ("What changed on Macs in Engineering : Product?" came back as Configuration profiles,
# because a profile is the kind of thing that has a name like that). Not a word list over the
# question that refuses anything (#442): it only decides whether to keep a value the model chose.
_SECTION_NAMED_BY: dict[str, tuple[str, ...]] = {
    "applications": ("app", "application"),
    "configuration_profiles": ("profile",),
    "group_memberships": ("group",),
    "local_user_accounts": ("account",),
    "certificates": ("certificate", "cert"),
    "extension_attributes": ("extension attribute", "attribute"),
    "software_updates": ("update",),
    "hardware": ("hardware",),
    "operating_system": ("os", "macos", "operating system"),
    "security": ("security",),
    "disk_encryption": ("filevault", "encryption"),
}
_SECTION_DISPLAY = {key: name for name, key in SECTIONS.items()}


def _question_names_section(question: str, section: str) -> bool:
    words = _SECTION_NAMED_BY.get(section, ())
    return any(re.search(rf"\b{re.escape(word)}s?\b", question, re.I) for word in words)


async def _one_department(db: AsyncSession, name: str) -> tuple[str, str] | None:
    """The department id a name means, as `(id, name)` — or None when no department has that name,
    or when two connections name different ids with it. The page's filter is an id, and it cannot
    say "5 on one Jamf and 12 on the other"; guessing one would narrow the answer silently."""
    pairs = await ids_for_name(db, kind=DEPARTMENT, name=name)
    ids = {external_id for _, external_id in pairs}
    if len(ids) != 1:
        return None
    (external_id,) = ids
    return external_id, name.strip()


async def _dimension_repair(
    db: AsyncSession, question: str, filters: dict[str, str | None], dimensions: dict[str, str | None]
) -> tuple[list[str], str | None]:
    """A value the model put in the wrong box, moved to the dimension it names (#447 ruling H4,
    #450). Mutates both dicts; returns the repairs, and the department's name when one was set,
    for the readback.

    The model's vocabulary is full — #443 measured a sixth reply field at 2 to 6 wrong answers
    of 68, and the injection refusal broke in every arrangement — so the dimensions are reached
    from the bar this way instead: the instructions do not change, and neither does their
    measurement.

    **Search.** Asked "which MacBook Airs installed Wireshark", the model puts "MacBook Air" in
    Search, where it matches no device name, no serial and no Jamf id. A device always wins: the
    first question is whether any change row names this device, because a Mac can be named after
    anything — "Kyle's Mac mini" is a device name, and so is a Mac named after its own
    department. Only a Search that matches no device is read as a dimension, in this order: the
    words for management state, a model, an OS version, a department from Jamf's own catalog.

    **Filter to one thing** (#450). Asked "What changed on Macs in Engineering : Product?", the
    model read the department as the name of a profile: Filter to one thing "Engineering :
    Product", Section Configuration profiles — zero rows, over a question the feed can answer. A
    thing always wins here the same way a device does: only a value no change row names is read
    as a department, and only when Jamf's catalog holds exactly that name. The section the model
    chose beside it goes too, unless the question named that section itself, because the model
    only chose it from the misread. Both moves are one correction of one reading, so the answer
    runs on Enter rather than waiting for Apply (Kyle, 2026-09-16).

    Names are matched exactly, case aside (`app.mdm.org_units.ids_for_name`), and a department
    name that cached catalog no longer holds — the API client lost "Read Departments", and its
    names were cleared — moves nothing.

    Cost: one EXISTS read to settle the device or the thing, then up to three more on a miss, two
    of them over `device_meta` with no index (the trade `change_conditions` records for
    `artifact`). They run only after a miss, behind a model call that already cost a second.
    """

    async def matches(**where: str | None) -> bool:
        return (await db.execute(select(literal(1)).where(*change_conditions(**where)).limit(1))).scalar() is not None

    search = filters.get("q")
    if search and not await matches(q=search):
        word = search.strip().lower()
        if word in _MANAGEMENT_WORDS:
            filters["q"], dimensions["managed"] = None, _MANAGEMENT_WORDS[word]
            return [f"Read “{search}” as Macs Jamf does not manage: it names no device."], None
        if await matches(model=search):
            filters["q"], dimensions["model"] = None, search
            return [f"Read “{search}” as {_MODEL}: it names no device, and it does name a Mac's model."], None
        if _VERSIONISH.fullmatch(word) and await matches(os_version=search):
            filters["q"], dimensions["os_version"] = None, search
            return [f"Read “{search}” as {_OS_VERSION}: it names no device, and Macs were observed on it."], None
        unit = await _one_department(db, search)
        if unit is not None:
            filters["q"], dimensions["department"] = None, unit[0]
            return [f"Read “{search}” as {_DEPARTMENT} {unit[1]}, Jamf's department {unit[0]}: it names no device."], unit[1]

    artifact = filters.get("artifact")
    if artifact and not await matches(artifact=artifact):
        unit = await _one_department(db, artifact)
        if unit is not None:
            filters["artifact"], dimensions["department"] = None, unit[0]
            repairs = [
                f"Read “{artifact}” as {_DEPARTMENT} {unit[1]}, Jamf's department {unit[0]}: "
                "no app, profile, group or account has that name."
            ]
            section = filters.get("section")
            if section and not _question_names_section(question, section):
                filters["section"] = None
                repairs.append(
                    f"Cleared Section {_SECTION_DISPLAY.get(section, section)}: the model chose it because it read “{artifact}” "
                    "as the name of one, and the question does not ask about it."
                )
            return repairs, unit[1]
    return [], None


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


async def _summary(
    db: AsyncSession, filters: dict[str, str | None], dimensions: dict[str, str | None], since: datetime | None = None
) -> PromptSummaryOut:
    """What the page will show for ``filters``: the rows, the computers among them, newest
    first, and when they were observed. Three scans, whatever the fleet's size.

    ``dimensions`` are the stamped ones a repair moved a Search value into (#447) and ``since``
    the start the question's own words asked for (#444), counted here for the same reason every
    other filter is: the numbers in the box are the page's numbers."""
    conditions = change_conditions(
        q=filters["q"],
        artifact=filters["artifact"],
        level=filters["level"],
        section=filters["section"],
        change=filters["change"],
        since=since,
        **dimensions,
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

    config = await chosen_config(db, payload.provider)
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

    # The clock is this server's and the zone the browser's: between them a question's own words
    # may set a start (#444). The model is not asked for one and never sees either.
    answered = result.outcome == OUTCOME_ANSWERED
    interpretation = interpret(question, result.content, datetime.now(UTC), payload.zone) if answered else None
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
    # A Search the fleet has no device for, but does have a model, an OS version, a department
    # or a management state for, is read as that instead (#447). It narrows what would otherwise
    # have matched nothing, so it does not hold the answer back for an Apply.
    dimensions: dict[str, str | None] = dict.fromkeys(PROMPT_DIMENSIONS)
    moved, department_name = await _dimension_repair(db, question, interpretation.filters, dimensions)
    repairs = [str(repair) for repair in interpretation.repairs] + moved
    since = interpretation.since_asked
    summary = await _summary(db, interpretation.filters, dimensions, since.at if since else None)
    _audited(outcome, provider, destination, latency_ms, repairs=len(repairs), window=since is not None)
    return PromptOut(
        outcome=outcome,
        filters=PromptFiltersOut(**interpretation.filters, **dimensions, department_name=department_name),
        unsupported=interpretation.unsupported,
        # Plain strings on the wire: each repair is a `Repair`, a str carrying its direction.
        repairs=repairs,
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
