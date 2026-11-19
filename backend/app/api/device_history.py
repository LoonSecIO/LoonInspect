"""Bounded device history and up to twenty user/tenant slots; this read never invokes inference (#605)."""

import json
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import String, case, cast, exists, func, literal, select, tuple_, union_all
from sqlalchemy.dialects.postgresql import insert

from app.changes.derive import load_policy
from app.changes.policy import ENTRY_RULES, FIELD_RULES, is_system_app
from app.core.ai import ai_features_enabled
from app.core.auth import Principal, current_principal, require
from app.core.database import get_db
from app.core.permissions import Permission
from app.models.schema import Device, InventorySummarySettings, ObservationEntry, ObservationSection
from app.models.schema import DeviceHistoryPoint as Point
from app.models.schema import DeviceHistoryPreference as Preference
from app.models.schema import ObservationSpan as Span
from app.observations.read import aperture_sections
from app.summaries.evidence import digest

router = APIRouter(prefix="/api/devices", tags=["device history"], dependencies=[Depends(require(Permission.DEVICE_READ))])
DEFAULTS = [
    "operating_system.version",
    "applications.count",
    "findings.total",
    "findings.critical",
    "disk_encryption.fileVault2Enabled",
    "security.firewallEnabled",
]
SCAN = 200  # The most earlier states one previous-value lookup reads, however long the history grows (#617).


class Selection(BaseModel):
    slots: list[str] = Field(max_length=20)
    point: str | None = Field(default=None, max_length=40)


async def device_for(db, device_id):
    device = await db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "Device not found")
    return device


def points_query(device):
    scope = [
        Span.mdm_connection_id == device.mdm_connection_id,
        Span.subject_kind == "computer",
        Span.subject_id == device.external_id,
    ]
    # Legacy inventory states remain readable without inventing past assessments.
    legacy = select(
        (literal("s:") + cast(Span.id, String)).label("key"),
        Span.id.label("span_id"),
        Span.first_observed_at.label("observed_at"),
        Span.first_collected_at.label("collected_at"),
        literal("inventory").label("kind"),
    ).where(*scope, ~exists(select(Point.id).where(Point.span_id == Span.id)))
    recorded = select(
        (literal("p:") + cast(Point.id, String)).label("key"),
        Point.span_id,
        Point.observed_at,
        Point.collected_at,
        case((Point.source_id.is_(None), "assessment"), else_="inventory").label("kind"),
    ).where(Point.device_id == device.id)
    return union_all(legacy, recorded).subquery()


def place(query, row, key):
    """A state's place in the timeline's one total order: (the columns, this state's values)."""
    return tuple_(query.c.observed_at, query.c.collected_at, query.c.key), tuple_(row["observed_at"], row["collected_at"], key)


async def point_for(db, device, key):
    query = points_query(device)
    row = (await db.execute(select(query).where(query.c.key == key))).mappings().first()
    if row is None:
        raise HTTPException(404, "Recorded observation not found for this device")
    span = await db.get(Span, row["span_id"])
    point = await db.get(Point, uuid.UUID(key[2:])) if key.startswith("p:") else None
    return row, span, point


async def documents(db, span, only=None, entries=None):
    """Each section's document; `only` reads one section, and `entries` keeps entry rows across calls (#617)."""
    if not span:
        return {}
    digests = [digest for name, digest in span.section_digests.items() if only in (None, name)]
    sections = (await db.scalars(select(ObservationSection).where(ObservationSection.digest.in_(digests)))).all()
    entries = {} if entries is None else entries
    entry_ids = {d for section in sections for d in (section.entry_digests or [])} - entries.keys()
    entries |= (
        {e.digest: e for e in (await db.scalars(select(ObservationEntry).where(ObservationEntry.digest.in_(entry_ids)))).all()}
        if entry_ids
        else {}
    )
    return {
        s.section: (
            dict(s.body or {})
            if s.entry_digests is None
            else [{**entries[d].body, "_label": entries[d].label} for d in s.entry_digests if d in entries]
        )
        for s in sections
    }


def path_value(body, path):
    for part in path.split("."):
        if not isinstance(body, dict) or part not in body:
            return None
        body = body[part]
    return body


def eligible(choice, policy):
    if choice["key"] == "observation.lastCheckIn":
        return True  # Observation context requested explicitly; not a change-log event.
    kind = choice.get("kind")
    if kind:
        if kind == "application" and choice.get("system") and not policy.system_apps_individually:
            return False
        if kind == "extension_attribute" and policy.extension_attribute_muted(choice["identity"].get("definitionId")):
            return False
        if kind == "group_membership" and policy.group_muted(choice["identity"].get("groupId")):
            return False
        return policy.entry_enabled(kind, "updated", choice["field"])
    if choice["key"] in ("applications.count", "findings.total", "findings.critical"):
        return all(policy.entry_enabled("application", op) for op in ("added", "removed"))
    return policy.field_enabled(choice["section"], choice["field"])


def choices_for(docs, policy, connection_id):
    choices = {}
    choices["observation.lastCheckIn"] = {
        "key": "observation.lastCheckIn",
        "label": "Last check-in",
        "section": "general",
        "field": "lastCheckIn",
    }
    for rule in FIELD_RULES:
        if rule.section == "definition":
            continue
        choices[rule.key] = {"key": rule.key, "label": rule.label, "section": rule.section, "field": rule.field}
    for key, label in (
        ("applications.count", "Applications"),
        ("findings.total", "Open vulnerability findings"),
        ("findings.critical", "Critical findings"),
    ):
        choices[key] = {"key": key, "label": label, "section": "applications", "field": key.split(".")[1]}
    for rule in ENTRY_RULES:
        for body in docs.get(rule.section, []):
            identity = {k: body.get(k) for k in rule.identity}
            # Connection-local definition IDs must not identify an EA/group on another connector.
            connection = None if rule.kind == "application" else connection_id
            for field in rule.fields:
                key = "entry:" + digest([connection, rule.kind, identity, field.name])
                label = str(body.get("_label") or body.get("name") or body.get("username") or next(iter(identity.values())))
                choices[key] = {
                    "key": key,
                    "label": f"{label} · {field.label}",
                    "section": rule.section,
                    "field": field.name,
                    "kind": rule.kind,
                    "identity": identity,
                    "connectionId": connection,
                    "system": is_system_app(body),
                    "preview": {k: v for k, v in body.items() if k != "_label"},
                    "name": label,
                }
    choices["operating_system.version"]["includeBuild"] = policy.field_enabled("operating_system", "build")
    return {key: {**c, "enabled": eligible(c, policy)} for key, c in choices.items()}


def value_for(choice, docs, aperture, assessment, connection_id):
    if not choice["enabled"]:
        return {"state": "disabled", "value": None}
    section, key = choice["section"], choice["key"]
    if key == "observation.lastCheckIn":
        value = assessment.get("lastCheckIn") if assessment else None
        return {"state": "present" if value else "not_recorded", "value": value}
    if section not in docs:
        return {"state": "not_observed" if section in aperture else "outside_aperture", "value": None}
    if key.startswith("findings."):
        value = assessment.get(choice["field"]) if assessment else None
        return {"state": "present" if value is not None else "not_recorded", "value": value}
    if key == "applications.count":
        return {"state": "present", "value": len(docs[section])}
    if choice.get("kind"):
        if choice.get("connectionId") not in (None, connection_id):
            return {"state": "not_observed", "value": None}
        matches = [body for body in docs[section] if all(body.get(k) == v for k, v in choice["identity"].items())]
        if not matches:
            return {"state": "empty", "value": None}
        values = [path_value(body, choice["field"]) for body in matches]
        value = values[0] if len(values) == 1 else values
        if choice.get("kind") == "extension_attribute" and isinstance(value, list):
            value = value[0] if value else ""
    else:
        value = path_value(docs[section], choice["field"])
        if key == "operating_system.version" and choice.get("includeBuild") and value is not None:
            build = docs[section].get("build")
            value = f"{value} ({build})" if build else value
    return {"state": "not_observed" if value is None else "empty" if value == [] or value == "" else "present", "value": value}


@router.get("/{device_id}/history")
async def history(
    device_id: int, page: int = Query(1, ge=1), point: Annotated[str | None, Query(max_length=40)] = None, db=Depends(get_db)
):
    device = await device_for(db, device_id)
    query = points_query(device)
    if point:  # The page holding this state, counted as it is read, so a jump to it selects exactly it (#617).
        columns, values = place(query, (await point_for(db, device, point))[0], point)
        page = await db.scalar(select(func.count()).select_from(query).where(columns > values)) // 12 + 1
    rows = (
        (
            await db.execute(
                select(query)
                .order_by(query.c.observed_at.desc(), query.c.collected_at.desc(), query.c.key.desc())
                .offset((page - 1) * 12)
                .limit(13)
            )
        )
        .mappings()
        .all()
    )
    return {
        "items": [
            {"id": r["key"], "observedAt": r["observed_at"], "collectedAt": r["collected_at"], "kind": r["kind"]}
            for r in rows[:12]
        ],
        "hasMore": len(rows) > 12,
        "page": page,
    }


async def context(db, device, key, principal):
    row, span, point = await point_for(db, device, key)
    policy = await load_policy(db)
    docs = await documents(db, span)
    current = await db.scalar(
        select(Span).where(
            Span.mdm_connection_id == device.mdm_connection_id,
            Span.subject_kind == "computer",
            Span.subject_id == device.external_id,
            Span.is_current.is_(True),
        )
    )
    current_docs = docs if current and current.id == span.id else await documents(db, current)
    options = {
        **choices_for(docs, policy, device.mdm_connection_id),
        **choices_for(current_docs, policy, device.mdm_connection_id),
    }
    pref = await db.get(Preference, (principal.tenant_id, principal.account.id))
    slots = pref.slots if pref else [options[key] for key in DEFAULTS]
    slots = [{**options.get(c["key"], c), "enabled": eligible(c, policy)} for c in slots]
    return row, span, point, docs, options, slots


@router.get("/{device_id}/history/point")
async def detail(
    device_id: int, point: str = Query(max_length=40), db=Depends(get_db), principal: Principal = Depends(current_principal)
):
    device = await device_for(db, device_id)
    row, span, recorded, docs, options, slots = await context(db, device, point, principal)
    query = points_query(device)
    # Same total ordering as the timeline, including equal inventory timestamps.
    prior_key = await db.scalar(
        select(query.c.key)
        .where(
            tuple_(query.c.observed_at, query.c.collected_at, query.c.key)
            < tuple_(row["observed_at"], row["collected_at"], point)
        )
        .order_by(query.c.observed_at.desc(), query.c.collected_at.desc(), query.c.key.desc())
        .limit(1)
    )
    previous_docs, previous_assessment, previous_aperture = {}, None, []
    if prior_key:
        _, previous_span, previous = await point_for(db, device, prior_key)
        previous_docs = await documents(db, previous_span)
        previous_assessment = previous.assessment if previous else None
        previous_aperture = await aperture_sections(db, previous_span.aperture_digest)
    aperture = await aperture_sections(db, span.aperture_digest)
    values = []
    for choice in slots:
        values.append(
            {
                **choice,
                **value_for(choice, docs, aperture, recorded.assessment if recorded else None, device.mdm_connection_id),
                "before": value_for(choice, previous_docs, previous_aperture, previous_assessment, device.mdm_connection_id)
                if prior_key
                else None,
            }
        )
    # The ledger sections this observation moved, against the span before it in the ledger's
    # own chain (#644): what the card can name when the AI comparison had nothing in its scope
    # to say. Empty for a first span, and for a state the ledger did not open a span for.
    recorded_sections: list[str] = []
    if span.previous_id:
        before_span = await db.get(Span, span.previous_id)
        previous_digests = (before_span.section_digests or {}) if before_span else {}
        recorded_sections = [name for name, value in (span.section_digests or {}).items() if previous_digests.get(name) != value]
    settings = await db.scalar(select(InventorySummarySettings))
    status = recorded.summary_status if recorded else "unavailable"
    if status in ("unavailable", "pending", "processing") and (
        not settings or not settings.enabled or not await ai_features_enabled(db)
    ):
        status = "disabled"
    return {
        "id": point,
        "kind": row["kind"],
        "spanId": str(span.id),
        "observedAt": row["observed_at"],
        "collectedAt": row["collected_at"],
        "values": values,
        "choices": [
            {
                **choice,
                "sample": value_for(choice, docs, aperture, recorded.assessment if recorded else None, device.mdm_connection_id),
            }
            for choice in options.values()
        ],
        "baseline": prior_key is None,
        "recordedSections": recorded_sections,
        "assessment": recorded.assessment if recorded else None,
        "summary": {
            "status": status,
            "text": recorded.summary if recorded else None,
            "provider": recorded.summary_provider if recorded else None,
            "reason": recorded.summary_reason if recorded else None,
        },
    }


@router.put("/{device_id}/history/preferences")
async def save_preferences(
    device_id: int, body: Selection, db=Depends(get_db), principal: Principal = Depends(current_principal)
):
    device = await device_for(db, device_id)
    if len(set(body.slots)) != len(body.slots):
        raise HTTPException(422, "Choose each value only once")
    if not body.point:
        raise HTTPException(422, "Select a recorded observation first")
    _, _, _, _, choices, old = await context(db, device, body.point, principal)
    existing = {s["key"]: s for s in old}
    chosen = []
    for key in body.slots:
        choice = choices.get(key)
        if choice and choice["enabled"]:
            chosen.append({k: v for k, v in choice.items() if k != "preview"})
        elif key in existing:  # A disabled or absent saved slot may remain while another slot is edited.
            chosen.append({k: v for k, v in existing[key].items() if k != "preview"})
        else:
            raise HTTPException(422, "This value is not available under the current Change Log policy")
    statement = insert(Preference).values(account_id=principal.account.id, slots=chosen)
    await db.execute(statement.on_conflict_do_update(index_elements=["tenant_id", "account_id"], set_={"slots": chosen}))
    await db.commit()
    return {"slots": [s["key"] for s in chosen]}


def as_recorded(value):
    """A value's identity: its state and its JSON, so 0, false and missing evidence never compare equal."""
    return value["state"], json.dumps(value["value"], sort_keys=True, default=str)


@router.get("/{device_id}/history/previous")
async def previous_value(
    device_id: int,
    point: str = Query(max_length=40),
    slot: str = Query(max_length=200),
    db=Depends(get_db),
    principal: Principal = Depends(current_principal),
):
    """The newest state before `point` whose recorded value for `slot` differs from the value at `point` (#617):
    recorded content and retained assessments only, never today's corpus; at most SCAN earlier states, newest
    first, reading each section's content once however many of them share it."""
    device = await device_for(db, device_id)
    row, span, recorded, docs, options, slots = await context(db, device, point, principal)
    choice = next((c for c in slots if c["key"] == slot), None) or options.get(slot)
    if choice is None:
        raise HTTPException(404, "This value is not recorded for this device")
    section, apertures, entries = choice["section"], {}, {}
    contents = {span.section_digests.get(section): docs}  # The selected state's own, as the card read it.

    async def value_at(then, assessment):
        digest = then.section_digests.get(section)
        if digest not in contents:
            own = slot.startswith(("findings.", "observation."))  # A total or a clock is the point's, not the section's.
            contents[digest] = ({section: []} if digest else {}) if own else await documents(db, then, section, entries)
        if then.aperture_digest not in apertures:
            apertures[then.aperture_digest] = await aperture_sections(db, then.aperture_digest)
        return value_for(choice, contents[digest], apertures[then.aperture_digest], assessment, device.mdm_connection_id)

    selected = as_recorded(await value_at(span, recorded.assessment if recorded else None))
    query = points_query(device)
    columns, values = place(query, row, point)
    newest_first = query.c.observed_at.desc(), query.c.collected_at.desc(), query.c.key.desc()  # The timeline's order.
    statement = select(query).where(columns < values).order_by(*newest_first).limit(SCAN + 1)
    rows = (await db.execute(statement)).mappings().all()
    spans = {s.id: s for s in await db.scalars(select(Span).where(Span.id.in_({r["span_id"] for r in rows})))}
    fields = (choice["field"], "lastCheckIn")  # All value_for reads of an assessment; never its evidence body.
    ids = [uuid.UUID(r["key"][2:]) for r in rows if r["key"].startswith("p:")]
    found = await db.execute(select(Point.id, *(Point.assessment[f] for f in fields)).where(Point.id.in_(ids)))
    held = {f"p:{i}": dict(zip(fields, v, strict=True)) for i, *v in found}
    for searched, r in enumerate(rows[:SCAN], 1):
        value = await value_at(spans[r["span_id"]], held.get(r["key"]))
        if as_recorded(value) != selected:
            state = {"id": r["key"], "kind": r["kind"], "observedAt": r["observed_at"], "collectedAt": r["collected_at"]}
            return {"previous": {**state, **value}, "searched": searched, "complete": True}
    return {"previous": None, "searched": min(len(rows), SCAN), "complete": len(rows) <= SCAN}
