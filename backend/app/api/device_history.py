"""Bounded device history and up to twenty user/tenant slots; this read never invokes inference (#605)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, exists, literal, select, union_all
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
    ).where(*scope, ~exists(select(Point.id).where(Point.span_id == Span.id)))
    recorded = select(
        (literal("p:") + cast(Point.id, String)).label("key"), Point.span_id, Point.observed_at, Point.collected_at
    ).where(Point.device_id == device.id)
    return union_all(legacy, recorded).subquery()


async def point_for(db, device, key):
    query = points_query(device)
    row = (await db.execute(select(query).where(query.c.key == key))).mappings().first()
    if row is None:
        raise HTTPException(404, "Recorded observation not found for this device")
    span = await db.get(Span, row["span_id"])
    point = await db.get(Point, uuid.UUID(key[2:])) if key.startswith("p:") else None
    return row, span, point


async def documents(db, span):
    if not span:
        return {}
    sections = (
        await db.scalars(select(ObservationSection).where(ObservationSection.digest.in_(list(span.section_digests.values()))))
    ).all()
    entry_ids = {d for section in sections for d in (section.entry_digests or [])}
    entries = (
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
async def history(device_id: int, page: int = Query(1, ge=1), db=Depends(get_db)):
    device = await device_for(db, device_id)
    query = points_query(device)
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
        "items": [{"id": r["key"], "observedAt": r["observed_at"], "collectedAt": r["collected_at"]} for r in rows[:12]],
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
    from sqlalchemy import tuple_

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
    settings = await db.scalar(select(InventorySummarySettings))
    status = recorded.summary_status if recorded else "unavailable"
    if status in ("unavailable", "pending", "processing") and (
        not settings or not settings.enabled or not await ai_features_enabled(db)
    ):
        status = "disabled"
    return {
        "id": point,
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
