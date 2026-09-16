from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import ColumnElement, String, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.changes.policy import CHANGE_POLICY_VERSION, LEVELS, EffectivePolicy, Overrides, levels_at_least
from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.runs import TRIGGER_MANUAL, TRIGGER_SWEEP, TRIGGER_WEBHOOK
from app.models.schema import ChangePolicy, DeviceChange, ObservationEntry, ObservationSpan
from app.schemas.changes import (
    ChangePolicyOut,
    ChangePolicyUpdate,
    DeviceChangeListResponse,
    DeviceChangeOut,
    KnownExtensionAttribute,
    KnownGroup,
)

router = APIRouter(prefix="/api/changes", tags=["changes"])


def _to_out(row: DeviceChange) -> DeviceChangeOut:
    return DeviceChangeOut(
        id=row.id,
        mdm_connection_id=row.mdm_connection_id,
        subject_kind=row.subject_kind,
        subject_id=row.subject_id,
        subject_label=row.subject_label,
        serial_number=row.serial_number,
        udid=row.udid,
        span_id=str(row.span_id) if row.span_id else None,
        previous_span_id=str(row.previous_span_id) if row.previous_span_id else None,
        observed_at=row.observed_at,
        collected_at=row.collected_at,
        trigger=row.trigger,
        section=row.section,
        field=row.field,
        entry_kind=row.entry_kind,
        entry_identity=row.entry_identity,
        entry_label=row.entry_label,
        change=row.change,
        old_value=row.old_value,
        new_value=row.new_value,
        level=row.level,
        details=row.details,
        device_meta=row.device_meta,
        policy_version=row.policy_version,
    )


# macOS names a Mac "Kyle's Mac mini" with U+2019, the typographic apostrophe, and Jamf
# reports the name as the Mac has it; nobody types one. `q` folds it to the ASCII
# apostrophe on both sides, so the name as typed finds the name as reported.
_TYPOGRAPHIC_APOSTROPHE = "\u2019"

# What `device_changes.change` holds: an entry in a list section is added, removed or
# updated (app.changes.diff); a field is changed (app.changes.derive).
CHANGE_KINDS: tuple[str, ...] = ("added", "removed", "updated", "changed")

# What started the observation a change was found in. The ledger's three words, one
# vocabulary (app.core.runs) — refused like `change` rather than answered with an empty feed.
TRIGGERS: tuple[str, ...] = (TRIGGER_SWEEP, TRIGGER_MANUAL, TRIGGER_WEBHOOK)

# The stamped dimensions this feed filters on, and how each one matches (#447). The stamp holds
# more than this — `modelIdentifier`, `appleSilicon`, `osBuild`, `supervised`, `enrolledAt`,
# `buildingId`, `position` (app.changes.derive.DEVICE_META_KEYS) — because what is worth
# *keeping* on a row and what is worth a query parameter are different questions, and adding one
# of those later is a parameter, not a migration.
#
# `contains` is a needle anywhere in the value, for a model an operator half-remembers
# ("Air" finds "MacBook Air (M3, 2024)"). `starts` is a version prefix, so `osVersion=26`
# covers 26.6.2 and `version=153` covers Chrome's 153.0.7049.84 — the shape of the question
# nobody asks with a full build string. `is` is exact, for an id from Jamf's own catalog and for
# a boolean.
_DIMENSION_MATCHES: dict[str, tuple[str, str]] = {
    "model": ("model", "contains"),
    "os_version": ("osVersion", "starts"),
    "file_vault": ("fileVault", "is"),
    "site": ("siteId", "is"),
    "department": ("departmentId", "is"),
    "managed": ("managed", "is"),
    # Any of the three the ledger holds for the assigned person, because an operator asking
    # for "the VP's Mac" has one of them to hand, not all three (#446 will tokenize them).
    "user": (("username", "realName", "email"), "contains"),
}


def change_conditions(
    *,
    connection_id: int | None = None,
    subject_id: str | None = None,
    subject_kind: str | None = None,
    section: str | None = None,
    level: str | None = None,
    min_level: str | None = None,
    change: str | None = None,
    q: str | None = None,
    artifact: str | None = None,
    since: datetime | None = None,
    trigger: str | None = None,
    span_id: str | None = None,
    version: str | None = None,
    **dimensions: str | None,
) -> list[ColumnElement[bool]]:
    """The feed's WHERE clause, ANDed, for the filters `list_changes` documents. Raises
    the feed's own 422s. Shared with the Changes Prompt bar (app.api.changes_prompt), so
    the count its summary states is the count the page then shows for the same filters."""
    conditions: list[ColumnElement[bool]] = []
    if connection_id is not None:
        conditions.append(DeviceChange.mdm_connection_id == connection_id)
    if subject_id:
        conditions.append(DeviceChange.subject_id == subject_id)
    if subject_kind:
        conditions.append(DeviceChange.subject_kind == subject_kind)
    if section:
        conditions.append(DeviceChange.section == section)
    if level and min_level:
        # Refused rather than composed. ANDing them is well-defined and useless —
        # `level=low&minLevel=normal` is "low changes that are at least normal", which is
        # always empty — and an empty feed reads as "nothing happened", which is the one
        # thing this product refuses to let a shape say by accident (#150, and the
        # no-zero-priming rule). A caller that meant one of them should be told.
        raise HTTPException(status_code=422, detail="level and minLevel are mutually exclusive")
    if level:
        if level not in LEVELS:
            raise HTTPException(status_code=422, detail=f"level must be one of {', '.join(LEVELS)}")
        conditions.append(DeviceChange.level == level)
    if min_level:
        # The feed's own filter, and the one three surfaces need: "notable and above" is
        # `minLevel=normal`. `level` stays exact-match — it is what the Changes page's
        # dropdown means and what any bookmarked URL already carries.
        if min_level not in LEVELS:
            raise HTTPException(status_code=422, detail=f"minLevel must be one of {', '.join(LEVELS)}")
        conditions.append(DeviceChange.level.in_(levels_at_least(min_level)))
    if change:
        # Exact, like `level`: the Changes page's Change dropdown. An unknown kind is
        # refused, not answered with an empty feed that reads as "nothing happened".
        if change not in CHANGE_KINDS:
            raise HTTPException(status_code=422, detail=f"change must be one of {', '.join(CHANGE_KINDS)}")
        conditions.append(DeviceChange.change == change)
    if since is not None:
        conditions.append(DeviceChange.observed_at >= since)
    if trigger:
        if trigger not in TRIGGERS:
            raise HTTPException(status_code=422, detail=f"trigger must be one of {', '.join(TRIGGERS)}")
        conditions.append(DeviceChange.trigger == trigger)
    if span_id:
        # Every change found in one observation of one subject — the local `deviceMeta.eventID`:
        # "what else moved at the same time", which the feed could only answer by eye.
        try:
            conditions.append(DeviceChange.span_id == uuid.UUID(span_id))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="spanId must be a UUID") from exc
    if version:
        # The value a change moved TO, which is the one the question names ("who moved to
        # Chrome 153"); the value it moved from is a different query surface, as `old_value`
        # and `new_value` still are. A prefix, so a marketing version finds a build string.
        conditions.append(DeviceChange.new_value["version"].astext.ilike(f"{version.strip()}%"))
    for name, value in dimensions.items():
        if not value:
            continue
        keys, how = _DIMENSION_MATCHES[name]
        keys = (keys,) if isinstance(keys, str) else keys
        needle = value.strip()
        matches = [
            DeviceChange.device_meta[key].astext.ilike(f"%{needle}%")
            if how == "contains"
            else DeviceChange.device_meta[key].astext.ilike(f"{needle}%")
            if how == "starts"
            else DeviceChange.device_meta[key].astext == needle
            for key in keys
        ]
        conditions.append(or_(*matches) if len(matches) > 1 else matches[0])
    if q:
        needle = f"%{q.strip()}%"
        label = func.replace(DeviceChange.subject_label, _TYPOGRAPHIC_APOSTROPHE, "'", type_=String)
        conditions.append(
            label.ilike(needle.replace(_TYPOGRAPHIC_APOSTROPHE, "'"))
            | DeviceChange.serial_number.ilike(needle)
            | DeviceChange.subject_id.ilike(needle)
            # The fourth name a Mac has, and the one a link from another system carries: the
            # UDID is on every row and was reachable from nowhere (#447).
            | DeviceChange.udid.ilike(needle)
        )
    if artifact:
        # `entry_identity` holds only the kind's identity fields (app: name/bundleId/path,
        # local account: uid/username), so these four expressions are the whole of what a
        # row says the changed thing is *called*. A field change has no entry at all: its
        # entry_identity and entry_label are NULL, `->>` yields NULL, and NULL ILIKE never
        # matches — so `artifact` narrows to entry changes without a separate predicate.
        #
        # No index, measured rather than assumed. At 2M rows (1.8M in the tenant) on
        # postgres:17: page 1 is 3.6 ms, because ix_device_changes_recent still drives the
        # newest-first walk and LIMIT stops it early; the `total` beside it is a 324 ms
        # parallel seq scan, and a needle that matches nothing is 415 ms. Composing with
        # `since` bounds it proportionally (7 days: 212 ms) since that predicate rides the
        # same index. A GIN pg_trgm index over these four columns concatenated takes the
        # miss to 0.06 ms and the total to 168 ms for 43 MB and a per-insert maintenance
        # cost — worth taking when this table is tens of millions of rows, but it needs
        # CREATE EXTENSION at migration time, and buying a sub-second query with a
        # migration that can fail on an operator's database is the wrong trade this side
        # of the flip. The trade is recorded here so it does not have to be re-measured.
        needle = f"%{artifact.strip()}%"
        conditions.append(
            DeviceChange.entry_label.ilike(needle)
            | DeviceChange.entry_identity["name"].astext.ilike(needle)
            | DeviceChange.entry_identity["bundleId"].astext.ilike(needle)
            | DeviceChange.entry_identity["username"].astext.ilike(needle)
        )
    return conditions


@router.get(
    "",
    response_model=DeviceChangeListResponse,
    dependencies=[Depends(require(Permission.DEVICE_READ))],
)
async def list_changes(
    connection_id: int | None = Query(default=None, alias="connectionId"),
    subject_id: str | None = Query(default=None, alias="subjectId"),
    subject_kind: str | None = Query(default=None, alias="subjectKind"),
    section: str | None = None,
    level: str | None = None,
    min_level: str | None = Query(default=None, alias="minLevel"),
    change: str | None = None,
    q: str | None = None,
    artifact: str | None = None,
    since: datetime | None = None,
    trigger: str | None = None,
    span_id: str | None = Query(default=None, alias="spanId"),
    version: str | None = None,
    model: str | None = None,
    os_version: str | None = Query(default=None, alias="osVersion"),
    file_vault: str | None = Query(default=None, alias="fileVault"),
    site: str | None = None,
    department: str | None = None,
    managed: str | None = None,
    user: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
    db: AsyncSession = Depends(get_db),
) -> DeviceChangeListResponse:
    """The change feed, newest first.

    Two searches, because an investigation runs in two directions. `q` names the
    *device* — its name, serial, or Jamf id. `artifact` names the *thing that changed*
    — an application name or bundle id, a local account's username, or the label the
    contract carries for a group, a profile, or an extension attribute.

    They are separate parameters rather than one widened `q` for two reasons. Widening
    `q` would silently change what every existing caller gets back, the frontend and
    any bookmarked feed URL included. And one string cannot mean both: `q=MacBook Air`
    with `artifact=Wireshark` is "did this laptop family get Wireshark", which a single
    OR-ed needle can only answer as "either".

    Not searchable here, deliberately: `path` (an `artifact=/Applications` that matches
    the whole fleet is a worse answer than none), and old values — searching the value a
    change moved *from* is a different query surface, not a filter. A certificate is
    identified only by its SHA-1 fingerprint and carries no label, so it is reachable by
    `section=certificates`, not by name.

    **What is filterable is wider than what the table shows** (#447). Three keys come off the
    row itself — `trigger`, the observation the change was found in (`spanId`), and the version
    it moved to (`version`) — and seven read the dimensions stamped on the row when it was
    derived: `model`, `osVersion`, `fileVault`, `site`, `department`, `managed`, `user`. They are
    the Mac as *that observation* saw it, not as it is today, which is the whole reason they are
    stamped rather than joined (app.changes.derive.device_dimensions).

    Two bounds a caller has to know, because a filter that silently drops rows is the failure
    this feed exists to avoid:

    * a row derived before the stamp existed carries none, so it matches no dimension filter.
      The page says so beneath an empty table rather than letting an older change read as "not
      a MacBook Air";
    * a section outside the aperture of the observation stamps nothing, so a webhook's narrow
      read can leave a row with a model and no department.

    The page has controls for none of the ten. They arrive from a link, from a click on a row,
    or from the Prompt bar, and every one of them shows as a chip while it is applied.
    """
    conditions = change_conditions(
        connection_id=connection_id,
        subject_id=subject_id,
        subject_kind=subject_kind,
        section=section,
        level=level,
        min_level=min_level,
        change=change,
        q=q,
        artifact=artifact,
        since=since,
        trigger=trigger,
        span_id=span_id,
        version=version,
        model=model,
        os_version=os_version,
        file_vault=file_vault,
        site=site,
        department=department,
        managed=managed,
        user=user,
    )

    total = (await db.execute(select(func.count()).select_from(DeviceChange).where(*conditions))).scalar_one()
    rows = (
        (
            await db.execute(
                select(DeviceChange)
                .where(*conditions)
                .order_by(DeviceChange.observed_at.desc(), DeviceChange.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return DeviceChangeListResponse(items=[_to_out(r) for r in rows], total=total, page=page, page_size=page_size)


async def _policy_row(db: AsyncSession) -> ChangePolicy | None:
    return (await db.execute(select(ChangePolicy))).scalars().first()


async def _describe(db: AsyncSession, row: ChangePolicy | None) -> ChangePolicyOut:
    policy = EffectivePolicy(Overrides.from_document(row.overrides if row else None))
    document = policy.describe()
    # The catalog the mute lists pick from: every smart group and EA the ledger has seen.
    groups = (
        await db.execute(
            select(ObservationSpan.subject_id, ObservationSpan.label)
            .where(ObservationSpan.subject_kind == "computer_group", ObservationSpan.is_current.is_(True))
            .order_by(ObservationSpan.label)
        )
    ).all()
    document["knownGroups"] = [KnownGroup(id=g[0], name=g[1]) for g in groups]
    # Grouped by the output alias: asyncpg binds the JSON path as a parameter, and two
    # renderings of the same expression are two different placeholders to Postgres.
    definition_id = ObservationEntry.body["definitionId"].astext.label("definition_id")
    eas = (
        await db.execute(
            select(definition_id, func.max(ObservationEntry.label))
            .where(ObservationEntry.kind == "extension_attribute")
            .group_by(text("definition_id"))
        )
    ).all()
    document["knownExtensionAttributes"] = [
        KnownExtensionAttribute(definition_id=e[0], name=e[1]) for e in eas if e[0] is not None
    ]
    document["updatedAt"] = row.updated_at if row else None
    # Typed on the way out (#137): the document is built by `describe()` as plain dicts,
    # and validating it here is what puts a real schema in the OpenAPI document and
    # turns a field `describe()` renames into a failure in the test lane instead of a
    # client quietly reading `undefined`.
    return ChangePolicyOut.model_validate(document)


@router.get("/policy", response_model=ChangePolicyOut, dependencies=[Depends(require(Permission.DEVICE_READ))])
async def get_policy(db: AsyncSession = Depends(get_db)) -> ChangePolicyOut:
    """Defaults with their reasons, the tenant's overrides, and the effective result."""
    return await _describe(db, await _policy_row(db))


@router.put("/policy", response_model=ChangePolicyOut, dependencies=[Depends(require(Permission.CONNECTION_WRITE))])
async def put_policy(
    payload: ChangePolicyUpdate,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> ChangePolicyOut:
    """Replace the override document and return the effective policy.

    Writes ride `connection:write` — the interim home for admin-shaped writes until
    custom roles bring a verb of their own (#137, decided in session: the permission
    vocabulary is additive, so a later `policy:write` costs nothing now and this does
    not pre-empt it).
    """
    if payload.minimum_level not in LEVELS:
        raise HTTPException(status_code=422, detail=f"minimumLevel must be one of {', '.join(LEVELS)}")
    overrides = Overrides(
        minimum_level=payload.minimum_level,
        fields=dict(payload.fields),
        entries=dict(payload.entries),
        system_apps_individually=payload.system_apps_individually,
        muted_groups=tuple(payload.muted_groups),
        muted_extension_attributes=tuple(payload.muted_extension_attributes),
    )
    row = await _policy_row(db)
    if row is None:
        row = ChangePolicy(version=CHANGE_POLICY_VERSION, overrides=overrides.to_document())
        db.add(row)
    else:
        row.version = CHANGE_POLICY_VERSION
        row.overrides = overrides.to_document()
    row.updated_by_account_id = principal.account.id
    await db.commit()
    await db.refresh(row)

    audit(
        AuditAction.CHANGE_POLICY_UPDATED,
        target_type="change_policy",
        target_id=row.id,
        minimum_level=overrides.minimum_level,
        field_overrides=len(overrides.fields),
        entry_overrides=len(overrides.entries),
        muted_groups=len(overrides.muted_groups),
        muted_extension_attributes=len(overrides.muted_extension_attributes),
        system_apps_individually=overrides.system_apps_individually,
    )
    return await _describe(db, row)
