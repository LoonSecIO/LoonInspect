from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.changes.policy import CHANGE_POLICY_VERSION, LEVELS, EffectivePolicy, Overrides
from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.database import get_db
from app.core.permissions import Permission
from app.models.schema import ChangePolicy, DeviceChange, ObservationEntry, ObservationSpan
from app.schemas.changes import (
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
        policy_version=row.policy_version,
    )


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
    q: str | None = None,
    since: datetime | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
    db: AsyncSession = Depends(get_db),
) -> DeviceChangeListResponse:
    """The change feed, newest first. `q` matches the device name, serial, or Jamf id."""
    conditions = []
    if connection_id is not None:
        conditions.append(DeviceChange.mdm_connection_id == connection_id)
    if subject_id:
        conditions.append(DeviceChange.subject_id == subject_id)
    if subject_kind:
        conditions.append(DeviceChange.subject_kind == subject_kind)
    if section:
        conditions.append(DeviceChange.section == section)
    if level:
        if level not in LEVELS:
            raise HTTPException(status_code=422, detail=f"level must be one of {', '.join(LEVELS)}")
        conditions.append(DeviceChange.level == level)
    if since is not None:
        conditions.append(DeviceChange.observed_at >= since)
    if q:
        needle = f"%{q.strip()}%"
        conditions.append(
            DeviceChange.subject_label.ilike(needle)
            | DeviceChange.serial_number.ilike(needle)
            | DeviceChange.subject_id.ilike(needle)
        )

    total = (await db.execute(select(func.count()).select_from(DeviceChange).where(*conditions))).scalar_one()
    rows = (
        await db.execute(
            select(DeviceChange)
            .where(*conditions)
            .order_by(DeviceChange.observed_at.desc(), DeviceChange.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars().all()
    return DeviceChangeListResponse(items=[_to_out(r) for r in rows], total=total, page=page, page_size=page_size)


async def _policy_row(db: AsyncSession) -> ChangePolicy | None:
    return (await db.execute(select(ChangePolicy))).scalars().first()


async def _describe(db: AsyncSession, row: ChangePolicy | None) -> dict:
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
    document["knownGroups"] = [KnownGroup(id=g[0], name=g[1]).model_dump(by_alias=True) for g in groups]
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
        KnownExtensionAttribute(definition_id=e[0], name=e[1]).model_dump(by_alias=True)
        for e in eas
        if e[0] is not None
    ]
    document["updatedAt"] = row.updated_at.isoformat() if row else None
    return document


@router.get("/policy", dependencies=[Depends(require(Permission.DEVICE_READ))])
async def get_policy(db: AsyncSession = Depends(get_db)) -> dict:
    """Defaults with their reasons, the tenant's overrides, and the effective result."""
    return await _describe(db, await _policy_row(db))


@router.put("/policy", dependencies=[Depends(require(Permission.CONNECTION_WRITE))])
async def put_policy(
    payload: ChangePolicyUpdate,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> dict:
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
