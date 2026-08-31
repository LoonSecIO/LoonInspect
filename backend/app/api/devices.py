from __future__ import annotations

import re
from datetime import datetime
from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import ColumnElement, func, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.mdm.org_units import BUILDING, DEPARTMENT, OrgUnitNames, ids_for_name, load_names, name_for
from app.models.schema import Device, DeviceExtensionAttribute
from app.schemas.devices import (
    DeviceDetailOut,
    DeviceListResponse,
    DeviceOut,
    ExtensionAttributeFilter,
    VersionOperator,
)

# Applied at router level rather than per route: every endpoint here reads device
# inventory, so a route added later inherits the requirement instead of needing it
# remembered.
router = APIRouter(
    prefix="/api/devices",
    tags=["devices"],
    dependencies=[Depends(require(Permission.DEVICE_READ))],
)

_DeviceOutT = TypeVar("_DeviceOutT", bound=DeviceOut)


def _parse_ea_filters(ea: list[str] | None) -> list[ExtensionAttributeFilter]:
    filters: list[ExtensionAttributeFilter] = []
    for item in ea or []:
        if ":" not in item:
            continue
        key, value = item.split(":", 1)
        filters.append(ExtensionAttributeFilter(key=key, value=value))
    return filters


async def _org_unit_where(
    db: AsyncSession, kind: str, column: ColumnElement[str | None], value: str
) -> ColumnElement[bool]:
    """The department / building filter: a name in, the device rows out.

    Devices carry Jamf's ids, so the typed name is resolved to `(connection, id)` pairs
    first and matched as pairs — department 7 at one Jamf Pro instance is not
    department 7 at another, and matching the id alone would pull a second instance's
    unrelated department into the same answer.

    The raw id is accepted too. Resolving names needs the "Read Departments" /
    "Read Buildings" privilege, and where an API client lacks it the id is all anyone
    has — the filter should still work for them, rather than becoming the second
    version of the bug this replaced.
    """
    pairs = await ids_for_name(db, kind=kind, name=value)
    by_id = column == value
    if not pairs:
        return by_id
    return or_(tuple_(Device.mdm_connection_id, column).in_(pairs), by_id)


def _with_names(out: _DeviceOutT, device: Device, names: OrgUnitNames) -> _DeviceOutT:
    """Stamp the resolved department and building onto a serialized device. One dict
    lookup per device against a table of tens of rows, rather than a join per row."""
    connection_id = device.mdm_connection_id
    return out.model_copy(
        update={
            "building": name_for(names, connection_id=connection_id, kind=BUILDING, external_id=device.building_id),
            "department": name_for(
                names, connection_id=connection_id, kind=DEPARTMENT, external_id=device.department_id
            ),
        }
    )


def _parse_version(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value))


def _version_matches(device_version: str | None, operator: VersionOperator, value: str) -> bool:
    if device_version is None:
        return False

    if operator == VersionOperator.regex:
        try:
            return re.search(value, device_version) is not None
        except re.error:
            return False

    device_tuple = _parse_version(device_version)
    target_tuple = _parse_version(value)

    if operator == VersionOperator.lt:
        return device_tuple < target_tuple
    if operator == VersionOperator.lte:
        return device_tuple <= target_tuple
    if operator == VersionOperator.gt:
        return device_tuple > target_tuple
    if operator == VersionOperator.gte:
        return device_tuple >= target_tuple

    return device_version == value


@router.get("", response_model=DeviceListResponse)
async def list_devices(
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(default=None),
    os_version: str | None = Query(default=None, alias="osVersion"),
    os_version_operator: VersionOperator = Query(default=VersionOperator.eq, alias="osVersionOperator"),
    site: str | None = Query(default=None),
    building: str | None = Query(default=None),
    department: str | None = Query(default=None),
    managed: bool | None = Query(default=None),
    supervised: bool | None = Query(default=None),
    last_check_in_after: datetime | None = Query(default=None, alias="lastCheckInAfter"),
    last_check_in_before: datetime | None = Query(default=None, alias="lastCheckInBefore"),
    last_inventory_after: datetime | None = Query(default=None, alias="lastInventoryAfter"),
    last_inventory_before: datetime | None = Query(default=None, alias="lastInventoryBefore"),
    mdm_connection_id: int | None = Query(default=None, alias="mdmConnectionId"),
    ea: list[str] | None = Query(default=None, description="Repeated key:value extension-attribute filters"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
) -> DeviceListResponse:
    stmt = select(Device)

    if q:
        like = f"%{q}%"
        stmt = stmt.where((Device.hostname.ilike(like)) | (Device.serial_number.ilike(like)))
    if os_version and os_version_operator == VersionOperator.eq:
        stmt = stmt.where(Device.os_version == os_version)
    if site:
        stmt = stmt.where(Device.site == site)
    if building:
        stmt = stmt.where(await _org_unit_where(db, BUILDING, Device.building_id, building))
    if department:
        stmt = stmt.where(await _org_unit_where(db, DEPARTMENT, Device.department_id, department))
    if managed is not None:
        stmt = stmt.where(Device.managed == managed)
    if supervised is not None:
        stmt = stmt.where(Device.supervised == supervised)
    if last_check_in_after:
        stmt = stmt.where(Device.last_check_in >= last_check_in_after)
    if last_check_in_before:
        stmt = stmt.where(Device.last_check_in <= last_check_in_before)
    if last_inventory_after:
        stmt = stmt.where(Device.last_inventory_at >= last_inventory_after)
    if last_inventory_before:
        stmt = stmt.where(Device.last_inventory_at <= last_inventory_before)
    if mdm_connection_id is not None:
        stmt = stmt.where(Device.mdm_connection_id == mdm_connection_id)

    for ea_filter in _parse_ea_filters(ea):
        stmt = stmt.where(
            Device.id.in_(
                select(DeviceExtensionAttribute.device_id).where(
                    DeviceExtensionAttribute.key == ea_filter.key,
                    DeviceExtensionAttribute.value == ea_filter.value,
                )
            )
        )

    # os_version is a free-text string, and comparing it as one misorders multi-digit
    # segments (e.g. "14.9" > "14.10"), so lt/lte/gt/gte/regex are evaluated in Python
    # over the SQL-filtered set instead of pushed into the WHERE clause. Postgres could
    # express this natively — string_to_array(os_version, '.')::int[] compares
    # correctly and is indexable — but only for values that are strictly numeric dotted
    # segments, and MDM-reported versions are not reliably that ("14.5 (23F79)",
    # "10.15.7 Beta"). A cast that raises on one device's version string would take out
    # the whole page. Revisit if this list ever gets large enough for the in-Python
    # pass to matter. The eq case (the default) stays a normal indexed SQL filter.
    needs_python_version_filter = bool(os_version) and os_version_operator != VersionOperator.eq

    if needs_python_version_filter:
        result = await db.execute(stmt.order_by(Device.hostname))
        matching = [
            device
            for device in result.scalars().all()
            if _version_matches(device.os_version, os_version_operator, os_version)
        ]
        total = len(matching)
        start = (page - 1) * page_size
        devices = matching[start : start + page_size]
    else:
        count_result = await db.execute(select(func.count()).select_from(stmt.subquery()))
        total = count_result.scalar_one()

        stmt = stmt.order_by(Device.hostname).offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(stmt)
        devices = result.scalars().all()

    names = await load_names(db)
    return DeviceListResponse(
        items=[_with_names(DeviceOut.model_validate(device), device, names) for device in devices],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{device_id}", response_model=DeviceDetailOut)
async def get_device(device_id: int, db: AsyncSession = Depends(get_db)) -> DeviceDetailOut:
    result = await db.execute(
        select(Device)
        .where(Device.id == device_id)
        .options(selectinload(Device.apps), selectinload(Device.extension_attributes))
    )
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return _with_names(DeviceDetailOut.model_validate(device), device, await load_names(db))
