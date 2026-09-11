from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime
from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import ColumnElement, func, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.vuln import VulnCorpus
from app.core.vuln_answer import stored_corpus
from app.core.vuln_library import earned_corpus
from app.core.vuln_read import assess, corpus_as_of, today
from app.mdm.org_units import BUILDING, DEPARTMENT, OrgUnitNames, ids_for_name, load_names, name_for
from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp
from app.observations.read import device_observation
from app.schemas.devices import (
    DeviceDetailOut,
    DeviceListResponse,
    DeviceObservationOut,
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
    """`ea=<definition id or name>:<value>`, repeated. A term with no colon asks only
    that the device carry the attribute, whatever its value."""
    filters: list[ExtensionAttributeFilter] = []
    for item in ea or []:
        key, colon, value = item.partition(":")
        if not key:
            continue
        filters.append(ExtensionAttributeFilter(key=key, value=value if colon else None))
    return filters


async def _org_unit_where(db: AsyncSession, kind: str, column: ColumnElement[str | None], value: str) -> ColumnElement[bool]:
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
            "department": name_for(names, connection_id=connection_id, kind=DEPARTMENT, external_id=device.department_id),
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
    platform: str | None = Query(default=None, max_length=16),
    last_check_in_after: datetime | None = Query(default=None, alias="lastCheckInAfter"),
    last_check_in_before: datetime | None = Query(default=None, alias="lastCheckInBefore"),
    last_inventory_after: datetime | None = Query(default=None, alias="lastInventoryAfter"),
    last_inventory_before: datetime | None = Query(default=None, alias="lastInventoryBefore"),
    mdm_connection_id: int | None = Query(default=None, alias="mdmConnectionId"),
    app_hash: str | None = Query(default=None, alias="appHash", max_length=32),
    version_hash: str | None = Query(default=None, alias="versionHash", max_length=32),
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
    if platform is not None:
        stmt = stmt.where(Device.platform == platform)
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
    if app_hash or version_hash:
        # The carriers of one application or of one build (#299), in the idiom the EA
        # filter below uses, served by the indexes on installed_apps.app_hash and
        # version_hash. Both together narrow to one build of one app; the application
        # record page links here per row.
        carrying = select(InstalledApp.device_id)
        if app_hash:
            carrying = carrying.where(InstalledApp.app_hash == app_hash)
        if version_hash:
            carrying = carrying.where(InstalledApp.version_hash == version_hash)
        stmt = stmt.where(Device.id.in_(carrying))

    for ea_filter in _parse_ea_filters(ea):
        # By definition id or by name (#197): the id is the identity a script can rely
        # on across a rename, the name is what a person types.
        carrying = select(DeviceExtensionAttribute.device_id).where(
            or_(
                DeviceExtensionAttribute.definition_id == ea_filter.key,
                DeviceExtensionAttribute.name == ea_filter.key,
            )
        )
        if ea_filter.value is not None:
            # Containment, not equality: a multi-value EA matches on any of its elements.
            carrying = carrying.where(DeviceExtensionAttribute.values.contains([ea_filter.value]))
        stmt = stmt.where(Device.id.in_(carrying))

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
            device for device in result.scalars().all() if _version_matches(device.os_version, os_version_operator, os_version)
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


def _assessed(out: DeviceDetailOut, rows: Sequence[InstalledApp], *, corpus: VulnCorpus) -> DeviceDetailOut:
    """LoonInspect's own answer for each of this device's apps, and the stamp it came from
    (#251, `docs/vulnerabilities.md` §4a).

    The answer is **read off the rows**, never derived here (#381): the local join ran once
    per distinct build at judge time, so a device page with 250 apps issues no per-app
    lookup of any kind. `stored_corpus` turns the rows this response already loaded into
    the same two-member seam `vuln_block` has always been asked, so a person reading this
    response and a person reading the Splunk event still see the same three words. Under
    the corpus every container ships today (`NO_CORPUS`) it is one `is None` and no per-row
    work at all.

    The corpus is a parameter rather than a call here because reading it now costs one
    query — this tenant's data-sharing tier (#248, §8) — and that question is asked once
    per response, above, not once per app.

    Rows are paired by id rather than by position: `model_validate` does preserve list
    order, but `selectinload` does not promise one, and pairing a `vuln` block with the
    wrong app is the kind of wrong that looks right.
    """
    as_of = today()
    by_id = {row.id: row for row in rows}
    stored = stored_corpus(corpus, rows)
    return out.model_copy(
        update={
            # The stamp stays the corpus's own, not the stored answer's: `corpusAsOf` names
            # the epoch answering now, which is exactly why an answer judged against a
            # different one is not served under it.
            "corpus_as_of": corpus_as_of(corpus),
            "apps": [app.model_copy(update={"vuln": assess(stored, by_id[app.id], as_of=as_of)}) for app in out.apps],
        }
    )


@router.get("/{device_id}/observation", response_model=DeviceObservationOut)
async def get_device_observation(device_id: int, db: AsyncSession = Depends(get_db)) -> DeviceObservationOut:
    """What the ledger currently holds for one Mac, by section, with the four-state
    absence vocabulary explicit (#368): present, empty, not observed, outside the
    aperture. Groups ride beside the sections, named from their own spans and marked when
    departed. Its own endpoint rather than a bigger device payload: the detail read stays
    two cheap selects and flat in fleet size, and this read — up to fourteen digest
    lookups and their bodies — is lazy on the page. Gated like the device."""
    device = await db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return DeviceObservationOut.model_validate(await device_observation(db, device))


@router.get("/{device_id}", response_model=DeviceDetailOut)
async def get_device(device_id: int, db: AsyncSession = Depends(get_db)) -> DeviceDetailOut:
    result = await db.execute(
        select(Device).where(Device.id == device_id).options(selectinload(Device.apps), selectinload(Device.extension_attributes))
    )
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    detail = _with_names(DeviceDetailOut.model_validate(device), device, await load_names(db))
    # One read of this tenant's data-sharing tier for the whole response, not one per app:
    # the corpus a tenant has earned is a per-tenant fact and the gate reads it here
    # (#248, docs/vulnerabilities.md §8).
    return _assessed(detail, device.apps, corpus=await earned_corpus(db))
