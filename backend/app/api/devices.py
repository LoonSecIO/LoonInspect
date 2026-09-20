from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Literal, TypeVar
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import ColumnElement, and_, func, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.catalog.service import title_names
from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.database import get_db
from app.core.egress import BlockedBaseUrl, validate_mdm_base_url
from app.core.permissions import Permission
from app.core.vuln import VulnCorpus
from app.core.vuln_answer import counted, served, stored_corpus
from app.core.vuln_library import earned_corpus, loaded_epoch_signature
from app.core.vuln_read import NO_ANSWER, assess, corpus_as_of, today, update_line
from app.core.vuln_targets import load_title_updates
from app.mdm.device_refresh import DeviceRefreshError, refresh_device
from app.mdm.jamf.contract import SUBJECT_COMPUTER
from app.mdm.org_units import BUILDING, DEPARTMENT, OrgUnitNames, ids_for_name, load_names, name_for
from app.models.schema import Device, DeviceExtensionAttribute, InstalledApp, MdmConnection
from app.observations.departure import gone_for_good, open_departures
from app.observations.read import device_observation
from app.schemas.catalog import CatalogTitleRef, VulnTitleUpdateOut
from app.schemas.devices import (
    DeviceDetailOut,
    DeviceListItemOut,
    DeviceListResponse,
    DeviceObservationOut,
    DeviceOut,
    DeviceVulnAppsOut,
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


def jamf_computer_url(base_url: str | None, external_id: str) -> str | None:
    """A record link from the device's own connection, never a credential-bearing URL."""
    if not base_url or not external_id:
        return None
    try:
        base = validate_mdm_base_url(base_url).rstrip("/")
    except BlockedBaseUrl:
        return None
    return f"{base}/computers.html?{urlencode({'id': external_id, 'o': 'r'})}"


@router.post("/{device_id}/refresh", dependencies=[Depends(require(Permission.DEVICE_SYNC))])
async def update_device_from_jamf(
    device_id: int, principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)
) -> dict:
    device = await db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.mdm_provider != "jamf" or device.platform != "macos" or device.mdm_connection_id is None:
        raise HTTPException(status_code=409, detail="This device has no supported Jamf connection.")
    connection = await db.get(MdmConnection, device.mdm_connection_id)
    if connection is None or not connection.is_active:
        raise HTTPException(status_code=409, detail="The Jamf connection is unavailable or inactive.")
    audit(AuditAction.DEVICE_REFRESH_REQUESTED, target_type="device", target_id=device_id, connection_id=connection.id)
    try:
        return await refresh_device(db, connection, device.external_id, actor_label=principal.account.email)
    except DeviceRefreshError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


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


def _stamped(out: _DeviceOutT, device: Device, names: OrgUnitNames, departed: Mapping[tuple[int, str], datetime]) -> _DeviceOutT:
    """Stamp the per-request lookups onto a serialized device: the resolved department and building,
    and the census that first did not name this Mac (#183). One dict lookup each against tables of
    tens of rows, rather than a join per device row."""
    connection_id = device.mdm_connection_id
    return out.model_copy(
        update={
            "building": name_for(names, connection_id=connection_id, kind=BUILDING, external_id=device.building_id),
            "department": name_for(names, connection_id=connection_id, kind=DEPARTMENT, external_id=device.department_id),
            "departed_at": departed.get((connection_id, device.external_id)) if connection_id is not None else None,
        }
    )


def _counted(band: str):
    """One count off a device's own copy of the answer — `vuln_answer.counted`, scoped to
    this table. NULL where the copy will not parse, which is the row the cell reads as
    `unknown_app` rather than raising."""
    return counted(InstalledApp.vuln_counts, band)


async def _vuln_apps(db: AsyncSession, device_ids: Sequence[int], *, epoch: str | None) -> dict[int, DeviceVulnAppsOut]:
    """Apps with findings, apps on KEV and apps outside the corpus — per device, in ONE
    grouped read bounded by the page's ids (the `_device_counts` shape, `app.api.catalog`),
    stamped onto the rows like the org-unit names and the departure census above. Never a
    query per row and never a count over the tenant: the fleet-wide totals are the night's
    tape (§4g, §7). **Apps, not findings** — two vulnerable builds is *2*, and a per-Mac sum
    of `counts.total` is a number nobody ruled.

    **The three buckets partition, and the unknowns are why.** *Served* is
    `vuln_answer.served`, the rule the cell obeys, so a copy from an epoch that has moved is
    outside the corpus here exactly as on the Mac's own page (§4f). The third count is
    `IS NOT TRUE` over that rule — never `NOT (…)`, since an unassessed row's assessment is
    NULL — widened by the copy whose counts will not parse. `total` decides readable, KEV
    included: a corrupted answer can carry a good `kev: 1` beside a `total` that is not a
    number, and counting it would report *0 with findings · 1 on KEV* for a row the cell
    reads as outside the corpus. An app falling out of all three would be §4a's silent zero.
    """
    if not device_ids:
        return {}
    covered = served(InstalledApp.vuln_assessment, InstalledApp.vuln_signature, epoch=epoch)
    total_findings = _counted("total")
    readable, outside = and_(covered, total_findings.is_not(None)), or_(covered.is_not(True), total_findings.is_(None))
    rows = await db.execute(
        select(
            InstalledApp.device_id,
            func.count().filter(and_(readable, total_findings > 0)),
            func.count().filter(and_(readable, _counted("kev") > 0)),
            func.count().filter(outside),
        )
        .where(InstalledApp.device_id.in_(device_ids))
        .group_by(InstalledApp.device_id)
    )
    return {
        device_id: DeviceVulnAppsOut(with_findings=findings, on_kev=kev, outside_corpus=outside)
        for device_id, findings, kev, outside in rows
    }


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
    # Macs carrying at least one app with findings, or one on CISA's KEV list (#535). SERVED,
    # not stored: a copy judged by an epoch that has moved is outside the corpus here too.
    vuln: Literal["findings", "kev"] | None = Query(default=None),
    include_departed: bool = Query(
        default=False,
        alias="includeDeparted",
        description="Also list Macs that left the fleet — absent from every clean census for seven days.",
    ),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
) -> DeviceListResponse:
    stmt = select(Device)
    if not include_departed:
        # The default answer is the current fleet (#183), pushed into the WHERE clause rather
        # than filtered after paging, so `total` and page 2 are about the same population.
        stmt = stmt.where(~gone_for_good(Device.mdm_connection_id, Device.external_id, at=datetime.now(UTC)))

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

    # One corpus object for the whole response (#535): the gate this filter is refused by,
    # the rule the rollup judges a copy against, and the stamp under the list — three reads
    # of a moving fact would let a column disagree with the header above it.
    corpus, epoch = await earned_corpus(db), loaded_epoch_signature()
    if vuln is not None:
        if corpus.as_of is None:
            # Refused, never empty: an empty page under `vuln=kev` reads as *no Mac carries
            # one*, which is §4a's failure written in a query string.
            raise HTTPException(status_code=409, detail=NO_ANSWER)
        # The carriers of a finding, in the idiom `versionHash` uses above — one semi-join
        # over this Mac's own copies, served by `ix_installed_apps_vuln_served`. `kev` keeps
        # the redundant `total > 0`: KEV findings are a subset, so it excludes nothing and
        # one predicate serves both.
        carrying = select(InstalledApp.device_id).where(
            served(InstalledApp.vuln_assessment, InstalledApp.vuln_signature, epoch=epoch),
            _counted("total") > 0,
        )
        if vuln == "kev":
            carrying = carrying.where(_counted("kev") > 0)
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
    departed = await open_departures(db, subject_kind=SUBJECT_COMPUTER)
    # Nothing answering, no column: the rollup is not computed, the rows carry no `vulnApps`
    # and `corpusAsOf` is null, which is how the page knows there is no column to render
    # rather than a row of zeros to explain away (§4a).
    rollup = {} if corpus.as_of is None else await _vuln_apps(db, [device.id for device in devices], epoch=epoch)
    return DeviceListResponse(
        items=[
            _stamped(DeviceListItemOut.model_validate(device), device, names, departed).model_copy(
                update={"vuln_apps": rollup.get(device.id)}
            )
            for device in devices
        ],
        total=total,
        page=page,
        page_size=page_size,
        corpus_as_of=corpus_as_of(corpus),
    )


def _assessed(
    out: DeviceDetailOut,
    rows: Sequence[InstalledApp],
    *,
    corpus: VulnCorpus,
    title_updates: Mapping[tuple[str, str], list[VulnTitleUpdateOut]] | None = None,
) -> DeviceDetailOut:
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
            "apps": [
                app.model_copy(
                    update={
                        "vuln": assess(stored, by_id[app.id], as_of=as_of),
                        # And what updating would do to it (#482), off the same row.
                        "vuln_update": update_line(by_id[app.id], corpus=stored),
                        "vuln_updates": (title_updates or {}).get((out.platform, app.version_hash), []),
                    }
                )
                for app in out.apps
            ],
        }
    )


def _titled(out: DeviceDetailOut, names: dict[str, str]) -> DeviceDetailOut:
    """The matched titles by name on every app (#313), from one read of the global catalog
    for the whole page — `title_names` in `app.catalog.service` says why per request.

    A title the read could not name is left out of `jamf_titles` and stays on
    `jamf_title_ids`: the page then knows it has an unnamed title rather than a shorter
    match, and never prints an id as if it were a name.
    """
    return out.model_copy(
        update={
            "apps": [
                app.model_copy(
                    update={
                        "jamf_titles": [
                            CatalogTitleRef(id=title_id, name=names[title_id])
                            for title_id in (app.jamf_title_ids or [])
                            if title_id in names
                        ]
                    }
                )
                for app in out.apps
            ]
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
    departed = await open_departures(db, subject_kind=SUBJECT_COMPUTER)
    detail = _stamped(DeviceDetailOut.model_validate(device), device, await load_names(db), departed)
    base_url = await db.scalar(select(MdmConnection.base_url).where(MdmConnection.id == device.mdm_connection_id))
    if device.mdm_provider == "jamf" and device.platform == "macos":
        detail.jamf_url = jamf_computer_url(base_url, device.external_id)
    # One read of this tenant's data-sharing tier for the whole response, not one per app:
    # the corpus a tenant has earned is a per-tenant fact and the gate reads it here
    # (#248, docs/vulnerabilities.md §8).
    corpus = await earned_corpus(db)
    targets = await load_title_updates(db, device.apps, corpus=corpus, platform=device.platform)
    assessed = _assessed(detail, device.apps, corpus=corpus, title_updates=targets)
    # One read of the global catalog for every title this Mac's apps matched (#313): the
    # names a person can read, beside the ids the rows store.
    return _titled(assessed, await title_names(db, (title_id for app in device.apps for title_id in (app.jamf_title_ids or []))))
