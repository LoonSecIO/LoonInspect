"""Devices > Applications > Fleet catalog: Fleet's maintained Mac apps beside what this
organization has installed (#794).

Four routes. The read joins the global catalogue (`app.core.fleet_catalog`) to this
organization's installed apps by bundle identifier and counts Macs; it asks GitHub nothing.
The refresh is a person's check, with the same permission as Jamf's catalogue sync because
it is the same kind of act: an outbound read of a public catalogue. A title's history
(#838) is read the same two ways: what the instance holds, and a person's read of it from
Fleet's commits (`app.core.fleet_history`), with the refresh's permission for its reason.

The flag decides all four. Off, the read answers `enabled: false` with no titles and the
other three are refused in words, so an organization that never asked for this reads nothing
another organization's flag had fetched.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import String, column, distinct, func, select, tuple_, values
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import fleet_catalog, fleet_history
from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.mdm.patch.requirements import compare_versions
from app.models.schema import Device, FleetAppVersion, FleetCatalogState, FleetMaintainedApp, InstalledApp
from app.schemas.fleet_catalog import (
    FleetCatalogOut,
    FleetCatalogStateOut,
    FleetCatalogTitleOut,
    FleetTitleHistoryOut,
    FleetVersionOut,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/fleet-catalog", tags=["fleet-catalog"])

# Fleet's Mac manifests describe Mac apps; a bundle identifier an iOS app shares is not one.
_PLATFORM = "macos"


async def device_counts(db: AsyncSession, titles: list[FleetMaintainedApp]) -> dict[str, tuple[int, int]]:
    """slug -> (Macs with the title installed, Macs with any copy older than Fleet's latest).

    Three statements whatever the fleet's size, each on `installed_apps.bundle_id`'s index:
    the Macs per bundle identifier, the distinct versions installed, and the Macs per title
    holding a version the comparison below called older. The comparison is
    `app.mdm.patch.requirements.compare_versions`, the one the Jamf Patch matcher uses, on
    the installed `version`, which is the short version Jamf reports and the string Fleet's
    own check compares. A Mac is behind when **any** copy is older, as Fleet's is: a second,
    stale copy of an app is still a stale copy on that Mac.

    The match is the exact bundle identifier. Fleet's query for a title is an equality too.
    """
    if not titles:
        return {}
    fleet_bundles = select(FleetMaintainedApp.bundle_id)
    installed = (
        select(InstalledApp.bundle_id, InstalledApp.version, InstalledApp.device_id)
        .join(Device, Device.id == InstalledApp.device_id)
        .where(Device.platform == _PLATFORM, InstalledApp.bundle_id.in_(fleet_bundles))
        .subquery()
    )
    per_bundle = dict(
        (
            await db.execute(
                select(installed.c.bundle_id, func.count(distinct(installed.c.device_id))).group_by(installed.c.bundle_id)
            )
        ).all()
    )
    if not per_bundle:
        return {title.slug: (0, 0) for title in titles}

    versions_by_bundle: dict[str, set[str]] = {}
    for bundle_id, version in (await db.execute(select(installed.c.bundle_id, installed.c.version).distinct())).all():
        versions_by_bundle.setdefault(bundle_id, set()).add(version)

    # Per title rather than per bundle identifier: two of Fleet's titles can name one
    # identifier with different latest versions, and each is judged against its own.
    older = [
        (title.slug, title.bundle_id, version)
        for title in titles
        for version in versions_by_bundle.get(title.bundle_id, ())
        if compare_versions(version, title.latest_version) < 0
    ]
    behind: dict[str, int] = {}
    if older:
        stale = values(column("slug", String), column("bundle_id", String), column("version", String), name="stale").data(older)
        behind = dict(
            (
                await db.execute(
                    select(stale.c.slug, func.count(distinct(installed.c.device_id)))
                    .select_from(installed)
                    .join(stale, (stale.c.bundle_id == installed.c.bundle_id) & (stale.c.version == installed.c.version))
                    .group_by(stale.c.slug)
                )
            ).all()
        )
    return {title.slug: (int(per_bundle.get(title.bundle_id, 0)), int(behind.get(title.slug, 0))) for title in titles}


async def latest_since(db: AsyncSession, titles: list[FleetMaintainedApp]) -> dict[str, FleetAppVersion]:
    """slug -> the version history's row for the title's latest version (#838): when Fleet's
    catalog first carried it, and the version it replaced.

    Only where that row is the title's newest dated arrival. A version that left and came back
    keeps the date of its first arrival, which is not when it became the latest again; the
    move this instance saw says that better, so the row is not offered. Two statements for the
    page, each on the table's primary key."""
    latest = {title.slug: title.latest_version for title in titles if title.history_read_at is not None}
    if not latest:
        return {}
    rows = (
        (
            await db.execute(
                select(FleetAppVersion).where(tuple_(FleetAppVersion.slug, FleetAppVersion.version).in_(list(latest.items())))
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return {}
    newest = dict(
        (
            await db.execute(
                select(FleetAppVersion.slug, func.max(FleetAppVersion.seen_at))
                .where(FleetAppVersion.slug.in_([row.slug for row in rows]))
                .group_by(FleetAppVersion.slug)
            )
        ).all()
    )
    return {row.slug: row for row in rows if newest.get(row.slug) == row.seen_at}


@router.get("", response_model=FleetCatalogOut, dependencies=[Depends(require(Permission.APP_READ))])
async def read_catalog(
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(default=None, max_length=200),
    installed_only: bool = Query(default=True, alias="installedOnly"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=5000, alias="pageSize"),
) -> FleetCatalogOut:
    """Fleet's titles, each with this organization's Macs counted against Fleet's latest
    version, and what the last check found. `installedOnly` (the default) keeps the titles
    at least one Mac has; `q` narrows by name, bundle identifier or slug.

    Reads what is stored and never asks GitHub: a page load is not a check. With the flag
    off for this organization the answer is `enabled: false` and nothing else.
    """
    if not await fleet_catalog.enabled(db):
        return FleetCatalogOut(enabled=False, source=fleet_catalog.REPOSITORY, page=page, page_size=page_size)

    state = await db.get(FleetCatalogState, 1)
    # A few hundred rows, so the filter, the sort and the page are taken here rather than in
    # three shapes of SQL: the counts have to exist before `installedOnly` can be applied.
    titles = list((await db.execute(select(FleetMaintainedApp))).scalars().all())
    counts = await device_counts(db, titles)
    installed_titles = sum(1 for title in titles if counts[title.slug][0] > 0)
    installed_with_history = sum(1 for title in titles if counts[title.slug][0] > 0 and title.history_read_at is not None)

    needle = (q or "").strip().casefold()
    shown = [
        title
        for title in titles
        if (not installed_only or counts[title.slug][0] > 0)
        and (
            not needle
            or needle in title.name.casefold()
            or needle in title.bundle_id.casefold()
            or needle in title.slug.casefold()
        )
    ]
    shown.sort(key=lambda title: (title.name.casefold(), title.slug))
    start = (page - 1) * page_size

    page_titles = shown[start : start + page_size]
    since = await latest_since(db, page_titles)
    items = []
    for title in page_titles:
        device_count, devices_behind = counts[title.slug]
        dated = since.get(title.slug)
        items.append(
            FleetCatalogTitleOut(
                slug=title.slug,
                name=title.name,
                bundle_id=title.bundle_id,
                latest_version=title.latest_version,
                previous_version=title.previous_version,
                version_changed_at=title.version_changed_at,
                first_seen_at=title.first_seen_at,
                device_count=device_count,
                devices_behind=devices_behind,
                devices_current=device_count - devices_behind,
                in_catalog_since=dated.seen_at if dated is not None else None,
                version_before=dated.previous_version if dated is not None else None,
                history_read_at=title.history_read_at,
            )
        )
    return FleetCatalogOut(
        enabled=True,
        source=fleet_catalog.REPOSITORY,
        state=FleetCatalogStateOut.model_validate(state) if state is not None else None,
        items=items,
        total=len(shown),
        page=page,
        page_size=page_size,
        installed_titles=installed_titles,
        installed_titles_with_history=installed_with_history,
    )


@router.post(
    "/refresh",
    response_model=FleetCatalogStateOut,
    # Jamf's catalogue sync's permission, for that permission's own reason: an outbound read
    # of a public catalogue is not sensitive, but it hits a third party, so a read-only role
    # may not fire it in a loop. Not SYSTEM_WRITE: nothing about the instance is configured.
    dependencies=[Depends(require(Permission.PATCH_CATALOG_SYNC))],
)
async def refresh_catalog(db: AsyncSession = Depends(get_db)) -> FleetCatalogStateOut:
    """Check Fleet's catalogue now: the daily check, with a person waiting.

    Unchanged, it is one request to GitHub and returns at once. The first check reads every
    Mac manifest and takes about fifteen seconds. A refusal is a 409 whose `detail` is the
    sentence to read (docs/diagnosability.md rule 3): the flag is off, a check is already
    running, or GitHub could not be read, in which case the same sentence is stored as the
    catalogue's state and stays on the page until a later check answers.
    """
    if not await fleet_catalog.enabled(db):
        raise HTTPException(status_code=409, detail=fleet_catalog.FLAG_OFF)
    try:
        state = await fleet_catalog.check_now(db)
    except fleet_catalog.CheckBusy as exc:
        raise HTTPException(status_code=409, detail=fleet_catalog.BUSY) from exc

    failed = state.outcome in fleet_catalog.FAILED
    audit(
        AuditAction.FLEET_CATALOG_CHECKED,
        outcome="failure" if failed else "success",
        target_type="fleet_catalog",
        result=state.outcome,
        app_count=state.app_count,
    )
    if failed:
        raise HTTPException(status_code=409, detail=state.detail)
    return FleetCatalogStateOut.model_validate(state)


# Fleet's directory name for a title, as `app.core.fleet_catalog` admits it into a URL path.
_SLUG = Path(pattern=rf"^{fleet_catalog.SLUG_PATTERN}$")


def _not_held(slug: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail=(
            f"Fleet's catalog, as this instance last read it, holds no Mac title {slug}. Check now reads it "
            "again; a title Fleet stopped listing is removed with its history."
        ),
    )


async def _history_out(db: AsyncSession, title: FleetMaintainedApp) -> FleetTitleHistoryOut:
    return FleetTitleHistoryOut(
        slug=title.slug,
        name=title.name,
        latest_version=title.latest_version,
        history_read_at=title.history_read_at,
        history_since=title.history_since,
        history_through=title.history_through,
        history_complete=title.history_complete,
        history_detail=title.history_detail,
        versions=[FleetVersionOut.model_validate(row) for row in await fleet_history.versions_of(db, title.slug)],
    )


@router.get(
    "/{slug}/history",
    response_model=FleetTitleHistoryOut,
    dependencies=[Depends(require(Permission.APP_READ))],
)
async def read_title_history(slug: str = _SLUG, db: AsyncSession = Depends(get_db)) -> FleetTitleHistoryOut:
    """One title's version history as this instance holds it (#838), newest first. Asks
    GitHub nothing: a title never read answers `historyReadAt: null` and no versions."""
    if not await fleet_catalog.enabled(db):
        raise HTTPException(status_code=409, detail=fleet_catalog.FLAG_OFF)
    title = await db.get(FleetMaintainedApp, slug)
    if title is None:
        raise _not_held(slug)
    return await _history_out(db, title)


@router.post(
    "/{slug}/history",
    response_model=FleetTitleHistoryOut,
    # The refresh's permission, for the refresh's reason: an outbound read of a public
    # repository that a read-only role may not fire in a loop.
    dependencies=[Depends(require(Permission.PATCH_CATALOG_SYNC))],
)
async def read_title_history_now(slug: str = _SLUG, db: AsyncSession = Depends(get_db)) -> FleetTitleHistoryOut:
    """Read one title's whole version history from Fleet's commits now, with a person waiting.

    One request to the GitHub API per hundred changes to the title's manifest, then the
    manifest at each change, four at a time: a few seconds for most titles. Any title, on a
    Mac here or not. A refusal is a 409 whose `detail` is the sentence (docs/diagnosability.md
    rule 3): the flag is off, a history read is already running, GitHub's allowance for this
    address is down to the reserve the background leaves, or GitHub could not be read.
    """
    if not await fleet_catalog.enabled(db):
        raise HTTPException(status_code=409, detail=fleet_catalog.FLAG_OFF)
    if await db.get(FleetMaintainedApp, slug) is None:
        raise _not_held(slug)
    try:
        title = await fleet_history.read_now(db, slug)
    except fleet_history.HistoryBusy as exc:
        raise HTTPException(status_code=409, detail=fleet_history.BUSY) from exc
    except fleet_history.HistoryFailed as failed:
        audit(
            AuditAction.FLEET_CATALOG_HISTORY_READ,
            outcome="failure",
            target_type="fleet_catalog",
            target_id=slug,
            result=failed.outcome,
        )
        raise HTTPException(status_code=409, detail=failed.detail) from failed
    out = await _history_out(db, title)
    audit(
        AuditAction.FLEET_CATALOG_HISTORY_READ,
        outcome="success",
        target_type="fleet_catalog",
        target_id=slug,
        result=fleet_history.OUTCOME_OK,
        versions=len(out.versions),
    )
    return out
