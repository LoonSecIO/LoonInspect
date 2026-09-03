"""The tenant app catalog: the fleet's distinct apps with first/last seen and Jamf's answer, and
the local lookup by the hashes every installed app carries. See docs/app-catalog.md."""

from __future__ import annotations

from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.index import lookup_versions
from app.catalog.service import refresh_tenant
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.vuln import VulnCorpus, loaded_corpus
from app.core.vuln_read import assess, corpus_as_of, today
from app.mdm.patch.requirements import version_tuple
from app.models.schema import AppCatalogEntry, AppCatalogVersion, InstalledApp, JamfPatchTitle
from app.schemas.catalog import (
    CatalogEntryOut,
    CatalogListResponse,
    CatalogLookupOut,
    CatalogLookupRequest,
    CatalogRefreshResult,
    CatalogSummaryOut,
    CatalogTitleRef,
    CatalogVersionOut,
)

router = APIRouter(prefix="/api/catalog", tags=["catalog"])


def _device_counts():
    """version_hash -> distinct devices carrying it now (tenant-scoped by RLS on installed_apps)."""
    return (
        select(InstalledApp.version_hash, func.count(distinct(InstalledApp.device_id)).label("devices"))
        .group_by(InstalledApp.version_hash)
        .subquery()
    )


async def _title_refs(db: AsyncSession, entries: list[AppCatalogEntry]) -> dict[str, CatalogTitleRef]:
    ids = {title_id for entry in entries for title_id in (entry.jamf_title_ids or [])}
    if not ids:
        return {}
    rows = (await db.execute(select(JamfPatchTitle.id, JamfPatchTitle.name).where(JamfPatchTitle.id.in_(ids)))).all()
    return {title_id: CatalogTitleRef(id=title_id, name=name) for title_id, name in rows}


def _entry_out(
    entry: AppCatalogEntry,
    devices: int,
    refs: dict[str, CatalogTitleRef],
    *,
    corpus: VulnCorpus,
    as_of: date,
) -> CatalogEntryOut:
    out = CatalogEntryOut.model_validate(entry)
    out.device_count = int(devices or 0)
    out.jamf_titles = [refs[title_id] for title_id in (entry.jamf_title_ids or []) if title_id in refs]
    # #251: the corpus's answer for this exact build, keyed on the content keys the row
    # already carries — the same local hash-join the wire runs, through the same seam. The
    # corpus is a required argument rather than a default so a `CatalogEntryOut` built
    # anywhere carries a real answer; a row that quietly defaulted to `off` while a corpus
    # was loaded would be a lie in the one column that exists to prevent them.
    out.vuln = assess(corpus, entry, as_of=as_of)
    return out


@router.get("", response_model=CatalogListResponse, dependencies=[Depends(require(Permission.APP_READ))])
async def list_catalog(
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(default=None, max_length=255),
    jamf: Literal["all", "matched", "unmatched"] = Query(default="all"),
    installed_only: bool = Query(default=True, alias="installedOnly"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=5000, alias="pageSize"),
) -> CatalogListResponse:
    counts = _device_counts()
    devices = func.coalesce(counts.c.devices, 0)
    stmt = select(AppCatalogEntry, devices.label("devices")).outerjoin(
        counts, counts.c.version_hash == AppCatalogEntry.version_hash
    )
    if installed_only:
        stmt = stmt.where(devices > 0)
    if jamf == "matched":
        stmt = stmt.where(AppCatalogEntry.jamf_title_ids.is_not(None))
    elif jamf == "unmatched":
        stmt = stmt.where(AppCatalogEntry.jamf_title_ids.is_(None))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(AppCatalogEntry.name.ilike(like), AppCatalogEntry.bundle_id.ilike(like), AppCatalogEntry.version.ilike(like))
        )

    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    ordered = stmt.order_by(devices.desc(), AppCatalogEntry.name, AppCatalogEntry.version)
    page_rows = (await db.execute(ordered.offset((page - 1) * page_size).limit(page_size))).all()
    entries = [row[0] for row in page_rows]
    refs = await _title_refs(db, entries)
    # One corpus object for the whole response, so every row's `corpusAsOf` and the
    # header stamp below are the same fact rather than two reads of a moving one. The
    # lookup is per row of THIS page — distinct builds, not installs, so it does not grow
    # with the fleet — and reads no database; under `NO_CORPUS` it does no per-row work.
    corpus, as_of = loaded_corpus(), today()
    items = [
        _entry_out(entry, row[1], refs, corpus=corpus, as_of=as_of)
        for entry, row in zip(entries, page_rows, strict=True)
    ]

    summary_row = (
        await db.execute(
            select(
                func.count(),
                func.count().filter(devices > 0),
                func.count().filter(AppCatalogEntry.jamf_title_ids.is_not(None)),
                func.count().filter(AppCatalogEntry.jamf_title_ids.is_(None)),
            )
            .select_from(AppCatalogEntry)
            .outerjoin(counts, counts.c.version_hash == AppCatalogEntry.version_hash)
        )
    ).one()
    summary = CatalogSummaryOut(
        entries=int(summary_row[0]), installed=int(summary_row[1]), matched=int(summary_row[2]), unmatched=int(summary_row[3])
    )
    return CatalogListResponse(
        items=items, total=int(total), summary=summary, corpus_as_of=corpus_as_of(corpus)
    )


def _answer(key: str, tenant: CatalogEntryOut | None, versions: list[AppCatalogVersion]) -> CatalogLookupOut:
    out = CatalogLookupOut(key=key, tenant=tenant, jamf=[CatalogVersionOut.model_validate(v) for v in versions])
    if tenant is not None and tenant.jamf_title_ids:
        out.jamf_title_ids = list(tenant.jamf_title_ids)
        out.is_latest = tenant.is_latest
        out.latest = tenant.latest_version
        out.latest_released_at = tenant.latest_released_at
        out.this_version_seen = bool(tenant.this_version_seen)
        out.released_at = tenant.released_at
        return out
    if versions:
        out.jamf_title_ids = sorted({v.title_id for v in versions})
        out.this_version_seen = True
        out.is_latest = any(v.is_latest for v in versions)
        reference = next((v for v in versions if v.is_latest), None)
        if reference is None:
            # Behind: the latest of the title with the highest current version is what matters;
            # the row carries only its own version, so report the newest release date we know.
            out.latest = None
            out.latest_released_at = None
        else:
            out.latest = reference.version
            out.latest_released_at = reference.released_at
        out.released_at = min((v.released_at for v in versions if v.released_at is not None), default=None)
    return out


async def _lookup(
    db: AsyncSession, *, version_hashes: list[str], key_fulls: list[str], app_hashes: list[str]
) -> list[CatalogLookupOut]:
    keys = [*version_hashes, *key_fulls, *app_hashes]
    if not keys:
        return []
    counts = _device_counts()
    devices = func.coalesce(counts.c.devices, 0)
    tenant_rows = (
        await db.execute(
            select(AppCatalogEntry, devices)
            .outerjoin(counts, counts.c.version_hash == AppCatalogEntry.version_hash)
            .where(
                or_(
                    AppCatalogEntry.version_hash.in_(version_hashes or [""]),
                    AppCatalogEntry.key_full.in_(key_fulls or [""]),
                    AppCatalogEntry.app_hash.in_(app_hashes or [""]),
                )
            )
        )
    ).all()
    entries = [row[0] for row in tenant_rows]
    refs = await _title_refs(db, entries)
    corpus, as_of = loaded_corpus(), today()
    by_key: dict[str, CatalogEntryOut] = {}
    for entry, count in tenant_rows:
        out = _entry_out(entry, count, refs, corpus=corpus, as_of=as_of)
        by_key.setdefault(entry.version_hash, out)
        by_key.setdefault(entry.key_full, out)
        # app_hash answers the *title*, not a version; the newest version seen stands in.
        previous = by_key.get(entry.app_hash)
        if previous is None or version_tuple(entry.version) > version_tuple(previous.version):
            by_key[entry.app_hash] = out
    jamf_rows = await lookup_versions(db, version_hashes=version_hashes, key_fulls=key_fulls, app_hashes=app_hashes)
    jamf_by_key: dict[str, list[AppCatalogVersion]] = {}
    for row in jamf_rows:
        for key in (row.version_hash, row.key_full, row.app_hash):
            if key:
                jamf_by_key.setdefault(key, []).append(row)
    return [_answer(key, by_key.get(key), jamf_by_key.get(key, [])) for key in keys]


@router.get("/lookup", response_model=list[CatalogLookupOut], dependencies=[Depends(require(Permission.APP_READ))])
async def lookup_get(
    db: AsyncSession = Depends(get_db),
    version_hash: list[str] = Query(default=[], alias="versionHash", max_length=500),
    key_full: list[str] = Query(default=[], alias="keyFull", max_length=500),
    app_hash: list[str] = Query(default=[], alias="appHash", max_length=500),
) -> list[CatalogLookupOut]:
    return await _lookup(db, version_hashes=version_hash, key_fulls=key_full, app_hashes=app_hash)


@router.post("/lookup", response_model=list[CatalogLookupOut], dependencies=[Depends(require(Permission.APP_READ))])
async def lookup_post(payload: CatalogLookupRequest, db: AsyncSession = Depends(get_db)) -> list[CatalogLookupOut]:
    return await _lookup(db, version_hashes=payload.version_hashes, key_fulls=payload.key_fulls, app_hashes=payload.app_hashes)


@router.post("/refresh", response_model=CatalogRefreshResult, dependencies=[Depends(require(Permission.PATCH_CATALOG_SYNC))])
async def refresh(db: AsyncSession = Depends(get_db)) -> CatalogRefreshResult:
    """Re-judge every row of this tenant against the current Jamf catalog."""
    evaluated = await refresh_tenant(db, force=True)
    await db.commit()
    return CatalogRefreshResult(evaluated=evaluated)
