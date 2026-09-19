"""The tenant app catalog: the fleet's distinct apps with first/last seen and Jamf's answer, and
the local lookup by the hashes every installed app carries. See docs/app-catalog.md."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalog.index import lookup_versions
from app.catalog.service import refresh_tenant, title_names
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.vuln import VulnCorpus
from app.core.vuln_answer import counted, served, stored_corpus
from app.core.vuln_library import earned_corpus, loaded_epoch_signature
from app.core.vuln_read import NO_ANSWER, assess, corpus_as_of, seen_here_days, today, update_line
from app.mdm.patch.requirements import version_tuple
from app.models.schema import AppCatalogEntry, AppCatalogVersion, InstalledApp
from app.schemas.catalog import (
    CatalogEntryAssessedOut,
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


def _counted(band: str, counts=AppCatalogEntry.vuln_counts):
    """One count off a stored answer — `vuln_answer.counted`, scoped to this table. The guard
    on the cast, and why it is load-bearing, live there (#529, #535).

    `counts` is the build's own by default and the TARGET's for #532's difference, so both
    sides of that subtraction are guarded by one rule rather than by two — and NULL on
    either side, a row with no number to be right about, falls out of `> 0` on its own.
    """
    return counted(counts, band)


def _device_counts(app_hash: str | None = None):
    """version_hash -> distinct devices carrying it now (tenant-scoped by RLS on installed_apps).

    `app_hash` is pushed inside the subquery on purpose (#299). The list joins this on the
    nullable side of an outer join, where Postgres cannot push the caller's predicate in,
    and evaluates it once per use — three times a request. Filtering only the outer
    `AppCatalogEntry` would leave the record page walking every install in the tenant to
    answer for one app; scoped here, its cost grows with one app's popularity and not
    with the fleet's app count.
    """
    stmt = select(InstalledApp.version_hash, func.count(distinct(InstalledApp.device_id)).label("devices"))
    if app_hash is not None:
        stmt = stmt.where(InstalledApp.app_hash == app_hash)
    return stmt.group_by(InstalledApp.version_hash).subquery()


async def _title_refs(db: AsyncSession, entries: list[AppCatalogEntry]) -> dict[str, CatalogTitleRef]:
    names = await title_names(db, (title_id for entry in entries for title_id in (entry.jamf_title_ids or [])))
    return {title_id: CatalogTitleRef(id=title_id, name=name) for title_id, name in names.items()}


def _stamp(out: CatalogEntryOut, devices: int, refs: dict[str, CatalogTitleRef], entry: AppCatalogEntry) -> None:
    out.device_count = int(devices or 0)
    out.jamf_titles = [refs[title_id] for title_id in (entry.jamf_title_ids or []) if title_id in refs]


def _entry_out(entry: AppCatalogEntry, devices: int, refs: dict[str, CatalogTitleRef]) -> CatalogEntryOut:
    """A row with no assessment on it — what the lookup returns.

    The lookup answers by `appHash` as well as by build, and under `appHash` this row is a
    stand-in for the newest version the tenant has seen, not the caller's build. `vuln` is
    scoped to `key_full`, so there is nothing honest to put here (#251,
    `docs/vulnerabilities.md` §4a): the model simply has no such field.
    """
    out = CatalogEntryOut.model_validate(entry)
    _stamp(out, devices, refs, entry)
    return out


def _assessed_entry_out(
    entry: AppCatalogEntry,
    devices: int,
    refs: dict[str, CatalogTitleRef],
    *,
    corpus: VulnCorpus,
    as_of: date,
    seen_here: Mapping[str, int] | None = None,
) -> CatalogEntryAssessedOut:
    """The same row, plus the corpus's answer for **this exact build** (#251).

    Keyed on the content keys the row already carries — the same seam the wire reads, over
    the answer stored on the row itself (#381). The corpus is a required argument rather
    than a default so a row built anywhere carries a real answer; one that quietly defaulted
    to `off` while a corpus was loaded would be a lie in the one column that exists to
    prevent them.
    """
    out = CatalogEntryAssessedOut.model_validate(entry)
    _stamp(out, devices, refs, entry)
    out.vuln = assess(corpus, entry, as_of=as_of)
    # And what updating this build would do to that answer (#482) — off the same row, by
    # the same seam. The Catalog page does not paint it yet; the application record reads
    # this endpoint scoped to one `appHash` and does.
    out.vuln_update = update_line(entry, corpus=corpus)
    # *Seen here* (#591), from the ONE grouped ledger query the caller ran for the whole page:
    # a `.get` and not a query, so no row here can grow a statement of its own. Absent where
    # the ledger holds no open row for the build — a dash on the page, and never a zero.
    out.seen_here_days = (seen_here or {}).get(entry.key_full)
    return out


@router.get("", response_model=CatalogListResponse, dependencies=[Depends(require(Permission.APP_READ))])
async def list_catalog(
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(default=None, max_length=255),
    jamf: Literal["all", "matched", "unmatched"] = Query(default="all"),
    installed_only: bool = Query(default=True, alias="installedOnly"),
    # One application's rows (#299): `app_hash = md5(name:bundle_id)`, so two apps sharing
    # a bundle ID under different names are two records and stay two. Served by
    # `ix_app_catalog_app`, and pushed inside the device counts too (see `_device_counts`).
    app_hash: str | None = Query(default=None, alias="appHash", max_length=32),
    # The stored answer as a WHERE (#529). `unknown_app` is the ruled spelling (§4b) and is
    # SERVED, not stored: a row judged by an epoch that has moved reads it whatever its
    # counts say, which is `served()`'s rule and not a copy of it.
    # `patchable` is #532's: served, with findings, and an update that closes more than it
    # opens. Its rule is below, beside the order that ranks it.
    vuln: Literal["all", "findings", "kev", "unknown_app", "clean", "patchable"] = Query(default="all"),
    band: Literal["critical", "high", "medium", "low"] | None = Query(default=None),
    order: Literal["exposure", "age", "payoff"] = Query(default="exposure"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=5000, alias="pageSize"),
) -> CatalogListResponse:
    counts = _device_counts(app_hash)
    devices = func.coalesce(counts.c.devices, 0)
    stmt = select(AppCatalogEntry, devices.label("devices")).outerjoin(
        counts, counts.c.version_hash == AppCatalogEntry.version_hash
    )
    if app_hash is not None:
        stmt = stmt.where(AppCatalogEntry.app_hash == app_hash)
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

    # One corpus object for the whole response, so every row's `corpusAsOf`, the header
    # stamp and the filter below are the same fact rather than three reads of a moving one.
    corpus, as_of = await earned_corpus(db), today()
    epoch = loaded_epoch_signature()
    covered = served(AppCatalogEntry.vuln_assessment, AppCatalogEntry.vuln_signature, epoch=epoch)
    total_findings, kev_findings = _counted("total"), _counted("kev")
    # The target's answer, under the SAME rule and the SAME signature column: one row is
    # judged by one statement, so the pair can never be read across two epochs (#482, §4f).
    # And what updating would close, as a number the database can sort on — the uncapped
    # totals, never the id lists, because a set difference over a capped list under-reports
    # and would do so in the direction that flatters an upgrade.
    target_covered = served(AppCatalogEntry.vuln_target_assessment, AppCatalogEntry.vuln_signature, epoch=epoch)
    net_closed = total_findings - _counted("total", AppCatalogEntry.vuln_target_counts)
    filtered = vuln != "all" or band is not None
    if filtered and corpus.as_of is None:
        raise HTTPException(status_code=409, detail=NO_ANSWER)
    if vuln == "findings":
        stmt = stmt.where(covered, total_findings > 0)
    elif vuln == "kev":
        stmt = stmt.where(covered, kev_findings > 0)
    elif vuln == "clean":
        stmt = stmt.where(covered, total_findings == 0)
    elif vuln == "unknown_app":
        # `IS NOT TRUE`, never `NOT (…)`: an unassessed row's assessment is NULL, so the
        # comparison is NULL and a plain negation would drop the rows being asked for. The
        # second arm is the unreadable row — served, and with no number to be right about —
        # which is `unknown_app` to the cell too (`vuln_answer._unreadable`).
        stmt = stmt.where(or_(covered.is_not(True), total_findings.is_(None)))
    elif vuln == "patchable":
        # Easily patchable (#532): findings this build carries, a target the epoch holds a
        # row for, and an update that closes more than it opens. A build whose update opens
        # MORE than it closes — the lab's Wireshark 4.2.0 at 17 findings to 4.6.8 at 94 —
        # is left out rather than ranked last, because a low rank on this list still reads
        # as *and then do this one*, and the list is a claim about every row on it.
        stmt = stmt.where(covered, total_findings > 0, target_covered, net_closed > 0)
    if band is not None:
        stmt = stmt.where(covered, _counted(band) > 0)

    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    # The two axes a Mac fleet has that a cloud estate does not: how many Macs carry the
    # build, and how long it has been exposed. Today's order stays where no vulnerability
    # filter is in play, so the Catalog tab's own list is untouched.
    if not filtered:
        ordered = stmt.order_by(devices.desc(), AppCatalogEntry.name, AppCatalogEntry.version)
    elif order == "age":
        # The stamp is the format's own `YYYY-MM-DDTHH:MM:SSZ`, so text order IS date order.
        ordered = stmt.order_by(AppCatalogEntry.vuln_oldest_published["total"].astext.asc().nulls_last(), devices.desc())
    elif order == "payoff":
        # Findings closed, times the Macs carrying the build (#532): the third Mac-fleet axis, and
        # the one that says what the next push buys. `nulls_last` because a row with no
        # judged target has no payoff to compare — `vuln=patchable` serves none, and under
        # any other filter such a row sorts after every row that has one rather than above
        # them all, which is where DESC would put a NULL.
        ordered = stmt.order_by((net_closed * devices).desc().nulls_last(), net_closed.desc().nulls_last(), AppCatalogEntry.name)
    else:
        ordered = stmt.order_by(
            (kev_findings > 0).desc().nulls_last(),
            devices.desc(),
            total_findings.desc().nulls_last(),
            AppCatalogEntry.name,
            AppCatalogEntry.version,
        )
    page_rows = (await db.execute(ordered.offset((page - 1) * page_size).limit(page_size))).all()
    entries = [row[0] for row in page_rows]
    refs = await _title_refs(db, entries)
    # The answers themselves are the ones stored on these very rows (#381) — the join ran
    # once per distinct build at judge time — so this reads no database and does no lookup;
    # under `NO_CORPUS` it does no per-row work at all.
    stored = stored_corpus(corpus, entries)
    # One grouped ledger read for the page's builds (#591) — the rule `vuln_read` states: never
    # one per row. It runs whatever the filter is, because *Seen here* is a column of both lists.
    seen_here = await seen_here_days(db, [entry.key_full for entry in entries], as_of=as_of)
    items = [
        _assessed_entry_out(entry, row[1], refs, corpus=stored, as_of=as_of, seen_here=seen_here)
        for entry, row in zip(entries, page_rows, strict=True)
    ]

    # The summary counts every row the tenant has against the device-count join. Once
    # that join holds one app's version hashes (`appHash`), `installed` would count
    # near-zero for the whole tenant and render as a plausible, wrong number — so a scoped
    # request carries no summary at all rather than a corrupt one (#299).
    summary: CatalogSummaryOut | None = None
    if app_hash is None:
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
    # Has ANY row of this tenant been judged by the epoch answering now? One indexed EXISTS
    # and no count: an epoch that moved an hour ago leaves every row reading `unknown_app`,
    # and a list that then says *0 with findings* is the picture §4a exists to prevent.
    judged = False
    if epoch is not None:
        judged = bool((await db.execute(select(select(AppCatalogEntry.id).where(covered).exists()))).scalar())
    return CatalogListResponse(
        items=items,
        total=int(total),
        page=page,
        page_size=page_size,
        summary=summary,
        corpus_as_of=corpus_as_of(corpus),
        vuln_judged=judged,
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
    db: AsyncSession,
    *,
    version_hashes: list[str],
    key_fulls: list[str],
    app_hashes: list[str],
    platform: str = "macos",
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
                # One platform's rows (#236): a hash a universal app shares is two rows with
                # two answers, and first-wins would have handed back whichever sorted first.
                AppCatalogEntry.platform == platform,
                or_(
                    AppCatalogEntry.version_hash.in_(version_hashes or [""]),
                    AppCatalogEntry.key_full.in_(key_fulls or [""]),
                    AppCatalogEntry.app_hash.in_(app_hashes or [""]),
                ),
            )
        )
    ).all()
    entries = [row[0] for row in tenant_rows]
    refs = await _title_refs(db, entries)
    by_key: dict[str, CatalogEntryOut] = {}
    for entry, count in tenant_rows:
        # No corpus here, deliberately: this endpoint answers by `appHash` too, and the row
        # it returns under that key stands in for a different build (#251).
        out = _entry_out(entry, count, refs)
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
    platform: str = Query(default="macos", max_length=16),
) -> list[CatalogLookupOut]:
    return await _lookup(db, version_hashes=version_hash, key_fulls=key_full, app_hashes=app_hash, platform=platform)


@router.post("/lookup", response_model=list[CatalogLookupOut], dependencies=[Depends(require(Permission.APP_READ))])
async def lookup_post(payload: CatalogLookupRequest, db: AsyncSession = Depends(get_db)) -> list[CatalogLookupOut]:
    return await _lookup(
        db,
        version_hashes=payload.version_hashes,
        key_fulls=payload.key_fulls,
        app_hashes=payload.app_hashes,
        platform=payload.platform,
    )


@router.post("/refresh", response_model=CatalogRefreshResult, dependencies=[Depends(require(Permission.PATCH_CATALOG_SYNC))])
async def refresh(db: AsyncSession = Depends(get_db)) -> CatalogRefreshResult:
    """Re-judge every row of this tenant against the current Jamf catalog."""
    evaluated = await refresh_tenant(db, force=True)
    await db.commit()
    return CatalogRefreshResult(evaluated=evaluated)
