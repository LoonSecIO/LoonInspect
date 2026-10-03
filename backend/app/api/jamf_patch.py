from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Integer, and_, case, cast, distinct, false, func, literal, null, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.settings import patching_rules
from app.catalog.index import rebuild_index
from app.catalog.service import refresh_tenant
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.posture import patch_pair_counts
from app.core.vuln_answer import counted, served
from app.core.vuln_library import earned_corpus, loaded_epoch_signature
from app.core.vuln_read import today
from app.core.vuln_versions import title_version_vulns
from app.mdm.patch.jamf_catalog import sync_catalog
from app.mdm.patch.matching import STATE_BEHIND, CatalogTitle, classify
from app.mdm.patch.policy import Rules, judge
from app.models.schema import AppCatalogEntry, AppCatalogTitleMatch, InstalledApp, JamfPatchTitle
from app.schemas.jamf_patch import (
    JamfPatchCoverageOut,
    JamfPatchSyncResult,
    JamfPatchTitleDetailOut,
    JamfPatchTitleListResponse,
    JamfPatchTitleOut,
    PolicyVersionOut,
    TitlePolicyOut,
)
from app.schemas.payload import VULN_ASSESSMENT_COVERED, VulnEnrichment

router = APIRouter(prefix="/api/jamf-patch", tags=["jamf-patch"])


def _matched_devices():
    """Title matches → the catalog row → every installed app with that version hash. All three
    tables are tenant-scoped (RLS), so a tenant-bound session only ever counts its own fleet."""
    return (
        select(
            AppCatalogTitleMatch.title_id,
            AppCatalogTitleMatch.on_latest,
            AppCatalogTitleMatch.state,
            AppCatalogTitleMatch.installed_version,
            AppCatalogTitleMatch.first_newer_released_at,
            AppCatalogTitleMatch.releases_missed,
            # The build's stored vulnerability answer, for a rule with a severe limit.
            AppCatalogEntry.vuln_assessment,
            AppCatalogEntry.vuln_signature,
            AppCatalogEntry.vuln_counts,
            InstalledApp.device_id,
        )
        .join(AppCatalogEntry, AppCatalogEntry.id == AppCatalogTitleMatch.app_catalog_id)
        .join(InstalledApp, InstalledApp.version_hash == AppCatalogEntry.version_hash)
    )


async def title_device_counts(db: AsyncSession, title_ids: list[str]) -> dict[str, tuple[int, int, int]]:
    """title id -> (distinct devices with a matched app, on the title's latest, genuinely behind).

    The third number is not derivable from the first two, which is the whole reason it is here
    (#314): `device_count - devices_on_latest` counts a device running a build NEWER than the
    title lists as behind, and that is the steady state for anything that auto-updates. One more
    conditional aggregate over a subquery already being scanned — no extra join, no extra pass.
    """
    if not title_ids:
        return {}
    matched = _matched_devices().where(AppCatalogTitleMatch.title_id.in_(title_ids)).subquery()
    on_latest_device = case((matched.c.on_latest.is_(True), matched.c.device_id))
    behind_device = case((matched.c.state == STATE_BEHIND, matched.c.device_id))
    stmt = select(
        matched.c.title_id,
        func.count(distinct(matched.c.device_id)),
        func.count(distinct(on_latest_device)),
        func.count(distinct(behind_device)),
    )
    rows = (await db.execute(stmt.group_by(matched.c.title_id))).all()
    return {title_id: (int(devices), int(on_latest), int(behind)) for title_id, devices, on_latest, behind in rows}


def _title_limit(title_id, rules: Rules, limit: str):
    """One limit as SQL, per row's title: the title's own rule where it has one, else the
    organization's. An integer or NULL, NULL being *this limit is not set*."""

    def value(rule) -> object:
        number = getattr(rule, limit) if rule is not None else None
        return cast(null(), Integer) if number is None else literal(number, Integer)

    own = [(title_id == other, value(rule)) for other, rule in rules.overrides.items()]
    return case(*own, else_=value(rules.default)) if own else value(rules.default)


def _severe(matched, epoch: str | None):
    """Whether a matched build carries a critical or high finding, as SQL: its stored answer,
    served by the epoch answering now (`vuln_answer.served`), with either band above zero.
    False — never NULL — for a build nobody assessed or with nothing answering, which is
    `Rule.days_for`'s "unknown is not severe"."""
    if epoch is None:
        return false()
    findings = func.coalesce(counted(matched.c.vuln_counts, "critical"), 0) + func.coalesce(
        counted(matched.c.vuln_counts, "high"), 0
    )
    return func.coalesce(served(matched.c.vuln_assessment, matched.c.vuln_signature, epoch=epoch) & (findings > 0), false())


def out_of_policy(matched, rules: Rules, *, now: datetime, epoch: str | None = None):
    """`policy.judge(...).state == OUT` as a WHERE over `_matched_devices()` — the same
    predicate in SQL, so the list's device count and the title page's verdicts cannot
    disagree. Behind-only; an exempt title matches nothing; a NULL limit or a NULL fact
    falls out of its own arm, exactly as `judge` skips it. `epoch` is the corpus answering
    for this tenant, read once by the caller; it matters only to a severe limit."""
    days = _title_limit(matched.c.title_id, rules, "max_days_behind")
    if rules.reads_severity:
        severe_days = _title_limit(matched.c.title_id, rules, "max_days_behind_severe")
        # `Rule.days_for`: the severe limit for a severe build where the rule has one.
        days = case((and_(_severe(matched, epoch), severe_days.is_not(None)), severe_days), else_=days)
    releases = _title_limit(matched.c.title_id, rules, "max_releases_behind")
    exempt = [title_id for title_id, rule in rules.overrides.items() if rule.exempt]
    past_days = matched.c.first_newer_released_at + func.make_interval(0, 0, 0, days) < now
    past_releases = matched.c.releases_missed > releases
    clause = and_(matched.c.state == STATE_BEHIND, or_(past_days, past_releases))
    return and_(clause, matched.c.title_id.not_in(exempt)) if exempt else clause


async def title_out_of_policy_counts(
    db: AsyncSession, title_ids: list[str], rules: Rules, *, epoch: str | None = None
) -> dict[str, int]:
    """title id -> distinct devices out of policy, for the titles a rule judges. One grouped
    statement for the page, and none at all when no rule is confirmed. A title with nobody
    out of policy is absent; the caller knows which titles were judged and reads it as 0."""
    if not title_ids or not rules.judges:
        return {}
    matched = _matched_devices().where(AppCatalogTitleMatch.title_id.in_(title_ids)).subquery()
    stmt = (
        select(matched.c.title_id, func.count(distinct(matched.c.device_id)))
        .where(out_of_policy(matched, rules, now=datetime.now(UTC), epoch=epoch))
        .group_by(matched.c.title_id)
    )
    return {title_id: int(devices) for title_id, devices in (await db.execute(stmt)).all()}


async def title_build_severity(db: AsyncSession, title_id: str, *, epoch: str | None) -> dict[str, bool | None]:
    """installed version -> whether a build of it on a device is severe, from the very rows
    and the very expression the device count reads: True, False, or None where no build of
    that version has a served answer. The title page reads this for the versions devices are
    on, so its verdict for such a version is the one the count was made with."""
    if epoch is None:
        return {}
    matched = _matched_devices().where(AppCatalogTitleMatch.title_id == title_id).subquery()
    assessed = func.coalesce(served(matched.c.vuln_assessment, matched.c.vuln_signature, epoch=epoch), false())
    stmt = select(matched.c.installed_version, func.bool_or(_severe(matched, epoch)), func.bool_or(assessed)).group_by(
        matched.c.installed_version
    )
    return {version or "": (bool(severe) if known else None) for version, severe, known in (await db.execute(stmt)).all()}


def _block_severe(block: VulnEnrichment) -> bool | None:
    """A version's `vuln{}` as the severe question: None unless the corpus assessed it."""
    if block.assessment != VULN_ASSESSMENT_COVERED or block.counts is None:
        return None
    return block.counts.severity.critical + block.counts.severity.high > 0


def _stamp_policy(out: JamfPatchTitleOut, rules: Rules, counts: dict[str, int]) -> None:
    rule, source = rules.for_title(out.id)
    if rule is None:
        return
    if rule.exempt:
        out.policy_source = "exempt"
    elif rule.judges:
        out.policy_source, out.devices_out_of_policy = source, counts.get(out.id, 0)


def title_policy(
    title: JamfPatchTitle,
    versions: list[str],
    rules: Rules,
    *,
    now: datetime,
    severity: Mapping[str, bool | None] | None = None,
    answering: bool = False,
) -> TitlePolicyOut | None:
    """Every version of one title against the rule that judges it. `classify` is the
    matcher's own, asked about a version rather than about an installed app, so a verdict
    here is the one a Mac on that version carries. `severity` is each version's answer to
    *does this build carry a critical or high finding* — missing or None is not assessed —
    and `answering` whether a corpus answers for this tenant at all."""
    rule, source = rules.for_title(title.id)
    if rule is None or source is None:
        return None
    out = TitlePolicyOut(
        source=source,
        exempt=rule.exempt,
        max_days_behind=rule.max_days_behind,
        max_releases_behind=rule.max_releases_behind,
        max_days_behind_severe=rule.max_days_behind_severe,
        severity_answering=answering if rule.judges and rule.max_days_behind_severe is not None else None,
    )
    if not rule.judges:
        return out
    catalog_title = CatalogTitle.build(
        id=title.id,
        name=title.name,
        bundle_id=title.bundle_id,
        current_version=title.current_version,
        patches=title.patches,
        requirements=title.requirements,
    )
    for version in versions:
        match = classify([version], catalog_title)
        verdict = judge(
            match.state, match.first_newer_released_at, match.releases_missed, rule, now=now, severe=(severity or {}).get(version)
        )
        out.versions[version] = PolicyVersionOut(
            state=verdict.state,
            reason=verdict.reason,
            since=verdict.since,
            days_behind=verdict.days_behind,
            releases_behind=verdict.releases_behind,
            limit_days=verdict.limit_days,
            severe=verdict.severe,
        )
    return out


async def title_version_counts(db: AsyncSession, title_id: str) -> dict[str, int]:
    """installed version -> distinct devices, for the apps matched to one title."""
    matched = _matched_devices().where(AppCatalogTitleMatch.title_id == title_id).subquery()
    rows = (
        await db.execute(
            select(matched.c.installed_version, func.count(distinct(matched.c.device_id))).group_by(matched.c.installed_version)
        )
    ).all()
    return {version or "": int(count) for version, count in rows}


@router.post(
    "/sync",
    response_model=JamfPatchSyncResult,
    dependencies=[Depends(require(Permission.PATCH_CATALOG_SYNC))],
)
async def sync_titles(db: AsyncSession = Depends(get_db)) -> JamfPatchSyncResult:
    """Refresh the catalog now: the same work as the hourly job, with a person waiting.

    **Cold, this is the long one, and cold is not rare.** The hourly job fires on
    `CronTrigger(minute=0)` and not at startup, so a container started at ten past the
    hour holds an empty catalog for fifty minutes — which is exactly when someone who has
    just finished setup presses this button. Cold means every title in the catalog is a
    definition to fetch, `DETAIL_CONCURRENCY` at a time, so the request is held open for
    minutes rather than seconds.

    **Nothing cancels it.** The page sends no `AbortSignal` (`frontend/src/config/api.ts`)
    and the shipped compose stack has no reverse proxy to cut a long request off, so a
    press the operator walks away from still runs to completion on the server; only the
    button stops waiting. Nothing serialises two presses either — this route takes no
    run lock — which is the reason the fan-out's bound is chosen against this caller and
    not only against the hourly job (`jamf_catalog.py`).

    Warm — which is every press after the first — it is one summary read and a handful of
    definitions, and returns in about as long as one HTTP round trip.
    """
    synced = await sync_catalog(db)
    # The catalog moved: rebuild the lookup index and re-judge this tenant's rows against it.
    await rebuild_index(db)
    await refresh_tenant(db)
    await db.commit()
    return JamfPatchSyncResult(synced=synced)


@router.get(
    "/coverage",
    response_model=JamfPatchCoverageOut,
    dependencies=[Depends(require(Permission.APP_READ))],
)
async def coverage(db: AsyncSession = Depends(get_db)) -> JamfPatchCoverageOut:
    """Distinct (device, matched title) pairs, and how many are on the title's current
    version — the live reading of the posture recorder's `patch.pairs_*` definition, from
    the recorder's own function, so the Overview tile and the nightly tape agree (#109).
    The ratio derives at render; both inputs are served so it stays auditable. The departure
    cut (#476) is drawn at `now()` here and at `captured_at` in the recorder: one predicate,
    each reading as of its own instant.
    """
    total, on_latest = await patch_pair_counts(db, at=datetime.now(UTC))
    return JamfPatchCoverageOut(pairs_total=total, pairs_on_latest=on_latest)


@router.get(
    "/titles",
    response_model=JamfPatchTitleListResponse,
    dependencies=[Depends(require(Permission.APP_READ))],
)
async def list_titles(
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=5000, alias="pageSize"),
) -> JamfPatchTitleListResponse:
    stmt = select(JamfPatchTitle)
    if q:
        like = f"%{q}%"
        stmt = stmt.where((JamfPatchTitle.name.ilike(like)) | (JamfPatchTitle.bundle_id.ilike(like)))

    count_result = await db.execute(select(func.count()).select_from(stmt.subquery()))
    total = count_result.scalar_one()

    stmt = stmt.order_by(JamfPatchTitle.name).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    titles = result.scalars().all()
    counts = await title_device_counts(db, [title.id for title in titles])
    rules = await patching_rules(db)
    # A severe limit reads the corpus's stored answers, so the gate is asked first, once.
    epoch = None
    if rules.reads_severity:
        await earned_corpus(db)
        epoch = loaded_epoch_signature()
    out_of_policy_counts = await title_out_of_policy_counts(db, [title.id for title in titles], rules, epoch=epoch)

    items = []
    for title in titles:
        out = JamfPatchTitleOut.model_validate(title)
        out.device_count, out.devices_on_latest, out.devices_behind = counts.get(title.id, (0, 0, 0))
        _stamp_policy(out, rules, out_of_policy_counts)
        items.append(out)
    return JamfPatchTitleListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        severity_answering=(epoch is not None) if rules.reads_severity else None,
    )


@router.get(
    "/titles/{title_id}",
    response_model=JamfPatchTitleDetailOut,
    dependencies=[Depends(require(Permission.APP_READ))],
)
async def get_title(title_id: str, db: AsyncSession = Depends(get_db)) -> JamfPatchTitleDetailOut:
    title = await db.get(JamfPatchTitle, title_id)
    if title is None:
        raise HTTPException(status_code=404, detail="Patch title not found")
    out = JamfPatchTitleDetailOut.model_validate(title)
    out.device_count, out.devices_on_latest, out.devices_behind = (await title_device_counts(db, [title.id])).get(
        title.id, (0, 0, 0)
    )
    out.version_device_counts = await title_version_counts(db, title.id)
    # The Vulnerability column: each listed version's own answer, from the corpus this
    # organization has earned. One corpus object for the stamp and the rows under it.
    corpus = await earned_corpus(db)
    out.corpus_as_of = corpus.as_of
    listed = [str(patch.get("version") or "") for patch in title.patches or [] if isinstance(patch, dict)]
    listed = [version for version in listed if version]
    out.version_vulns = await title_version_vulns(db, title.id, listed, corpus=corpus, as_of=today())
    # And each version against the organization's confirmed rule, where one judges this
    # title: the listed versions and the unlisted ones a device is on.
    rules = await patching_rules(db)
    epoch = loaded_epoch_signature()
    _stamp_policy(out, rules, await title_out_of_policy_counts(db, [title.id], rules, epoch=epoch))
    judged = list(dict.fromkeys([*listed, *(version for version in out.version_device_counts if version)]))
    severity: dict[str, bool | None] = {}
    rule, _ = rules.for_title(title.id)
    if rule is not None and rule.judges and rule.max_days_behind_severe is not None:
        # A version no device is on is read from the library, as its Vulnerability cell is.
        # A version a device IS on is read from that build's stored answer — the rows the
        # device count above was made from — so the two cannot disagree about one Mac.
        severity = {version: _block_severe(block) for version, block in out.version_vulns.items()}
        severity.update(await title_build_severity(db, title.id, epoch=epoch))
    out.policy = title_policy(title, judged, rules, now=datetime.now(UTC), severity=severity, answering=epoch is not None)
    return out
