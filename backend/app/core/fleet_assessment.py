"""Compare one Mac app's installed builds with a Fleet target version, build by build, and judge
each against the organization's confirmed patch rule.

`_ambiguous`, `_policy` and `_summary` are pure. `installed_evidence`, `_inventory`, `_answers`, `_read` and
`app_assessments` read the database, but never the corpus gate, the epoch or the rules: their caller reads each once
for the whole response, so one response never carries two releases. `installed_evidence` asks the corpus nothing.

A build's verdict is its Jamf Patch title page's: `policy.judge` for its one Jamf title, under the
rule `Rules.for_title` picks, never a third, stricter reading (review finding BC-3). Verdicts and
reasons leave as codes, which the page words.

`_ambiguous` flags a bundle identifier more than one Fleet title shares, more than one Jamf title,
or a Jamf match on an assumed extension attribute: build by build, the three identity conditions
`patch_plans.build_snapshot` checks before it offers a Fleet target (`len(candidates) == 1`, no
`assumed` build, `len(ids) <= 1`). Where one holds, neither surface names a Fleet target until the
identity is reviewed: Patch Plans offers none, and here an older build reads `ambiguous` and the
app `review_identity`. The app-level differences between the two rules belong to #895, not here.

**Where `answers` comes from.** `_read` fills the mapping `_summary` reads both ends of a comparison from, keyed by
`key_full`, from the one release the caller's epoch names. An installed build's entry is its catalog row's stored answer
as `stored_corpus` serves it, the answer the Jamf Patch title page reads severity from, so both judge a build by the same
day limit; an answer another release signed is left out and reads `unknown_source`, never clean. A target version some
scoped build carries is read the same way, and only one no scoped build carries is asked of the library, by `_answers`.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Literal

from sqlalchemy import String, any_, bindparam, case, distinct, exists, func, select
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.selectable import FromClause

from app.core.application_risk import stored_answer
from app.core.config import settings
from app.core.content_keys import app_full_key
from app.core.patch_plans import release_order
from app.core.vuln import AssessedBuild, VulnCorpus
from app.core.vuln_answer import stored_corpus
from app.core.vuln_read import corpus_as_of
from app.core.vuln_versions import _assessed
from app.mdm.patch import policy
from app.mdm.patch.matching import BASIS_REQUIREMENTS
from app.models.schema import (
    AppCatalogEntry,
    AppCatalogTitleMatch,
    FleetAppVersion,
    FleetMaintainedApp,
    InstalledApp,
    VulnCorpusReleaseRow,
    VulnLibraryEpoch,
    VulnLibraryRow,
)
from app.schemas.fleet_assessment import FleetAssessmentOut, FleetBuildAssessmentOut
from app.schemas.fleet_migration import InstalledEvidence
from app.schemas.jamf_patch import PolicyVersionOut
from app.schemas.settings import PatchRule


@dataclass(frozen=True)
class _Match:
    title_id: str
    basis: str
    state: str
    first_newer: datetime | None
    missed: int | None


@dataclass
class _Build:
    app_hash: str
    bundle: str
    name: str
    version: str
    key: str
    device_count: int
    matches: list[_Match] = field(default_factory=list)


def _in_array(column, name: str, values: Sequence[str]):
    # One bind, even when a large estate has more exact builds than asyncpg's parameter limit.
    return column == any_(bindparam(name, list(values), type_=ARRAY(String)))


async def installed_evidence(
    db: AsyncSession, devices, *, as_of: date | None, epoch: str | None, app_hashes: Sequence[str] | None = None
) -> dict[str, InstalledEvidence]:
    """Each app's distinct builds on `devices` (anything with an `id` column), every app there unless
    `app_hashes` names some. A build is assessed only when every selected copy carries an answer
    Installed Apps would serve (`stored_answer`); its counts are that answer's, never a sum."""
    app = InstalledApp
    known, counts = stored_answer(epoch)
    builds = (
        select(
            app.app_hash,
            func.bool_and(func.coalesce(known, False)).label("assessed"),
            *(func.max(case((known, counts[band]))).label(band) for band in ("total", "critical", "high", "kev")),
        )
        .join(devices, devices.c.id == app.device_id)
        .group_by(app.app_hash, app.version_hash)
    )
    if app_hashes is not None:
        builds = builds.where(_in_array(app.app_hash, "app_hashes", app_hashes))
    b = builds.subquery()
    query = select(
        b.c.app_hash,
        func.count().filter(b.c.assessed).label("assessed_builds"),
        func.count().filter(~b.c.assessed).label("unknown_builds"),
        func.count().filter(b.c.assessed, b.c.total > 0).label("affected_builds"),
        func.count().filter(b.c.assessed, b.c.critical + b.c.high > 0).label("high_or_critical_builds"),
        func.count().filter(b.c.assessed, b.c.kev > 0).label("kev_builds"),
    ).group_by(b.c.app_hash)
    evidence = {}
    for row in (await db.execute(query)).all():
        values = dict(row._mapping)
        state = "partial" if row.unknown_builds else "covered"
        if epoch is None or not row.assessed_builds:  # Nobody looked: no finding counts, never zeros.
            state = "off" if epoch is None else "unknown_app"
            values.update(affected_builds=None, high_or_critical_builds=None, kev_builds=None)
        evidence[values.pop("app_hash")] = InstalledEvidence(assessment=state, as_of=None if epoch is None else as_of, **values)
    return evidence


async def _inventory(db: AsyncSession, bundles: Sequence[str], eligible: FromClause) -> tuple[list[_Build], list]:
    """The builds of `bundles` on `eligible`, each counted once per Mac before its Jamf matches are joined, so neither a
    repeated install nor a second match multiplies the count; and one row per build carrying its catalog row's keys and
    stored answer, which `_read` hands `stored_corpus`."""
    app = InstalledApp
    columns = [app.app_hash, app.bundle_id, app.name, app.version, app.key_full, app.version_hash]
    counts = (
        select(*columns, func.count(distinct(app.device_id)).label("device_count"))
        .join(eligible, eligible.c.id == app.device_id)
        .where(_in_array(app.bundle_id, "bundles", bundles))
        .group_by(*columns)
        .subquery()
    )
    entry, match = AppCatalogEntry, AppCatalogTitleMatch
    answer = [entry.key_title, entry.vuln_assessment, entry.vuln_signature, entry.vuln_counts, entry.vuln_oldest_published]
    jamf = [match.title_id, match.basis, match.state, match.first_newer_released_at, match.releases_missed]
    query = (
        select(counts, *answer, entry.vuln_ids, entry.vuln_ids_truncated, *jamf)
        .select_from(counts)
        .outerjoin(entry, (entry.platform == "macos") & (entry.version_hash == counts.c.version_hash))
        .outerjoin(match, match.app_catalog_id == entry.id)
        .order_by(counts.c.name, counts.c.version, counts.c.key_full, match.title_id)
    )
    by_key: dict[tuple[str, str], _Build] = {}
    rows = []
    for row in (await db.execute(query)).all():
        key = (row.app_hash, row.version_hash)
        if key not in by_key:
            by_key[key] = _Build(row.app_hash, row.bundle_id, row.name, row.version, row.key_full, row.device_count)
            rows.append(row)
        if row.title_id is not None:
            by_key[key].matches.append(
                _Match(row.title_id, row.basis, row.state, row.first_newer_released_at, row.releases_missed)
            )
    return list(by_key.values()), rows


async def _answers(db: AsyncSession, keys: set[str], signature: str | None) -> dict[str, AssessedBuild]:
    """The library's answer for each of `keys`, from the release `signature` names. The second reader that asks the
    library rather than the tenant's catalog, for `vuln_versions`' reason: its caller asks only about a Fleet target
    version no scoped build carries, and no catalog row holds an answer for a version on no Mac."""
    if not keys or signature is None:
        return {}
    if settings.vuln_tenant_selection:
        row = VulnCorpusReleaseRow
        same_release = row.signature == signature
    else:
        row = VulnLibraryRow
        # The legacy library is atomically replaced on import. Check its singleton stamp
        # in the same SELECT as the rows, including if an import raced the tier lookup.
        same_release = exists(select(1).where(VulnLibraryEpoch.signature == signature))
    query = select(row.key_full, row.counts, row.oldest_published, row.ids, row.truncated).where(
        same_release, _in_array(row.key_full, "keys", sorted(keys))
    )
    answers = {}
    for key, counts, oldest, ids, truncated in (await db.execute(query)).all():
        answer = _assessed(key, counts, oldest, ids, truncated)
        if answer is not None:
            answers[key] = answer
    return answers


def _ambiguous(build: _Build, shared_bundle: bool) -> bool:
    return shared_bundle or len(build.matches) > 1 or any(match.basis != BASIS_REQUIREMENTS for match in build.matches)


def _policy(
    row: FleetBuildAssessmentOut, build: _Build, rules: policy.Rules, source: AssessedBuild | None, now: datetime, ambiguous: bool
) -> None:
    """Stamp `row` with the verdict for the build's one Jamf title. An exempt override reads
    `exempt` before anything is judged, where `judge` would say not judged. Unknown is not severe."""
    if len(build.matches) == 1:
        row.policy_title_id = build.matches[0].title_id
    if ambiguous or not build.matches:
        row.policy_unassessed = "identity" if ambiguous else "no_jamf_title"
        return
    match = build.matches[0]
    rule, row.policy_source = rules.for_title(match.title_id)
    if rule is None:
        row.policy_unassessed = "no_rule"
        return
    if rule.exempt:
        row.policy_state = "exempt"
        return
    severe = source.severity["critical"] + source.severity["high"] > 0 if source is not None else None
    verdict = policy.judge(match.state, match.first_newer, match.missed, rule, now=now, severe=severe)
    if verdict.state == policy.NOT_JUDGED:
        row.policy_unassessed = "not_judged"
        return
    row.policy_state = "out" if verdict.state == policy.OUT else "within"
    row.policy_rule = PatchRule.model_validate(rule.stored())
    row.policy_verdict = PolicyVersionOut.model_validate(verdict, from_attributes=True)
    if match.first_newer is not None and verdict.limit_days is not None:
        row.policy_due_at = match.first_newer + timedelta(days=verdict.limit_days)


def _summary(
    title: FleetMaintainedApp,
    target: str,
    builds: Sequence[_Build],
    *,
    shared_bundle: bool,
    answers: Mapping[str, AssessedBuild],
    as_of: date | None,
    rules: policy.Rules,
    now: datetime,
    recent: int,
    include_builds: bool,
    include_ids: bool,
) -> FleetAssessmentOut:
    """One assessment of `builds` against `target`. `answers` is keyed by `key_full`. An installed
    build's entry is its served stored answer, the one the Jamf Patch title page reads severity
    from. The target's, under `app_full_key(name, bundle, target, None)`, is the library's answer
    for the target version from the same epoch, or a scoped build's own where one carries that
    key. A key with no entry is unanswered, never clean."""
    result = FleetAssessmentOut(
        target_version=target, corpus_as_of=as_of, recent_versions=recent if title.history_read_at else None
    )
    addressed, introduced, remaining = set[str](), set[str](), set[str]()
    ambiguous_count = 0
    for build in builds:
        ambiguous = _ambiguous(build, shared_bundle)
        source = answers.get(build.key)
        after = answers.get(app_full_key(build.name, build.bundle, target, None))
        row = FleetBuildAssessmentOut(name=build.name, version=build.version, device_count=build.device_count, comparison="off")
        row.installed_kev = source.kev if source is not None else None
        _policy(row, build, rules, source, now, ambiguous)
        result.out_of_policy_builds += int(row.policy_state == "out")
        result.within_policy_builds += int(row.policy_state == "within")
        result.policy_exempt_builds += int(row.policy_state == "exempt")
        result.policy_unassessed_builds += int(row.policy_state == "unassessed")
        if not ambiguous and len(build.matches) == 1:
            match = build.matches[0]
            if match.state == "behind" and match.first_newer and match.first_newer <= now:
                result.oldest_gap_days = max(result.oldest_gap_days or 0, (now - match.first_newer).days)
        order = release_order(build.version, target)
        result.unordered_builds += int(order is None)
        if order is None or order >= 0:
            continue
        result.behind_builds += 1
        if source is not None:
            result.kev_builds = (result.kev_builds or 0) + int(source.kev > 0)
        if ambiguous:
            ambiguous_count += 1
            row.comparison = "ambiguous"
        elif as_of is not None:
            if source is None:
                row.comparison = "unknown_source"
            elif after is None:
                row.comparison = "unknown_target"
            elif source.truncated or after.truncated:
                row.comparison = "net_only"
                row.net = source.total - after.total
                result.net_only_builds += 1
            else:
                before_ids, after_ids = set(source.ids), set(after.ids)
                closes, opens, persists = before_ids - after_ids, after_ids - before_ids, before_ids & after_ids
                row.comparison = "exact"
                row.addresses, row.introduces, row.remains = len(closes), len(opens), len(persists)
                if include_builds and include_ids:
                    row.addressed_ids, row.introduced_ids, row.remaining_ids = sorted(closes), sorted(opens), sorted(persists)
                addressed.update(closes)
                introduced.update(opens)
                remaining.update(persists)
                result.exact_builds += 1
        if include_builds:
            result.builds.append(row)
    result.unknown_builds = result.behind_builds - result.exact_builds - result.net_only_builds
    if result.exact_builds:
        result.addresses, result.introduces, result.remains = len(addressed), len(introduced), len(remaining)
    if ambiguous_count:
        result.priority, result.priority_reason = "review_identity", "identity"
    elif result.behind_builds:
        result.management = "recurring" if result.recent_versions is not None and recent >= 2 else "one_time"
        if result.out_of_policy_builds:
            result.priority, result.priority_reason = "review_now", "out_of_policy"
        elif result.kev_builds:
            result.priority, result.priority_reason = "review_now", "kev"
        else:
            result.priority, result.priority_reason = "plan_update", "comparable"
    elif result.unordered_builds:
        result.priority_reason = "unordered"
    return result


async def _read(
    db: AsyncSession,
    targets: Mapping[str, FleetMaintainedApp],
    *,
    grain: Literal["app", "slug"],
    eligible_devices: FromClause,
    corpus: VulnCorpus,
    epoch: str | None,
    rules: policy.Rules,
    include_builds: bool = False,
    include_ids: bool = False,
    target_version: str | None = None,
) -> dict[str, FleetAssessmentOut]:
    """One assessment per key of `targets`, a local app hash or a Fleet slug, over the scoped builds that carry the
    title's exact bundle identifier: that app's own, or every app's under the slug."""
    if not targets:
        return {}
    if target_version is not None and len({title.slug for title in targets.values()}) != 1:
        raise ValueError("A selected version applies to a single Fleet target")
    now = datetime.now(UTC)
    as_of = corpus_as_of(corpus)
    bundles = sorted({title.bundle_id for title in targets.values()})
    inventory, rows = await _inventory(db, bundles, eligible_devices)
    grouped: dict[str, list[_Build]] = defaultdict(list)
    for build in inventory:
        grouped[build.app_hash if grain == "app" else build.bundle].append(build)
    scoped = {
        identity: [b for b in grouped[identity if grain == "app" else title.bundle_id] if b.bundle == title.bundle_id]
        for identity, title in targets.items()
    }
    asked: set[str] = set()
    for identity, title in targets.items():
        target = target_version or title.latest_version
        for build in scoped[identity]:
            order = release_order(build.version, target)
            if order is not None and order < 0:
                asked.add(app_full_key(build.name, build.bundle, target, None))
    answers: dict[str, AssessedBuild] = {}
    signature = epoch if as_of is not None else None
    if signature is not None:  # Never `served(..., epoch=None)`, which would serve an answer no release signed.
        stored = stored_corpus(corpus, rows, epoch=signature)
        for row in rows:
            if isinstance(found := stored.findings(key_title=row.key_title, key_full=row.key_full), AssessedBuild):
                answers[row.key_full] = found
    # The library is never asked about a key some scoped build carries: that build's stored answer is the answer.
    answers.update(await _answers(db, asked - {build.key for build in inventory}, signature))
    fleet, versions = FleetMaintainedApp, FleetAppVersion
    shared = select(fleet.bundle_id).where(_in_array(fleet.bundle_id, "bundles", bundles)).group_by(fleet.bundle_id)
    shared_bundles = set((await db.scalars(shared.having(func.count() > 1))).all())
    recent = select(versions.slug, func.count()).where(
        _in_array(versions.slug, "slugs", sorted({title.slug for title in targets.values()})),
        versions.seen_at.between(now - timedelta(days=90), now),
    )
    dates = dict((await db.execute(recent.group_by(versions.slug))).all())
    return {
        identity: _summary(
            title,
            target_version or title.latest_version,
            scoped[identity],
            shared_bundle=title.bundle_id in shared_bundles,
            answers=answers,
            as_of=as_of,
            rules=rules,
            now=now,
            recent=dates.get(title.slug, 0),
            include_builds=include_builds,
            include_ids=include_ids,
        )
        for identity, title in targets.items()
    }


async def app_assessments(
    db: AsyncSession,
    app_titles: Mapping[str, FleetMaintainedApp],
    *,
    eligible_devices: FromClause,
    corpus: VulnCorpus,
    epoch: str | None,
    rules: policy.Rules,
    include_builds: bool = False,
    include_ids: bool = False,
    target_version: str | None = None,
) -> dict[str, FleetAssessmentOut]:
    """One assessment per local app hash, against its one Fleet title, over that app's scoped builds only."""
    read = {"corpus": corpus, "epoch": epoch, "rules": rules, "include_builds": include_builds, "include_ids": include_ids}
    return await _read(db, app_titles, grain="app", eligible_devices=eligible_devices, target_version=target_version, **read)
