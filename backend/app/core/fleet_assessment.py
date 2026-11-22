"""Compare observed Mac builds with a Fleet target inside the report's inventory scope.

Inventory is grouped before joining Jamf matches so repeated installations and multiple
matching patch titles cannot multiply the number of Macs on a build. Corpus rows for both
ends of every comparison come from the same answering release. No upstream reads occur.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Literal

from sqlalchemy import String, any_, bindparam, distinct, exists, func, select
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.selectable import FromClause

from app.core.config import settings
from app.core.content_keys import app_full_key
from app.core.fleet_migration import release_order
from app.core.vuln import AssessedBuild
from app.core.vuln_library import earned_corpus, loaded_epoch_signature
from app.core.vuln_versions import _assessed
from app.mdm.patch import policy
from app.mdm.patch.matching import BASIS_REQUIREMENTS
from app.models.schema import (
    AppCatalogEntry,
    AppCatalogTitleMatch,
    FleetAppVersion,
    FleetMaintainedApp,
    InstalledApp,
    PatchingPolicy,
    VulnCorpusReleaseRow,
    VulnLibraryEpoch,
    VulnLibraryRow,
)
from app.schemas.fleet_assessment import FleetAssessmentOut, FleetBuildAssessmentOut
from app.schemas.fleet_migration import InstalledEvidence, LocalApp


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


async def _inventory(db: AsyncSession, bundles: Sequence[str], eligible: FromClause) -> list[_Build]:
    app = InstalledApp
    columns = [app.app_hash, app.bundle_id, app.name, app.version, app.key_full, app.version_hash]
    counts = (
        select(*columns, func.count(distinct(app.device_id)).label("device_count"))
        .join(eligible, eligible.c.id == app.device_id)
        .where(_in_array(app.bundle_id, "bundles", bundles))
        .group_by(*columns)
        .subquery()
    )
    entry = AppCatalogEntry
    match = AppCatalogTitleMatch
    query = (
        select(
            counts,
            match.title_id,
            match.basis,
            match.state,
            match.first_newer_released_at,
            match.releases_missed,
        )
        .select_from(counts)
        .outerjoin(entry, (entry.platform == "macos") & (entry.version_hash == counts.c.version_hash))
        .outerjoin(match, match.app_catalog_id == entry.id)
        .order_by(counts.c.name, counts.c.version, counts.c.key_full, match.title_id)
    )
    by_key: dict[tuple[str, str], _Build] = {}
    for row in (await db.execute(query)).all():
        key = (row.app_hash, row.version_hash)
        if key not in by_key:
            by_key[key] = _Build(row.app_hash, row.bundle_id, row.name, row.version, row.key_full, row.device_count)
        if row.title_id is not None:
            by_key[key].matches.append(
                _Match(row.title_id, row.basis, row.state, row.first_newer_released_at, row.releases_missed)
            )
    return list(by_key.values())


async def _answers(db: AsyncSession, keys: set[str], signature: str | None) -> dict[str, AssessedBuild]:
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


async def installed_evidence(db: AsyncSession, eligible: FromClause, items: Sequence[LocalApp]) -> dict[str, InstalledEvidence]:
    """Count covered builds even when no Fleet target exists. Never sum CVE counts across versions."""
    if not items:
        return {}
    corpus = await earned_corpus(db)
    results = {item.app_hash: InstalledEvidence(as_of=corpus.as_of, unknown_builds=item.version_count) for item in items}
    signature = loaded_epoch_signature() if corpus.as_of is not None else None
    if signature is None:
        return results
    app = InstalledApp
    builds = (
        await db.execute(
            select(app.app_hash, app.version_hash, app.key_full)
            .join(eligible, eligible.c.id == app.device_id)
            .where(_in_array(app.app_hash, "app_hashes", list(results)))
            .distinct()
        )
    ).all()
    answers = await _answers(db, {row.key_full for row in builds}, signature)
    for row in builds:
        answer = answers.get(row.key_full)
        if answer is None:
            continue
        counts = results[row.app_hash]
        counts.assessed_builds += 1
        counts.unknown_builds -= 1
        counts.affected_builds += int(answer.total > 0)
        counts.high_or_critical_builds += int(answer.severity["high"] + answer.severity["critical"] > 0)
        counts.kev_builds += int(answer.kev > 0)
    return results


def _ambiguous(build: _Build, shared_bundle: bool) -> bool:
    return shared_bundle or len(build.matches) > 1 or any(match.basis != BASIS_REQUIREMENTS for match in build.matches)


def _policy(
    row: FleetBuildAssessmentOut,
    build: _Build,
    rules: policy.Rules,
    source: AssessedBuild | None,
    now: datetime,
    ambiguous: bool,
) -> None:
    if ambiguous:
        row.policy_reason = "Confirm the release channel before selecting a Jamf title rule."
        return
    if not build.matches:
        return
    match = build.matches[0]
    rule, rule_source = rules.for_title(match.title_id)
    if rule is None:
        row.policy_reason = f"No confirmed patch rule applies to Jamf title {match.title_id}."
        return
    row.policy_source = rule_source
    if rule.exempt:
        row.policy_state = "exempt"
        row.policy_reason = f"Jamf title {match.title_id} is exempt under its confirmed override."
        return
    severe = source.severity["critical"] + source.severity["high"] > 0 if source is not None else None
    verdict = policy.judge(match.state, match.first_newer, match.missed, rule, now=now, severe=severe)
    if verdict.state == policy.NOT_JUDGED:
        row.policy_reason = f"Jamf title {match.title_id} has no dated patch judgment for this build."
        return
    # The general Jamf evaluator skips an unavailable clock. Never claim this build
    # satisfies a day/release condition whose input was missing.
    if (
        match.state == "behind"
        and verdict.state != policy.OUT
        and (
            (rule.days_for(severe) is not None and match.first_newer is None)
            or (rule.max_releases_behind is not None and match.missed is None)
            or (rule.days_for(severe) is None and rule.max_releases_behind is None)
        )
    ):
        row.policy_reason = f"Jamf title {match.title_id} has insufficient evidence to evaluate the confirmed limits."
        return
    row.policy_state = "out" if verdict.state == policy.OUT else "within"
    if match.first_newer and verdict.limit_days is not None:
        row.policy_due_at = match.first_newer + timedelta(days=verdict.limit_days)
    if verdict.reason == policy.REASON_DAYS:
        row.policy_reason = (
            f"Jamf title {match.title_id} exceeded its {verdict.limit_days}-day limit from the earliest newer Jamf release."
        )
    elif verdict.reason == policy.REASON_RELEASES:
        row.policy_reason = (
            f"Jamf title {match.title_id} is {match.missed} releases behind against a limit of {rule.max_releases_behind}."
        )
    else:
        row.policy_reason = f"The installed build is within the confirmed {rule_source} rule for Jamf title {match.title_id}."
    if rule.max_days_behind_severe is not None and source is None:
        row.policy_reason += " Installed severity is unknown."


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
    result = FleetAssessmentOut(
        target_version=target,
        reason="No older build was observed in this scope.",
        management_reason="No update is proposed for this scope.",
        corpus_as_of=as_of,
        recent_versions=recent if title.history_read_at else None,
        history_read_at=title.history_read_at,
        history_since=title.history_since,
        history_through=title.history_through,
        history_complete=title.history_complete,
        history_detail=title.history_detail,
    )
    addressed: set[str] = set()
    introduced: set[str] = set()
    remaining: set[str] = set()
    ambiguous_count = 0
    for build in builds:
        ambiguous = _ambiguous(build, shared_bundle)
        source = answers.get(build.key)
        after = answers.get(app_full_key(build.name, build.bundle, target, None))
        row = FleetBuildAssessmentOut(
            name=build.name,
            version=build.version,
            device_count=build.device_count,
            comparison="off",
            installed_kev=source.kev if source is not None else None,
            policy_reason="No Jamf title rule is mapped to this Fleet build.",
        )
        _policy(row, build, rules, source, now, ambiguous)
        result.out_of_policy_builds += int(row.policy_state == "out")
        result.within_policy_builds += int(row.policy_state == "within")
        result.policy_exempt_builds += int(row.policy_state == "exempt")
        result.policy_unassessed_builds += int(row.policy_state == "unassessed")
        if not ambiguous and len(build.matches) == 1:
            match = build.matches[0]
            if match.state == "behind" and match.first_newer and match.first_newer <= now:
                days = (now - match.first_newer).days
                result.oldest_gap_days = max(result.oldest_gap_days or 0, days)
        order = release_order(build.version, target)
        if order is None:
            result.unordered_builds += 1
            continue
        if order >= 0:
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
                    row.addressed_ids = sorted(closes)
                    row.introduced_ids = sorted(opens)
                    row.remaining_ids = sorted(persists)
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
        result.priority = "review_identity"
        result.reason = "Resolve overlapping Fleet or Jamf titles or assumed channel evidence before choosing an update."
        result.management_reason = "Confirm the title and release channel before planning deployment."
    elif result.behind_builds:
        result.management = "one_time"
        result.management_reason = (
            "Review the observed version gap once. Recurring management needs evidence of repeated updates."
        )
        if result.recent_versions is not None and recent >= 2:
            result.management = "recurring"
            result.management_reason = (
                f"Consider recurring patch review. Fleet recorded {recent} dated versions in the past 90 days."
            )
        if result.out_of_policy_builds:
            result.priority = "review_now"
            result.reason = "An older installed build exceeds its confirmed Jamf patch rule."
        elif result.kev_builds:
            result.priority = "review_now"
            result.reason = "An older installed build carries a finding on CISA's Known Exploited Vulnerabilities list."
        else:
            result.priority = "plan_update"
            result.reason = "An older installed build is eligible for a version comparison with the selected Fleet target."
    elif result.unordered_builds:
        result.reason = "Some installed versions could not be ordered against the target."
    return result


async def _read(
    db: AsyncSession,
    targets: Mapping[str, FleetMaintainedApp],
    *,
    grain: Literal["app", "slug"],
    eligible_devices: FromClause,
    include_builds: bool,
    include_ids: bool,
    target_version: str | None,
) -> dict[str, FleetAssessmentOut]:
    if not targets:
        return {}
    if target_version is not None and len({title.slug for title in targets.values()}) != 1:
        raise ValueError("A selected version applies to a single Fleet target")
    now = datetime.now(UTC)
    bundles = sorted({title.bundle_id for title in targets.values()})
    inventory = await _inventory(db, bundles, eligible_devices)
    grouped: dict[str, list[_Build]] = defaultdict(list)
    for build in inventory:
        grouped[build.app_hash if grain == "app" else build.bundle].append(build)
    keys: set[str] = set()
    for identity, title in targets.items():
        target = target_version or title.latest_version
        for build in grouped[identity if grain == "app" else title.bundle_id]:
            if build.bundle == title.bundle_id:
                keys.add(build.key)
                order = release_order(build.version, target)
                if order is not None and order < 0:
                    keys.add(app_full_key(build.name, build.bundle, target, None))
    corpus = await earned_corpus(db)
    answers = await _answers(db, keys, loaded_epoch_signature() if corpus.as_of is not None else None)
    stored = (await db.execute(select(PatchingPolicy.rules))).scalar_one_or_none()
    rules = policy.Rules.from_stored(stored)
    shared = set(
        (
            await db.scalars(
                select(FleetMaintainedApp.bundle_id)
                .where(_in_array(FleetMaintainedApp.bundle_id, "bundles", bundles))
                .group_by(FleetMaintainedApp.bundle_id)
                .having(func.count() > 1)
            )
        ).all()
    )
    dates = dict(
        (
            await db.execute(
                select(FleetAppVersion.slug, func.count())
                .where(
                    _in_array(FleetAppVersion.slug, "slugs", sorted({title.slug for title in targets.values()})),
                    FleetAppVersion.seen_at.between(now - timedelta(days=90), now),
                )
                .group_by(FleetAppVersion.slug)
            )
        ).all()
    )
    return {
        identity: _summary(
            title,
            target_version or title.latest_version,
            [b for b in grouped[identity if grain == "app" else title.bundle_id] if b.bundle == title.bundle_id],
            shared_bundle=title.bundle_id in shared,
            answers=answers,
            as_of=corpus.as_of,
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
    include_builds: bool = False,
    include_ids: bool = False,
    target_version: str | None = None,
) -> dict[str, FleetAssessmentOut]:
    """One assessment per local app hash, including only that app's scoped builds."""
    return await _read(
        db,
        app_titles,
        grain="app",
        eligible_devices=eligible_devices,
        include_builds=include_builds,
        include_ids=include_ids,
        target_version=target_version,
    )


async def fleet_assessments(
    db: AsyncSession,
    titles: Sequence[FleetMaintainedApp],
    *,
    eligible_devices: FromClause,
    include_builds: bool = False,
    include_ids: bool = False,
    target_version: str | None = None,
) -> dict[str, FleetAssessmentOut]:
    """One assessment per Fleet slug across scoped builds sharing its exact bundle identifier."""
    return await _read(
        db,
        {title.slug: title for title in titles},
        grain="slug",
        eligible_devices=eligible_devices,
        include_builds=include_builds,
        include_ids=include_ids,
        target_version=target_version,
    )
