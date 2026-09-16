"""Which bundle IDs no public source on this container knows, and what a glob matches (#483).

Settings > Data Sharing > **Excluded bundle IDs** is a textarea an operator fills from
memory. Nothing on the page said which bundle IDs the fleet carries, which of them look
like the organization's own, or what a pattern matches — and the preview cannot say,
because its app rows are hashes: it shows that a glob removed *some* rows, never which.

Two answers, both from inventory this container already holds and neither from a model:

1. **Candidates.** A title is one when no `app_catalog_title_matches` row exists for any
   build of it (the Jamf Patch answer, reached from `installed_apps` by `version_hash`)
   and no `vuln_library_titles.key_title` equals its key. Grouped by reverse-DNS prefix,
   with `com.acme.*` proposed where several unknown titles share a prefix no *known*
   title uses. Unknown is necessary and not sufficient: Jamf's catalog holds about 1,550
   titles, so most of any fleet's long tail is public software it has never heard of.
   The surface says *no public source here knows these*, never *these are yours*.
2. **Counts.** Every glob, typed or suggested, evaluated by the very `_excluded` the
   exchange filters with — imported rather than reimplemented, so what the page says and
   what leaves the box cannot disagree. A glob that matches nothing says so, and a
   bundle ID a case-insensitive comparison *would* have matched is named as a near-miss
   rather than left silently absent: `fnmatch` is case-sensitive in the Linux container,
   which is how `com.acme.*` quietly misses `com.Acme.Deploy`.

Nothing here writes. An accepted suggestion goes through the audited
`PUT /api/system/data-sharing` exactly as a hand-typed glob does.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

from sqlalchemy import case, distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.sharing import _excluded
from app.models.schema import (
    AppCatalogEntry,
    AppCatalogTitleMatch,
    InstalledApp,
    JamfPatchTitle,
    VulnLibraryTitle,
)

# Ceilings, because the long tail is the fleet. A group list past a screenful stops being
# a suggestion and becomes an inventory report, which the Applications page already is.
MAX_GROUPS = 12
MAX_APPS_PER_GROUP = 12
MAX_GLOBS = 40
MAX_CASE_MISSES = 5

# The one reason a row can be on this list today. Carried per row rather than stated once
# because a second reason (low prevalence, a name the connection's hostname echoes) is the
# next thing this surface grows, and a reader that ignores an unknown value is cheaper to
# write now than a shape change later.
REASON_UNKNOWN = "no_public_source"


@dataclass(frozen=True)
class CandidateApp:
    name: str
    bundle_id: str
    device_count: int
    reason: str


@dataclass(frozen=True)
class CandidateGroup:
    prefix: str
    suggestion: str | None
    excluded: bool
    app_count: int
    device_count: int
    apps: list[CandidateApp]


@dataclass(frozen=True)
class GlobCount:
    glob: str
    source: str
    app_count: int
    device_count: int
    case_misses: list[str]


@dataclass(frozen=True)
class ExclusionCandidates:
    groups: list[CandidateGroup]
    more_groups: int
    globs: list[GlobCount]
    catalog_titles: int
    library_titles: int


@dataclass(frozen=True)
class _Row:
    bundle_id: str
    key_title: str
    name: str
    device_count: int
    known: bool


def prefix_of(bundle_id: str) -> str | None:
    """`com.acme` from `com.acme.payroll`. None where there is nothing to generalize.

    Two labels are the organization, the third is the product, so a bundle ID with fewer
    than three has no prefix that says less than the ID itself — proposing `com.acme.*`
    for `com.acme` would name a pattern that does not even match the app it came from.
    """
    labels = bundle_id.split(".")
    return ".".join(labels[:2]) if len(labels) >= 3 and all(labels[:2]) else None


async def _rows(db: AsyncSession) -> list[_Row]:
    """Every (bundle ID, title) the fleet carries, with its device count and whether a
    Jamf Patch title matched any of its builds.

    One aggregate rather than two passes: the same rows answer *what is unknown* and
    *what a glob matches*, and a known-title set computed from a separate query could
    disagree with the candidate list by a sweep.

    The match test is at title grain, not row grain. A title with one matched build and
    one unmatched build is **known** — an outer join counted to zero says that, while a
    correlated `NOT EXISTS` per row would file the unmatched build as a candidate and
    invite an operator to exclude software Jamf publishes.
    """
    result = await db.execute(
        select(
            InstalledApp.bundle_id,
            InstalledApp.key_title,
            func.min(InstalledApp.name).label("name"),
            func.count(distinct(InstalledApp.device_id)).label("device_count"),
            func.count(AppCatalogTitleMatch.id).label("matches"),
        )
        .outerjoin(AppCatalogEntry, AppCatalogEntry.version_hash == InstalledApp.version_hash)
        .outerjoin(AppCatalogTitleMatch, AppCatalogTitleMatch.app_catalog_id == AppCatalogEntry.id)
        .where(InstalledApp.bundle_id != "")
        .group_by(InstalledApp.bundle_id, InstalledApp.key_title)
    )
    library = set((await db.execute(select(VulnLibraryTitle.key_title))).scalars())
    return [
        _Row(
            bundle_id=row.bundle_id,
            key_title=row.key_title,
            name=row.name,
            device_count=row.device_count,
            known=row.matches > 0 or row.key_title in library,
        )
        for row in result.all()
    ]


async def _device_counts(db: AsyncSession, sets: list[set[str]]) -> list[int]:
    """Distinct devices carrying at least one app from each bundle-ID set, in one query.

    Per-app counts cannot be summed — a Mac with three of the organization's four apps
    would be counted three times — so each set gets its own `count(distinct …)` over a
    `CASE` that answers NULL off-set, and `COUNT DISTINCT` drops the NULLs.
    """
    wanted: set[str] = set().union(*sets) if sets else set()
    if not wanted:
        return [0] * len(sets)
    columns = [
        func.count(distinct(case((InstalledApp.bundle_id.in_(sorted(group)), InstalledApp.device_id)))) for group in sets if group
    ]
    values = iter((await db.execute(select(*columns).where(InstalledApp.bundle_id.in_(sorted(wanted))))).one())
    return [int(next(values) or 0) if group else 0 for group in sets]


def _spelling(bundle_ids: list[str]) -> str | None:
    """Which casing of a prefix to show when the fleet spells it more than one way.

    The commonest wins, and an all-lowercase spelling breaks the tie: a glob is matched
    case-sensitively, so this choice decides which of the group's apps a suggestion
    actually covers — and the near-misses beside the count name the rest. None when no
    member has a prefix at all, which is a group of one short bundle ID.
    """
    counts: dict[str, int] = {}
    for bundle_id in bundle_ids:
        if prefix := prefix_of(bundle_id):
            counts[prefix] = counts.get(prefix, 0) + 1
    return max(sorted(counts), key=lambda p: (counts[p], p == p.lower())) if counts else None


async def build_candidates(db: AsyncSession, globs: list[str]) -> ExclusionCandidates:
    """The whole answer for one tenant: candidate groups, and a count for every glob.

    `globs` is what the operator has in the box — the stored list, or the draft the page
    is holding, which is why a pattern can be counted before it is saved.
    """
    rows = await _rows(db)
    known_prefixes = {p.lower() for row in rows if row.known and (p := prefix_of(row.bundle_id))}
    all_bundle_ids = {row.bundle_id for row in rows}

    grouped: dict[str, list[_Row]] = {}
    for row in rows:
        if not row.known:
            grouped.setdefault((prefix_of(row.bundle_id) or row.bundle_id).lower(), []).append(row)

    ordered = sorted(grouped.values(), key=lambda g: (-sum(r.device_count for r in g), -len(g), g[0].bundle_id))
    shown, more = ordered[:MAX_GROUPS], max(0, len(ordered) - MAX_GROUPS)

    typed = [g for g in dict.fromkeys(globs) if g][:MAX_GLOBS]
    labels = [_spelling([row.bundle_id for row in group]) for group in shown]
    suggestions = [
        # Several titles, and a prefix no known title uses: the two conditions that make
        # "everything under this prefix" a statement about the organization rather than
        # about one obscure public app that happens to be unmatched.
        f"{label}.*" if label and len(group) >= 2 and label.lower() not in known_prefixes else None
        for label, group in zip(labels, shown, strict=True)
    ]

    evaluated = typed + [s for s in dict.fromkeys(suggestions) if s and s not in typed]
    sources = ["typed"] * len(typed) + ["suggested"] * (len(evaluated) - len(typed))
    matched = [{b for b in all_bundle_ids if _excluded(b, [glob])} for glob in evaluated]

    group_sets = [{row.bundle_id for row in group} for group in shown]
    counts = await _device_counts(db, group_sets + matched)

    return ExclusionCandidates(
        groups=[
            CandidateGroup(
                prefix=label or group[0].bundle_id,
                suggestion=suggestion,
                # Already covered: every app here is one a stored glob removes today, so
                # there is nothing to accept and the page says so rather than offering it.
                excluded=all(_excluded(row.bundle_id, typed) for row in group),
                app_count=len(group),
                device_count=count,
                apps=[
                    CandidateApp(row.name, row.bundle_id, row.device_count, REASON_UNKNOWN)
                    for row in sorted(group, key=lambda r: (-r.device_count, r.bundle_id))[:MAX_APPS_PER_GROUP]
                ],
            )
            for group, label, suggestion, count in zip(shown, labels, suggestions, counts[: len(group_sets)], strict=True)
        ],
        more_groups=more,
        globs=[
            GlobCount(
                glob=glob,
                source=source,
                app_count=len(hits),
                device_count=count,
                case_misses=sorted(b for b in all_bundle_ids if b not in hits and fnmatch(b.lower(), glob.lower()))[
                    :MAX_CASE_MISSES
                ],
            )
            for glob, source, hits, count in zip(evaluated, sources, matched, counts[len(group_sets) :], strict=True)
        ],
        catalog_titles=(await db.execute(select(func.count(JamfPatchTitle.id)))).scalar_one(),
        library_titles=(await db.execute(select(func.count(VulnLibraryTitle.title_id)))).scalar_one(),
    )
