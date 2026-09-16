"""Bundle IDs no public source on this container knows, and what a glob matches (#483).

Settings > Data Sharing > **Excluded bundle IDs** is a textarea an operator fills from
memory: nothing on the page said which bundle IDs the fleet carries, nor what a pattern
matches. The preview cannot say either — its app rows are hashes, so it shows that a glob
removed *some* rows and never which.

Two answers, both from inventory already here and neither from a model. A title is a
**candidate** when no `app_catalog_title_matches` row exists for any of its builds (the
Jamf Patch answer, reached from `installed_apps` by `version_hash`) and no
`vuln_library_titles.key_title` equals its key. Candidates group by reverse-DNS prefix,
and a prefix no *known* title uses with several unknown titles under it earns a
`com.acme.*` suggestion. Unknown is necessary and not sufficient — Jamf's catalog holds
about 1,550 titles, so most of a fleet's long tail is public software it has never heard
of — so this says *no public source here knows these* and never *these are yours*.

**Counts** come from the exchange's own `_excluded`, imported rather than reimplemented,
so what the page says and what leaves the box cannot disagree. A glob that matches nothing
says so, and a bundle ID a case-insensitive comparison would have matched is named as a
near-miss: `fnmatch` is case-sensitive in the Linux container, which is how `com.acme.*`
quietly misses `com.Acme.Deploy`. Nothing here writes — an accepted suggestion goes
through the audited `PUT /api/system/data-sharing` exactly as a typed glob does.
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
from app.schemas.system import (
    ExclusionCandidateAppOut,
    ExclusionCandidateGroupOut,
    ExclusionCandidatesOut,
    ExclusionGlobCountOut,
)

# Ceilings, because the long tail is the fleet: a list past a screenful stops being a
# suggestion and becomes the inventory report the Applications page already is.
MAX_GROUPS = 12
MAX_APPS_PER_GROUP = 12
MAX_GLOBS = 40
MAX_CASE_MISSES = 5

# The one reason a row can be here today, carried per row because the next thing this
# surface grows is a second one.
REASON_UNKNOWN = "no_public_source"


@dataclass(frozen=True)
class _Row:
    bundle_id: str
    key_title: str
    name: str
    device_count: int
    known: bool


def prefix_of(bundle_id: str) -> str | None:
    """`com.acme` from `com.acme.payroll`; None where there is nothing to generalize.

    Two labels are the organization and the third is the product, so a bundle ID with
    fewer than three has no prefix that says less than the ID itself — `com.acme.*` does
    not even match `com.acme`.
    """
    labels = bundle_id.split(".")
    return ".".join(labels[:2]) if len(labels) >= 3 and all(labels[:2]) else None


async def _rows(db: AsyncSession) -> list[_Row]:
    """Every (bundle ID, title) the fleet carries, its device count, and whether a public
    source knows it. One aggregate, because the same rows answer *what is unknown* and
    *what a glob matches* and two queries could disagree by a sweep.

    The match test is at title grain: a title with one matched build and one unmatched
    build is **known**, which an outer join counted to zero says and a per-row `NOT
    EXISTS` would not — that would file the unmatched build as a candidate and invite an
    operator to exclude software Jamf publishes.
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
    return [_Row(r.bundle_id, r.key_title, r.name, r.device_count, r.matches > 0 or r.key_title in library) for r in result.all()]


async def _device_counts(db: AsyncSession, sets: list[set[str]]) -> list[int]:
    """Distinct devices carrying at least one app from each bundle-ID set, in one query.

    Per-app counts cannot be summed — a Mac with three of the organization's four apps
    would be counted three times — so each set gets a `count(distinct …)` over a `CASE`
    that answers NULL off-set, and `COUNT DISTINCT` drops the NULLs.
    """
    wanted: set[str] = set().union(*sets) if sets else set()
    if not wanted:
        return [0] * len(sets)
    columns = [func.count(distinct(case((InstalledApp.bundle_id.in_(sorted(s)), InstalledApp.device_id)))) for s in sets if s]
    values = iter((await db.execute(select(*columns).where(InstalledApp.bundle_id.in_(sorted(wanted))))).one())
    return [int(next(values) or 0) if s else 0 for s in sets]


def _spelling(bundle_ids: list[str]) -> str | None:
    """Which casing of a prefix to show where the fleet spells it more than one way: the
    commonest, with an all-lowercase spelling breaking the tie. A glob matches
    case-sensitively, so this decides which of the group a suggestion covers — and the
    near-misses beside its count name the rest."""
    counts: dict[str, int] = {}
    for bundle_id in bundle_ids:
        if prefix := prefix_of(bundle_id):
            counts[prefix] = counts.get(prefix, 0) + 1
    return max(sorted(counts), key=lambda p: (counts[p], p == p.lower())) if counts else None


async def build_candidates(db: AsyncSession, globs: list[str]) -> ExclusionCandidatesOut:
    """Candidate groups, and a count for every glob. `globs` is the box as it stands — the
    stored list, or the draft the page is holding, which is how a pattern can be counted
    before it is saved."""
    rows = await _rows(db)
    known_prefixes = {p.lower() for r in rows if r.known and (p := prefix_of(r.bundle_id))}
    all_bundle_ids = {r.bundle_id for r in rows}

    grouped: dict[str, list[_Row]] = {}
    for row in rows:
        if not row.known:
            grouped.setdefault((prefix_of(row.bundle_id) or row.bundle_id).lower(), []).append(row)
    ordered = sorted(grouped.values(), key=lambda g: (-sum(r.device_count for r in g), -len(g), g[0].bundle_id))
    shown, more = ordered[:MAX_GROUPS], max(0, len(ordered) - MAX_GROUPS)

    typed = [g for g in dict.fromkeys(globs) if g][:MAX_GLOBS]
    labels = [_spelling([r.bundle_id for r in group]) for group in shown]
    # Several titles, and a prefix no known title uses: the two conditions that make
    # "everything under this prefix" a statement about the organization rather than about
    # one obscure public app that happens to be unmatched.
    suggestions = [
        f"{label}.*" if label and len(group) >= 2 and label.lower() not in known_prefixes else None
        for label, group in zip(labels, shown, strict=True)
    ]
    evaluated = typed + [s for s in dict.fromkeys(suggestions) if s and s not in typed]
    sources = ["typed"] * len(typed) + ["suggested"] * (len(evaluated) - len(typed))
    matched = [{b for b in all_bundle_ids if _excluded(b, [glob])} for glob in evaluated]
    group_sets = [{r.bundle_id for r in group} for group in shown]
    counts = await _device_counts(db, group_sets + matched)

    return ExclusionCandidatesOut(
        groups=[
            ExclusionCandidateGroupOut(
                prefix=label or group[0].bundle_id,
                suggestion=suggestion,
                # Covered already: every app here is one a glob in the box removes today,
                # so the page says so instead of offering a glob it already holds.
                excluded=all(_excluded(r.bundle_id, typed) for r in group),
                app_count=len(group),
                device_count=count,
                apps=[
                    ExclusionCandidateAppOut(
                        name=r.name, bundle_id=r.bundle_id, device_count=r.device_count, reason=REASON_UNKNOWN
                    )
                    for r in sorted(group, key=lambda r: (-r.device_count, r.bundle_id))[:MAX_APPS_PER_GROUP]
                ],
            )
            for group, label, suggestion, count in zip(shown, labels, suggestions, counts, strict=False)
        ],
        more_groups=more,
        globs=[
            ExclusionGlobCountOut(
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
