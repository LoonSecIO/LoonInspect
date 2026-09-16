"""Bundle IDs no public source on this container knows, and what a glob matches (#483).

**Excluded bundle IDs** is a textarea an operator fills from memory, and the preview cannot
check it: its app rows are hashes, so it shows that a glob removed *some* rows and never
which. Two answers, from inventory already here, with no model in either.

A title is a **candidate** when no `app_catalog_title_matches` row exists for any of its
builds (the Jamf Patch answer, reached from `installed_apps` by `version_hash`) and no
`vuln_library_titles.key_title` equals its key. Candidates group by reverse-DNS prefix, and
a prefix no *known* title uses earns a `com.acme.*` suggestion. Unknown is necessary and
not sufficient — Jamf's catalog holds about 1,550 titles, so most of a fleet's long tail is
public software it never heard of — so this says *no public source here knows these* and
never *these are yours*.

**Counts** use the exchange's own `_excluded`, imported rather than reimplemented, and they
count *rows* — one per (bundle ID, title) — because that is the grain the exchange drops at.
One bundle ID carries two titles whenever two display names share it (a rename mid-rollout,
a white-labelled build, a localized name: `key_title` hashes the name), so counting matched
bundle IDs would tell the operator a glob removes fewer apps than it does, on the one
surface built to judge a pattern's reach. One word, one grain: `groups[].appCount` counts
the same rows. A glob matching nothing says so, and a bundle ID a case-insensitive
comparison would have matched is named as a near-miss: `fnmatch` is case-sensitive in the
container, which is how `com.acme.*` misses `com.Acme.Deploy`. Nothing here writes — an
accepted suggestion goes through the audited PUT like a typed one.
"""

from __future__ import annotations

from fnmatch import fnmatch
from typing import NamedTuple

from sqlalchemy import ARRAY, ColumnElement, String, any_, case, distinct, func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.sharing import _excluded
from app.models.schema import AppCatalogEntry, AppCatalogTitleMatch, InstalledApp, JamfPatchTitle, VulnLibraryTitle
from app.schemas.system import ExclusionCandidateAppOut as AppOut
from app.schemas.system import ExclusionCandidateGroupOut as GroupOut
from app.schemas.system import ExclusionCandidatesOut, ExclusionGlobCountOut

# Ceilings, because the long tail is the fleet: a list past a screenful stops being a
# suggestion and becomes the inventory report the Applications page already is.
MAX_GROUPS, MAX_APPS_PER_GROUP, MAX_GLOBS, MAX_CASE_MISSES = 12, 12, 40, 5

# The one reason a row can be here today, carried per row because the next thing this
# surface grows is a second one.
REASON_UNKNOWN = "no_public_source"


class _Row(NamedTuple):
    bundle_id: str
    name: str
    device_count: int
    known: bool


def prefix_of(bundle_id: str) -> str | None:
    """`com.acme` from `com.acme.payroll`; None below three labels, where the prefix would
    say no less than the ID itself and `com.acme.*` would not even match it."""
    labels = bundle_id.split(".")
    return ".".join(labels[:2]) if len(labels) >= 3 and all(labels[:2]) else None


async def _rows(db: AsyncSession) -> list[_Row]:
    """Every (bundle ID, title) the fleet carries, its device count, and whether a public
    source knows it — one aggregate, because the same rows answer *what is unknown* and
    *what a glob matches*, and two queries could disagree by a sweep.

    At title grain: a title with one matched build and one unmatched build is **known**,
    which an outer join counted to zero says and a per-row `NOT EXISTS` would not — that
    files the unmatched build as a candidate and invites excluding software Jamf ships.
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
    return [_Row(r.bundle_id, r.name, r.device_count, r.matches > 0 or r.key_title in library) for r in result.all()]


async def _device_counts(db: AsyncSession, sets: list[set[str]]) -> list[int]:
    """Distinct devices carrying at least one app from each bundle-ID set, in one query.
    Per-app counts cannot be summed — a Mac with three of four would count three times —
    so each set gets a `count(distinct …)` over a `CASE` that is NULL off-set.

    Each set travels as **one** array parameter, not an `IN (…)` list of them: `com.*` over
    a real fleet is thousands of bundle IDs, some sixty sets are evaluated per call, and
    asyncpg refuses a statement past 32,767 parameters — a ceiling an operator would meet as
    a raised `InterfaceError` and a panel that stopped answering.
    """

    def one_of(bundle_ids: set[str]) -> ColumnElement[bool]:
        return InstalledApp.bundle_id == any_(literal(sorted(bundle_ids), ARRAY(String)))

    wanted: set[str] = set().union(*sets) if sets else set()
    if not wanted:
        return [0] * len(sets)
    columns = [func.count(distinct(case((one_of(s), InstalledApp.device_id)))) for s in sets if s]
    values = iter((await db.execute(select(*columns).where(one_of(wanted)))).one())
    return [int(next(values) or 0) if s else 0 for s in sets]


def _spelling(bundle_ids: list[str]) -> str | None:
    """Which casing to show where the fleet spells a prefix more than one way: the
    commonest, lowercase breaking the tie. A glob matches case-sensitively, so this decides
    which of the group a suggestion covers; the near-misses beside it name the rest."""
    counts: dict[str, int] = {}
    for bundle_id in bundle_ids:
        if prefix := prefix_of(bundle_id):
            counts[prefix] = counts.get(prefix, 0) + 1
    return max(sorted(counts), key=lambda p: (counts[p], p == p.lower())) if counts else None


async def build_candidates(db: AsyncSession, globs: list[str]) -> ExclusionCandidatesOut:
    """Candidate groups, and a count for every glob. `globs` is the box as it stands — the
    stored list, or the draft the page holds, so a pattern is counted before it is saved."""
    rows = await _rows(db)
    known_prefixes = {p.lower() for r in rows if r.known and (p := prefix_of(r.bundle_id))}
    all_bundle_ids = {r.bundle_id for r in rows}

    grouped: dict[str, list[_Row]] = {}
    for row in rows:
        if not row.known:
            # A bundle ID with no prefix of its own (`com.acme`) groups alone, under a key
            # starting with a dot so no prefix can collide with it: inside `com.acme`'s
            # group it would be counted by a `com.acme.*` suggestion that cannot match it.
            prefix = prefix_of(row.bundle_id)
            grouped.setdefault(prefix.lower() if prefix else f".{row.bundle_id.lower()}", []).append(row)
    ordered = sorted(grouped.values(), key=lambda g: (-sum(r.device_count for r in g), -len(g), g[0].bundle_id))
    shown, more = ordered[:MAX_GROUPS], max(0, len(ordered) - MAX_GROUPS)

    typed = [g for g in dict.fromkeys(globs) if g][:MAX_GLOBS]
    labels = [_spelling([r.bundle_id for r in group]) for group in shown]
    # Several titles, under a prefix no known title uses: the two conditions that make
    # "everything under this prefix" a statement about the organization rather than about
    # one obscure public app that happens to be unmatched.
    suggestions = [
        f"{label}.*" if label and len(group) >= 2 and label.lower() not in known_prefixes else None
        for label, group in zip(labels, shown, strict=True)
    ]
    evaluated = typed + [s for s in dict.fromkeys(suggestions) if s and s not in typed]
    sources = ["typed"] * len(typed) + ["suggested"] * (len(evaluated) - len(typed))
    # Rows, not bundle IDs: two titles under one bundle ID are two apps the exchange drops,
    # and this page says "app" in exactly one grain. The ID set beside it is for the device
    # count, which is per device and so cannot be taken at the row grain at all.
    matched = [[r for r in rows if _excluded(r.bundle_id, [glob])] for glob in evaluated]
    matched_ids = [{r.bundle_id for r in hits} for hits in matched]
    group_sets = [{r.bundle_id for r in group} for group in shown]
    counts = await _device_counts(db, group_sets + matched_ids)

    return ExclusionCandidatesOut(
        groups=[
            GroupOut(
                prefix=label or group[0].bundle_id,
                suggestion=suggestion,
                # Covered already: every app here is one a glob in the box removes today, so
                # the page says so instead of offering a glob the box already holds.
                excluded=all(_excluded(r.bundle_id, typed) for r in group),
                app_count=len(group),
                device_count=count,
                apps=[
                    AppOut(name=r.name, bundle_id=r.bundle_id, device_count=r.device_count, reason=REASON_UNKNOWN)
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
                case_misses=sorted(b for b in all_bundle_ids if b not in ids and fnmatch(b.lower(), glob.lower()))[
                    :MAX_CASE_MISSES
                ],
            )
            for glob, source, hits, ids, count in zip(
                evaluated, sources, matched, matched_ids, counts[len(group_sets) :], strict=True
            )
        ],
        catalog_titles=(await db.execute(select(func.count(JamfPatchTitle.id)))).scalar_one(),
        library_titles=(await db.execute(select(func.count(VulnLibraryTitle.title_id)))).scalar_one(),
    )
