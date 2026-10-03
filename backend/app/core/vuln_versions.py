"""The corpus's answer for each version a Jamf title lists — the Jamf Patch title page's
Vulnerability column, at the grain that page is about.

#298 deleted the column that stood there and said a real one could not be built at this
grain: the corpus is keyed on the installed app's name (`key_full`), which a Jamf title's
version row did not carry. Both halves of that have since moved. #385 gave every title the
app name a Mac reports, and `app_catalog_versions` holds the content key for every
(title, bundle ID, listed version) — the very key the compiler hashes, because the corpus is
compiled from Jamf's catalog (docs/vulnerabilities.md §1). So a listed version is a build
the epoch can be asked about whether or not any Mac in this tenant carries it, which is the
question a version history is read with: *what would this release put on a Mac*.

**The verdict is still a row and nothing else** (ruling R-D). A listed version the epoch
holds no row for reads `unknown_app`, dated, never zero — a title nothing names an app for
(#385's `unnamed`) has no key to ask with and reads the same.

**It reads the library and not the tenant's catalog**, which is the one place this differs
from every other reader (`vuln_read`): `app_catalog` holds an answer only for builds the
fleet has shown, and most of a title's versions are on no Mac. The gate does not move —
`earned_corpus` decides whether anything answers for this tenant at all, and under tenant
selection the rows are the selected release's and no other's. One statement per title.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date
from types import SimpleNamespace

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.vuln import AssessedBuild, VulnCorpus, vuln_block
from app.core.vuln_answer import StoredAnswers, stored_build
from app.core.vuln_library import loaded_epoch_signature
from app.models.schema import AppCatalogVersion, VulnCorpusReleaseRow, VulnLibraryRow
from app.schemas.payload import VULN_ASSESSMENT_COVERED, VulnEnrichment


async def title_version_vulns(
    db: AsyncSession, title_id: str, versions: Sequence[str], *, corpus: VulnCorpus, as_of: date
) -> dict[str, VulnEnrichment]:
    """`version -> vuln{}` for every version in `versions`, or `{}` where nothing answers.

    `{}` is `off` for the whole title and the page draws no column: a version missing from a
    non-empty answer does not happen, so an absent key is never a build to guess about.

    A title that speaks for several bundle IDs has several keys per version. The first one
    the epoch holds a row for answers, in the order the catalog walks them; a version is
    `unknown_app` only when none of its keys has a row.
    """
    if corpus.as_of is None or not versions:
        return {}
    row_type = VulnCorpusReleaseRow if settings.vuln_tenant_selection else VulnLibraryRow
    on = row_type.key_full == AppCatalogVersion.key_full
    if row_type is VulnCorpusReleaseRow:
        on = and_(on, row_type.signature == loaded_epoch_signature())
    stmt = (
        select(
            AppCatalogVersion.version,
            AppCatalogVersion.key_title,
            AppCatalogVersion.key_full,
            row_type.counts,
            row_type.oldest_published,
            row_type.ids,
            row_type.truncated,
        )
        .join(row_type, on)
        .where(AppCatalogVersion.title_id == title_id)
        .order_by(AppCatalogVersion.id)
    )
    keys: dict[str, tuple[str, str]] = {}
    answers: dict[str, AssessedBuild] = {}
    for version, key_title, key_full, counts, oldest, ids, truncated in (await db.execute(stmt)).all():
        if version in keys:
            continue
        build = _assessed(key_full, counts, oldest, ids, truncated)
        if build is not None:
            keys[version] = (key_title, key_full)
            answers[key_full] = build

    answering = StoredAnswers(corpus.as_of, answers)
    blocks: dict[str, VulnEnrichment] = {}
    for listed in versions:
        key_title, key_full = keys.get(listed.strip(), ("", ""))
        blocks[listed] = vuln_block(answering, key_title=key_title, key_full=key_full, as_of=as_of)
    return blocks


def _assessed(key_full: str, counts: Mapping, oldest: Mapping, ids: Sequence[str], truncated: bool) -> AssessedBuild | None:
    """A library row as the seam's `AssessedBuild`, through `stored_build` so the parse and
    its invariants are the ones every other reader uses. A row that will not parse is left
    out — the version reads `unknown_app` — for `vuln_answer._unreadable`'s reason: the
    import validated it, so this is a store that moved, and a title page is not the place
    to raise about it."""
    row = SimpleNamespace(
        key_full=key_full,
        vuln_assessment=VULN_ASSESSMENT_COVERED,
        vuln_counts=counts,
        vuln_oldest_published=oldest,
        vuln_ids=ids,
        vuln_ids_truncated=truncated,
    )
    try:
        return stored_build(row)  # type: ignore[arg-type]
    except (KeyError, TypeError, ValueError):
        return None
