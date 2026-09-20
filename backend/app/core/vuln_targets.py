"""Read stored per-title update effects for a device or catalog page in one batch (#526)."""

from collections.abc import Sequence

from sqlalchemy import select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.vuln import VulnCorpus
from app.core.vuln_library import loaded_epoch_signature
from app.core.vuln_read import update_line
from app.models.schema import AppCatalogEntry, AppCatalogTitleMatch, InstalledApp, JamfPatchTitle
from app.schemas.catalog import VulnTitleUpdateOut


async def load_title_updates(
    db: AsyncSession, rows: Sequence[AppCatalogEntry | InstalledApp], *, corpus: VulnCorpus, platform: str | None = None
) -> dict[tuple[str, str], list[VulnTitleUpdateOut]]:
    if corpus.as_of is None or not rows:
        return {}
    by_build = {(platform or row.platform, row.version_hash): row for row in rows}
    query = (
        select(
            AppCatalogTitleMatch,
            AppCatalogEntry.platform,
            AppCatalogEntry.version_hash,
            AppCatalogEntry.reference_title_id,
            JamfPatchTitle.name,
        )
        .join(AppCatalogEntry, AppCatalogEntry.id == AppCatalogTitleMatch.app_catalog_id)
        .join(JamfPatchTitle, JamfPatchTitle.id == AppCatalogTitleMatch.title_id)
        .where(
            tuple_(AppCatalogEntry.platform, AppCatalogEntry.version_hash).in_(list(by_build)),
            AppCatalogEntry.vuln_signature == loaded_epoch_signature(),
            JamfPatchTitle.name != "",
        )
        .order_by(AppCatalogTitleMatch.title_id)
        .execution_options(populate_existing=True)
    )
    result: dict[tuple[str, str], list[VulnTitleUpdateOut]] = {}
    for target, kind, version_hash, reference, name in (await db.execute(query)).all():
        key = (kind, version_hash)
        effect = update_line(by_build[key], corpus=corpus, target=target)
        if effect is None:
            continue
        line = VulnTitleUpdateOut(**effect.model_dump(), title_id=target.title_id, title_name=name)
        lines = result.setdefault(key, [])
        if target.title_id == reference:
            lines.insert(0, line)
        else:
            lines.append(line)
    return result
