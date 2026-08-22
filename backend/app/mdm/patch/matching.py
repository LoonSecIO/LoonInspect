"""Match installed apps to Jamf Patch titles at device process, and record the answers.

Three questions per installed app, answered against the locally cached catalog
(`jamf_patch_titles`, global and credential-free, refreshed hourly):

1. which title(s) the app belongs to — decided by each title's `requirements`
   (`app.mdm.patch.requirements`), never by the `bundle_id` column alone: 91 bundle IDs are
   shared by 504 titles (Jamf models major versions as separate titles), and 201 titles have no
   bundle ID column at all;
2. whether the installed version is the title's `currentVersion` — "latest" means that field,
   not `patches[0]` (seven titles differ, thirty-one patch lists are not date-sorted);
3. whether Jamf has seen the installed version (`patches[].version`, exact) and when it said the
   version was released.

One app can legitimately belong to more than one title — Jamf keeps versioned titles beside
rolling ones ("Wireshark 4.2" and "Wireshark"; "TechSmith Camtasia 2022" and "TechSmith
Camtasia") — so matches are stored one row per (app, title) and the summary columns on
`installed_apps` are derived from the set.

Which titles are considered (Kyle, 2026-08-22): only those with at least one recon test on the
bundle ID or the application title — the tests that can identify an installed app. Device-level
titles ("Apple macOS …"), attribute-only titles (the `jamf-patch-*` set: JDKs, Node, Python,
daemons, and a few apps Jamf tells apart only by attribute — PyCharm Professional, Firefox) and
version-only titles are not considered; they are the patching agent's business.

Extension attributes inside a considered title are Jamf's *scoping* device for collisions
(PyCharm Community vs Professional, Firefox vs ESR), not a fact about the app: one the device
carries is evaluated for real; one it does not carry resolves TRUE, and the match is recorded
with `basis = "ea_assumed"` so the assumption stays visible. A group made only of attribute tests
can never identify an app by itself and is ignored (JetBrains PyCharm Community is `[attribute]
OR [Bundle ID is com.jetbrains.pycharm.ce]` — the second group decides).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.mdm.patch.requirements import (
    EXTENSION_ATTRIBUTE,
    Facts,
    Verdict,
    compare_versions,
    evaluate_group,
    is_app_level,
    required_bundle_ids,
    version_tuple,
)
from app.models.schema import JamfPatchTitle

logger = logging.getLogger(__name__)

BASIS_REQUIREMENTS = "requirements"
BASIS_EA_ASSUMED = "ea_assumed"  # an absent extension attribute was resolved TRUE

STATE_LATEST = "latest"
STATE_BEHIND = "behind"
STATE_AHEAD = "ahead"
STATE_UNKNOWN = "unknown"  # not a version Jamf has listed, and not newer than the latest


def _fold(value: str | None) -> str:
    return (value or "").strip().casefold()


def parse_release_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True)
class Patch:
    version: str
    released_at: datetime | None


@dataclass(frozen=True)
class CatalogTitle:
    id: str
    name: str
    bundle_id: str | None
    current_version: str
    publisher: str | None
    app_name: str | None
    patches: tuple[Patch, ...]
    requirements: tuple[Mapping, ...]
    # Extension-attribute definitions the title ships: key -> display name. Jamf Pro creates the
    # attribute under the display name when a tenant subscribes to the title, while the
    # requirement names the key; the matcher accepts either.
    extension_attribute_names: Mapping[str, str]
    app_level: bool
    required_bundle_ids: frozenset[str] | None
    # Casefolded names of the attribute tests (plus the definitions' keys and display names):
    # what the device would have to carry for the title to be decided without assuming.
    attribute_names: frozenset[str]

    @classmethod
    def build(
        cls,
        *,
        id: str,
        name: str,
        bundle_id: str | None,
        current_version: str,
        patches: Iterable[Mapping] | None,
        requirements: Iterable[Mapping] | None,
        extension_attributes: Iterable[Mapping] | None = None,
        publisher: str | None = None,
        app_name: str | None = None,
    ) -> CatalogTitle:
        groups = tuple(dict(group) for group in (requirements or []))
        definitions = {
            str(ea.get("key")): str(ea.get("displayName") or ea.get("key"))
            for ea in (extension_attributes or [])
            if ea.get("key")
        }
        tests = [test for group in groups for test in (group.get("tests") or [])]
        attribute_tests = [test for test in tests if test.get("type") == EXTENSION_ATTRIBUTE]
        attribute_names: set[str] = {_fold(str(test.get("name"))) for test in attribute_tests}
        if attribute_tests:
            for key, display_name in definitions.items():
                attribute_names.update((_fold(key), _fold(display_name)))
        return cls(
            id=id,
            name=name,
            bundle_id=bundle_id,
            current_version=current_version or "",
            publisher=publisher,
            app_name=app_name,
            patches=tuple(
                Patch(version=str(patch.get("version") or ""), released_at=parse_release_date(patch.get("releaseDate")))
                for patch in (patches or [])
            ),
            requirements=groups,
            extension_attribute_names=definitions,
            app_level=is_app_level(groups),
            required_bundle_ids=required_bundle_ids(groups),
            attribute_names=frozenset(attribute_names),
        )

    def patch_for(self, version: str | None) -> Patch | None:
        wanted = _fold(version)
        if not wanted:
            return None
        for patch in self.patches:
            if _fold(patch.version) == wanted:
                return patch
        return None

    @property
    def latest_released_at(self) -> datetime | None:
        patch = self.patch_for(self.current_version)
        return patch.released_at if patch else None


class Catalog:
    """The considered titles, indexed for the per-app lookup: titles whose every group pins a
    bundle ID with `is` are reached through that index; everything else is evaluated for every
    app. Titles with no identifying test (see the module docstring) are not here at all."""

    def __init__(self, titles: Iterable[CatalogTitle], signature: tuple = ()) -> None:
        self.signature = signature
        self.titles: list[CatalogTitle] = [title for title in titles if title.app_level]
        self.by_bundle: dict[str, list[CatalogTitle]] = {}
        self.broad: list[CatalogTitle] = []
        for title in self.titles:
            if title.required_bundle_ids is None:
                self.broad.append(title)
                continue
            for bundle in title.required_bundle_ids:
                self.by_bundle.setdefault(bundle, []).append(title)

    @classmethod
    def from_records(cls, records: Iterable[Mapping], signature: tuple = ()) -> Catalog:
        """From the catalog's own JSON shape (`bundleId`, `currentVersion`, …), as the API and the
        test fixtures carry it."""
        return cls(
            (
                CatalogTitle.build(
                    id=str(record["id"]),
                    name=str(record.get("name") or ""),
                    bundle_id=record.get("bundleId"),
                    current_version=str(record.get("currentVersion") or ""),
                    patches=record.get("patches"),
                    requirements=record.get("requirements"),
                    extension_attributes=record.get("extensionAttributes"),
                    publisher=record.get("publisher"),
                    app_name=record.get("appName"),
                )
                for record in records
            ),
            signature,
        )

    @classmethod
    def from_rows(cls, rows: Iterable[JamfPatchTitle], signature: tuple = ()) -> Catalog:
        return cls(
            (
                CatalogTitle.build(
                    id=row.id,
                    name=row.name,
                    bundle_id=row.bundle_id,
                    current_version=row.current_version,
                    patches=row.patches,
                    requirements=row.requirements,
                    extension_attributes=row.extension_attributes,
                    publisher=row.publisher,
                    app_name=row.app_name,
                )
                for row in rows
            ),
            signature,
        )

    def candidates(self, bundle_id: str | None) -> list[CatalogTitle]:
        return self.by_bundle.get(_fold(bundle_id), []) + self.broad


@dataclass(frozen=True)
class TitleMatch:
    title: CatalogTitle
    basis: str
    installed_version: str | None
    version_known: bool
    on_latest: bool
    state: str
    installed_released_at: datetime | None
    latest_version: str
    latest_released_at: datetime | None
    # Jamf's release date of the earliest listed version newer than the installed one — when
    # a patch first became available, by the catalog's clock.
    first_newer_released_at: datetime | None


def classify(versions: Sequence[str], title: CatalogTitle) -> TitleMatch:
    """The version questions for one (app, title) pair; `basis` is filled in by the caller."""
    known: Patch | None = None
    installed: str | None = versions[0] if versions else None
    for version in versions:
        patch = title.patch_for(version)
        if patch is not None:
            known, installed = patch, version
            break

    on_latest = any(_fold(version) == _fold(title.current_version) for version in versions)
    if on_latest:
        state = STATE_LATEST
    elif installed and compare_versions(installed, title.current_version) > 0:
        state = STATE_AHEAD
    elif known is not None:
        state = STATE_BEHIND
    else:
        state = STATE_UNKNOWN

    first_newer: datetime | None = None
    if state in (STATE_BEHIND, STATE_UNKNOWN) and installed:
        newer = [
            patch.released_at
            for patch in title.patches
            if patch.released_at is not None and compare_versions(patch.version, installed) > 0
        ]
        first_newer = min(newer) if newer else title.latest_released_at

    return TitleMatch(
        title=title,
        basis=BASIS_REQUIREMENTS,
        installed_version=installed,
        version_known=known is not None,
        on_latest=on_latest,
        state=state,
        installed_released_at=known.released_at if known else None,
        latest_version=title.current_version,
        latest_released_at=title.latest_released_at,
        first_newer_released_at=first_newer,
    )


def _facts_for(facts: Facts, title: CatalogTitle) -> tuple[Facts, set[str]]:
    """The facts as this title sees them, and the casefolded attribute names the device does
    carry for it — by the requirement's name (the definition's key) or by the definition's
    display name, which is what Jamf Pro calls the attribute it creates. Absent attributes
    resolve TRUE (see the module docstring)."""
    present = {_fold(name): value for name, value in facts.extension_attributes.items()}
    extra: dict[str, str | None] = {}
    for key, display_name in title.extension_attribute_names.items():
        if _fold(key) not in present and _fold(display_name) in present:
            extra[key] = present[_fold(display_name)]
    carried = set(present) | {_fold(key) for key in extra}
    return (
        Facts(
            app_name=facts.app_name,
            bundle_id=facts.bundle_id,
            versions=facts.versions,
            os_version=facts.os_version,
            platform=facts.platform,
            extension_attributes={**facts.extension_attributes, **extra},
            assume_missing_attributes=True,
        ),
        carried,
    )


def _decide(title: CatalogTitle, facts: Facts) -> str | None:
    """The basis on which this title matches the app, or None. Groups are evaluated one by
    one so the basis reflects the group that carried the match; a group made only of
    attribute tests identifies nothing by itself."""
    title_facts, carried = _facts_for(facts, title)
    basis: str | None = None
    for group in title.requirements:
        tests = list(group.get("tests") or [])
        attribute_tests = [test for test in tests if test.get("type") == EXTENSION_ATTRIBUTE]
        if attribute_tests and len(attribute_tests) == len(tests):
            continue  # device scoping, not an app test
        if evaluate_group(group, title_facts) is not Verdict.MATCHED:
            continue
        assumed = any(_fold(str(test.get("name"))) not in carried for test in attribute_tests)
        if not assumed:
            return BASIS_REQUIREMENTS
        basis = BASIS_EA_ASSUMED
    return basis


def match_app(facts: Facts, catalog: Catalog) -> list[TitleMatch]:
    """Every title this app belongs to, with the version answers. Deterministic order:
    fully-evaluated matches first, then by title name."""
    matches: list[TitleMatch] = []
    for title in catalog.candidates(facts.bundle_id):
        basis = _decide(title, facts)
        if basis is None:
            continue
        answer = classify(facts.versions, title)
        matches.append(TitleMatch(**{**answer.__dict__, "basis": basis}))
    matches.sort(key=lambda match: (match.basis != BASIS_REQUIREMENTS, match.title.name.casefold(), match.title.id))
    return matches


@dataclass(frozen=True)
class AppPatchSummary:
    """The per-app columns on `installed_apps`, derived from the app's matches.

    `is_latest` is Kyle's rule: at least one matched title says the installed version is its
    current one — so a Firefox ESR user on the latest ESR is latest even though the rolling
    "Mozilla Firefox" title says behind, and Camtasia 2022 on 2022.6.10 is latest on its line.
    The title that says so supplies the state and the latest version; otherwise the rolling title
    (the highest `currentVersion` among the matches) does, so an app behind everywhere shows what
    the vendor ships now. A patch is available only when no title says latest and one says behind.
    """

    title_ids: list[str]
    state: str
    is_compliant: bool
    patch_available: bool
    patch_available_since: datetime | None
    this_version_seen: bool
    latest_version: str
    latest_released_at: datetime | None


def summarize(matches: Sequence[TitleMatch]) -> AppPatchSummary | None:
    if not matches:
        return None
    on_latest = [match for match in matches if match.on_latest]
    reference = (
        on_latest[0]
        if on_latest
        else max(matches, key=lambda match: (version_tuple(match.latest_version), match.basis == BASIS_REQUIREMENTS))
    )
    behind = [match for match in matches if match.state in (STATE_BEHIND, STATE_UNKNOWN)]
    patch_available = not on_latest and bool(behind)
    since = [match.first_newer_released_at for match in behind if match.first_newer_released_at is not None]
    return AppPatchSummary(
        title_ids=[match.title.id for match in matches],
        state=STATE_LATEST if on_latest else reference.state,
        is_compliant=bool(on_latest),
        patch_available=patch_available,
        patch_available_since=min(since) if patch_available and since else None,
        this_version_seen=any(match.version_known for match in matches),
        latest_version=reference.latest_version,
        latest_released_at=reference.latest_released_at,
    )


_cache: Catalog | None = None


async def load_catalog(db: AsyncSession) -> Catalog:
    """The catalog, built once per process and rebuilt when the table's row count or newest
    `synced_at` moves — the two things the hourly sync changes."""
    global _cache
    count, newest = (await db.execute(select(func.count(), func.max(JamfPatchTitle.synced_at)).select_from(JamfPatchTitle))).one()
    signature = (count, newest)
    if _cache is not None and _cache.signature == signature:
        return _cache
    rows = (await db.execute(select(JamfPatchTitle))).scalars().all()
    catalog = Catalog.from_rows(rows, signature)
    logger.info("jamf patch catalog indexed", extra={"titles": len(catalog.titles), "broad": len(catalog.broad)})
    _cache = catalog
    return catalog


def reset_catalog_cache() -> None:
    global _cache
    _cache = None
