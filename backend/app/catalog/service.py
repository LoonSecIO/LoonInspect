"""The tenant app catalog — the rows, when they are written, and when they are judged.

A row is one distinct (name, bundle ID, version[, short version]) the tenant's fleet has shown,
keyed by `version_hash` (the same md5 every installed app carries), with `first_seen_at` and
`last_seen_at` on any device. The Jamf answer on the row — which titles, is it the latest, has
Jamf seen this version, when was it released — comes from the #65 rules (`app.mdm.patch.matching`)
evaluated against the row's own facts: no device facts, so extension attributes resolve TRUE,
which is Kyle's practice for them anyway.

The **vulnerability** answer for the row is judged in the same place and kept in the same shape
(#381): a `key_full` equality against the corpus epoch this container has loaded
(`vuln_library_rows`, #248), run as one `UPDATE … FROM` per epoch per tenant and copied onto
`installed_apps` exactly as the Jamf answer is. A row in the library is the only thing that
means "assessed", so a build with no row reads `unknown_app` and never a clean bill
(docs/vulnerabilities.md §4f). The two answers have two clocks — the Jamf catalog moves hourly,
the corpus daily — so they have two signatures and each is re-judged when its own moves.

When rows are judged:

* **at first sight** — `record_device_apps` runs inside `process_sync`: it upserts the device's
  apps into the catalog (first/last seen), evaluates every row whose answer is missing or older
  than the current catalog (its `evaluated_signature`), joins the rows whose corpus epoch moved
  (`vuln_signature`), and copies the answer onto the device's `installed_apps` columns so the
  device pages need no join;
* **after every Jamf catalog sync** — `refresh_tenant` re-evaluates the rows whose signature is
  stale (a new release changes "latest" for a whole title the hour it lands), re-joins the rows
  whose epoch moved, and refreshes the copies; a sync that changed nothing costs nothing.

Devices reach their answer through `installed_apps.version_hash`; the per-device matches table
from #65 is gone.

Why it is built as cache tables at all (Kyle, 2026-08-22): the question is how to get a device
from Jamf Pro to Splunk as fast as possible — wait for as little as possible, have as much as
possible cached. Jamf patching, vulnerability and the other enrichments are *lookups*, not
things calculated per device; calculating them means touching hundreds of MB for each device
when the goal is 40k devices in ten minutes. So the per-device cost of this module is kept to
its own rows: one SELECT of the device's apps, one SELECT of their catalog rows by hash, the
inserts for triples the fleet has never shown, a `last_seen_at` write at most once per
`LAST_SEEN_GRANULARITY` per distinct app (not once per device carrying it), an in-memory rule
pass only for rows the current catalog has not judged, and copies onto app rows only when a row
is new or its answer moved. Nothing per device reads the catalog tables themselves; the title
index lives in process memory, is asked whether it is current at most once per
`CATALOG_PROBE_INTERVAL` rather than once per device (#142), and is rebuilt only when the
catalog changes.

Follow-ups: a per-device override that reads a carried extension attribute, and rows for apps
that arrive through other paths than an MDM inventory (HEC).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, case, delete, null, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased
from sqlalchemy.orm.attributes import set_committed_value

from app.core.config import settings
from app.core.content_keys import app_full_key
from app.core.tenant_jobs import operational_tenant_ids, tenant_job
from app.core.vuln_answer import VULN_ANSWER_COLUMNS
from app.core.vuln_library import loaded_epoch_signature, read_tenant_tier
from app.mdm.patch.matching import CATALOG_PROBE_INTERVAL, Catalog, TitleMatch, load_catalog, match_app, summarize
from app.mdm.patch.requirements import Facts, jamf_platform_name
from app.models.schema import (
    AppCatalogEntry,
    AppCatalogTitleMatch,
    Device,
    InstalledApp,
    JamfPatchTitle,
    VulnCorpusReleaseRow,
    VulnLibraryRow,
)
from app.schemas.payload import VULN_ASSESSMENT_COVERED

logger = logging.getLogger(__name__)

# "Most recently seen on a device" is answered to this granularity: a row's last_seen_at moves
# when it is older than this, so a sweep writes it about once per distinct app rather than once
# per device carrying the app (40k devices x 80 apps would otherwise be ~3M row updates a sweep).
LAST_SEEN_GRANULARITY = timedelta(minutes=15)


def catalog_signature(catalog: Catalog) -> str:
    """The match shape and catalog revision; v2 re-matches existing rows for per-title targets (#526)."""
    count, newest = (*catalog.signature, None, None)[:2]
    stamp = newest.isoformat() if isinstance(newest, datetime) else ""
    return f"titles-v2:{count or 0}:{stamp}"


def _released_at(matches: Sequence[TitleMatch]) -> datetime | None:
    for match in matches:
        if match.version_known and match.installed_released_at is not None:
            return match.installed_released_at
    return None


def _apply_summary(entry: AppCatalogEntry, matches: Sequence[TitleMatch], *, now: datetime, signature: str) -> None:
    summary = summarize(matches)
    entry.evaluated_at = now
    entry.evaluated_signature = signature
    if summary is None:
        entry.jamf_title_ids = None
        entry.patch_state = None
        entry.is_latest = None
        entry.patch_available = None
        entry.patch_available_since = None
        entry.releases_missed = None
        entry.this_version_seen = None
        entry.latest_version = None
        entry.latest_released_at = None
        entry.ea_assumed = None
        entry.reference_title_id = None
        entry.sentence_title_id = None
        entry.released_at = None
        entry.vuln_target_key = None
        return
    entry.jamf_title_ids = summary.title_ids
    entry.patch_state = summary.state
    entry.is_latest = summary.is_compliant
    entry.patch_available = summary.patch_available
    entry.patch_available_since = summary.patch_available_since
    entry.releases_missed = summary.releases_missed
    entry.this_version_seen = summary.this_version_seen
    entry.latest_version = summary.latest_version
    entry.latest_released_at = summary.latest_released_at
    entry.ea_assumed = summary.ea_assumed
    entry.reference_title_id = summary.reference_title_id
    entry.sentence_title_id = summary.sentence_title_id
    entry.released_at = _released_at(matches)
    # The corpus key for the build this one would become (#482), written here because it
    # is a fact about the JAMF answer and moves on the Jamf clock: this row's own name and
    # bundle id with the reference title's latest version in the version slot and `None` in
    # the fourth, which is how `vuln_library_rows` is keyed (§4f). Formed from the installed
    # build's own identity, so #385's unnamed titles never reach it.
    entry.vuln_target_key = app_full_key(entry.name, entry.bundle_id, summary.latest_version, None)


async def judge_vuln(
    db: AsyncSession, entries: Sequence[AppCatalogEntry] | None, *, now: datetime, release: str | None = None
) -> int:
    """The local join (#381): the loaded epoch's answer for a build, onto the catalog row.

    **One statement, whatever the scope.** `entries` names the rows to judge — the ones a
    device just showed, or the ones a catalog pass just re-matched — and `None` means *every
    row of this tenant whose answer came from a different epoch*, which is the shape a new
    epoch costs: one `UPDATE … FROM` per epoch per tenant, over distinct builds, never over
    devices. The join is `key_full` equality against `vuln_library_rows` and nothing else
    (ruling R-D): a build with a row is `covered` with that row's aggregates — clean when its
    ids are empty — and a build without one is left NULL, which reads `unknown_app`. The
    coverage metadata in `vuln_library_titles` is not consulted and must never become an
    input here.

    The outer join is what makes it one statement rather than two: the same pass that writes
    an answer onto the rows the epoch assessed clears it off the rows it did not.

    **A named scope is re-written even when its signature already names this epoch**, and
    that is deliberate rather than an oversight in the two-clocks story: a caller that hands
    over rows is asking for them to be judged now, and it is what makes *Refresh* the repair
    `docs/troubleshooting.md` §5 step 4 promises for a stored answer that will not parse. A
    signature filter here would cost a catalog sync one rewrite less and would leave a
    corrupted row unrepairable by the only button the operator has. The `entries is None`
    scope — the epoch's own pass — does filter on the signature, which is where the cost
    that grows with the fleet actually lives.

    With tenant selection enabled, the writer first locks the tenant and refreshes its
    selection. Both installed and target joins use retained rows constrained by digest.
    Only the selection transaction passes `release` explicitly, after checking acquisition.
    The following gate description applies to the default legacy path.

    **Which epoch, and the gate.** `loaded_epoch_signature()` costs no query and already
    applies #281 Option A's per-tenant gate, so a tenant whose data-sharing tier is `off`
    judges to `None` and carries no corpus-derived columns at all — the library's rows are
    kept, this tenant simply has no answer from them (docs/vulnerabilities.md §8). Flipping
    the tier back makes every row's signature stale and the next pass re-judges, with no
    download.

    Returns the number of catalog rows whose answer was written.
    """
    if settings.vuln_tenant_selection:
        from app.core.vuln_selection import lock_assessment

        await lock_assessment(db)
    epoch = release if release is not None else loaded_epoch_signature()
    row_type = VulnCorpusReleaseRow if settings.vuln_tenant_selection or release is not None else VulnLibraryRow

    def matching(row, key):
        match = row.key_full == key
        return and_(match, row.signature == epoch) if row_type is VulnCorpusReleaseRow else match

    if entries is not None:
        if not entries:
            return 0
        # Nothing loaded and nothing stored: there is no answer to write and none to clear,
        # so this costs no statement at all. That is the whole of the `off` path on the
        # sweep's per-device hot line, and it is why `assessment: off` is still free.
        if epoch is None and not any(entry.vuln_signature is not None for entry in entries):
            return 0
        scope = AppCatalogEntry.id.in_([entry.id for entry in entries])
    else:
        scope = AppCatalogEntry.vuln_signature.is_distinct_from(epoch)

    if epoch is None:
        stmt = update(AppCatalogEntry).where(scope).values(**dict.fromkeys(VULN_ANSWER_COLUMNS, None), vuln_evaluated_at=now)
    else:
        # `UPDATE app_catalog SET … FROM (app_catalog LEFT JOIN vuln_library_rows) …`. The
        # left join has to live in a subquery because an `UPDATE … FROM` cannot outer-join
        # its own target, and outer is the point: an inner join would leave a build the new
        # epoch dropped still carrying the old epoch's `covered`.
        # The second outer join is the target build's answer (#482): same table, same
        # primary key, one equality per row against `vuln_target_key`. Outer for the reason
        # the first is — a target the new epoch dropped must stop reading `covered` — and in
        # THIS statement so the two answers on a row can never come from two epochs.
        target = aliased(row_type)
        # `vuln_target_version` is the record of WHICH release this pass looked up, so it may
        # only be written where a lookup happened — hence the `case` rather than the column.
        # The two clocks make the difference a real state and not a theoretical one: the key
        # moves on the JAMF clock and the answer on the CORPUS clock, so from this column's
        # migration until the next catalog sync every row carries a NULL key beside a
        # non-NULL `latest_version`, and a corpus epoch that moves first comes through here
        # over exactly those rows. Writing the version unguarded stored version-present /
        # assessment-NULL, which renders as `unknown_app` — *not in the corpus of <date>*, in
        # the warning colour, about a release nothing ever asked the corpus about, on every
        # device page and application record for the length of the window. A lookup that
        # never happened is not a missing row (R-D); only a row that HAS a key can be told
        # that the epoch holds nothing for it.
        joined = (
            select(
                AppCatalogEntry.id.label("id"),
                row_type.key_full.is_not(None).label("covered"),
                row_type.counts.label("counts"),
                row_type.oldest_published.label("oldest_published"),
                row_type.ids.label("ids"),
                row_type.truncated.label("truncated"),
                case((AppCatalogEntry.vuln_target_key.is_not(None), AppCatalogEntry.latest_version), else_=null()).label(
                    "target_version"
                ),
                target.key_full.is_not(None).label("target_covered"),
                target.counts.label("target_counts"),
                target.ids.label("target_ids"),
                target.truncated.label("target_truncated"),
            )
            .select_from(AppCatalogEntry)
            .outerjoin(row_type, matching(row_type, AppCatalogEntry.key_full))
            .outerjoin(target, matching(target, AppCatalogEntry.vuln_target_key))
            .where(scope)
            .subquery()
        )
        stmt = (
            update(AppCatalogEntry)
            .where(AppCatalogEntry.id == joined.c.id)
            .values(
                vuln_assessment=case((joined.c.covered, VULN_ASSESSMENT_COVERED), else_=null()),
                vuln_counts=joined.c.counts,
                vuln_oldest_published=joined.c.oldest_published,
                vuln_ids=joined.c.ids,
                vuln_ids_truncated=joined.c.truncated,
                vuln_signature=epoch,
                vuln_evaluated_at=now,
                vuln_target_version=joined.c.target_version,
                vuln_target_assessment=case((joined.c.target_covered, VULN_ASSESSMENT_COVERED), else_=null()),
                vuln_target_counts=joined.c.target_counts,
                vuln_target_ids=joined.c.target_ids,
                vuln_target_ids_truncated=joined.c.target_truncated,
            )
        )
    # The ORM cannot reconcile a criteria-driven UPDATE with what it holds in memory, and
    # must not try: `fetch` would issue a second SELECT. The instances that need the new
    # values get them from RETURNING below, as committed values — so `copy_answer` copies
    # what the database now holds, and nothing is marked dirty for a redundant flush.
    # A data-modifying CTE keeps each title's answer and the parent build on the same epoch
    # in ONE SQL statement. Both scopes see the pre-update snapshot, including the stale signature.
    match = AppCatalogTitleMatch
    if epoch is None:
        titles = (
            update(match)
            .where(match.app_catalog_id.in_(select(AppCatalogEntry.id).where(scope)))
            .values(**dict.fromkeys([name for name in VULN_ANSWER_COLUMNS if name.startswith("vuln_target_")], None))
        )
    else:
        target_rows = (
            select(
                match.id.label("id"),
                case((match.vuln_target_key.is_not(None), match.latest_version), else_=null()).label("version"),
                row_type.key_full.is_not(None).label("covered"),
                row_type.counts,
                row_type.ids,
                row_type.truncated,
            )
            .select_from(match)
            .join(AppCatalogEntry, AppCatalogEntry.id == match.app_catalog_id)
            .outerjoin(row_type, matching(row_type, match.vuln_target_key))
            .where(scope)
            .subquery()
        )
        titles = (
            update(match)
            .where(match.id == target_rows.c.id)
            .values(
                vuln_target_version=target_rows.c.version,
                vuln_target_assessment=case((target_rows.c.covered, VULN_ASSESSMENT_COVERED), else_=null()),
                vuln_target_counts=target_rows.c.counts,
                vuln_target_ids=target_rows.c.ids,
                vuln_target_ids_truncated=target_rows.c.truncated,
            )
        )
    stmt = stmt.add_cte(titles.returning(match.id).cte("judged_title_targets"))
    stmt = stmt.execution_options(synchronize_session=False)
    if entries is None:
        return int((await db.execute(stmt)).rowcount)
    answered = (
        await db.execute(stmt.returning(AppCatalogEntry.id, *(getattr(AppCatalogEntry, name) for name in VULN_ANSWER_COLUMNS)))
    ).all()
    by_id = {entry.id: entry for entry in entries}
    for row in answered:
        entry = by_id.get(row[0])
        if entry is None:  # pragma: no cover - the scope is these ids
            continue
        for name, value in zip(VULN_ANSWER_COLUMNS, row[1:], strict=True):
            set_committed_value(entry, name, value)
    return len(answered)


async def copy_vuln_answers(db: AsyncSession) -> int:
    """Every catalog row's vulnerability answer onto the device rows carrying that build —
    one `UPDATE … FROM` for the whole tenant.

    The bulk half of `copy_answer`, and it exists for the two cases `copy_answer` cannot
    reach. One: an epoch moved, so thousands of catalog rows were re-judged by one statement
    and the copies have to follow without a loop per row or a pass per device. Two, and the
    reason `refresh_tenant` runs this whether or not it re-judged anything: a build judged by
    one Mac's sweep leaves every other Mac carrying it with a stale copy that no per-device
    pass will write, because the catalog row is already current when those Macs sync.

    Platform-scoped like every other copy here (#236): the same `version_hash` on two
    platforms is two catalog rows. Restricted to rows whose copy actually differs, so a
    tenant whose epoch did not move pays nothing and a re-run writes nothing.
    """
    stmt = (
        update(InstalledApp)
        .where(
            InstalledApp.version_hash == AppCatalogEntry.version_hash,
            InstalledApp.device_id == Device.id,
            Device.platform == AppCatalogEntry.platform,
            InstalledApp.vuln_signature.is_distinct_from(AppCatalogEntry.vuln_signature),
        )
        .values({name: getattr(AppCatalogEntry, name) for name in VULN_ANSWER_COLUMNS})
        .execution_options(synchronize_session=False)
    )
    return int((await db.execute(stmt)).rowcount)


async def evaluate_entries(db: AsyncSession, entries: Sequence[AppCatalogEntry], catalog: Catalog, *, now: datetime) -> int:
    """Judge these rows against the catalog: replace their title matches and the answer columns.
    The rows must be flushed (they need ids). Returns the number of rows judged.

    Both answers are written here — Jamf Patch from the in-memory rule pass, and the
    vulnerability answer from one set-based join (`judge_vuln`) — so a build the fleet has
    never shown carries both the moment it is first seen."""
    if not entries:
        return 0
    signature = catalog_signature(catalog)
    await db.execute(delete(AppCatalogTitleMatch).where(AppCatalogTitleMatch.app_catalog_id.in_([entry.id for entry in entries])))
    for entry in entries:
        facts = Facts(
            app_name=entry.name,
            bundle_id=entry.bundle_id,
            versions=tuple(version for version in (entry.version, entry.short_version) if version),
            # From the row, never a default (#236): a non-macOS row considers no titles,
            # and the row's `platform` is the record of why it carries no answer.
            platform=jamf_platform_name(entry.platform),
        )
        matches = match_app(facts, catalog)
        _apply_summary(entry, matches, now=now, signature=signature)
        for match in matches:
            db.add(
                AppCatalogTitleMatch(
                    app_catalog_id=entry.id,
                    title_id=match.title.id,
                    basis=match.basis,
                    state=match.state,
                    version_known=match.version_known,
                    on_latest=match.on_latest,
                    installed_version=match.installed_version,
                    installed_released_at=match.installed_released_at,
                    latest_version=match.latest_version,
                    vuln_target_key=app_full_key(entry.name, entry.bundle_id, match.latest_version, None)
                    if match.latest_version
                    else None,
                    latest_released_at=match.latest_released_at,
                    first_newer_released_at=match.first_newer_released_at,
                    releases_missed=match.releases_missed,
                    evaluated_at=now,
                )
            )
    # After the rule pass, not inside it: the join is one statement over every row this
    # call judged, and it has to see them flushed (the execute below autoflushes the
    # summary columns and the title matches added above).
    await judge_vuln(db, entries, now=now)
    return len(entries)


async def title_names(db: AsyncSession, title_ids: Iterable[str]) -> dict[str, str]:
    """Title id -> name off the global `jamf_patch_titles`, one primary-key read for a whole
    page of rows (#313).

    The pages resolve names per request rather than storing them beside the ids: a rename in
    Jamf then changes the label and never the identity, which is the same rule
    `ExtensionAttributeOut` follows (#197). A title the table holds no name for — a row Jamf
    served with an empty `name`, or an id with no row at all (`sync_catalog` only ever
    upserts, so that takes a hand-edited table) — is absent from the result, and the caller
    leaves that title out of the named list rather than shipping its id in disguise; the ids
    themselves stay whole on `jamf_title_ids`, so a page can always tell "unnamed" from
    "unmatched". The process cache (`matching.cached_title_names`) is deliberately not read
    here: on an API worker it may hold nothing or an older catalog, and this is one indexed
    read per page, not one per device.
    """
    ids = {title_id for title_id in title_ids if title_id}
    if not ids:
        return {}
    rows = (await db.execute(select(JamfPatchTitle.id, JamfPatchTitle.name).where(JamfPatchTitle.id.in_(ids)))).all()
    return {title_id: name for title_id, name in rows if name}


def answer_columns(entry: AppCatalogEntry) -> dict[str, object]:
    """The catalog row's answer as `installed_apps` column values — the ONE definition of what
    "the answer" is, in column terms.

    It exists because there are two paths that copy it and they used to spell the list twice:
    `copy_answer` below (per row, at device process) and `refresh_tenant`'s bulk UPDATE (per
    catalog row, after a catalog sync). #311 added `ea_assumed` to one of them and the other
    silently kept writing nine columns — the answer was correct on a freshly judged build and
    permanently null on every row the hourly refresh maintained, which is most of a stable
    fleet. Caught in the container, not by a test, which is exactly the failure mode a second
    hand-written list produces. Now a column added here reaches both paths or neither.

    `last_patch_check_at` is deliberately NOT here: it is the copier's own clock, not the
    entry's answer, and both callers set it themselves from their own `now`.

    The vulnerability answer (#381) rides the same list, for the same reason: it is a
    property of the build, judged once, and every device carrying that build reads the copy.
    Its column names live in `app.core.vuln_answer` because a third path copies them —
    `copy_vuln_answers`, the set-based pass a new epoch triggers.
    """
    return {
        "jamf_title_ids": entry.jamf_title_ids,
        "patch_state": entry.patch_state,
        "is_compliant": entry.is_latest,
        "patch_available": entry.patch_available,
        "patch_available_since": entry.patch_available_since,
        "releases_missed": entry.releases_missed,
        "this_version_seen": entry.this_version_seen,
        "latest_version": entry.latest_version,
        "latest_released_at": entry.latest_released_at,
        "ea_assumed": entry.ea_assumed,
        "reference_title_id": entry.reference_title_id,
        "sentence_title_id": entry.sentence_title_id,
        **{name: getattr(entry, name) for name in VULN_ANSWER_COLUMNS},
    }


def copy_answer(entry: AppCatalogEntry, app: InstalledApp, *, now: datetime) -> None:
    """The row's answer onto a device's installed-app row (the older compliance columns and the
    #65 summary columns), so device pages and the Applications overview need no join."""
    for column, value in answer_columns(entry).items():
        setattr(app, column, value)
    app.last_patch_check_at = now


async def record_device_apps(db: AsyncSession, device: Device, *, now: datetime | None = None) -> int:
    """`process_sync`'s hook, after the device's app rows are flushed: every app the device
    reports is seen now (first_seen_at on creation; last_seen_at moved when older than the
    granularity), rows the current catalog has not judged are judged, and app rows that are new,
    whose row's answer moved, or whose stored corpus epoch is not the one their catalog row
    now carries get their copy. Returns the rows judged."""
    if settings.vuln_tenant_selection:
        from app.core.vuln_selection import prepare_assessment

        await prepare_assessment(db)
    rows = (await db.execute(select(InstalledApp).where(InstalledApp.device_id == device.id))).scalars().all()
    if not rows:
        return 0
    now = now or datetime.now(UTC)
    hashes = {row.version_hash for row in rows if row.version_hash}
    # The device's platform scopes the rows (#236): a universal app is one hash and two
    # catalog rows, judged differently, and this device's apps belong to its own.
    existing = {
        entry.version_hash: entry
        for entry in (
            await db.execute(
                select(AppCatalogEntry).where(
                    AppCatalogEntry.platform == device.platform, AppCatalogEntry.version_hash.in_(hashes)
                )
            )
        )
        .scalars()
        .all()
    }
    for row in rows:
        if not row.version_hash:
            continue
        entry = existing.get(row.version_hash)
        if entry is None:
            entry = AppCatalogEntry(
                name=row.name,
                bundle_id=row.bundle_id,
                version=row.version,
                short_version=row.short_version,
                app_hash=row.app_hash,
                version_hash=row.version_hash,
                platform=device.platform,
                key_title=row.key_title,
                key_full=row.key_full,
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(entry)
            existing[row.version_hash] = entry
        elif entry.last_seen_at is None or now - entry.last_seen_at >= LAST_SEEN_GRANULARITY:
            entry.last_seen_at = now
    await db.flush()

    # The process cache, trusted for the interval: asking the table whether the catalog moved
    # cost one query per device — forty thousand a sweep — for an answer that changes hourly
    # at most (#142). The refresh paths still ask every time; see `load_catalog`.
    catalog = await load_catalog(db, max_age=CATALOG_PROBE_INTERVAL)
    signature = catalog_signature(catalog)
    stale = [entry for entry in existing.values() if entry.evaluated_signature != signature]
    judged = await evaluate_entries(db, stale, catalog, now=now)
    moved = {entry.version_hash for entry in stale}

    # The corpus epoch moved under rows the Jamf catalog did not (#381): judged on their
    # own, in one statement over this device's builds, rather than by re-running a title
    # match whose answer has not changed. `loaded_epoch_signature()` costs no query, and
    # on the ordinary sweep — no new epoch since the last device — this list is empty and
    # nothing is executed. The rows `evaluate_entries` just judged are already current.
    epoch = loaded_epoch_signature()
    epoch_stale = [entry for entry in existing.values() if entry.vuln_signature != epoch]
    if epoch_stale:
        await judge_vuln(db, epoch_stale, now=now)
        moved |= {entry.version_hash for entry in epoch_stale}
    for row in rows:
        entry = existing.get(row.version_hash)
        if entry is None:
            continue
        # A copy costs an UPDATE per app row; only when the row is new (no answer yet), when
        # the catalog row it points at was just judged, or when this row's stored epoch is
        # not the one its catalog row now carries. That last clause is the build ANOTHER
        # Mac's sweep judged: nothing this device did put it in `moved`, and without it this
        # device would keep reading `unknown_app` for an assessed build until the hourly
        # pass. Refreshes after a catalog sync update the copies in bulk (refresh_tenant).
        if row.last_patch_check_at is None or row.version_hash in moved or row.vuln_signature != entry.vuln_signature:
            copy_answer(entry, row, now=now)
    return judged


async def refresh_tenant(db: AsyncSession, *, force: bool = False, now: datetime | None = None) -> int:
    """Re-judge the tenant's rows whose answer predates the current catalog (all of them with
    `force`), and refresh the copies on `installed_apps`. Returns the rows judged.

    Also the hourly pass that catches a corpus epoch that moved (#381): the Jamf catalog and
    the corpus move on different clocks, so a row whose only stale half is the epoch is
    re-judged by one `UPDATE … FROM` rather than by a full title re-match it does not need.
    And it is the tenant-wide **copy** repair — the one pass that reaches a device nobody
    has swept since the build it carries was judged. That copy runs every pass, not only
    when this one re-judged something; see below.
    """
    now = now or datetime.now(UTC)
    # This tenant's data-sharing tier, once for the whole pass (#248, §8). It is what
    # `loaded_epoch_signature()` reads below, and the gate is fail-closed: without this the
    # pass would judge every row to "no epoch" and clear answers the sweep had just written.
    await read_tenant_tier(db)
    if settings.vuln_tenant_selection:
        from app.core.vuln_selection import prepare_assessment

        await prepare_assessment(db)
    catalog = await load_catalog(db)
    signature = catalog_signature(catalog)
    stmt = select(AppCatalogEntry)
    if not force:
        stmt = stmt.where((AppCatalogEntry.evaluated_signature.is_(None)) | (AppCatalogEntry.evaluated_signature != signature))
    entries = (await db.execute(stmt)).scalars().all()
    judged = await evaluate_entries(db, entries, catalog, now=now)
    for entry in entries:
        await db.execute(
            update(InstalledApp)
            # This platform's rows only (#236): the same hash on the other platform is a
            # different catalog row with a different answer.
            .where(
                InstalledApp.version_hash == entry.version_hash,
                InstalledApp.device_id.in_(select(Device.id).where(Device.platform == entry.platform)),
            )
            # The same column list `copy_answer` uses, from the same function — see
            # `answer_columns`. Spelling it here a second time is what left `ea_assumed`
            # permanently null on the path that maintains a stable fleet.
            .values(**answer_columns(entry), last_patch_check_at=now)
        )
    # Every remaining row whose vulnerability answer came from a different epoch — the rows
    # above are current already, having just been judged. Two statements for the whole
    # tenant, and both are no-ops when the epoch has not moved.
    rejudged = await judge_vuln(db, None, now=now)
    # Unconditional, and NOT `if rejudged`: the copy is not this statement's follow-up, it is
    # the only pass that reaches every device. A sweep that judges a build before this pass
    # does leaves every OTHER Mac carrying that build with no copy — `record_device_apps`
    # copies onto the device whose own pass judged, and by the time the next Mac syncs the
    # catalog row already names the current epoch, so neither copier writes. Gating this on
    # `rejudged` made that a permanent false negative: the device page and the
    # `loon:jamf:mac:app` event read `unknown_app` for a build the corpus assessed, on every
    # Mac but the first, until somebody pressed *Refresh*. `copy_vuln_answers`'s own
    # `is_distinct_from` predicate writes nothing when the copies already agree, so a quiet
    # tenant pays one no-op UPDATE an hour for the bounds §4f states.
    copied = await copy_vuln_answers(db)
    if rejudged or copied:
        logger.info("vulnerability answers refreshed", extra={"builds": rejudged, "apps": copied})
    if judged:
        logger.info("app catalog refreshed", extra={"rows": judged, "signature": signature})
    return judged


# --- the pass that follows an import (#554) ---------------------------------------------
#
# Every stored answer is stamped with the epoch that judged it and is not served under a
# newer one (§4f): that is the rule that keeps one epoch's counts from appearing under
# another's date. Its cost, until this landed, was an hour of *not yet judged* on the
# Vulnerabilities page after every corpus arrival — the import replaced the library and
# nothing re-judged until the hourly refresh, so the findings sat in the database, stamped
# with the previous epoch, and no page served them. The corpus arrives daily, so that was a
# daily blank hour, on every organization of a box at once. The pass below is the repair:
# the epoch half of `refresh_tenant`, once per organization, run by the exchange the moment
# it has installed a new epoch.

REJUDGED_AFTER_IMPORT = "vulnerability answers re-judged after import"
REJUDGE_AFTER_IMPORT_FAILED = "vulnerability answers NOT re-judged after import"


async def rejudge_epoch(db: AsyncSession, *, now: datetime | None = None) -> tuple[int, int]:
    """The epoch half of `refresh_tenant`, on its own: this tenant's rows whose answer came
    from a different epoch, re-judged by one statement, and the copies on `installed_apps`
    refreshed by one more. Returns (builds re-judged, app rows copied).

    Nothing here touches the Jamf half. A corpus that moved is not a catalog that moved
    (§4f, two clocks), and the title re-match is the pass whose cost grows with the tenant.
    """
    now = now or datetime.now(UTC)
    # The tenant's tier, once, before the join — the same fail-closed gate `refresh_tenant`
    # reads first: `loaded_epoch_signature()` answers "no epoch" for a tenant whose tier was
    # never read, and the join would then clear every answer instead of writing one.
    await read_tenant_tier(db)
    if settings.vuln_tenant_selection:
        from app.core.vuln_selection import prepare_assessment

        await prepare_assessment(db)
    rejudged = await judge_vuln(db, None, now=now)
    copied = await copy_vuln_answers(db)
    return rejudged, copied


async def rejudge_every_tenant(epoch_id: str) -> None:
    """Every operational tenant, the moment a new epoch is installed (#554).

    The library is one global set of tables and the answers are per tenant, so the exchange
    that imports an epoch for the box — run for one tenant, in that tenant's session — owes
    a pass to every other tenant too. One session each, the two statements, one commit; and
    the same enumeration the scheduler's jobs use, so a tenant this pass could reach and
    did not is a tenant the hourly refresh could not reach either.

    **It never raises into the exchange.** The day's share-log row is durable and the epoch
    is installed before this runs; a join that fails for one tenant is that tenant's
    problem for an hour — the hourly refresh runs the same two statements, and *Refresh* on
    the Catalog tab runs them now — and the sentence below says exactly that. Turning it
    into a failed exchange would re-send the day's snapshot for a fault the snapshot had no
    part in.
    """
    for tenant_id in await operational_tenant_ids():
        try:
            async with tenant_job(tenant_id) as db:
                rejudged, copied = await rejudge_epoch(db)
                await db.commit()
        except Exception:
            logger.exception(
                "%s for one organization, so its apps read outside the corpus of epoch %s until the hourly "
                "refresh repairs them; Devices › Applications › Catalog › Refresh does it now "
                "(docs/troubleshooting.md §5 step 3)",
                REJUDGE_AFTER_IMPORT_FAILED,
                epoch_id,
                extra={"tenant_id": str(tenant_id), "epoch_id": epoch_id},
            )
            continue
        logger.info(
            REJUDGED_AFTER_IMPORT,
            extra={"tenant_id": str(tenant_id), "epoch_id": epoch_id, "builds": rejudged, "apps": copied},
        )
