"""The posture snapshot recorder — the nightly tape (#102, docs/posture-snapshot.md).

Fires as the last act of every closed full sweep (app.core.runs.finish, lock class
`device_sweep`), success and failure alike: a failed night's database state is real,
and the failed run id stamped on the rows is what makes staleness visible. History not
recorded can never be backfilled, which is why this exists before any pixel does —
recording buys zero surface.

Every metric is one bounded SQL query against the database directly, never through the
application's own HTTP API. No key waits on an endpoint or a query parameter when its
source table exists; where an API computes the same number (the catalog summary, the
patch title counts), the recorder mirrors that query's semantics rather than calling
the route.

The vocabulary is Definitions v1 — `ACTIVE_KEYS` below, one frozen definition per key
in docs/posture-snapshot.md. Definitions are immutable per key: a change mints a new
key and retires the old, so a chart never silently changes meaning under its own
history. `RESERVED_KEYS` holds the names whose definitions are ruled before their
writers exist; no key records before its feature's table exists — a run of primed zeros
is a lie about when measurement began.

Four writing rules the reader of the table must be able to rely on:

* **Absent means "did not apply", never zero.** `outbox.oldest_pending_age_s` writes
  no row when zero rows were pending — coercing that to 0 would make "empty queue"
  indistinguishable from "a delivery is due right now".
* **The four `vuln.*` keys write nothing until something has been assessed.** The same
  rule with a whole key family behind it (#250, docs/vulnerabilities.md §7): a tenant
  the corpus join has never judged gets no rows, because `0 apps affected` would read as
  a clean bill of health for a fleet nobody looked at. `_vuln_values` is the gate.
* **Ratios are never stored.** Numerator and denominator land as separate keys and
  the percentage derives at render, so the inputs stay auditable forever.
* **Every row names the population it counted.** `platform` is stamped from
  `CAPTURE_PLATFORM`, so a number is never read against a fleet it did not measure.
  Eighteen active keys change meaning the night a sweep observes more than Macs, and
  immutable definitions leave no way to say so afterwards (#230).

Recorder failure never fails the run: the caller (runs.finish) catches everything,
logs, and lets the run's verdict stand. A night can lose its capture; it must never
lose its sweep.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import Integer, and_, distinct, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.changes.policy import NORMAL, levels_at_least
from app.core.permissions import Role
from app.core.runs import STATUS_FAILED, STATUS_SUCCEEDED, TRIGGER_SWEEP
from app.core.vuln_answer import served
from app.mdm.patch.matching import STATE_AHEAD, STATE_BEHIND, STATE_LATEST, STATE_UNKNOWN
from app.models.schema import (
    Account,
    AccountRole,
    Alert,
    ApiToken,
    AppCatalogEntry,
    AppCatalogTitleMatch,
    Device,
    DeviceChange,
    DeviceFinding,
    EventOutbox,
    InstalledApp,
    MdmConnection,
    OutboxDelivery,
    PostureSnapshot,
    Run,
    VulnLibraryEpoch,
)
from app.observations.departure import gone_for_good
from app.schemas.payload import VULN_ASSESSMENT_COVERED

logger = logging.getLogger(__name__)

# 7 days and the trailing day, in hours — spelled out because "7d" in a key name is a
# frozen 168 hours from the capture instant, not a calendar boundary.
_STALE_HOURS = 168
_WINDOW_HOURS = 24
# The laggard cut: 14 days in exact hours from the capture instant (#68).
_LAGGARD_HOURS = 336

# "Notable" is the closed LEVELS ordering at NORMAL or above — the same cut the change
# policy's default preset draws ("high + normal on, low off"), and the same cut
# `GET /api/changes?minLevel=normal` returns.
#
# Read from `levels_at_least` rather than sliced here (#107). This line used to compute
# the set itself, which made the ordering two facts in two modules: `policy._RANK` and
# this slice. They agreed, and nothing would have failed if a level inserted into LEVELS
# had moved only one of them.
NOTABLE_LEVELS: tuple[str, ...] = levels_at_least(NORMAL)

# The four vulnerability keys, activated 2026-09-11 (#250, docs/vulnerabilities.md §7) on
# the per-build answers #381 stores. Named as their own tuple because they are the one
# group in ACTIVE_KEYS with a gate in front of it: `_vuln_values` writes **no rows at all**
# — not zeros — until the corpus join has judged this tenant. Every other active key
# answers its question on every pod, every night, from the first night.
#
# A zero here would be a different sentence than the one the fleet can support. `0 apps
# affected` from a tenant nobody assessed is a clean bill of health for a fleet nobody
# looked at, which is `assessment: off` (docs/vulnerabilities.md §4a) broken one layer
# down, in a tape that is read years later by a reader who cannot ask what the pod's
# consent tier was that night. The tape starts the night the join first runs.
VULN_KEYS: tuple[str, ...] = (
    "vuln.apps_affected",
    "vuln.apps_kev_affected",
    "vuln.apps_unknown",
    "vuln.devices_affected",
)

# The finding ledger's three, activated 2026-09-19 (#591) over the store #590 landed. Their own family because their
# gate is their own: the four wait on the corpus having judged this tenant, these on `device_findings` holding a row at
# all — a tenant judged for months whose Macs have not been swept since has nothing to count, and a zero would date its
# exposure to a store that was not keeping it. Findings, never devices (#589 ruling 1).
FINDING_KEYS: tuple[str, ...] = ("vuln.findings_open", "vuln.findings_new_24h", "vuln.findings_resolved_24h")

# Definitions v1 — the 37 active keys, in the order their rows are written. The names
# are the contract: a definition change mints a new key, so a name in this tuple means
# exactly what docs/posture-snapshot.md says it means, forever.
#
# Corrected before launch on 2026-09-04 (#314), while the tape was nine snapshots deep on a
# dev instance and no customer series existed to orphan. The `patch.pairs_*` keys did not
# partition `pairs_total` — an `ahead` pair sat in none of them, and so did a `behind` pair
# inside the fourteen-day cut — and `titles_with_laggards` counted a device running a build
# NEWER than Jamf publishes as a laggard. Both had the same root: `ahead` had no key of its
# own, so every rollup either ignored it or absorbed it silently. It is not a rare state —
# Chrome and Safari auto-update ahead of the catalog on essentially every Mac fleet — so the
# tenant patching fastest scored worst. `pairs_ahead` and `pairs_behind_under_14d` close the
# set; `titles_with_laggards` is behind-only; and `_capture_patch` asserts the partition
# rather than trusting it.
ACTIVE_KEYS: tuple[str, ...] = (
    "devices.total",
    "devices.stale_checkin_7d",
    "devices.unmanaged",
    "devices.stale_inventory_7d",
    # Activated 2026-09-16 (#476) with the build that can evaluate a departure (#183).
    "devices.departed_24h",
    "catalog.entries",
    "catalog.installed",
    "catalog.matched",
    "catalog.unmatched",
    "catalog.installed_not_latest",
    "apps.distinct",
    "patch.pairs_total",
    "patch.pairs_on_latest",
    "patch.titles_with_laggards",
    "patch.pairs_behind_under_14d",
    "patch.pairs_laggard_over_14d",
    "patch.pairs_unknown_build",
    "patch.pairs_ahead",
    "changes.notable_24h",
    "alerts.open",
    "alerts.opened_24h",
    "runs.sweeps_succeeded_24h",
    "runs.failed_24h",
    "runs.full_sweep_duration_s",
    "outbox.pending",
    "outbox.failed_24h",
    "outbox.oldest_pending_age_s",
    "accounts.total",
    "accounts.admins",
    "tokens.active",
    # Last, and conditional: these four are absent on a tenant the corpus has never judged.
    *VULN_KEYS,
    # And these three while its finding ledger holds no row — one gate further in.
    *FINDING_KEYS,
)

# The population a capture counted (#230). v0 reads computers only
# (docs/mobile-devices.md), so every row this recorder writes is `macos` — a fact about
# what the sweep observed, not a default standing in for an unknown. The vocabulary is
# one value per Apple OS — `macos`, `ios`, `ipados`, `tvos`, `visionos` (Kyle,
# 2026-09-02: the content-key OS spelling `os_key("macos", …)` carries, not the
# sourcetype segment's `mac`) — and a value is never reused for a different population.
CAPTURE_PLATFORM = "macos"

# Reserved for a capture that counted every platform at once. A single-platform run
# never writes it: a roll-up is a different number, not a synonym for the only
# population that existed the night it ran.
PLATFORM_ROLLUP = "all"

# Frozen definitions, no writer yet — each activates with its feature's table, never
# before (docs/posture-snapshot.md carries the definitions and the gates).
#
# The reservation is a mechanism rather than a list: a key whose definition is ruled
# before its writer exists is declared here, and `tests/test_posture_registry.py` is what
# keeps it out of `ACTIVE_KEYS` until its rows are real. The tuple emptied on 2026-09-11,
# when the four `vuln.*` names reserved since #102 moved into `VULN_KEYS` above, and it
# stayed named for exactly the case below.
#
# It emptied a second time on 2026-09-16, when `devices.departed_24h` — reserved five days
# earlier, when nothing here could say a device was gone — activated with #183's census (#476).
RESERVED_KEYS: tuple[str, ...] = ()

# The population vocabulary, ruled 2026-09-02 (#230): one value per Apple OS, never reused for
# a different population. In code because `GET /api/posture` (#470) reads one of these and
# refuses every other name — `PLATFORM_ROLLUP` included, since a population nothing writes,
# answered with an empty page, spells "nothing was ever captured" for a question nobody asked.
PLATFORMS: tuple[str, ...] = ("macos", "ios", "ipados", "tvos", "visionos")

# What each key means, in the doc's own opening words — served by `GET /api/posture/registry`
# (#470) so a reader holding a value need not go and find the document to interpret it. **Not a
# second home for the definitions**: docs/posture-snapshot.md holds them, every line below is a
# verbatim prefix of that key's row there (`…` marks where the row goes on), and
# `tests/test_posture_registry.py` refuses a sentence the doc does not open with.
KEY_DEFINITIONS: dict[str, str] = {
    "devices.total": "Device rows across active connections that the last clean census still observed.",
    "devices.stale_checkin_7d": "`last_check_in` older than capture − 168h, NULLs included, over that same population: active…",
    "devices.unmanaged": "`managed = false`, over that same population: active connections, still observed by the last clean…",
    "devices.stale_inventory_7d": "`last_inventory_at` older than capture − 168h, NULLs included, over that same population…",
    "devices.departed_24h": "Devices that left the counted population in the trailing 24h — in it at capture − 24h, gone for…",
    "catalog.entries": "All `app_catalog` rows.",
    "catalog.installed": "Entries with at least one install.",
    "catalog.matched": "Entries with `jamf_title_ids` not null.",
    "catalog.unmatched": "Entries with `jamf_title_ids` null.",
    "catalog.installed_not_latest": "Installed entries where `is_latest = false` and `latest_version` is present.",
    "apps.distinct": "Distinct `app_hash` groups in the fleet.",
    "patch.pairs_total": "Distinct (device, matched title) install pairs.",
    "patch.pairs_on_latest": "Pairs where the installed version equals the title's latest (`on_latest`).",
    "patch.titles_with_laggards": "Matched titles carrying at least one pair with `state = behind`.",
    "patch.pairs_laggard_over_14d": "Pairs with `state = behind` whose `first_newer_released_at` — Jamf's release date of the…",
    "patch.pairs_behind_under_14d": "Pairs with `state = behind` that the laggard cut does not reach: `first_newer_released_at`…",
    "patch.pairs_unknown_build": "Pairs with `state = unknown`: the installed build is one Jamf never listed and is not newer…",
    "patch.pairs_ahead": "Pairs with `state = ahead`: installed newer than anything the title lists.",
    "changes.notable_24h": "`device_changes` rows at level ≥ notable (the closed LEVELS ordering at `normal` or above — one SQL…",
    "alerts.open": "`alerts` rows with `closed_at` null at capture, on devices whose connection is active.",
    "alerts.opened_24h": "`alerts` rows with `opened_at` in the trailing 24h, on devices whose connection is active — including…",
    "runs.sweeps_succeeded_24h": "Runs with `trigger = sweep`, `status = succeeded`, finished in the window.",
    "runs.failed_24h": "Runs with `status = failed` (any trigger), finished in the window.",
    "runs.full_sweep_duration_s": "`finished_at − started_at` of the very run this capture stamps.",
    "outbox.pending": "`event_outbox` rows awaiting delivery (not yet fanned out, or holding a pending delivery).",
    "outbox.failed_24h": "`outbox_deliveries` rows entering `failed` (dead-lettered) in the window, timed by the last attempt.",
    # Two sentences, for the key the absence rule was written for.
    "outbox.oldest_pending_age_s": "Max age of undelivered `event_outbox` rows at capture. If zero rows are pending…",
    "accounts.total": "Non-revoked accounts (`status = active`).",
    "accounts.admins": "Active accounts holding the admin role — the same cut the accounts API's last-admin guard counts.",
    "tokens.active": "API tokens with `revoked_at` null.",
    "vuln.apps_affected": "Installed builds whose stored answer is `covered` under the answering epoch with `counts.total > 0`…",
    "vuln.apps_kev_affected": "The same population with `counts.kev > 0` — carrying a KEV-listed vulnerability.",
    "vuln.apps_unknown": "Installed builds the corpus cannot assess (`unknown_app` — a ruled wire value, deliberately…",
    "vuln.devices_affected": "Distinct devices on active connections carrying at least one build `apps_affected` counted.",
    "vuln.findings_open": "Open `device_findings` rows — one per (Mac, carrier title, finding id) still detected as of that…",
    "vuln.findings_new_24h": "Ledger rows whose `first_observed_at` falls in the trailing 24h — findings this pod saw on a Mac…",
    "vuln.findings_resolved_24h": "Ledger rows closed in the trailing 24h, by `resolved_at`, whatever the reason — including…",
}


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _in_the_fleet(at: datetime):
    """**The departure cut, written once for the twenty keys that have to agree** (#476).

    `gone_for_good` is the one definition of the terminal exit — the end of #183's seven-day
    tail — and spelling "departed_at plus a week" a second time is how twenty keys start
    disagreeing about one Mac on a tape nobody can re-run. Asked at `captured_at`, never at
    `now()`: a capture is as of its instant. `Device` must be in the caller's FROM — the three
    install-grain helpers join `devices` for no other reason. Deliberately NOT narrowed to
    active connections; docs/posture-snapshot.md rules that second narrowing out.
    """
    return ~gone_for_good(Device.mdm_connection_id, Device.external_id, at=at)


def _devices_on_active_connections(at: datetime):
    """The device population every devices.* key counts over: rows on active connections
    that had not left the fleet at `at`."""
    return (
        select(func.count())
        .select_from(Device)
        .join(MdmConnection, MdmConnection.id == Device.mdm_connection_id)
        .where(MdmConnection.is_active.is_(True), _in_the_fleet(at))
    )


def _alerts_on_active_connections(at: datetime):
    """The alert population both alerts.* keys count over: latches on devices whose
    connection is active and that are still in the fleet (#476) — the same cut
    `_devices_on_active_connections` draws, and the same cut `GET /api/alerts` returns, so the
    tape and the surface can never disagree about how many things need attention. A departed
    Mac's latch is also closed in the table (`app.alerts.service.close_departed_device_latches`);
    neither half makes the other redundant."""
    return (
        select(func.count())
        .select_from(Alert)
        .join(Device, Device.id == Alert.device_id)
        .join(MdmConnection, MdmConnection.id == Device.mdm_connection_id)
        .where(MdmConnection.is_active.is_(True), _in_the_fleet(at))
    )


def _installed(at: datetime):
    """An app_catalog row someone actually has: at least one installed app **on a Mac still in
    the fleet** carries its hash — the same "devices > 0" cut CatalogSummaryOut draws, computed
    recorder-side. A departed Mac's rows stay and stop being evidence anybody has the build."""
    return exists(
        select(InstalledApp.id)
        .join(Device, Device.id == InstalledApp.device_id)
        .where(InstalledApp.version_hash == AppCatalogEntry.version_hash, _in_the_fleet(at))
    )


async def patch_pair_counts(db: AsyncSession, *, at: datetime) -> tuple[int, int]:
    """`(pairs_total, pairs_on_latest)` — the two inputs the coverage ratio derives from,
    at the pair grain the recorder writes them at. The one implementation of that
    definition (#109): the recorder calls this for the nightly row, and
    `GET /api/jamf-patch/coverage` calls it for the live tile, so the tile and the tape
    can never disagree about what "on latest" means. `at` is where the departure cut is drawn
    (#476): `captured_at` for the tape, `now()` for the tile."""
    total = await _count(db, select(func.count()).select_from(_patch_pairs(at)))
    on_latest = await _count(db, select(func.count()).select_from(_patch_pairs(at, AppCatalogTitleMatch.on_latest.is_(True))))
    return total, on_latest


def _patch_pairs(at: datetime, *criteria):
    """Distinct (device, matched Jamf Patch title) install pairs — the
    AppCatalogTitleMatch → catalog row → InstalledApp join /api/jamf-patch counts devices
    through, kept at the pair grain. `criteria` are predicates on the match row: `on_latest`
    follows the standing "latest = any title says so" semantics the matcher already stamped
    on the row, and the dates are the row's own, so no fold across titles ever happens here."""
    stmt = (
        select(InstalledApp.device_id, AppCatalogTitleMatch.title_id)
        .join_from(AppCatalogTitleMatch, AppCatalogEntry, AppCatalogEntry.id == AppCatalogTitleMatch.app_catalog_id)
        .join(InstalledApp, InstalledApp.version_hash == AppCatalogEntry.version_hash)
        .join(Device, Device.id == InstalledApp.device_id)
        .where(_in_the_fleet(at))
    )
    if criteria:
        stmt = stmt.where(*criteria)
    return stmt.distinct().subquery()


# The closed set of states `classify()` can assign, named here so a fixture can be held to
# covering all of it (`tests/test_posture_db.py`) — the cheap defence against the #314 shape,
# where a state absent from the fixture left two rollups untested and a third defect invisible.
PATCH_STATES: tuple[str, ...] = (STATE_LATEST, STATE_BEHIND, STATE_AHEAD, STATE_UNKNOWN)


def _partitions(values: dict[str, float], total: str, parts: tuple[str, ...], *, what: str) -> None:
    """Refuse a snapshot whose parts do not add up to their whole.

    The one guard that catches the defect class the 2026-09-04 checking pass kept finding: a
    value correct on its own and wrong in company. Every assertion in the test suite compares a
    value to an expectation, and in each of those defects no value was wrong — what was wrong
    was a relationship between values, which only an identity can express. So the identities get
    stated, once a night, over integers already in hand.

    Raising loses the snapshot and never the sweep: `runs.finish` wraps the recorder in
    `except Exception`, rolls back, and logs — "a night can lose its snapshot, it must never
    lose its sweep". That is the right trade here. A tape row set whose parts do not sum is
    worse than an absent one, because absence is already a signal this tape defines and a
    quietly wrong number is not.
    """
    summed = sum(values[part] for part in parts)
    if summed != values[total]:  # pragma: no cover — an identity; the guard is the point
        raise ValueError(f"{what} does not partition {total}: {' + '.join(parts)} = {summed} != {values[total]}")


def _outbox_pending_where():
    """An event still awaiting delivery: not yet fanned out, or holding at least one
    delivery row that is still pending. A nightly point-sample by construction — the
    caveat is frozen into the key's definition."""
    pending_delivery = exists(
        select(OutboxDelivery.id).where(OutboxDelivery.outbox_event_id == EventOutbox.id, OutboxDelivery.status == "pending")
    )
    return or_(EventOutbox.fanned_out.is_(False), pending_delivery)


def outbox_failed_window_where(until: datetime, hours: int = _WINDOW_HOURS):
    """Delivery rows that entered `failed` — gave up after ten attempts, a dead letter —
    inside the trailing window, timed by the last attempt.

    `outbox.failed_24h`'s own predicate, named rather than inlined because the destination
    row's `failed24h` (#469) is this same window scoped to one destination. Two spellings of
    one window drift apart the first time either is touched, and the tape and the page then
    disagree about what "failing now" means.
    """
    entered_failed_at = func.coalesce(OutboxDelivery.last_attempted_at, OutboxDelivery.created_at)
    return and_(
        OutboxDelivery.status == "failed",
        entered_failed_at > until - timedelta(hours=hours),
        entered_failed_at <= until,
    )


async def _count(db: AsyncSession, stmt) -> int:
    return int((await db.execute(stmt)).scalar_one())


def _findings(band: str):
    """One band of a stored answer's counts, as an integer to compare against.

    The aggregates are the epoch's own, stored as JSONB by the judge pass — read, never
    recomputed. Counting `vuln_ids` instead would under-report by exactly the number of
    ids the published cap dropped (docs/vulnerabilities.md §4a, §4e), which is the shape
    of wrong number this tape has no way to notice a year later.
    """
    return AppCatalogEntry.vuln_counts[band].astext.cast(Integer)


async def _vuln_values(db: AsyncSession, at: datetime) -> dict[str, float]:
    """The four `vuln.*` keys — or an empty dict, which writes no rows at all (#250).

    **The rule, and the whole reason this function is not four lines inside `_compute`:**
    while nothing has assessed this tenant, these keys record *nothing*. Not zero. A zero
    in this family does not say "no vulnerabilities", it says "never assessed", and a row
    saying zero is a clean bill of health for a fleet nobody looked at — the failure
    `assessment: off` exists to prevent on the wire (docs/vulnerabilities.md §4a),
    committed to a tape that outlives every operator who could explain it. It is also the
    standing no-zero-priming guardrail applied to the one case a naive recorder gets
    wrong, which is why it is ruled in the contract (§7) rather than left to be
    rediscovered. The keys activate the night the join first runs for this tenant, and
    their tape starts then.

    In the opt-in tenant-selection path the epoch is this tenant's selected digest,
    read directly from PostgreSQL. Populations, key meanings and the ever-judged guard
    are unchanged. The singleton and tier descriptions below cover the legacy path.

    **Two database facts open the gate, and nothing else.** The container holds an epoch
    (`vuln_library_epoch`), and at least one of this tenant's catalog rows carries a stored
    answer (`vuln_signature` not null) — *ever judged*, never *judged against tonight's
    epoch*. Both are reads, in keeping with "the recorder reads the DB never the API": the
    answers are the columns #381 stores, and nothing here re-derives a verdict, consults the
    library rows, or asks the corpus a question. It deliberately does not read
    `loaded_epoch_signature()` either — that is fail-closed process state behind a
    per-tenant tier the capture path never installs, so a recorder that trusted it would
    write an empty night indistinguishable from a tenant that was never assessed.

    **Why the second fact is "ever", corrected 2026-09-11 before the first row was ever
    written.** The gate first asked for equality with the answering epoch, and that made two
    different statements wear one shape. Reachable with nothing broken: a new epoch lands, a
    sweep then fails before it processes a single device — this recorder fires on failed
    sweeps by design — and the hourly re-judge (`refresh_tenant`) has not run yet. Every
    stored signature is one epoch behind, an equality gate finds nothing, and the night
    writes no rows at all: this family's one reserved sentence, *nothing has ever been
    assessed here*, said about a fleet assessed for months, in a tape nobody can re-date. So
    the gate asks the question it means. A tenant whose answers are merely behind writes its
    night, and the counts say what the wire said: `apps_unknown` carries the whole installed
    population (an answer from an epoch that no longer answers reads `unknown_app`, §4f)
    while the other three are honest zeros. `apps_unknown == catalog.installed` is that
    night's legible shape, and docs/posture-snapshot.md names it so a reader does not have
    to rediscover it.

    **What the row cannot say: which epoch answered.** `posture_snapshot` carries no epoch
    column — one row is one metric, one capture, one population, never a wide row (#102) —
    and `vuln_library_epoch` keeps a single row with no history, so a count is not
    re-datable to the corpus that produced it years later. The shape above is the substitute,
    and it is written down rather than left implicit.

    The gate closes again on its own, which is the behaviour a tier flip needs: a tenant
    turned back to `off` has its stored answers cleared by the next judge pass
    (`app.catalog.service.judge_vuln` with no epoch nulls `vuln_signature` with the rest of
    the answer), so the gate finds nothing and the tape stops rather than flatlining at zero
    under a fleet nobody is assessing any more.

    The population for the three app keys is `catalog.installed`'s exactly — distinct
    builds of this capture's platform that at least one device carries — so a reader has a
    denominator that means something: of N installed builds, A affected, U unassessed, and
    the rest assessed clean. `vuln.devices_affected` folds the same affected builds onto
    the device population every `devices.*` key counts, through the catalog row rather than
    through the copy on `installed_apps`: the build is what was judged, and the copy is
    allowed to lag a device's own sync by design (§4f), so counting copies would let the two
    keys disagree about one build on a night the tape cannot re-run. That is the copy-lag
    axis only. On the population axis the two halves draw different lines on purpose —
    `catalog.installed` counts a build any device row carries, `devices_affected` counts
    devices on active connections — so a build only a deactivated connection's Mac carries
    is counted in the three app keys and in no device here. Documented in the key rows
    rather than folded away, because making them agree would give the app keys a denominator
    `catalog.installed` no longer matches. The **departure** cut is the one line all four
    draw together (#476): a Mac that left the fleet carries no build in any of them.
    """
    from app.core.config import settings

    if settings.vuln_tenant_selection:
        from app.core.vuln_selection import selected_signature

        epoch = await selected_signature(db)
    else:
        epoch = (await db.execute(select(VulnLibraryEpoch.signature).limit(1))).scalars().first()
    if epoch is None:
        return {}
    # Has the join ever run for THIS tenant? One row is the whole question, so it is asked
    # with a LIMIT rather than a count. Deliberately NOT `== epoch`: see the docstring — an
    # equality gate spells "one epoch behind" the same way it spells "never assessed", and
    # absence in this family is a reserved sentence that must keep saying one thing. The
    # catalog rows are tenant-scoped by row-level security, so this sees the acting tenant's
    # rows only — one pod's judged tenant does not open the gate for its unjudged neighbour.
    judged = (await db.execute(select(AppCatalogEntry.id).where(AppCatalogEntry.vuln_signature.is_not(None)).limit(1))).first()
    if judged is None:
        return {}

    of_platform = AppCatalogEntry.platform == CAPTURE_PLATFORM
    # `covered`, judged against the epoch that is answering — `served()`'s rule rather than a
    # fourth hand-written copy of it, so the tape can never draw a line the wire does not: an
    # answer from an epoch that no longer answers is not stale-but-usable, it is `unknown_app`
    # until the next judge pass rewrites it. The epoch handed to it is the one read from the
    # database above and never `loaded_epoch_signature()` — the docstring says why.
    answered = served(AppCatalogEntry.vuln_assessment, AppCatalogEntry.vuln_signature, epoch=epoch)
    values: dict[str, float] = {}
    values["vuln.apps_affected"] = await _count(
        db,
        select(func.count()).select_from(AppCatalogEntry).where(of_platform, _installed(at), answered, _findings("total") > 0),
    )
    # KEV is a subset of affected, never its own population: a KEV-listed finding is one of
    # the findings `total` already counted, and the two keys land separately because ratios
    # are never stored.
    values["vuln.apps_kev_affected"] = await _count(
        db,
        select(func.count()).select_from(AppCatalogEntry).where(of_platform, _installed(at), answered, _findings("kev") > 0),
    )
    # Everything in the same population that is NOT answered: no row in the epoch, or an
    # answer from an epoch that is no longer the one answering. `is_distinct_from` because
    # both columns are nullable and a NULL is precisely the unassessed case — `!=` would
    # drop exactly the rows this key exists to count.
    values["vuln.apps_unknown"] = await _count(
        db,
        select(func.count())
        .select_from(AppCatalogEntry)
        .where(
            of_platform,
            _installed(at),
            or_(
                AppCatalogEntry.vuln_assessment.is_distinct_from(VULN_ASSESSMENT_COVERED),
                AppCatalogEntry.vuln_signature.is_distinct_from(epoch),
            ),
        ),
    )
    values["vuln.devices_affected"] = await _count(
        db,
        select(func.count(distinct(InstalledApp.device_id)))
        .select_from(InstalledApp)
        .join(Device, Device.id == InstalledApp.device_id)
        .join(MdmConnection, MdmConnection.id == Device.mdm_connection_id)
        # The same platform pin `copy_vuln_answers` joins on: one `version_hash` on two
        # platforms is two catalog rows, and a Mac must read the Mac one.
        .join(
            AppCatalogEntry,
            and_(AppCatalogEntry.version_hash == InstalledApp.version_hash, AppCatalogEntry.platform == Device.platform),
        )
        .where(MdmConnection.is_active.is_(True), _in_the_fleet(at), of_platform, answered, _findings("total") > 0),
    )

    # The ledger's three (#591). Its own gate, one EXISTS: a tenant whose Macs have not been swept since
    # `device_findings` landed holds no row, and the keys are absent rather than nought. No device join and no departure
    # cut, deliberately: `device_departed` has no writer yet (#590), so a Mac deleted in Jamf keeps its open rows, and
    # hiding them here would make this key disagree with the page counting the same rows. The doc rows say so.
    if (await db.execute(select(DeviceFinding.id).limit(1))).first() is not None:
        window = at - timedelta(hours=_WINDOW_HOURS)
        counted = select(
            func.count().filter(DeviceFinding.resolved_at.is_(None)),
            func.count().filter(DeviceFinding.first_observed_at >= window),
            func.count().filter(DeviceFinding.resolved_at >= window),
        ).select_from(DeviceFinding)
        # Zipped onto FINDING_KEYS, so the tuple's order and the family's are one fact.
        values.update(zip(FINDING_KEYS, (int(n) for n in (await db.execute(counted)).one()), strict=True))
    return values


async def _compute(db: AsyncSession, run_id: uuid.UUID, captured_at: datetime) -> dict[str, float]:
    """Every active key's value, one bounded query each. A key absent from the result
    writes no row — `outbox.oldest_pending_age_s` on an empty queue, and the four `vuln.*`
    keys on a tenant the corpus join has never judged."""
    stale_cutoff = captured_at - timedelta(hours=_STALE_HOURS)
    window_start = captured_at - timedelta(hours=_WINDOW_HOURS)
    values: dict[str, float] = {}

    # devices.* — device rows across active connections that are still in the fleet
    # (`_in_the_fleet`, #476). NULLs count as stale in both staleness keys: a device that has
    # never checked in is the worst staleness there is.
    counted = _devices_on_active_connections(captured_at)
    values["devices.total"] = await _count(db, counted)
    values["devices.stale_checkin_7d"] = await _count(
        db, counted.where(or_(Device.last_check_in.is_(None), Device.last_check_in < stale_cutoff))
    )
    values["devices.unmanaged"] = await _count(db, counted.where(Device.managed.is_(False)))
    values["devices.stale_inventory_7d"] = await _count(
        db, counted.where(or_(Device.last_inventory_at.is_(None), Device.last_inventory_at < stale_cutoff))
    )
    # devices.departed_24h — the exit itself, the one key here that counts the Macs the four
    # above have just stopped counting. **Derived, never a column** (#183): an open departure row
    # IS the tail. The SAME predicate at two instants — in the population 24h ago, gone for good
    # by capture — so the key cannot drift from the exclusion it measures, and a Jamf id retired
    # by a serial match (#475) lands here on its own day seven.
    left = gone_for_good(Device.mdm_connection_id, Device.external_id, at=captured_at)
    values["devices.departed_24h"] = await _count(db, _devices_on_active_connections(window_start).where(left))

    # catalog.* — CatalogSummaryOut's semantics, computed here rather than through the
    # API. installed_not_latest is at the catalog-entry grain, deliberately not device
    # pairs: "how many distinct behind versions exist", not "how many installs are behind".
    # Rows of the population this capture counts (#236): a catalog row carries the platform
    # of the devices that showed it, and a mobile row — unmatchable by construction, Jamf
    # Patch being macOS-only — must not read as the Mac fleet's coverage collapsing.
    of_platform = AppCatalogEntry.platform == CAPTURE_PLATFORM
    values["catalog.entries"] = await _count(db, select(func.count()).select_from(AppCatalogEntry).where(of_platform))
    values["catalog.installed"] = await _count(
        db, select(func.count()).select_from(AppCatalogEntry).where(of_platform, _installed(captured_at))
    )
    values["catalog.matched"] = await _count(
        db,
        select(func.count()).select_from(AppCatalogEntry).where(of_platform, AppCatalogEntry.jamf_title_ids.is_not(None)),
    )
    values["catalog.unmatched"] = await _count(
        db,
        select(func.count()).select_from(AppCatalogEntry).where(of_platform, AppCatalogEntry.jamf_title_ids.is_(None)),
    )
    # `matched` and `unmatched` are complementary predicates on one column, so they partition
    # `entries` — asserted for the reason the patch states are below (#314): a pair of counts
    # that must add up is worth one comparison a night, and the alternative is discovering they
    # do not from a customer's dashboard. NOTE the denominator this makes explicit: both are
    # over `entries` (every row the fleet has ever shown), never over `installed` (rows on a
    # device right now), so a "what fraction can Jamf patch" ratio must pick one and say which.
    _partitions(values, "catalog.entries", ("catalog.matched", "catalog.unmatched"), what="catalog entries by match")

    values["catalog.installed_not_latest"] = await _count(
        db,
        select(func.count())
        .select_from(AppCatalogEntry)
        .where(
            of_platform,
            _installed(captured_at),
            AppCatalogEntry.is_latest.is_(False),
            AppCatalogEntry.latest_version.is_not(None),
        ),
    )

    installs = select(func.count(distinct(InstalledApp.app_hash))).join(Device, Device.id == InstalledApp.device_id)
    values["apps.distinct"] = await _count(db, installs.where(_in_the_fleet(captured_at)))

    # patch.* — the pair grain, and the per-title laggard cut /api/jamf-patch renders as
    # devices_on_latest < device_count. Coverage % derives at render; both inputs land.
    values["patch.pairs_total"], values["patch.pairs_on_latest"] = await patch_pair_counts(db, at=captured_at)
    # patch.pairs_laggard_over_14d — #68's clock, ruled 2026-09-02: Jamf's release date of the
    # earliest listed version newer than the installed one, read from the pair's own title row.
    # Behind only: an unlisted build cannot be placed against a specific missed update, so it
    # gets its own key rather than a silent seat in this one. Both error directions are part of
    # the definition — no severity filter (a superset of the Cyber Essentials number), and the
    # matcher's dateless-list fallback to the latest version's date (an age that reads smaller).
    laggard_cutoff = captured_at - timedelta(hours=_LAGGARD_HOURS)
    values["patch.pairs_laggard_over_14d"] = await _count(
        db,
        select(func.count()).select_from(
            _patch_pairs(
                captured_at,
                AppCatalogTitleMatch.state == STATE_BEHIND,
                AppCatalogTitleMatch.first_newer_released_at < laggard_cutoff,
            )
        ),
    )
    # patch.pairs_behind_under_14d — the rest of `behind`, so the five state keys partition
    # `pairs_total` exactly (#314). A dateless pair lands HERE, not in the laggard key: the
    # matcher leaves `first_newer_released_at` null when a title publishes no release date for
    # anything newer, and `< cutoff` excludes null in SQL, so before this key such a pair was in
    # no bucket at all — counted in the total and invisible everywhere else. Null goes to the
    # conservative side, which is the same direction the laggard key's documented under-count
    # already errs in: it can only make the laggard number smaller, never larger.
    values["patch.pairs_behind_under_14d"] = await _count(
        db,
        select(func.count()).select_from(
            _patch_pairs(
                captured_at,
                AppCatalogTitleMatch.state == STATE_BEHIND,
                or_(
                    AppCatalogTitleMatch.first_newer_released_at >= laggard_cutoff,
                    AppCatalogTitleMatch.first_newer_released_at.is_(None),
                ),
            )
        ),
    )
    values["patch.pairs_unknown_build"] = await _count(
        db, select(func.count()).select_from(_patch_pairs(captured_at, AppCatalogTitleMatch.state == STATE_UNKNOWN))
    )
    # patch.pairs_ahead — installed NEWER than anything the title lists. Given a key of its own
    # for the reason `pairs_unknown_build` has one (#314): before it, `ahead` was counted in
    # `pairs_total` and in nothing else, which made the state invisible and let two other keys
    # absorb it. Not rare — Chrome and Safari sit here on essentially every Mac fleet, because
    # they auto-update faster than Jamf's catalog publishes.
    values["patch.pairs_ahead"] = await _count(
        db, select(func.count()).select_from(_patch_pairs(captured_at, AppCatalogTitleMatch.state == STATE_AHEAD))
    )
    # The five state keys partition `pairs_total`, and this asserts it rather than trusting it.
    # `classify` assigns exactly one of latest/ahead/behind/unknown, `on_latest` is true iff the
    # state is latest, and the behind pair is split by a predicate whose two halves cover null —
    # so the sum is an identity, and a drift in any one predicate breaks it here rather than in
    # a customer's dashboard. Cheap: five integers already in hand, once a night.
    _partitions(
        values,
        "patch.pairs_total",
        (
            "patch.pairs_on_latest",
            "patch.pairs_behind_under_14d",
            "patch.pairs_laggard_over_14d",
            "patch.pairs_unknown_build",
            "patch.pairs_ahead",
        ),
        what="patch pairs by state",
    )

    # patch.titles_with_laggards — titles carrying at least one pair that is genuinely BEHIND.
    # Redefined 2026-09-04 (#314, Kyle) from "any device not on the title's current version",
    # which counted a device running a build NEWER than Jamf publishes as a laggard: on the
    # reference tenant it read 11 against 10 laggard pairs, and the extra title was Google
    # Chrome. Ahead and unknown are excluded for the reason `pairs_unknown_build` was split out
    # in the first place — a build that cannot be placed, or that is out in front, must not take
    # a silent seat in a laggard number. Both remain visible in their own keys. No 14-day cut
    # here: this key answers "which titles have someone behind at all", and the dated question
    # is `pairs_laggard_over_14d` one grain down.
    behind_pairs = _patch_pairs(captured_at, AppCatalogTitleMatch.state == STATE_BEHIND)
    values["patch.titles_with_laggards"] = await _count(
        db, select(func.count(distinct(behind_pairs.c.title_id))).select_from(behind_pairs)
    )

    # changes.notable_24h — one SQL predicate over the closed LEVELS ordering, on the
    # feed's own time axis (observed_at). No API parameter is involved or added.
    values["changes.notable_24h"] = await _count(
        db,
        select(func.count())
        .select_from(DeviceChange)
        .where(
            DeviceChange.level.in_(NOTABLE_LEVELS),
            DeviceChange.observed_at > window_start,
            DeviceChange.observed_at <= captured_at,
        ),
    )

    # alerts.* — the derived latch (#101, docs/alerts.md), on the same population every
    # devices.* key counts over: active connections, still in the fleet. `open` is "true of
    # the fleet at capture": the latch has no acknowledge path, so an open row is a live fact and
    # never a chore nobody ticked off. `opened_24h` counts rows that have since closed —
    # which is why closed rows are purged on a clock rather than deleted at close, and
    # why the count cannot ride the partial index the open read uses.
    values["alerts.open"] = await _count(db, _alerts_on_active_connections(captured_at).where(Alert.closed_at.is_(None)))
    values["alerts.opened_24h"] = await _count(
        db,
        _alerts_on_active_connections(captured_at).where(Alert.opened_at > window_start, Alert.opened_at <= captured_at),
    )

    # runs.* — 30-day run retention against 12-month audit periods: these rows are the
    # only durable run history, which is why they are captured rather than queried live.
    values["runs.sweeps_succeeded_24h"] = await _count(
        db,
        select(func.count())
        .select_from(Run)
        .where(
            Run.trigger == TRIGGER_SWEEP,
            Run.status == STATUS_SUCCEEDED,
            Run.finished_at > window_start,
            Run.finished_at <= captured_at,
        ),
    )
    values["runs.failed_24h"] = await _count(
        db,
        select(func.count())
        .select_from(Run)
        .where(Run.status == STATUS_FAILED, Run.finished_at > window_start, Run.finished_at <= captured_at),
    )
    stamping = (await db.execute(select(Run.started_at, Run.finished_at).where(Run.id == run_id))).first()
    if stamping is not None and stamping.started_at is not None and stamping.finished_at is not None:
        values["runs.full_sweep_duration_s"] = (stamping.finished_at - stamping.started_at).total_seconds()

    # outbox.* — pending is a nightly point-sample of a queue that drains continuously;
    # the caveat is part of the definition, not a footnote.
    values["outbox.pending"] = await _count(db, select(func.count()).select_from(EventOutbox).where(_outbox_pending_where()))
    values["outbox.failed_24h"] = await _count(
        db, select(func.count()).select_from(OutboxDelivery).where(outbox_failed_window_where(captured_at))
    )
    oldest_pending = (
        await db.execute(select(func.min(EventOutbox.created_at)).where(_outbox_pending_where()))
    ).scalar_one_or_none()
    if oldest_pending is not None:
        # Absent when nothing was pending — never coerced to 0, which would make "empty
        # queue" indistinguishable from "a delivery is due right now".
        values["outbox.oldest_pending_age_s"] = max((captured_at - oldest_pending).total_seconds(), 0.0)

    # accounts.* / tokens.* — the operator surface. accounts.total is the non-revoked
    # set (status "active"); admins mirrors the accounts API's own last-admin count.
    values["accounts.total"] = await _count(db, select(func.count()).select_from(Account).where(Account.status == "active"))
    values["accounts.admins"] = await _count(
        db,
        select(func.count(distinct(AccountRole.account_id)))
        .join_from(AccountRole, Account, Account.id == AccountRole.account_id)
        .where(Account.status == "active", AccountRole.role == Role.admin.value),
    )
    values["tokens.active"] = await _count(db, select(func.count()).select_from(ApiToken).where(ApiToken.revoked_at.is_(None)))

    # vuln.* — the stored per-build answers (#381), counted; or nothing at all on a tenant
    # the corpus join has never judged, which is the one place this recorder writes no rows
    # rather than zeros for a whole family of keys.
    values.update(await _vuln_values(db, captured_at))

    return values


async def record_full_sweep_snapshot(db: AsyncSession, *, run_id: uuid.UUID) -> int:
    """Capture every active key against the run that just closed. Returns rows written.

    Called by app.core.runs.finish after the run row is terminal — success and failure
    alike — and commits its own rows, so a capture can never hold the run's close
    hostage. The session is the sweep's own tenant-bound session: the tenant GUC stamps
    tenant_id and row-level security scopes every read, same as everywhere else.
    """
    captured_at = _utcnow()
    values = await _compute(db, run_id, captured_at)
    db.add_all(
        PostureSnapshot(
            metric_key=key,
            platform=CAPTURE_PLATFORM,
            value=values[key],
            captured_at=captured_at,
            full_sweep_run_id=run_id,
        )
        for key in ACTIVE_KEYS
        if key in values
    )
    await db.commit()
    written = sum(1 for key in ACTIVE_KEYS if key in values)
    logger.info(
        "posture snapshot captured",
        extra={
            "run_id": str(run_id),
            "keys": written,
            "captured_at": captured_at.isoformat(),
            # Which of the two legible shapes this capture has, named rather than left to
            # be inferred from a key count (docs/diagnosability.md rule 2): `unassessed` is
            # four keys deliberately absent, not four keys lost. It is the ordinary state on
            # a pod with no vulnerability library or with data sharing off, and the next
            # check for either is docs/troubleshooting.md §5. `counted` says the four rows
            # were written, not that anything was answered tonight: a tenant whose answers
            # are an epoch behind writes its night as `apps_unknown == catalog.installed`,
            # which the rows say and this field deliberately does not restate.
            "vuln": "counted" if any(key in values for key in VULN_KEYS) else "unassessed",
        },
    )
    return written
