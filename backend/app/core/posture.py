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
history. Reserved keys (`RESERVED_KEYS`) have frozen definitions and no writer yet;
no key records before its feature's table exists — a run of primed zeros is a lie
about when measurement began.

Three writing rules the reader of the table must be able to rely on:

* **Absent means "did not apply", never zero.** `outbox.oldest_pending_age_s` writes
  no row when zero rows were pending — coercing that to 0 would make "empty queue"
  indistinguishable from "a delivery is due right now".
* **Ratios are never stored.** Numerator and denominator land as separate keys and
  the percentage derives at render, so the inputs stay auditable forever.
* **Every row names the population it counted.** `platform` is stamped from
  `CAPTURE_PLATFORM`, so a number is never read against a fleet it did not measure.
  Thirteen active keys change meaning the night a sweep observes more than Macs, and
  immutable definitions leave no way to say so afterwards (#230).

Recorder failure never fails the run: the caller (runs.finish) catches everything,
logs, and lets the run's verdict stand. A night can lose its capture; it must never
lose its sweep.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import distinct, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.changes.policy import NORMAL, levels_at_least
from app.core.permissions import Role
from app.core.runs import STATUS_FAILED, STATUS_SUCCEEDED, TRIGGER_SWEEP
from app.mdm.patch.matching import STATE_AHEAD, STATE_BEHIND, STATE_UNKNOWN
from app.models.schema import (
    Account,
    AccountRole,
    Alert,
    ApiToken,
    AppCatalogEntry,
    AppCatalogTitleMatch,
    Device,
    DeviceChange,
    EventOutbox,
    InstalledApp,
    MdmConnection,
    OutboxDelivery,
    PostureSnapshot,
    Run,
)

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

# Definitions v1 — the 29 active keys, in the order their rows are written. The names
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
RESERVED_KEYS: tuple[str, ...] = (
    "vuln.apps_affected",
    "vuln.apps_kev_affected",
    "vuln.apps_unknown",
    "vuln.devices_affected",
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _devices_on_active_connections():
    """The device population every devices.* key counts over: rows on active connections."""
    return (
        select(func.count())
        .select_from(Device)
        .join(MdmConnection, MdmConnection.id == Device.mdm_connection_id)
        .where(MdmConnection.is_active.is_(True))
    )


def _alerts_on_active_connections():
    """The alert population both alerts.* keys count over: latches on devices whose
    connection is active — the same cut `_devices_on_active_connections` draws, and the
    same cut `GET /api/alerts` returns, so the tape and the surface can never disagree
    about how many things need attention."""
    return (
        select(func.count())
        .select_from(Alert)
        .join(Device, Device.id == Alert.device_id)
        .join(MdmConnection, MdmConnection.id == Device.mdm_connection_id)
        .where(MdmConnection.is_active.is_(True))
    )


def _installed():
    """An app_catalog row someone actually has: at least one installed app carries its hash —
    the same "devices > 0" cut CatalogSummaryOut draws, computed recorder-side."""
    return exists(select(InstalledApp.id).where(InstalledApp.version_hash == AppCatalogEntry.version_hash))


def _patch_pairs(*criteria):
    """Distinct (device, matched Jamf Patch title) install pairs — the
    AppCatalogTitleMatch → catalog row → InstalledApp join /api/jamf-patch counts devices
    through, kept at the pair grain. `criteria` are predicates on the match row: `on_latest`
    follows the standing "latest = any title says so" semantics the matcher already stamped
    on the row, and the dates are the row's own, so no fold across titles ever happens here."""
    stmt = (
        select(InstalledApp.device_id, AppCatalogTitleMatch.title_id)
        .join_from(
            AppCatalogTitleMatch, AppCatalogEntry, AppCatalogEntry.id == AppCatalogTitleMatch.app_catalog_id
        )
        .join(InstalledApp, InstalledApp.version_hash == AppCatalogEntry.version_hash)
    )
    if criteria:
        stmt = stmt.where(*criteria)
    return stmt.distinct().subquery()


def _outbox_pending_where():
    """An event still awaiting delivery: not yet fanned out, or holding at least one
    delivery row that is still pending. A nightly point-sample by construction — the
    caveat is frozen into the key's definition."""
    pending_delivery = exists(
        select(OutboxDelivery.id).where(
            OutboxDelivery.outbox_event_id == EventOutbox.id, OutboxDelivery.status == "pending"
        )
    )
    return or_(EventOutbox.fanned_out.is_(False), pending_delivery)


async def _count(db: AsyncSession, stmt) -> int:
    return int((await db.execute(stmt)).scalar_one())


async def _compute(db: AsyncSession, run_id: uuid.UUID, captured_at: datetime) -> dict[str, float]:
    """Every active key's value, one bounded query each. A key absent from the result
    writes no row — currently only outbox.oldest_pending_age_s exercises that."""
    stale_cutoff = captured_at - timedelta(hours=_STALE_HOURS)
    window_start = captured_at - timedelta(hours=_WINDOW_HOURS)
    values: dict[str, float] = {}

    # devices.* — device rows across active connections. NULLs count as stale in both
    # staleness keys: a device that has never checked in is the worst staleness there is.
    values["devices.total"] = await _count(db, _devices_on_active_connections())
    values["devices.stale_checkin_7d"] = await _count(
        db,
        _devices_on_active_connections().where(
            or_(Device.last_check_in.is_(None), Device.last_check_in < stale_cutoff)
        ),
    )
    values["devices.unmanaged"] = await _count(
        db, _devices_on_active_connections().where(Device.managed.is_(False))
    )
    values["devices.stale_inventory_7d"] = await _count(
        db,
        _devices_on_active_connections().where(
            or_(Device.last_inventory_at.is_(None), Device.last_inventory_at < stale_cutoff)
        ),
    )

    # catalog.* — CatalogSummaryOut's semantics, computed here rather than through the
    # API. installed_not_latest is at the catalog-entry grain, deliberately not device
    # pairs: "how many distinct behind versions exist", not "how many installs are behind".
    values["catalog.entries"] = await _count(db, select(func.count()).select_from(AppCatalogEntry))
    values["catalog.installed"] = await _count(
        db, select(func.count()).select_from(AppCatalogEntry).where(_installed())
    )
    values["catalog.matched"] = await _count(
        db, select(func.count()).select_from(AppCatalogEntry).where(AppCatalogEntry.jamf_title_ids.is_not(None))
    )
    values["catalog.unmatched"] = await _count(
        db, select(func.count()).select_from(AppCatalogEntry).where(AppCatalogEntry.jamf_title_ids.is_(None))
    )
    values["catalog.installed_not_latest"] = await _count(
        db,
        select(func.count())
        .select_from(AppCatalogEntry)
        .where(_installed(), AppCatalogEntry.is_latest.is_(False), AppCatalogEntry.latest_version.is_not(None)),
    )

    values["apps.distinct"] = await _count(db, select(func.count(distinct(InstalledApp.app_hash))))

    # patch.* — the pair grain, and the per-title laggard cut /api/jamf-patch renders as
    # devices_on_latest < device_count. Coverage % derives at render; both inputs land.
    values["patch.pairs_total"] = await _count(db, select(func.count()).select_from(_patch_pairs()))
    values["patch.pairs_on_latest"] = await _count(
        db, select(func.count()).select_from(_patch_pairs(AppCatalogTitleMatch.on_latest.is_(True)))
    )
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
                AppCatalogTitleMatch.state == STATE_BEHIND,
                or_(
                    AppCatalogTitleMatch.first_newer_released_at >= laggard_cutoff,
                    AppCatalogTitleMatch.first_newer_released_at.is_(None),
                ),
            )
        ),
    )
    values["patch.pairs_unknown_build"] = await _count(
        db, select(func.count()).select_from(_patch_pairs(AppCatalogTitleMatch.state == STATE_UNKNOWN))
    )
    # patch.pairs_ahead — installed NEWER than anything the title lists. Given a key of its own
    # for the reason `pairs_unknown_build` has one (#314): before it, `ahead` was counted in
    # `pairs_total` and in nothing else, which made the state invisible and let two other keys
    # absorb it. Not rare — Chrome and Safari sit here on essentially every Mac fleet, because
    # they auto-update faster than Jamf's catalog publishes.
    values["patch.pairs_ahead"] = await _count(
        db, select(func.count()).select_from(_patch_pairs(AppCatalogTitleMatch.state == STATE_AHEAD))
    )
    # The five state keys partition `pairs_total`, and this asserts it rather than trusting it.
    # `classify` assigns exactly one of latest/ahead/behind/unknown, `on_latest` is true iff the
    # state is latest, and the behind pair is split by a predicate whose two halves cover null —
    # so the sum is an identity, and a drift in any one predicate breaks it here rather than in
    # a customer's dashboard. Cheap: five integers already in hand, once a night.
    partition = (
        values["patch.pairs_on_latest"]
        + values["patch.pairs_behind_under_14d"]
        + values["patch.pairs_laggard_over_14d"]
        + values["patch.pairs_unknown_build"]
        + values["patch.pairs_ahead"]
    )
    if partition != values["patch.pairs_total"]:  # pragma: no cover — an identity, guarded
        raise ValueError(
            f"patch pair states do not partition pairs_total: {partition} != {values['patch.pairs_total']}"
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
    behind_pairs = _patch_pairs(AppCatalogTitleMatch.state == STATE_BEHIND)
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

    # alerts.* — the derived latch (#101, docs/alerts.md), on the same active-connection
    # population every devices.* key counts over. `open` is literally "true of the fleet
    # at capture": the latch has no acknowledge path, so an open row is a live fact and
    # never a chore nobody ticked off. `opened_24h` counts rows that have since closed —
    # which is why closed rows are purged on a clock rather than deleted at close, and
    # why the count cannot ride the partial index the open read uses.
    values["alerts.open"] = await _count(db, _alerts_on_active_connections().where(Alert.closed_at.is_(None)))
    values["alerts.opened_24h"] = await _count(
        db,
        _alerts_on_active_connections().where(
            Alert.opened_at > window_start, Alert.opened_at <= captured_at
        ),
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
    stamping = (
        await db.execute(select(Run.started_at, Run.finished_at).where(Run.id == run_id))
    ).first()
    if stamping is not None and stamping.started_at is not None and stamping.finished_at is not None:
        values["runs.full_sweep_duration_s"] = (stamping.finished_at - stamping.started_at).total_seconds()

    # outbox.* — pending is a nightly point-sample of a queue that drains continuously;
    # the caveat is part of the definition, not a footnote.
    values["outbox.pending"] = await _count(
        db, select(func.count()).select_from(EventOutbox).where(_outbox_pending_where())
    )
    entered_failed_at = func.coalesce(OutboxDelivery.last_attempted_at, OutboxDelivery.created_at)
    values["outbox.failed_24h"] = await _count(
        db,
        select(func.count())
        .select_from(OutboxDelivery)
        .where(
            OutboxDelivery.status == "failed",
            entered_failed_at > window_start,
            entered_failed_at <= captured_at,
        ),
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
    values["accounts.total"] = await _count(
        db, select(func.count()).select_from(Account).where(Account.status == "active")
    )
    values["accounts.admins"] = await _count(
        db,
        select(func.count(distinct(AccountRole.account_id)))
        .join_from(AccountRole, Account, Account.id == AccountRole.account_id)
        .where(Account.status == "active", AccountRole.role == Role.admin.value),
    )
    values["tokens.active"] = await _count(
        db, select(func.count()).select_from(ApiToken).where(ApiToken.revoked_at.is_(None))
    )

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
        extra={"run_id": str(run_id), "keys": written, "captured_at": captured_at.isoformat()},
    )
    return written
