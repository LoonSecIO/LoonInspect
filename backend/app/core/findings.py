"""The finding ledger's transition diff (#590, ruled in #589; docs/vulnerabilities.md §6).

`device_findings` holds one row per (tenant, device, carrier title, finding id), open while
the finding is still detected; migration `c5a2e9b71f34` carries the argument for its shape,
and this module is its only writer. S is read off the stored answer — the ids on the device's
own `installed_apps` rows, made current one statement earlier by `record_device_apps` (#381)
— so a reconcile costs one SELECT and no corpus lookup, an epoch that re-judged a build
reaches the ledger on that device's next sweep rather than at import, and an unchanged sweep
writes nothing at all (ruling 3), its diff running in memory."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime

from sqlalchemy import select
from sqlalchemy import update as sa_update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.vuln import validate_finding_id
from app.mdm.jamf.contract import SUBJECT_COMPUTER
from app.models.schema import Device, DeviceChange, DeviceFinding, InstalledApp
from app.schemas.payload import VULN_ASSESSMENT_COVERED

logger = logging.getLogger(__name__)

# Ruling 4 in full. `device_departed` is reserved: its writer, at the census, is a follow-up.
RESOLVED_BUILD_CHANGED, RESOLVED_APP_REMOVED = "build_changed", "app_removed"
RESOLVED_DEVICE_DEPARTED, RESOLVED_CORPUS_WITHDRAWN = "device_departed", "corpus_withdrawn"
RESOLVED_REASONS = (RESOLVED_BUILD_CHANGED, RESOLVED_APP_REMOVED, RESOLVED_DEVICE_DEPARTED, RESOLVED_CORPUS_WITHDRAWN)

# Whether `first_observed_at` was measured or reconstructed, so no reader confuses them.
BASIS_OBSERVED, BASIS_BACKFILL = "observed", "backfill"

_KEY = ("device_id", "carrier_key", "finding_id")  # the grain: the upsert's conflict target

# What to look at next, per reason, logged with the close (docs/troubleshooting.md §5.9).
NEXT_CHECK: Mapping[str, str] = {
    RESOLVED_CORPUS_WITHDRAWN: (
        "the corpus epoch this container has loaded no longer lists them for a build the Mac still carries, "
        "which is not the same as fixed — check which epoch is loaded (the date on Devices › Applications › Catalog)"
    ),
    RESOLVED_BUILD_CHANGED: "the Mac moved to a build that does not carry them — check the build on the Mac",
    RESOLVED_APP_REMOVED: "the app carrying them is no longer installed on the Mac",
    RESOLVED_DEVICE_DEPARTED: "the Mac has left the fleet",
}


def detected(rows: Iterable[InstalledApp]) -> dict[tuple[str, str], tuple[str, bool]]:
    """S — every (carrier title, finding id) this device's answers assert now, with the build
    carrying it and whether that build's list was truncated. `covered` rows with a non-empty
    list only (`unknown_app` is an absent answer, not a clean bill, §4a); the epoch signature
    is not re-checked, because re-gating here would close a ledger on a tier gone off."""
    found: dict[tuple[str, str], tuple[str, bool]] = {}
    for row in rows:
        if row.vuln_assessment != VULN_ASSESSMENT_COVERED or not row.vuln_ids:
            continue
        for finding_id in row.vuln_ids:
            try:
                validate_finding_id(finding_id)
            except ValueError as exc:
                # Refused as `VulnFinding` refuses it, but named rather than raised: an id the
                # epoch import should have caught must not fail every device sync on the box.
                message = "the stored answer for %s carries an id the finding ledger refuses, so no row is opened: %s"
                logger.warning(message, row.key_full, exc, extra={"state": "finding_id_refused", "key_full": row.key_full})
                continue
            found[(row.key_title, finding_id)] = (row.key_full, bool(row.vuln_ids_truncated))
    return found


async def reconcile_device_findings(
    db: AsyncSession, *, device: Device, rows: Sequence[InstalledApp], observed_at: datetime, device_is_new: bool = False
) -> Mapping[str, int]:
    """This device's ledger, brought level with the answers on `rows`; returns what it closed,
    by reason. Commits nothing. `observed_at` is the observation's inventory clock, collection
    time as its fallback — what `device_changes` is stamped with (ruling 2)."""
    now = detected(rows)
    # `populate_existing`: the upsert is Core, so a row this session holds would otherwise
    # come back from the identity map with its pre-reopen attributes.
    mine = select(DeviceFinding).where(DeviceFinding.device_id == device.id).execution_options(populate_existing=True)
    held = (await db.execute(mine)).scalars().all()
    by_key = {(row.carrier_key, row.finding_id): row for row in held}

    # The backfill (ruling 5), lazily on the first reconcile rather than as a migration data
    # step, which would block boot on a 40k-device walk.
    basis, arrivals = BASIS_OBSERVED, {}
    if now and not held and not device_is_new:
        basis = BASIS_BACKFILL
        arrivals = await backfill_clocks(db, device=device, rows=rows)

    upserts: list[dict] = []
    for (carrier, finding_id), (build, capped) in sorted(now.items()):
        row = by_key.get((carrier, finding_id))
        if row is None:
            first, mark = arrivals.get(build, observed_at), basis
        elif row.resolved_at is None and (row.build_key_full, row.capped) == (build, capped):
            continue  # open, and nothing moved: the sweep that writes nothing
        else:
            # A reopen — the same finding back on a Mac that never replaced the app — or a
            # build that bumped and still carries the id. Either way the row keeps its clock.
            first, mark = row.first_observed_at, row.first_seen_basis
        key = {"device_id": device.id, "carrier_key": carrier, "finding_id": finding_id}
        clock = {"first_observed_at": first, "first_seen_basis": mark}
        upserts.append({**key, **clock, "build_key_full": build, "capped": capped})

    builds: dict[str, set[str]] = {}
    for row in rows:
        builds.setdefault(row.key_title, set()).add(row.key_full)

    closing: dict[str, list[int]] = {}
    for row in held:
        if row.resolved_at is not None or (row.carrier_key, row.finding_id) in now:
            continue
        carried = builds.get(row.carrier_key)
        if not carried:
            reason = RESOLVED_APP_REMOVED
        elif row.build_key_full not in carried:
            reason = RESOLVED_BUILD_CHANGED
        elif row.capped:
            continue  # the build is still here and the list is the cap's; absence proves nothing
        else:
            reason = RESOLVED_CORPUS_WITHDRAWN
        closing.setdefault(reason, []).append(row.id)

    if upserts:
        # One statement for opens, reopens and refreshes, and ON CONFLICT rather than `db.add`
        # for the alert latch's reason: webhook ingests never take the sweep lock, so two
        # passes over one device can race one key. `first_observed_at` is not in the update
        # set, so a row's clock survives its reopen (ruling 1).
        statement = pg_insert(DeviceFinding.__table__).values(upserts)
        moved = {"build_key_full": statement.excluded.build_key_full, "capped": statement.excluded.capped}
        reopen = {"resolved_at": None, "resolved_reason": None, "last_observed_at": None}
        await db.execute(statement.on_conflict_do_update(index_elements=list(_KEY), set_={**moved, **reopen}))
    for reason, ids in closing.items():
        # `last_observed_at` is this observation's clock: nothing is written while a row is
        # open, so the close knows only that it was there before and is not now — an upper
        # bound by one inventory interval, which over-states exposure rather than a fix.
        values = {"resolved_at": observed_at, "resolved_reason": reason, "last_observed_at": observed_at}
        await db.execute(sa_update(DeviceFinding).where(DeviceFinding.id.in_(ids)).values(**values))
        line = "%d finding(s) on %s now read resolved (%s): %s (docs/troubleshooting.md §5 step 9)"
        marks = {"state": f"findings_{reason}", "device_id": device.id, "reason": reason, "findings": len(ids)}
        logger.info(line, len(ids), device.hostname, reason, NEXT_CHECK[reason], extra=marks)
    return {reason: len(ids) for reason, ids in closing.items()}


async def backfill_clocks(db: AsyncSession, *, device: Device, rows: Sequence[InstalledApp]) -> Mapping[str, datetime]:
    """When each build this Mac carries arrived on it, from the change log — ruling 5's clock,
    bounded by the tenant's own history by construction, which is the point of preferring it to
    the migration's own date. One query, once per device ever, and the LATEST arrival of that
    build. A build with no arrival row takes the clock of the reconcile that opens it,
    `backfill` either way, so neither reads as a measurement."""
    wanted = {(row.name, row.bundle_id, row.version): row.key_full for row in rows}
    columns = select(DeviceChange.entry_identity, DeviceChange.new_value, DeviceChange.observed_at)
    mine = (DeviceChange.mdm_connection_id == device.mdm_connection_id, DeviceChange.subject_id == device.external_id)
    apps = (DeviceChange.section == "applications", DeviceChange.entry_kind == "application")
    query = columns.where(*mine, *apps, DeviceChange.subject_kind == SUBJECT_COMPUTER).order_by(DeviceChange.observed_at)
    changes = (await db.execute(query)).all()
    arrivals: dict[str, datetime] = {}
    for identity, value, observed in changes:
        build = wanted.get(((identity or {}).get("name"), (identity or {}).get("bundleId"), (value or {}).get("version")))
        if build is not None:
            arrivals[build] = observed
    return arrivals
