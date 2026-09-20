"""The finding ledger's transition diff (#590, ruled in #589; docs/vulnerabilities.md §6).

One row per (tenant, device, carrier title, finding id), open while the finding is still detected,
diffed from `installed_apps.vuln_ids` as `record_device_apps` (#381) made them one statement earlier
— so a reconcile costs one SELECT, an epoch re-judge reaches a device on its next sweep and never at
import, and an unchanged sweep writes nothing (ruling 3). Its migration, `c5a2e9b71f34`, argues it."""

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
from app.observations.departure import gone_for_good
from app.schemas.payload import VULN_ASSESSMENT_COVERED

logger = logging.getLogger(__name__)

# Ruling 4 in full; the census closes departed devices after their seven-day tail (#607).
RESOLVED_BUILD_CHANGED, RESOLVED_APP_REMOVED = "build_changed", "app_removed"
RESOLVED_DEVICE_DEPARTED, RESOLVED_CORPUS_WITHDRAWN = "device_departed", "corpus_withdrawn"
RESOLVED_REASONS = (RESOLVED_BUILD_CHANGED, RESOLVED_APP_REMOVED, RESOLVED_DEVICE_DEPARTED, RESOLVED_CORPUS_WITHDRAWN)

BASIS_OBSERVED, BASIS_BACKFILL = "observed", "backfill"  # measured, or reconstructed

_KEY = ("device_id", "carrier_key", "finding_id")  # the grain: the upsert's conflict target

# What to look at next, per reason, logged with the close (docs/troubleshooting.md §5.9).
NEXT_CHECK: Mapping[str, str] = {
    RESOLVED_CORPUS_WITHDRAWN: (
        "the corpus epoch this container has loaded no longer lists them for a build the Mac still carries, which is "
        "not the same as fixed — check the epoch loaded and that the tier is still on (Devices › Applications › Catalog)"
    ),
    RESOLVED_BUILD_CHANGED: "the Mac moved to a build that does not carry them — check the build on the Mac",
    RESOLVED_APP_REMOVED: "the app carrying them is no longer installed on the Mac",
    RESOLVED_DEVICE_DEPARTED: "the Mac has left the fleet",
}


def detected(rows: Iterable[InstalledApp]) -> dict[tuple[str, str], tuple[str, bool]]:
    """S — every (carrier title, finding id) this device's answers assert now, with the build
    carrying it and whether that build's list was truncated. `covered` rows with a non-empty
    list only (`unknown_app` is an absent answer, not a clean bill, §4a). The epoch signature is not
    re-checked, for churn and not for safety, and that buys the ledger no independence from the
    corpus: `e1c7a4d9b520`, "what happens when the corpus stops answering"."""
    found: dict[tuple[str, str], tuple[str, bool]] = {}
    for row in rows:
        if row.vuln_assessment != VULN_ASSESSMENT_COVERED or not row.vuln_ids:
            continue
        for finding_id in row.vuln_ids:
            try:
                validate_finding_id(finding_id)
            except ValueError as exc:
                # Named, never raised: an id the import should have caught must not fail every sync.
                message = "the stored answer for %s carries an id the finding ledger refuses, so no row is opened: %s — "
                message += "the id came from the loaded corpus epoch, not Jamf; check which epoch (troubleshooting §5)"
                logger.warning(message, row.key_full, exc, extra={"state": "finding_id_refused", "key_full": row.key_full})
                continue
            # Two rows can share a title and both carry the id, but the ledger row is ONE: the build
            # recorded is the lowest `key_full`, never whichever came last, and `capped` is the OR
            # over the carriers (migration `e1c7a4d9b520`, "one title, two rows").
            key = (row.key_title, finding_id)
            build, capped = found.get(key, (row.key_full, False))
            found[key] = (min(build, row.key_full), capped or bool(row.vuln_ids_truncated))
    return found


async def reconcile_device_findings(
    db: AsyncSession, *, device: Device, rows: Sequence[InstalledApp], observed_at: datetime, device_is_new: bool = False
) -> Mapping[str, int]:
    """This device's ledger, brought level with the answers on `rows`; returns what it closed, by
    reason. Commits nothing. `observed_at` is the observation's inventory clock, collection time as
    its fallback — what `device_changes` is stamped with (ruling 2)."""
    now = detected(rows)
    # `populate_existing`: the upsert is Core, so the identity map's copy would be pre-reopen.
    mine = select(DeviceFinding).where(DeviceFinding.device_id == device.id).execution_options(populate_existing=True)
    held = (await db.execute(mine)).scalars().all()
    by_key = {(row.carrier_key, row.finding_id): row for row in held}

    # The backfill (ruling 5), lazily on a device's FIRST reconcile — a migration data step would
    # block boot on a 40k-device walk. The marker is on the DEVICE and never the presence of rows,
    # which a Mac reconciled and found clean does not have: migration `e1c7a4d9b520`.
    first_ever = device.findings_reconciled_at is None
    reconstruct = bool(now) and first_ever and not device_is_new
    arrivals = await backfill_clocks(db, device=device, rows=rows) if reconstruct else {}
    basis = BASIS_BACKFILL if reconstruct else BASIS_OBSERVED

    upserts: list[dict] = []
    for (carrier, finding_id), (build, capped) in sorted(now.items()):
        row = by_key.get((carrier, finding_id))
        if row is None:
            first, mark = arrivals.get(build, observed_at), basis
        elif row.resolved_at is None and (row.build_key_full, row.capped) == (build, capped):
            continue  # open, and nothing moved: the sweep that writes nothing
        else:
            # A reopen, or a build that bumped and still carries the id: the row keeps its clock.
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
        # One statement for opens, reopens and refreshes, ON CONFLICT rather than `db.add` for the
        # alert latch's reason: two passes over one device can race a key, webhook ingests never
        # taking the sweep lock. `first_observed_at` is not in the set, so a clock survives a reopen.
        statement = pg_insert(DeviceFinding.__table__).values(upserts)
        moved = {"build_key_full": statement.excluded.build_key_full, "capped": statement.excluded.capped}
        reopen = {"resolved_at": None, "resolved_reason": None, "last_observed_at": None}
        await db.execute(statement.on_conflict_do_update(index_elements=list(_KEY), set_={**moved, **reopen}))
    for reason, ids in closing.items():
        # `last_observed_at` is this observation's clock: nothing is written while a row is open, so a
        # close knows only that it was there before and is not now — high by one inventory interval.
        values = {"resolved_at": observed_at, "resolved_reason": reason, "last_observed_at": observed_at}
        await db.execute(sa_update(DeviceFinding).where(DeviceFinding.id.in_(ids)).values(**values))
        line = "%d finding(s) on %s now read resolved (%s): %s (docs/troubleshooting.md §5 step 9)"
        marks = {"state": f"findings_{reason}", "device_id": device.id, "reason": reason, "findings": len(ids)}
        logger.info(line, len(ids), device.hostname, reason, NEXT_CHECK[reason], extra=marks)
    if first_ever:  # once per device ever, so an unchanged sweep still issues no ledger statement
        device.findings_reconciled_at = observed_at
    return {reason: len(ids) for reason, ids in closing.items()}


async def backfill_clocks(db: AsyncSession, *, device: Device, rows: Sequence[InstalledApp]) -> Mapping[str, datetime]:
    """When each build this Mac carries arrived on it, from the change log — ruling 5's clock, bounded
    by the tenant's own history by construction. One query, once per device ever, and the LATEST
    arrival; a build with no arrival row takes the opening reconcile's clock, `backfill` either way."""
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


async def close_departed_device_findings(db: AsyncSession, *, connection_id: int, at: datetime) -> int:
    """Close findings when Macs leave the fleet after their departure tail (#607).

    Both census paths call this beside the alert close, in the same transaction. An incomplete
    sweep cannot establish a departure, but can finish a tail an earlier clean census established.
    Departure is not an observation: retain the device's last detection clock, including an
    unknown clock, and use `at` only for resolution. Closed rows are never rewritten or deleted.
    """
    result = await db.execute(
        sa_update(DeviceFinding)
        .where(
            DeviceFinding.resolved_at.is_(None),
            DeviceFinding.device_id == Device.id,
            Device.mdm_connection_id == connection_id,
            gone_for_good(Device.mdm_connection_id, Device.external_id, at=at),
        )
        .values(resolved_at=at, resolved_reason=RESOLVED_DEVICE_DEPARTED, last_observed_at=Device.last_seen_at)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount or 0
