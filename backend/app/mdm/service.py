from __future__ import annotations

import asyncio
import logging
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.alerts.service import sync_new_app_latches
from app.catalog.service import record_device_apps
from app.changes.derive import derive_and_record
from app.core.config import settings
from app.core.content_keys import app_full_key, app_title_key
from app.core.context import get_request_id
from app.core.hashing import compute_app_hash, compute_version_hash
from app.core.outbox import enqueue_event
from app.core.runs import (
    LOCK_WEBHOOK,
    TRIGGER_MANUAL,
    TRIGGER_SWEEP,
    TRIGGER_WEBHOOK,
    RunReclaimed,
    acquire,
    beat,
    entered,
    event_time,
    finish,
    get_run,
    pull_event_id,
    run_meta,
)
from app.core.runs import log as run_log
from app.core.vuln import loaded_corpus
from app.core.vuln_answer import stored_corpus
from app.core.vuln_library import read_tenant_tier
from app.core.wire import ENVELOPE, envelope, instance_label
from app.mdm.factory import get_mdm_client
from app.mdm.jamf.client import (
    DEFAULT_SWEEP_PAGE_SIZE,
    REACTIVE_WEBHOOK_EVENTS,
    JamfClient,
    normalize_computer,
    parse_webhook_event,
)
from app.mdm.jamf.contract import (
    SUBJECT_COMPUTER_GROUP,
    SUBJECT_EXTENSION_ATTRIBUTE_DEFINITION,
    V0_SECTIONS,
    Aperture,
    Observation,
    build_aperture,
    canonicalize_computer,
    canonicalize_extension_attribute_definition,
    canonicalize_smart_group,
    with_extension_attribute_carriers,
)
from app.mdm.org_units import BUILDING, DEPARTMENT, record_org_units
from app.mdm.patch.matching import cached_title_names
from app.mdm.snapshot import build_inventory_snapshot
from app.models.schema import (
    Collection,
    Device,
    DeviceExtensionAttribute,
    InstalledApp,
    MdmConnection,
    MdmSyncState,
    Run,
)
from app.observations.departure import reconcile_census
from app.observations.ledger import (
    RecordResult,
    current_span,
    ensure_aperture,
    is_stale,
    record_observation,
)
from app.schemas.payload import (
    WIRE_SCHEMA_VERSION,
    InventoryChangedEvent,
    NormalizedApp,
    NormalizedDevice,
    SyncStatus,
)

logger = logging.getLogger(__name__)

# What triggered an ingest. Stamped on every span as `last_trigger`, and now also the
# run's own `trigger` — one vocabulary across the ledger, the run, and the wire, which is
# what the note here promised before #31 landed. Defined in app.core.runs and re-exported
# so the existing importers of this module keep working.
__all__ = ["TRIGGER_MANUAL", "TRIGGER_SWEEP", "TRIGGER_WEBHOOK"]

# How many devices between progress lines in the run log. Chosen so a 40,000-device sweep
# writes 80 lines, not 40,000: the log is for someone watching a sweep move, not a record
# of every device (the ledger already is that).
_PROGRESS_EVERY = 500

# How much of a failing device's error lands in the run log. Enough to name the
# exception and its message; never a payload dump.
_FAILURE_ERROR_CHARS = 300


class SweepFailureThresholdExceeded(Exception):
    """More devices failed than one sweep is allowed to absorb (#92).

    Raised from the device loop the moment the count crosses `sweep_failures_allowed`,
    which is what stops a fleet-wide outage after the tolerance rather than grinding
    through 40,000 individually-logged failures. Carries the accounting at the point of
    the stop so the run row and the run.completed event report what was actually
    attempted, not zeros.
    """

    def __init__(self, message: str, *, devices_attempted: int, devices_processed: int, devices_failed: int) -> None:
        super().__init__(message)
        self.devices_attempted = devices_attempted
        self.devices_processed = devices_processed
        self.devices_failed = devices_failed


def sweep_failures_allowed(devices_attempted: int) -> int:
    """How many device failures a sweep tolerates: the larger of the absolute floor and
    the percentage of devices attempted so far. Evaluated as the sweep streams —
    totalCount from Jamf is a floor, not gospel, so "attempted so far" is the only
    denominator that actually exists mid-sweep. The consequence is deliberate: scattered
    failures across a big fleet stay inside a growing allowance, while a run where
    everything fails from the start is stopped just past the absolute floor.
    """
    percent_allowance = int(devices_attempted * settings.sweep_failure_max_percent / 100)
    return max(settings.sweep_failure_max_absolute, percent_allowance)


def apply_hashes(app: NormalizedApp) -> NormalizedApp:
    """Stamp both hashes onto a normalized app.

    Called from process_sync so recon sweeps, manual syncs, and inbound HEC webhooks
    all hash identically — the MDM clients deliberately don't do this themselves, or
    the three paths would drift.
    """
    app.app_hash = compute_app_hash(app.name, app.bundle_id)
    app.version_hash = compute_version_hash(app.name, app.bundle_id, app.version, app.short_version)
    app.key_title = app_title_key(app.name, app.bundle_id)
    app.key_full = app_full_key(app.name, app.bundle_id, app.version, app.short_version)
    return app


@dataclass(frozen=True, slots=True)
class ConnectionSyncResult:
    connection_id: int
    device_count: int = 0
    ok: bool = True
    skipped: bool = False
    error: str | None = None
    # Failure accounting (#92): device_count is the devices attempted, and
    # processed + failed = attempted. A result can be ok=True with failures — isolated
    # device failures inside the sweep's tolerance.
    devices_processed: int = 0
    devices_failed: int = 0
    # Ledger outcomes for this run, keyed by app.observations.ledger.Outcome, plus the
    # number of group definitions observed. Empty for providers without a ledger.
    observations: Mapping[str, int] = field(default_factory=dict)
    group_count: int = 0
    # Which collection this run served, when it served one (None for the generic path
    # and for connection-level runs that aggregate several).
    collection_id: int | None = None


def sync_result_kwargs(result: ConnectionSyncResult) -> dict[str, object]:
    """What `finish()` records about a completed sync — the ONE definition of it.

    Two call sites close a run from one of these results: the scheduled collection path
    (`app.mdm.collections`) and the manual connection sync (`app.api.connections`). Both used
    to spell the same seven keyword arguments by hand, which is the shape that produced the
    `refresh_tenant` defect in #311: a count added to this dataclass and threaded through one
    of them would make a scheduled run's `run.completed` and a manual run's disagree about the
    same fleet, with nothing failing. Named here so a field added above reaches both paths or
    neither.

    `ok` and `error` ride along because they come off the same result; `collection_id` does
    not — `finish` takes the run, and the run already knows which collection acquired it.
    """
    return {
        "ok": result.ok,
        "device_count": result.device_count,
        "group_count": result.group_count,
        "devices_processed": result.devices_processed,
        "devices_failed": result.devices_failed,
        "observations": dict(result.observations),
        "error": result.error,
    }


async def set_sync_status(db: AsyncSession, connection: MdmConnection, status: SyncStatus) -> None:
    """Upsert just the status field, leaving counts alone.

    Used to publish 'syncing' before a long pull starts and 'failed' after one dies, so
    the UI can show something other than a stale 'idle'.
    """
    result = await db.execute(select(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection.id))
    state = result.scalar_one_or_none()

    if state is None:
        state = MdmSyncState(mdm_connection_id=connection.id, provider=connection.provider)
        db.add(state)

    state.status = status.value
    await db.commit()


async def sync_connection(
    db: AsyncSession, connection: MdmConnection, *, trigger: str = TRIGGER_SWEEP, run: Run | None = None
) -> ConnectionSyncResult:
    """Pull inventory for a single connection.

    What to pull and how is a property of the connection's collections, not of the
    connection; the connection-level entry point runs every enabled device sweep it
    has (creating the defaults if none exist yet). Reports a connection-level failure
    rather than raising — an expired credential on one Jamf tenant must not abort a
    sweep across several.
    """
    from app.mdm.collections import run_connection  # local: collections imports this module

    return await run_connection(db, connection, trigger=trigger, run=run)


async def capture_aperture(
    client: JamfClient,
    http: httpx.AsyncClient,
    *,
    sections: Sequence[str] = V0_SECTIONS,
    quarantined_extension_attributes: Iterable[str] = (),
) -> Aperture:
    """Read how Jamf is configured to inventory, and stamp it with how we asked.

    Two reads per run (version, inventory-collection settings) — never per device.
    Either may be unavailable to an API client without the privilege; the aperture
    records the absence rather than failing the sweep. The sections and quarantine are
    the collection's, so a narrowed collection is an explicit aperture rather than
    every omitted section "disappearing".
    """
    version = await client.fetch_version(http)
    settings = await client.fetch_inventory_collection_settings(http)
    return build_aperture(
        host=client.host,
        jamf_version=version,
        sections=sections,
        inventory_collection=settings,
        quarantined_extension_attributes=quarantined_extension_attributes,
    )


async def run_jamf(
    db: AsyncSession,
    connection: MdmConnection,
    *,
    trigger: str,
    sections: Sequence[str] = V0_SECTIONS,
    selector: str | None = None,
    page_size: int | None = None,
    quarantined_extension_attributes: Iterable[str] = (),
    include_catalog: bool = True,
    collection_id: int | None = None,
    run: Run | None = None,
) -> ConnectionSyncResult:
    """One device sweep of a Jamf connection, as a collection describes it.

    Like sync_connection, this reports a failure rather than raising: the tick runs
    many collections in turn and one expired credential must not abort the rest.
    """
    quarantine = tuple(quarantined_extension_attributes)
    # Asking for EAs means reading the sections they are displayed under (#197). Closed
    # here, at the top of every sweep, so the aperture, the fetch and the merge agree —
    # for a collection row saved before the rule existed as much as for one saved after.
    sections = with_extension_attribute_carriers(sections)
    # Read while the instance is certainly live: the generic handler below runs after
    # a rollback, which expires every ORM instance in the session even with
    # expire_on_commit=False — and an expired attribute read under asyncio raises
    # MissingGreenlet instead of lazily refreshing (#125).
    connection_id = connection.id
    try:
        # This tenant's data-sharing tier, once for the whole sweep (#248,
        # docs/vulnerabilities.md §8). It decides whether `loaded_corpus()` answers for
        # this tenant at all, and it is a per-tenant row, so it is read here rather than
        # per device — the same reason the title names below ride a process cache.
        #
        # **Inside the guard, because it is a database read.** It is this function's first
        # I/O, and the docstring above is a contract: a failure here has to come back as a
        # failed sweep on this connection, not as an exception unwinding through
        # `run_connection` (which catches only `RunReclaimed`) into `collections_tick`'s
        # blanket handler, abandoning the rest of that tenant's due collections and leaving
        # the claimed run row to the reclaim.
        await read_tenant_tier(db)
        client = get_mdm_client(connection)
        result = await _sync_jamf(
            db,
            connection,
            client,
            trigger=trigger,
            sections=tuple(sections),
            selector=selector,
            page_size=page_size,
            quarantine=quarantine,
            include_catalog=include_catalog,
            run=run,
        )
    except RunReclaimed:
        # Not a connection failure, and not this frame's status to write: the reclaim
        # already closed the run, and a fresh acquisition may be sweeping this
        # connection right now — stamping `failed` on its sync state here would be the
        # reclaimed process narrating someone else's run. The run's owner stops the
        # rest of the work (app.mdm.collections.run_collection).
        raise
    except SweepFailureThresholdExceeded as exc:
        # No rollback here: the device loop rolled back the last failing device before
        # raising, so the session is clean — and the accounting on the exception is
        # what lets the run row report what was attempted rather than zeros.
        await set_sync_status(db, connection, SyncStatus.failed)
        logger.error(
            "jamf sweep failed: device failures exceeded the threshold",
            extra={
                "connection_id": connection.id,
                "collection_id": collection_id,
                "trigger": trigger,
                "devices_attempted": exc.devices_attempted,
                "devices_failed": exc.devices_failed,
            },
        )
        return ConnectionSyncResult(
            connection_id=connection.id,
            ok=False,
            error=str(exc),
            device_count=exc.devices_attempted,
            devices_processed=exc.devices_processed,
            devices_failed=exc.devices_failed,
            collection_id=collection_id,
        )
    except Exception as exc:
        await db.rollback()
        # Logged first, from the primitives captured above — the log line must land
        # with the right connection id even if the status write below cannot.
        logger.exception(
            "jamf sweep failed",
            extra={"connection_id": connection_id, "collection_id": collection_id, "trigger": trigger},
        )
        # The rollback expired the connection instance; reload it before
        # set_sync_status reads it, or the MissingGreenlet raised here left the
        # status stuck 'syncing' and collections_tick's blanket handler ate the
        # crash (#125). The sweep published 'syncing' before it started, so a
        # terminal status must land or the UI shows a sync that never ends.
        await db.refresh(connection)
        await set_sync_status(db, connection, SyncStatus.failed)
        return ConnectionSyncResult(connection_id=connection_id, ok=False, error=str(exc), collection_id=collection_id)

    logger.info(
        "jamf sweep finished",
        extra={
            "connection_id": connection.id,
            "collection_id": collection_id,
            "device_count": result.device_count,
            "devices_failed": result.devices_failed,
            "observations": dict(result.observations),
            "group_count": result.group_count,
            "trigger": trigger,
        },
    )
    return ConnectionSyncResult(
        connection_id=result.connection_id,
        device_count=result.device_count,
        devices_processed=result.devices_processed,
        devices_failed=result.devices_failed,
        observations=result.observations,
        group_count=result.group_count,
        collection_id=collection_id,
    )


async def run_jamf_catalog(
    db: AsyncSession,
    connection: MdmConnection,
    *,
    trigger: str,
    collection_id: int | None = None,
    run: Run | None = None,
) -> ConnectionSyncResult:
    """The catalog class on its own: smart-group definitions with criteria, no devices.
    Tens to hundreds of small reads, so it can run far more often than a sweep and
    timestamp a criteria edit finer than the sweep would."""
    # Same discipline as run_jamf (#125): captured before the handler's rollback can
    # expire the instance, because an expired read under asyncio raises MissingGreenlet.
    connection_id = connection.id
    try:
        client = get_mdm_client(connection)
        outcomes: Counter[str] = Counter()
        async with client.http() as http:
            aperture = await capture_aperture(client, http)
            aperture_digest = await ensure_aperture(db, connection_id=connection.id, aperture=aperture)
            connection.last_successful_auth_at = datetime.now(UTC)
            await db.commit()
            groups = await _observe_groups(db, connection, client, http, aperture_digest, trigger, outcomes)
            group_count = len(groups)
            definitions = await _observe_extension_attribute_definitions(
                db, connection, client, http, aperture_digest, trigger, outcomes
            )
            await _reconcile_departures(db, connection, run, groups=groups, definitions=definitions)
            # The catalog class is where the label catalogs belong too: a department
            # renamed between sweeps is visible at the catalog's cadence, without a
            # device read.
            org_units = await _refresh_org_units(db, connection, client, http)
            await db.commit()
            throttle = {**client.throttle.observations(), **client.adaptive.observations()}
            if run is not None:
                await beat(db, run)
                if client.adaptive.changes:
                    await run_log(db, run, "warning", "throttled: sweep width reduced", reductions=client.adaptive.changes)
                if throttle:
                    await run_log(db, run, "warning", "throttled by Jamf; backed off and continued", **throttle)
                await run_log(db, run, "info", "group definitions observed", groupCount=group_count)
                await _log_definition_census(db, run, definitions)
                await run_log(
                    db,
                    run,
                    "info",
                    "department and building names cached",
                    departments=org_units[DEPARTMENT],
                    buildings=org_units[BUILDING],
                )
    except RunReclaimed:
        # Same as run_jamf: the reclaim already closed the run; its owner stops the work.
        raise
    except Exception as exc:
        await db.rollback()
        logger.exception(
            "jamf catalog refresh failed",
            extra={"connection_id": connection_id, "collection_id": collection_id, "trigger": trigger},
        )
        return ConnectionSyncResult(connection_id=connection_id, ok=False, error=str(exc), collection_id=collection_id)

    logger.info(
        "jamf catalog refreshed",
        extra={"connection_id": connection.id, "collection_id": collection_id, "group_count": group_count, "trigger": trigger},
    )
    return ConnectionSyncResult(
        connection_id=connection.id,
        observations={**dict(outcomes), **throttle},
        group_count=group_count,
        collection_id=collection_id,
    )


async def _observe_groups(
    db: AsyncSession,
    connection: MdmConnection,
    client: JamfClient,
    http: httpx.AsyncClient,
    aperture_digest: str,
    trigger: str,
    outcomes: Counter[str],
) -> list[str]:
    """Observe every smart-group definition; returns the ids the census named (#181).
    `fetch_smart_groups` answers an empty list for a refused read as well as for a tenant
    with no groups — the breaker in `reconcile_census` is what keeps that from reading as
    every group departing at once."""
    observed: list[str] = []
    for raw_group in await client.fetch_smart_groups(http):
        observation = canonicalize_smart_group(raw_group)
        result = await record_observation(
            db,
            connection_id=connection.id,
            observation=observation,
            aperture_digest=aperture_digest,
            trigger=trigger,
        )
        if result.outcome == "changed":
            await derive_and_record(db, connection=connection, observation=observation, result=result, trigger=trigger)
        outcomes[f"group_{result.outcome}"] += 1
        observed.append(observation.subject_id)
    return observed


async def _reconcile_departures(
    db: AsyncSession,
    connection: MdmConnection,
    run: Run | None,
    *,
    groups: Iterable[str] | None,
    definitions: Iterable[str] | None,
) -> None:
    """The departure derivation for both object kinds the catalog pass took a census of
    (#181), logged on the run. Commits, so a departure lands with the census that found it."""
    at = datetime.now(UTC)
    for subject_kind, observed in ((SUBJECT_COMPUTER_GROUP, groups), (SUBJECT_EXTENSION_ATTRIBUTE_DEFINITION, definitions)):
        verdict = await reconcile_census(
            db,
            connection_id=connection.id,
            subject_kind=subject_kind,
            observed_ids=observed,
            at=at,
            census_run_id=run.id if run is not None else None,
        )
        if run is not None:
            level = "warning" if verdict.skipped else "info"
            await run_log(db, run, level, "departures reconciled", **verdict.as_log())
    await db.commit()


async def _observe_extension_attribute_definitions(
    db: AsyncSession,
    connection: MdmConnection,
    client: JamfClient,
    http: httpx.AsyncClient,
    aperture_digest: str,
    trigger: str,
    outcomes: Counter[str],
) -> list[str] | None:
    """The extension-attribute census (#178), the mirror of `_observe_groups`: every
    definition Jamf holds, recorded as its own subject in the ledger, so a definition's
    departure has something to be absent from (#181). Recorded in the catalog pass for
    the reason group definitions are — definitions are then never older than the values
    that reference them.

    Spans only, no derived change rows: what a SIEM receives about a definition that
    moved or departed is #179's shape, and the ledger is what that seam reads.

    None when the definitions could not be read at all — a missing privilege, an older
    Jamf Pro — which the caller logs as a skipped census. It is deliberately not zero.
    """
    definitions = await client.fetch_computer_extension_attributes(http)
    if definitions is None:
        return None
    observed: list[str] = []
    for raw_definition in definitions:
        observation = canonicalize_extension_attribute_definition(raw_definition)
        result = await record_observation(
            db,
            connection_id=connection.id,
            observation=observation,
            aperture_digest=aperture_digest,
            trigger=trigger,
        )
        outcomes[f"ea_definition_{result.outcome}"] += 1
        observed.append(observation.subject_id)
    return observed


async def _log_definition_census(db: AsyncSession, run: Run, observed: list[str] | None) -> None:
    if observed is None:
        await run_log(db, run, "warning", "extension attribute definitions not readable; census skipped")
    else:
        await run_log(db, run, "info", "extension attribute definitions observed", definitionCount=len(observed))


async def _refresh_org_units(
    db: AsyncSession, connection: MdmConnection, client: JamfClient, http: httpx.AsyncClient
) -> dict[str, int]:
    """Cache Jamf's department and building names for this connection.

    Two paged reads of tens of rows each — the whole cost of turning `departmentId: "7"`
    into "Engineering" for every device in the fleet (app.mdm.org_units). Not an
    observation and not hashed: renaming a department changes nothing about any Mac.
    """
    counts: dict[str, int] = {}
    for kind, units in (
        (DEPARTMENT, await client.fetch_departments(http)),
        (BUILDING, await client.fetch_buildings(http)),
    ):
        counts[kind] = await record_org_units(db, connection_id=connection.id, kind=kind, units=units)
    return counts


async def _sync_jamf(
    db: AsyncSession,
    connection: MdmConnection,
    client: JamfClient,
    *,
    trigger: str,
    sections: Sequence[str] = V0_SECTIONS,
    selector: str | None = None,
    page_size: int | None = None,
    quarantine: Sequence[str] = (),
    include_catalog: bool = True,
    run: Run | None = None,
) -> ConnectionSyncResult:
    outcomes: Counter[str] = Counter()
    device_count = 0
    devices_processed = 0
    devices_failed = 0
    group_count = 0

    async with client.http() as http:
        aperture = await capture_aperture(client, http, sections=sections, quarantined_extension_attributes=quarantine)
        aperture_digest = await ensure_aperture(db, connection_id=connection.id, aperture=aperture)
        connection.last_successful_auth_at = datetime.now(UTC)
        await db.commit()
        if run is not None:
            await run_log(
                db,
                run,
                "info",
                "aperture captured",
                apertureDigest=aperture_digest[:12],
                sections=list(sections),
                selector=selector,
            )

        # Names before ids. The loop below writes `departmentId` and `buildingId` onto
        # every device it touches, and those are only ever displayed through this
        # lookup — reading the two catalogs first means a device swept today is never
        # shown as a bare number. Unconditional, not behind include_catalog: that flag
        # exists to spare a device-only collection the hundreds of smart-group detail
        # reads, and this is two.
        org_units = await _refresh_org_units(db, connection, client, http)
        await db.commit()
        if run is not None:
            await run_log(
                db,
                run,
                "info",
                "department and building names cached",
                departments=org_units[DEPARTMENT],
                buildings=org_units[BUILDING],
            )

        # Group definitions ride along with the device sweep, and they go *first* (#136).
        # A membership change is judged by `changes.derive._membership_cause` as the
        # device is observed: it asks whether the group's current definition span opened
        # after the device was last seen. Observed after the loop — as this was — the
        # current span during the loop was still the pre-edit one, so every membership
        # change a criteria edit caused since the last catalog observation (hourly by
        # default) read as device drift, `criteriaChanged: false`. Observed here, the
        # definitions the loop judges against are this sweep's. The catalog is therefore
        # at most one sweep older than the memberships that reference it, which the
        # hourly catalog collection (docs/ingest-scheduling.md §6.2) closes on its own.
        if include_catalog:
            groups = await _observe_groups(db, connection, client, http, aperture_digest, trigger, outcomes)
            group_count = len(groups)
            await db.commit()
            if run is not None:
                await run_log(db, run, "info", "group definitions observed", groupCount=group_count)
            # The extension-attribute census rides the same pass, for the same reason
            # (#178): the definitions a device's values reference are never older than
            # the values.
            definitions = await _observe_extension_attribute_definitions(
                db, connection, client, http, aperture_digest, trigger, outcomes
            )
            await db.commit()
            if run is not None:
                await _log_definition_census(db, run, definitions)
            # And what the two censuses did not name (#181).
            await _reconcile_departures(db, connection, run, groups=groups, definitions=definitions)

        # Streamed, not collected: a 40,000-device tenant is paged through one record
        # at a time, and each device commits on its own (process_sync), so a failure on
        # device 30,000 leaves 29,999 correctly recorded. The selector is pushed into
        # Jamf's query rather than applied after the fetch — filtering client-side would
        # still spend the API budget the selector exists to save.
        # The collection's override wins, then the connection's setting, then the
        # default — the collection knows its sections, the connection its worst case.
        effective_page_size = page_size or connection.sweep_page_size or DEFAULT_SWEEP_PAGE_SIZE
        async for raw in client.iter_computers(http, sections, rsql_filter=selector, page_size=effective_page_size):
            device_count += 1
            try:
                result = await ingest_computer(
                    db,
                    connection,
                    raw,
                    aperture_digest=aperture_digest,
                    trigger=trigger,
                    sections=sections,
                    quarantined_extension_attributes=quarantine,
                )
            except (RunReclaimed, asyncio.CancelledError):
                # Neither is a device failure. A reclaim means this process's run is
                # already someone else's history (#94) and every further write is a
                # second, unaccounted copy of work — it must unwind, not be absorbed
                # into the failure count. Cancellation is the loop being told to stop.
                raise
            except Exception as exc:
                # One device must not kill the sweep (#92). Whatever this device's
                # ingest half-wrote — a ledger span, app rows, a change row — is rolled
                # back so the next device starts from a clean session; the devices
                # before it are safe behind their own commits.
                devices_failed += 1
                await db.rollback()
                # The rollback expired every ORM instance in the session; reload the
                # two the loop keeps using, or the next attribute read raises instead
                # of lazily refreshing (asyncio).
                await db.refresh(connection)
                jamf_id = raw.get("id")
                serial = (raw.get("hardware") or {}).get("serialNumber")
                failure = f"{type(exc).__name__}: {exc}"[:_FAILURE_ERROR_CHARS]
                logger.warning(
                    "device failed; sweep continues",
                    extra={
                        "connection_id": connection.id,
                        "jamf_id": jamf_id,
                        "serial_number": serial,
                        "devices_failed": devices_failed,
                        "error": failure,
                    },
                )
                if run is not None:
                    await db.refresh(run)
                    await run_log(
                        db,
                        run,
                        "warning",
                        "device failed; sweep continues",
                        jamfId=jamf_id,
                        serialNumber=serial,
                        error=failure,
                    )
                allowed = sweep_failures_allowed(device_count)
                if devices_failed > allowed:
                    raise SweepFailureThresholdExceeded(
                        f"{devices_failed} of {device_count} devices failed, over the "
                        f"tolerance of {allowed} (max of sweep_failure_max_absolute="
                        f"{settings.sweep_failure_max_absolute}, "
                        f"sweep_failure_max_percent={settings.sweep_failure_max_percent}% "
                        "of devices attempted); stopping rather than grinding through "
                        "a fleet-wide outage",
                        devices_attempted=device_count,
                        devices_processed=devices_processed,
                        devices_failed=devices_failed,
                    ) from exc
            else:
                outcomes[result.outcome] += 1
                devices_processed += 1

            if run is not None:
                # Between devices, not per device: the beat is throttled to one small
                # UPDATE every fifteen seconds, and the progress line to every few
                # hundred devices. Both live in the loop because this *is* the long
                # stretch — a forty-minute pull with no sign of life is exactly what the
                # reclaim would otherwise mistake for a dead process.
                await beat(db, run)
                if device_count % _PROGRESS_EVERY == 0:
                    await run_log(db, run, "info", "devices processed", deviceCount=device_count, outcomes=dict(outcomes))

        # Throttling is run-row data, not just log lines: the counters ride the same
        # observations JSONB the ledger outcomes do, so the run detail can show them
        # and a dynamic tuner (#74) reads structure instead of parsing text.
        throttle = {**client.throttle.observations(), **client.adaptive.observations()}
        if run is not None:
            if client.adaptive.changes:
                await run_log(db, run, "warning", "throttled: sweep width reduced", reductions=client.adaptive.changes)
            if throttle:
                await run_log(db, run, "warning", "throttled by Jamf; backed off and continued", **throttle)
            await run_log(
                db,
                run,
                "info",
                "sweep complete",
                deviceCount=device_count,
                groupCount=group_count,
                outcomes=dict(outcomes),
                **({"devicesFailed": devices_failed} if devices_failed else {}),
            )

    await sync_state(db, connection)
    await db.commit()
    return ConnectionSyncResult(
        connection_id=connection.id,
        device_count=device_count,
        devices_processed=devices_processed,
        devices_failed=devices_failed,
        observations={**dict(outcomes), **throttle},
        group_count=group_count,
    )


async def ingest_computer(
    db: AsyncSession,
    connection: MdmConnection,
    raw: dict,
    *,
    aperture_digest: str,
    trigger: str,
    sections: Sequence[str] = V0_SECTIONS,
    quarantined_extension_attributes: Iterable[str] = (),
) -> RecordResult:
    """One raw Jamf computer record, through both layers: the observation ledger and
    the current-state tables. The single function every Jamf ingest path — sweep,
    manual run, webhook — goes through, so the two layers can never disagree about
    what was seen.

    The ledger is consulted first because it owns the monotonic guard: if this record
    is older than what the ledger already holds for the device, neither layer is
    written. Otherwise the ledger write and process_sync's updates commit together.
    """
    observation = canonicalize_computer(raw, sections, quarantined_extension_attributes=quarantined_extension_attributes)
    current = await current_span(
        db,
        connection_id=connection.id,
        subject_kind=observation.subject_kind,
        subject_id=observation.subject_id,
    )
    collected_at = datetime.now(UTC)
    if is_stale(current, observation.observed_at or collected_at):
        logger.info(
            "stale observation ignored",
            extra={
                "connection_id": connection.id,
                "subject_id": observation.subject_id,
                "observed_at": observation.observed_at,
                "current_observed_at": current.last_observed_at if current else None,
                "trigger": trigger,
            },
        )
        return RecordResult(
            outcome="stale",
            head_digest="",
            span_id=current.id if current else None,
        )

    result = await record_observation(
        db,
        connection_id=connection.id,
        observation=observation,
        aperture_digest=aperture_digest,
        trigger=trigger,
        collected_at=collected_at,
        current=current,
        current_loaded=True,
    )
    if result.outcome == "changed":
        # The change log is derived from the two spans and written in the same
        # transaction as the device's state tables below.
        await derive_and_record(
            db, connection=connection, observation=observation, result=result, trigger=trigger, collected_at=collected_at
        )
    # The same sections the ledger just recorded as the aperture: the current-state
    # tables must not consume more of the record than the run declared it read (#93) —
    # and the same quarantine, so a quarantined EA is absent from both layers (#197).
    # The observation rides along because it is what the snapshot event is built from
    # (#241): the allowlisted view of exactly the record the ledger just wrote.
    await process_sync(
        db,
        normalize_computer(raw, sections, quarantined_extension_attributes=quarantined_extension_attributes),
        connection,
        observation=observation,
    )
    return result


async def ingest_webhook(db: AsyncSession, connection: MdmConnection, payload: dict) -> RecordResult | None:
    """A Jamf webhook names a computer; the inventory comes from a fetch.

    Returns None when the event does not warrant one (not in REACTIVE_WEBHOOK_EVENTS —
    a ComputerCheckIn above all, #76) or when the payload names nothing (no jssID) — a
    test webhook, or an event type that does not carry a computer. The aperture is captured per event (two small
    reads) under the connection's webhook collection, which may be scoped differently
    from the sweep's; an aperture is content-addressed, so an unchanged one is an upsert
    of `last_seen_at` and nothing more.
    """
    client = get_mdm_client(connection)
    event = parse_webhook_event(payload)
    if event.event_name not in REACTIVE_WEBHOOK_EVENTS:
        # Dropped by name, not by accident: a ComputerCheckIn is a heartbeat times
        # the whole fleet, and reacting would mint a run and burn three API reads
        # per heartbeat (#76). Nothing has been fetched and no run row exists yet.
        logger.info(
            "jamf webhook event does not warrant a fetch; dropped by design",
            extra={"connection_id": connection.id, "event": event.event_name, "jamf_id": event.jamf_id},
        )
        return None
    if event.jamf_id is None:
        logger.info(
            "jamf webhook carried no computer id; nothing to ingest",
            extra={"connection_id": connection.id, "event": event.event_name},
        )
        return None

    # One read of the tier per webhook, for the same reason the sweep reads it once per
    # run: one event is one device, and `loaded_corpus()` must not go asking per app.
    #
    # **Below both guards, not above them.** The dropped paths above never reach
    # `process_sync`, so nothing there ever reads the tier — and a ComputerCheckIn is a
    # heartbeat times the whole fleet, so a read above the guards would put a query on the
    # one path whose entire purpose is to cost nothing (#76).
    await read_tenant_tier(db)

    sections, quarantine = await webhook_scope(db, connection)

    # A webhook is a run with one device in it — it needs the jobID so its event is
    # correlatable and the log so it is accountable. It does *not* take the lock: the
    # index predicate excludes the webhook class, so a burst of them from a busy tenant
    # runs concurrently and never queues behind a forty-minute sweep (§4.4).
    acquisition = await acquire(db, connection, trigger=TRIGGER_WEBHOOK, lock_class=LOCK_WEBHOOK, actor_label=event.event_name)
    run = acquisition.run
    async with entered(run):
        try:
            async with client.http() as http:
                aperture = await capture_aperture(client, http, sections=sections, quarantined_extension_attributes=quarantine)
                aperture_digest = await ensure_aperture(db, connection_id=connection.id, aperture=aperture)
                raw = await client.fetch_computer_detail(http, event.jamf_id)

            result = await ingest_computer(
                db,
                connection,
                raw,
                aperture_digest=aperture_digest,
                trigger=TRIGGER_WEBHOOK,
                sections=sections,
                quarantined_extension_attributes=quarantine,
            )
        except Exception as exc:
            await db.rollback()
            # The rollback expired every ORM instance in the session; reload the run
            # before finish() reads its id, or the MissingGreenlet raised there let
            # the route 500 instead of answering its designed error and left the run
            # 'running' until the reclaim (#125). A fetch failure fails the run
            # deliberately — including Jamf answering 404 for a computer deleted
            # between the webhook and the fetch: there is no inventory to ingest, the
            # row records why, and run.failed carries it to the wire (#103).
            await db.refresh(run)
            await finish(db, run, ok=False, error=str(exc))
            raise
        # The return is deliberately unchecked: if a slow fetch let the reclaim take
        # this run, the refused finish leaves that verdict standing, and the device
        # write above stands on its own — it is fresh from Jamf, and staleness is the
        # ledger's monotonic guard's call, not the run bookkeeping's.
        await finish(db, run, ok=True, device_count=1, devices_processed=1, observations={result.outcome: 1})
        return result


async def webhook_scope(db: AsyncSession, connection: MdmConnection) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The sections and EA quarantine the webhook path fetches under: the connection's
    enabled webhook collection, or the whole contract when none exists."""
    result = await db.execute(
        select(Collection).where(
            Collection.mdm_connection_id == connection.id,
            Collection.kind == "webhook",
            Collection.enabled.is_(True),
        )
    )
    collection = result.scalars().first()
    if collection is None or not collection.sections:
        return tuple(V0_SECTIONS), ()
    # Closed for the same reason run_jamf closes the sweep's (#197).
    return (
        with_extension_attribute_carriers(collection.sections),
        tuple(collection.quarantined_extension_attributes or ()),
    )


async def sync_state(db: AsyncSession, connection: MdmConnection) -> None:
    """Stamp the run's end on the connection's sync state. Once per run, not per device:
    the previous per-device call recounted every device row each time, which made a
    sweep quadratic in fleet size."""
    result = await db.execute(select(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection.id))
    state = result.scalar_one_or_none()

    device_count = (
        await db.execute(select(func.count()).select_from(Device).where(Device.mdm_connection_id == connection.id))
    ).scalar_one()

    if state is None:
        state = MdmSyncState(mdm_connection_id=connection.id, provider=connection.provider)
        db.add(state)

    state.last_sync_at = datetime.now(UTC)
    state.status = SyncStatus.idle.value
    state.device_count = device_count


def _device_meta(existing: Device) -> dict[str, object]:
    """The device meta block (#189) — the keys stamped onto every sub-event a device
    produces, capped at thirteen and permanent once a customer's SPL references them.

    Eleven ship. The ruling spent twelve of the thirteen slots and held the thirteenth
    open deliberately; the twelfth, `custom`, reserves a name and zero bytes in v0 — the
    shape is frozen (`deviceMeta.custom.groups`, `deviceMeta.custom.ea`) so that a
    customer who writes `| fields deviceMeta.*` today has not written something whose
    expansion changes the day an object appears among these scalars.
    `tests/test_device_meta.py` holds the emitted set to exactly those names, and holds
    the ruling's whole refused table against it.

    Built HERE, at enqueue, and never at delivery. `_build_body` in app.core.outbox
    receives only the destination and the frozen payload — no session, no Device, no
    run — and the run itself is a ContextVar (app.core.runs) whose scope has already
    closed by the time the outbox worker's 30s tick fires. Anything sourced from the run
    or the device row has exactly one moment where it is reachable, and this is it.

    Null values are dropped rather than shipped. The block is over half the raw feed
    measured against a real tenant record, so a key that is null carries cost and no
    information; `NOT deviceMeta.x=*` finds the same events either way. `lastReportDate`
    is the key this is load-bearing for — a device Jamf has never completed inventory on
    ships without it rather than with a null.

    Reads the Device ROW, not the normalized view: under an aperture without HARDWARE
    the view's serial is "" while the row still holds the last real read's (#98).
    """
    run = get_run()
    meta: dict[str, object | None] = {
        # The run's half — jobID, trigger, connectionID, shortDate. Four keys, not six:
        # `comparison` and `collectionID` were cut by the ruling and are gone from
        # run_meta(), which has the argument for each.
        **run_meta(),
        # One id per device per pull, and the only key that can select a single device's
        # complete inventory pass: two sweeps in a day share a shortDate, and one sweep's
        # jobID is shared by every device in the fleet (#189).
        #
        # Derived rather than minted, so it needs no storage and no threading: uuid5 over
        # (run, platform, device) means a retry recomputes the same id rather than looking
        # one up — and the platform is in the name because Jamf's two ID spaces can share
        # a number (#234, `app.core.runs.pull_event_id`).
        #
        # It is derivable ON PURPOSE, so that any other producer of this pull can arrive
        # at the same value without either side passing it along. Nothing else does yet:
        # app.changes.derive now agrees on the run key (`jobID`) and on `jamfProID`, so
        # the join across families works, but it still mints no eventID of its own — a
        # device.change is joined to its pull through jobID + jamfProID rather than
        # through the single key the inventory family has.
        "eventID": pull_event_id(run.id, existing.platform, existing.external_id) if run else None,
        "serialNumber": existing.serial_number or None,
        # Jamf's own primary key, and the half of a deep link that cannot be
        # reconstructed. Emitted as the stored string, not coerced to an int: Splunk
        # searches both identically, and a sibling MDM's id need not be numeric.
        "jamfProID": existing.external_id,
        # The cross-tool identity. Every other sourcetype in a customer's Splunk — EDR,
        # DHCP, VPN, identity — keys on the hostname and none of them know a serial.
        "hostName": existing.hostname or None,
        # Whether the app list is current or six weeks stale. A vulnerability finding on
        # a device that has not reported since July is a different fact from one that
        # reported this morning, and nothing else on the event carries it.
        "lastReportDate": (existing.last_inventory_at.isoformat() if existing.last_inventory_at else None),
        # The compliance filter: two values fleet-wide, and the cheapest key in the
        # block. A bool rather than a `managementStatus` string — an enum with one value
        # invites a second, and additive-only leaves room for a richer field if a third
        # state ever exists.
        "managed": existing.managed,
        "schemaVersion": WIRE_SCHEMA_VERSION,
    }
    return {key: value for key, value in meta.items() if value is not None}


async def process_sync(
    db: AsyncSession, device: NormalizedDevice, connection: MdmConnection, *, observation: Observation
) -> InventoryChangedEvent | None:
    """Bring the current-state tables for one device up to date, emit the snapshot, and
    emit the delta when the app list moved.

    Commits. Anything the caller wrote to the session before this — the observation
    ledger's rows for the same device — lands in the same transaction, and so do both
    events: "we updated the database" and "we recorded the event" can never drift apart
    from a partial failure.

    Two events, one pull (#241). `device.inventory` is the state — one per device per
    pass that clears the ledger's monotonic guard, sweep and webhook alike, whether or
    not anything changed, built from `observation` by app.mdm.snapshot. It never fires
    on the stale path (ingest_computer returns before this is reached) and never for a
    device whose ingest raised and was rolled back. `device.inventory.changed` is what
    happened to the app list, and keeps shipping unchanged, only when something did.
    The two share `occurredAt`, the meta block and its `eventID` by design (#81 ruling
    4: one id per device per pull, stamped on every event of that pull).

    The NEW-app latch rides the same transaction (#101, docs/alerts.md): an app present
    now and absent from this device's previous inventory opens an alert row, an app that
    has gone closes one. Nothing about it reaches the wire.

    `device.apps is None` means the applications section was outside the read's
    aperture (Kyle's ruling, 2026-08-29): app rows, the catalog, and the event stream
    are left exactly as the last real read left them. Only [] — read, and genuinely
    empty — diffs to removals. The same discipline covers the rest of the row (#98):
    each scalar is written only when its owning section was read, and the extension-
    attribute replace runs only on a real read (None-vs-[] again). A read outside the
    aperture holds defaults, not observations — writing them would blank hostnames
    and wipe EA rows on every narrowly-scoped sweep or webhook. The snapshot reads the
    same rule per section: a section outside the aperture is absent from it, and only a
    read-and-empty section is `[]` — it never asserts an absence the read did not
    observe.
    """
    for app in device.apps or ():
        apply_hashes(app)

    result = await db.execute(
        # Both collections are eagerly loaded because the code below reads `apps` to
        # compute the delta and diffs `extension_attributes` against its rows. Under
        # asyncio a lazy load raises MissingGreenlet rather than quietly issuing a
        # query — and it only triggers on the *second* sync of a device, since the
        # first takes the `existing is None` path and never touches either.
        select(Device)
        .options(selectinload(Device.apps), selectinload(Device.extension_attributes))
        .where(
            Device.mdm_connection_id == connection.id,
            # Both, never the id alone: Jamf numbers computers and mobile devices in
            # separate sequences, so computer 42 and iPad 42 are two rows (#233).
            Device.platform == device.platform,
            Device.external_id == device.external_id,
        )
    )
    existing = result.scalar_one_or_none()

    previous_hashes: dict[str, InstalledApp] = {}
    # The NEW-app latch's two inputs, both captured here and neither derivable later
    # (#101, app.alerts.service).
    #
    # `device_is_new` has to be read before the row is created: afterwards there is no
    # way to ask the question, and every other candidate gate is wrong. `Run.comparison`
    # purges with runs at 30 days and partitions by lock class, so a webhook's first pass
    # on a year-old connection still reports `full`.
    #
    # `previous_app_hashes` is a second set rather than a reuse of `previous_hashes`
    # below, because that map is keyed by VERSION hash: reusing it would open a NEW-app
    # alert on every update the fleet takes.
    device_is_new = existing is None
    previous_app_hashes: set[str] = set()
    if existing is None:
        existing = Device(
            mdm_connection_id=connection.id,
            mdm_provider=device.mdm_provider.value,
            platform=device.platform,
            external_id=device.external_id,
            serial_number=device.serial_number,
            hostname=device.hostname,
        )
        db.add(existing)
    else:
        # Keyed on the version hash: a version bump is an install change, so the old
        # build shows as removed and the new one as added.
        previous_hashes = {app.version_hash: app for app in existing.apps}
        previous_app_hashes = {app.app_hash for app in existing.apps if app.app_hash}

    # Seen at all is section-independent; every field below is written only when its
    # owning section was inside the read's aperture (#98). The creation path above
    # already stamped hostname and serial (NOT NULL) with whatever the read carried;
    # for an existing row a narrow read leaves the last real observation standing.
    existing.last_seen_at = datetime.now(UTC)
    if device.observed("general"):
        existing.hostname = device.hostname
        existing.managed = device.managed
        existing.supervised = device.supervised
        existing.site = device.site
        existing.last_check_in = device.last_check_in
        existing.last_inventory_at = device.last_inventory_at
    if device.observed("hardware"):
        existing.serial_number = device.serial_number
    if device.observed("operating_system"):
        existing.os_version = device.os_version
    if device.observed("user_and_location"):
        existing.building_id = device.building_id
        existing.department_id = device.department_id
    if device.extension_attributes is not None:
        # Diffed against the rows already loaded, not replaced (#142). The replace —
        # clear, flush, re-insert — cost a DELETE and an INSERT per device per sweep for
        # a section that rarely moves, forty thousand times over for a fleet that
        # reported the same values as yesterday. Keyed on the definition id, the row's
        # identity (#197): a value that moved is an UPDATE of the row that holds it, a
        # definition the device no longer reports is an orphan (the relationship's
        # delete-orphan cascade issues the DELETE), a definition it reports for the
        # first time is an INSERT, and a row that matches is not written at all. No
        # flush is needed between: a DELETE and an INSERT can only share a key when the
        # same definition is both removed and re-added, which a diff never does.
        current = {row.definition_id: row for row in existing.extension_attributes}
        incoming = {ea.definition_id: ea for ea in device.extension_attributes}
        for definition_id, row in current.items():
            if definition_id not in incoming:
                existing.extension_attributes.remove(row)
        for definition_id, ea in incoming.items():
            values = list(ea.values)
            row = current.get(definition_id)
            if row is None:
                existing.extension_attributes.append(
                    DeviceExtensionAttribute(
                        definition_id=definition_id,
                        name=ea.name,
                        values=values,
                        source=ea.source,
                        enabled=ea.enabled,
                    )
                )
            elif (row.name, list(row.values), row.source, row.enabled) != (ea.name, values, ea.source, ea.enabled):
                row.name = ea.name
                row.values = values
                row.source = ea.source
                row.enabled = ea.enabled

    added: list[NormalizedApp] = []
    removed_rows: list[InstalledApp] = []
    # The rows the device holds AFTER this read: the kept ones plus the added ones, and
    # never `existing.apps` — SQLAlchemy does not prune a loaded collection on delete, so
    # that collection can still hold the removed rows after the flush below, and a removed
    # app must not reach the snapshot. Empty when apps were outside the aperture, where the
    # snapshot carries no `app` wrapper and reads nothing.
    current_rows: list[InstalledApp] = []
    if device.apps is not None:
        incoming_hashes = {app.version_hash: app for app in device.apps if app.version_hash}

        added = [app for version_hash, app in incoming_hashes.items() if version_hash not in previous_hashes]
        removed_rows = [row for version_hash, row in previous_hashes.items() if version_hash not in incoming_hashes]
        current_rows = [row for version_hash, row in previous_hashes.items() if version_hash in incoming_hashes]

        for row in removed_rows:
            await db.delete(row)

        for app in added:
            row = InstalledApp(
                device=existing,
                name=app.name,
                bundle_id=app.bundle_id,
                version=app.version,
                short_version=app.short_version,
                app_hash=app.app_hash,
                version_hash=app.version_hash,
                key_title=app.key_title,
                key_full=app.key_full,
            )
            db.add(row)
            current_rows.append(row)

    await db.flush()
    # The tenant app catalog: every app this device reports is seen now; a (name, bundle ID,
    # version) the fleet has not shown before is judged against Jamf's catalog right here, and
    # each app row gets its copy of the answer. Skipped when apps were not read: the rows
    # kept above are the last read's state, and a scoped fetch must not restamp them as
    # seen now.
    #
    # `copy_answer` writes the Jamf Patch answer onto the very instances `current_rows`
    # holds — the session's identity map hands `record_device_apps`'s SELECT the same
    # objects — which is what lets the snapshot read `patch.supported` off rows already in
    # the transaction with no second query. Cache, don't calculate.
    if device.apps is not None:
        await record_device_apps(db, existing)
        # The NEW-app latch (#101), on the same `device.apps is not None` guard and for
        # the same reason: a read outside the applications aperture observed no apps, so
        # it can neither open a latch nor close one. Rides this transaction, so the alert
        # and the app row it is about commit together. Costs nothing on a quiet pull —
        # no write when nothing arrived, no query when nothing left.
        run = get_run()
        await sync_new_app_latches(
            db,
            device_id=existing.id,
            previous_app_hashes=previous_app_hashes,
            current_rows=current_rows,
            device_is_new=device_is_new,
            run_id=run.id if run else None,
        )

    # Built once and read by both events: the root `jobID` on each is the same string
    # this block carries, taken from the block rather than from a second `get_run()`
    # call, so the duplicate the #220 ruling asked for cannot drift from its original.
    meta = _device_meta(existing)
    # Not `now`. Under a scheduled sweep this is the run's window, so every event the
    # sweep produces shares one `_time` instead of smearing across the forty minutes
    # the pull happened to take; a webhook carries the device's own reportDate. See
    # app.core.runs.event_time. One value for both events of this pull.
    occurred_at = event_time(device.last_inventory_at)
    # The envelope rides on each payload and is lifted off again at delivery
    # (app.core.wire) — `_build_body` can reach neither the run nor the connection, so
    # this is the only moment `source` and the occurrence time are both in hand.
    hints = envelope(occurred_at=occurred_at, host=existing.hostname, source=instance_label(connection.base_url))

    # The snapshot, first and unconditionally (#241). Enqueued in the same transaction as
    # the ledger write above and the row updates, before the delta's early return below,
    # so a device whose app list did not move still says what it IS.
    snapshot = build_inventory_snapshot(
        observation,
        extension_attributes=device.extension_attributes,
        apps=current_rows,
        occurred_at=occurred_at,
        device_meta=meta,
        # Title names for `patch.jamfPatch.titleNames` (#311), off the process cache that
        # `record_device_apps` refreshed a few statements above — no query, and `None` on the
        # scoped path where it was never called, which is the same path whose rows carry an
        # older answer. Reading it here rather than inside the producer keeps that coupling
        # visible at the one call site where the ordering is guaranteed.
        title_names=cached_title_names() if device.apps is not None else None,
        # The one place the container's corpus reaches the wire (#249). `NO_CORPUS` until
        # an epoch is loaded AND this tenant's tier earns it — both decided inside
        # `loaded_corpus()` and neither costing a query here: the tier was read once at the
        # top of this sweep (`run_jamf`) or of this webhook (`ingest_webhook`), which is why
        # this stays a dictionary lookup on a path that runs once per device.
        #
        # And the answers themselves come off `current_rows` (#381), which `copy_answer`
        # stamped a few statements above from a join that ran once per DISTINCT build. The
        # fan-out therefore derives nothing per device: `stored_corpus` is a dictionary
        # built from rows already in this transaction, and it hands back `NO_CORPUS`
        # untouched when nothing is answering, so `assessment: off` stays byte-identical.
        corpus=stored_corpus(loaded_corpus(), current_rows),
    )
    payload = snapshot.to_payload()
    payload[ENVELOPE] = dict(hints)
    await enqueue_event(db, snapshot.event, payload, request_id=get_request_id())

    if not added and not removed_rows:
        await db.commit()
        return None

    event = InventoryChangedEvent(
        provider=device.mdm_provider,
        device_external_id=device.external_id,
        added_apps=added,
        removed_apps=[
            NormalizedApp(
                name=row.name,
                bundle_id=row.bundle_id,
                version=row.version,
                short_version=row.short_version,
                app_hash=row.app_hash,
                version_hash=row.version_hash,
                # Carried so a removal and an addition are the same shape. Without these
                # the one event ships two different key sets for one object type, and a
                # consumer that reads keyTitle off addedApps gets null on every removal.
                key_title=row.key_title,
                key_full=row.key_full,
            )
            for row in removed_rows
        ],
        # The same instant the snapshot carries — see above.
        occurred_at=occurred_at,
        # The run at the event root, duplicating `deviceMeta.jobID` (#220, ruled
        # 2026-09-02). `.get`, not `[...]`: the block drops its nulls, so a run-less
        # enqueue leaves both copies absent rather than one absent and one null.
        job_id=meta.get("jobID"),
        device_meta=meta,
    )

    # Enqueued in the same transaction as the device/app state change below, so "we
    # updated the database" and "we recorded the event" can never drift apart from a
    # partial failure. Delivery itself happens later, on the outbox worker's own
    # schedule — a slow or down destination must never be able to block a sync.
    payload = event.model_dump(mode="json", by_alias=True)
    if payload["jobID"] is None:
        # Absent, not null — see the field's own note. Pydantic has no per-field
        # `exclude_none`, and `exclude_none=True` on the whole dump would silently strip
        # nulls out of every app in `addedApps` too, which is a shape change nobody ruled.
        del payload["jobID"]
    payload[ENVELOPE] = dict(hints)
    await enqueue_event(db, event.event, payload, request_id=get_request_id())
    await db.commit()
    return event
