from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import ValidationError
from pydantic.alias_generators import to_camel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.config import settings
from app.core.context import Actor, reset_actor, set_actor
from app.core.database import get_db, session_for_tenant
from app.core.permissions import Permission
from app.core.runs import (
    LOCK_DEVICE_SWEEP,
    STATUS_RUNNING,
    TRIGGER_MANUAL,
    RunReclaimed,
    acquire,
    entered,
    finish,
)
from app.core.tenancy import reset_tenant_id, set_tenant_id
from app.mdm.collections import ensure_default_collections
from app.mdm.credentials import CREDENTIAL_SCHEMAS, fingerprint_field
from app.mdm.jamf.client import JamfClient
from app.mdm.service import set_sync_status, sync_connection
from app.models.schema import (
    Device,
    DeviceExtensionAttribute,
    InstalledApp,
    MdmConnection,
    MdmSyncState,
    Run,
)
from app.schemas.connections import (
    MdmConnectionCreate,
    MdmConnectionOut,
    MdmConnectionTestRequest,
    MdmConnectionTestResult,
    MdmConnectionUpdate,
    MdmSyncTriggerResult,
    PatchManagementProvider,
    validate_jamf_specific_fields,
    validate_patch_provider_available,
)
from app.schemas.payload import MdmProvider, SyncStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/mdm/connections", tags=["connections"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _credentials_dict(conn: MdmConnection) -> dict[str, str]:
    if not conn.credentials_encrypted:
        return {}
    try:
        return json.loads(conn.credentials_encrypted)
    except (json.JSONDecodeError, TypeError):
        return {}


def _validate_credentials(provider: MdmProvider, credentials: dict[str, str]) -> dict[str, str]:
    schema_cls = CREDENTIAL_SCHEMAS.get(provider)
    if schema_cls is None:
        return credentials
    try:
        validated = schema_cls.model_validate(credentials)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return validated.model_dump()


def _normalize_credential_keys(provider: MdmProvider, raw: dict[str, str]) -> dict[str, str]:
    """Map camelCase wire keys (or already-canonical field names) to the schema's
    canonical (snake_case) field names, so merging with stored credentials overwrites
    the same key instead of adding a duplicate under the other casing."""
    schema_cls = CREDENTIAL_SCHEMAS.get(provider)
    if schema_cls is None:
        return raw
    alias_to_name = {(field.alias or name): name for name, field in schema_cls.model_fields.items()}
    return {alias_to_name.get(key, key): value for key, value in raw.items()}


def _to_out(conn: MdmConnection) -> MdmConnectionOut:
    credentials = _credentials_dict(conn)
    return MdmConnectionOut(
        id=conn.id,
        name=conn.name,
        provider=conn.provider,
        base_url=conn.base_url,
        is_active=conn.is_active,
        patch_management_provider=conn.patch_management_provider,
        loonsecio_data_sharing_enabled=conn.loonsecio_data_sharing_enabled,
        credential_fields_set=[to_camel(key) for key, value in credentials.items() if value],
        has_webhook_secret=bool(conn.webhook_secret_encrypted),
        has_loonsecio_license_key=bool(conn.loonsecio_license_key_encrypted),
        user_agent_override=conn.user_agent_override,
        sweep_page_size=conn.sweep_page_size,
        capability_devices=conn.capability_devices,
        capability_users=conn.capability_users,
        capability_webhooks=conn.capability_webhooks,
        capability_jamf_pro=conn.capability_jamf_pro,
        last_successful_auth_at=conn.last_successful_auth_at,
        credentials_rotated_at=conn.credentials_rotated_at,
        credentials_fingerprint=conn.credentials_fingerprint,
        created_at=conn.created_at,
        updated_at=conn.updated_at,
    )


async def _get_or_404(connection_id: int, db: AsyncSession) -> MdmConnection:
    connection = await db.get(MdmConnection, connection_id)
    if connection is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return connection


@router.post(
    "",
    response_model=MdmConnectionOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.CONNECTION_WRITE))],
)
async def create_connection(
    payload: MdmConnectionCreate, db: AsyncSession = Depends(get_db)
) -> MdmConnectionOut:
    validated_credentials = _validate_credentials(payload.provider, payload.credentials)

    connection = MdmConnection(
        name=payload.name,
        provider=payload.provider.value,
        base_url=payload.base_url,
        is_active=payload.is_active,
        credentials_encrypted=json.dumps(validated_credentials) if validated_credentials else None,
        webhook_secret_encrypted=payload.webhook_secret,
        patch_management_provider=payload.patch_management_provider.value,
        loonsecio_license_key_encrypted=payload.loonsecio_license_key,
        loonsecio_data_sharing_enabled=payload.loonsecio_data_sharing_enabled,
        user_agent_override=payload.user_agent_override,
        sweep_page_size=payload.sweep_page_size,
        capability_devices=payload.capability_devices,
        capability_users=payload.capability_users,
        capability_webhooks=payload.capability_webhooks,
        capability_jamf_pro=payload.capability_jamf_pro,
    )

    fp_field = fingerprint_field(payload.provider)
    if fp_field and validated_credentials.get(fp_field):
        connection.credentials_rotated_at = _utcnow()
        connection.credentials_fingerprint = validated_credentials[fp_field][:3]

    db.add(connection)
    await db.commit()
    await db.refresh(connection)

    # A connection that observes nothing happen reads as broken: the defaults are real
    # rows — a full device sweep, the group catalog, the webhook scope — visible and
    # editable under the connection (docs/ingest-scheduling.md §3.2).
    if await ensure_default_collections(db, connection):
        await db.commit()

    audit(
        AuditAction.CONNECTION_CREATED,
        target_type="mdm_connection",
        target_id=connection.id,
        name=connection.name,
        provider=connection.provider,
        # Field *names* only. Deliberately not called `credential_fields_set`: redact()
        # matches on "credential" and would blank out the one detail worth keeping.
        #
        # credentials_fingerprint is NOT recorded: it's the first three characters of
        # the plaintext secret, and writing secret-derived material into a long-lived
        # file on a shared volume is the exact thing this log must not do. The field
        # names already answer which credentials were set.
        fields_set=sorted(validated_credentials.keys()),
    )
    return _to_out(connection)


# Credential-tier, not write-tier: this exercises the live secret and will fall back
# to the *stored* one when the payload omits it, so it lets the caller use a credential
# they may not be able to see. That's the line CONNECTION_CREDENTIAL_READ draws.
@router.post(
    "/test",
    response_model=MdmConnectionTestResult,
    dependencies=[Depends(require(Permission.CONNECTION_CREDENTIAL_READ))],
)
async def test_connection(
    payload: MdmConnectionTestRequest, db: AsyncSession = Depends(get_db)
) -> MdmConnectionTestResult:
    existing: MdmConnection | None = None
    if payload.connection_id is not None:
        existing = await db.get(MdmConnection, payload.connection_id)

    client_secret = payload.client_secret
    if not client_secret and existing is not None:
        client_secret = _credentials_dict(existing).get("client_secret")

    if not client_secret:
        return MdmConnectionTestResult(success=False, message="Enter a client secret to test.")

    # Recorded because it's the case where the caller exercised a credential they were
    # never shown — the reason this endpoint sits behind CONNECTION_CREDENTIAL_READ.
    used_stored_secret = not payload.client_secret

    def _audit_test(outcome: str, **extra: object) -> None:
        audit(
            AuditAction.CONNECTION_TESTED,
            outcome=outcome,
            target_type="mdm_connection",
            target_id=payload.connection_id,
            provider=payload.provider.value,
            base_url=payload.base_url,
            used_stored_secret=used_stored_secret,
            **extra,
        )

    user_agent_override = payload.user_agent_override or (existing.user_agent_override if existing else None)
    jamf_client = JamfClient(
        base_url=payload.base_url,
        client_id=payload.client_id,
        client_secret=client_secret,
        user_agent_override=user_agent_override,
    )

    try:
        token_info = await jamf_client.test_connection()
    except httpx.HTTPStatusError as exc:
        _audit_test("failure", reason="rejected", status_code=exc.response.status_code)
        return MdmConnectionTestResult(
            success=False,
            message=f"Jamf rejected the request ({exc.response.status_code}).",
            detail=f"HTTP {exc.response.status_code}\n{exc.response.text}",
        )
    except httpx.RequestError as exc:
        _audit_test("failure", reason="unreachable")
        return MdmConnectionTestResult(
            success=False, message=f"Could not reach {payload.base_url}.", detail=str(exc)
        )

    if existing is not None:
        existing.last_successful_auth_at = _utcnow()
        await db.commit()

    _audit_test("success")
    return MdmConnectionTestResult(
        success=True,
        message="Connected — received a short-lived access token.",
        detail=json.dumps(token_info, indent=2),
    )


@router.get(
    "",
    response_model=list[MdmConnectionOut],
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def list_connections(db: AsyncSession = Depends(get_db)) -> list[MdmConnectionOut]:
    result = await db.execute(select(MdmConnection))
    return [_to_out(conn) for conn in result.scalars().all()]


@router.get(
    "/{connection_id}",
    response_model=MdmConnectionOut,
    dependencies=[Depends(require(Permission.CONNECTION_READ))],
)
async def get_connection(connection_id: int, db: AsyncSession = Depends(get_db)) -> MdmConnectionOut:
    connection = await _get_or_404(connection_id, db)
    return _to_out(connection)


@router.patch(
    "/{connection_id}",
    response_model=MdmConnectionOut,
    dependencies=[Depends(require(Permission.CONNECTION_WRITE))],
)
async def update_connection(
    connection_id: int, payload: MdmConnectionUpdate, db: AsyncSession = Depends(get_db)
) -> MdmConnectionOut:
    connection = await _get_or_404(connection_id, db)
    data = payload.model_dump(exclude_unset=True, mode="json")

    if "name" in data:
        connection.name = data["name"]
    if "provider" in data:
        connection.provider = data["provider"]
    if "base_url" in data:
        connection.base_url = data["base_url"]
    if "is_active" in data:
        connection.is_active = data["is_active"]
    if "webhook_secret" in data:
        connection.webhook_secret_encrypted = data["webhook_secret"]
    if "patch_management_provider" in data:
        try:
            validate_patch_provider_available(PatchManagementProvider(data["patch_management_provider"]))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        connection.patch_management_provider = data["patch_management_provider"]
    if "loonsecio_license_key" in data:
        connection.loonsecio_license_key_encrypted = data["loonsecio_license_key"]
    if "loonsecio_data_sharing_enabled" in data:
        connection.loonsecio_data_sharing_enabled = data["loonsecio_data_sharing_enabled"]
    if "user_agent_override" in data:
        connection.user_agent_override = data["user_agent_override"]
    if "sweep_page_size" in data:
        connection.sweep_page_size = data["sweep_page_size"]
    if "capability_devices" in data:
        connection.capability_devices = data["capability_devices"]
    if "capability_users" in data:
        connection.capability_users = data["capability_users"]
    if "capability_webhooks" in data:
        connection.capability_webhooks = data["capability_webhooks"]
    if "capability_jamf_pro" in data:
        connection.capability_jamf_pro = data["capability_jamf_pro"]

    credential_fields_changed: list[str] = []

    if data.get("credentials"):
        provider = MdmProvider(connection.provider)
        existing_credentials = _credentials_dict(connection)
        incoming = _normalize_credential_keys(provider, {k: v for k, v in data["credentials"].items() if v})
        merged = {**existing_credentials, **incoming}
        validated = _validate_credentials(provider, merged)

        credential_fields_changed = sorted(
            key for key, value in incoming.items() if existing_credentials.get(key) != value
        )

        fp_field = fingerprint_field(provider)
        if fp_field and validated.get(fp_field) != existing_credentials.get(fp_field):
            connection.credentials_rotated_at = _utcnow()
            connection.credentials_fingerprint = validated[fp_field][:3]

        connection.credentials_encrypted = json.dumps(validated)

    try:
        validate_jamf_specific_fields(
            MdmProvider(connection.provider),
            PatchManagementProvider(connection.patch_management_provider),
            connection.capability_jamf_pro,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    await db.commit()
    await db.refresh(connection)

    audit(
        AuditAction.CONNECTION_UPDATED,
        target_type="mdm_connection",
        target_id=connection.id,
        name=connection.name,
        changed=sorted(data.keys()),
    )

    if credential_fields_changed:
        # Separate event, and a higher-signal one: rotating a Jamf secret is the kind
        # of thing a detection rule should fire on independently of routine edits.
        # Field names only — never values, and never the fingerprint (see above).
        audit(
            AuditAction.CONNECTION_CREDENTIALS_UPDATED,
            target_type="mdm_connection",
            target_id=connection.id,
            name=connection.name,
            changed_fields=credential_fields_changed,
        )

    return _to_out(connection)


async def _run_connection_sync(
    connection_id: int, actor: Actor, tenant_id: uuid.UUID, job_id: uuid.UUID
) -> None:
    """Background worker for a manually triggered sync.

    Runs outside the request, so it opens its own session — the request's is closed by
    the time this executes — and re-establishes the triggering actor, which otherwise
    would not survive into the background task's context and would leave the sync's
    audit trail attributed to nobody.

    The tenant is passed in for the same reason and carries more weight: the request's
    context is gone by now, so a session opened here would reach the database with no
    tenant bound and every query against a tenant-scoped table would fail. Taking it
    as an argument means the tenant the sync runs as is the tenant that asked for it,
    fixed at enqueue time.

    The run is acquired in the request rather than here, because the response has to
    carry its jobID — the caller is handed an id to poll before this task has started.
    So this takes the id and reloads the row; the lock is already held by the time the
    202 goes out, which is also what makes a second click land on the first run's log
    instead of starting a duplicate pull.
    """
    token = set_actor(actor)
    tenant_token = set_tenant_id(tenant_id)
    try:
        async with session_for_tenant(tenant_id) as db:
            connection = await db.get(MdmConnection, connection_id)
            run = await db.get(Run, job_id)
            if connection is None or run is None:
                return
            async with entered(run):
                try:
                    result = await sync_connection(db, connection, trigger=TRIGGER_MANUAL, run=run)
                except RunReclaimed:
                    # Already handled where it was detected: the reclaim closed the
                    # run, run_collection recorded the abort on the collection row,
                    # and any remaining sweeps were abandoned with it. Nothing to
                    # finish — the row's verdict is the reclaim's — and nothing to
                    # re-raise: a reclaimed run is an understood outcome, not a crash
                    # for the task machinery to report.
                    await db.rollback()
                    logger.warning(
                        "manual sync aborted: its run was reclaimed mid-flight",
                        extra={"connection_id": connection_id, "job_id": str(job_id)},
                    )
                    return
                except Exception as exc:
                    # The lock is this run row. An unhandled failure that left it
                    # `running` would block the connection until the heartbeat went
                    # stale — recoverable, but five minutes of silence for something
                    # already known to be over.
                    await db.rollback()
                    await finish(db, run, ok=False, error=str(exc))
                    raise
                await finish(
                    db,
                    run,
                    ok=result.ok,
                    device_count=result.device_count,
                    group_count=result.group_count,
                    devices_processed=result.devices_processed,
                    devices_failed=result.devices_failed,
                    observations=dict(result.observations),
                    error=result.error,
                )
    finally:
        reset_tenant_id(tenant_token)
        reset_actor(token)


@router.post(
    "/{connection_id}/sync",
    response_model=MdmSyncTriggerResult,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require(Permission.DEVICE_SYNC))],
)
async def trigger_sync(
    connection_id: int,
    background_tasks: BackgroundTasks,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> MdmSyncTriggerResult:
    """Pull inventory now instead of waiting for the nightly sweep.

    Returns 202 immediately and runs in the background: a full fleet pull paginates
    through every device and would otherwise hold the request open past any sensible
    timeout. The response carries the jobID to poll — `GET /api/runs/{jobId}` for state,
    `GET /api/runs/{jobId}/log` for the engine lines.

    **Contention returns 202, not 409.** Clicking "Run now" during a cron sweep means
    "is my fleet syncing?", and showing the running sweep's log answers that better than
    an error does. `started` says which happened, so the UI can say "joined the sweep
    already in progress" rather than implying this click caused it
    (docs/ingest-scheduling.md §4.2).
    """
    connection = await _get_or_404(connection_id, db)

    if not connection.is_active:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Connection is not active")

    # Acquiring here, in the request, is what closes the race the old check-then-set
    # left open: two clicks arriving together both INSERT, the index rejects one, and
    # the loser is handed the winner's jobID instead of starting a second pull against
    # the same Jamf server.
    acquisition = await acquire(
        db,
        connection,
        trigger=TRIGGER_MANUAL,
        lock_class=LOCK_DEVICE_SWEEP,
        actor_label=principal.account.email,
    )

    if not acquisition.started:
        return MdmSyncTriggerResult(
            connection_id=connection.id,
            job_id=acquisition.run.id,
            status=SyncStatus.syncing.value,
            started=False,
        )

    # The connection-level status the Connections list renders. Derived from the run
    # now rather than being the lock itself — kept because the UI reads it, and set
    # here so it flips the moment the lock is taken rather than when the task starts.
    await set_sync_status(db, connection, SyncStatus.syncing)

    audit(
        AuditAction.CONNECTION_SYNC_TRIGGERED,
        target_type="mdm_connection",
        target_id=connection.id,
        name=connection.name,
        provider=connection.provider,
        job_id=str(acquisition.run.id),
    )

    background_tasks.add_task(
        _run_connection_sync,
        connection.id,
        Actor(
            type="account",
            id=principal.account.id,
            label=principal.account.email,
            tenant_id=principal.tenant_id,
        ),
        principal.tenant_id,
        acquisition.run.id,
    )

    return MdmSyncTriggerResult(
        connection_id=connection.id,
        job_id=acquisition.run.id,
        status=SyncStatus.syncing.value,
        started=True,
    )


@router.delete(
    "/{connection_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.CONNECTION_WRITE))],
)
async def delete_connection(connection_id: int, db: AsyncSession = Depends(get_db)) -> None:
    """Remove a connection and everything collected through it.

    **Deleting a connection deletes its fleet.** Six of the eight foreign keys into
    `mdm_connections` already declare ON DELETE CASCADE — collections, runs and their
    logs, observation spans, apertures, org units, change rows — so this has always
    been a history-destroying act, and `JamfOrgUnit`'s docstring says so outright. The
    two keys that did not were the accident, not the intent: `mdm_sync_state`'s plain
    FK turned every delete into a raw 500 the moment a connection had ever *started* a
    sync (`set_sync_status` writes that row before the first page is fetched), and
    `devices`' plain FK meant the ORM would have nullified the fleet instead —
    device rows, apps, extension attributes and all, surviving forever attached to no
    connection, in `/api/devices` but out of every `devices.*` posture key (#185).

    Refusing instead (409, "delete its devices first") was rejected because there is no
    endpoint that deletes a device: the instruction would name a step the operator
    cannot take. Marking the connection departed was rejected as front-running #135,
    which has not been ruled — and a departed connection still holds live credentials,
    which is not what "delete" was asked for.

    What survives, deliberately: `event_outbox` rows already emitted (the wire is an
    append-only record of what was reported, and deleting a connection must not rewrite
    history a SIEM already indexed), `posture_snapshot` (tenant history; its run
    reference is ON DELETE SET NULL by design), `app_catalog`, and the content-addressed
    `observation_sections`/`observation_entries`, which are per-tenant and shared across
    connections.

    The child rows are removed with explicit statements rather than by adding ON DELETE
    CASCADE in a migration. Postgres runs a referential cascade as an internal RI action
    that bypasses row-level security; these run on the request's tenant-scoped session,
    so RLS constrains them the way it constrains every other write in this router.
    """
    connection = await _get_or_404(connection_id, db)
    name, provider = connection.name, connection.provider

    # A live sweep is writing devices and spans under this connection right now, and
    # deleting the run row out from under it is the expired-instance sad path (#125) in
    # a new place. Gated on the heartbeat, not on `status == 'running'` alone: a run
    # whose process died sits `running` until the next acquisition reclaims it, and
    # "start a sync before you can delete it" is not an instruction to hand anyone.
    # After the stale window the connection becomes deletable on its own.
    cutoff = _utcnow() - timedelta(seconds=settings.run_stale_after_seconds)
    live_run = (
        await db.execute(
            select(Run.id)
            .where(
                Run.mdm_connection_id == connection_id,
                Run.status == STATUS_RUNNING,
                Run.heartbeat_at >= cutoff,
            )
            .limit(1)
        )
    ).scalars().first()
    if live_run is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            # Names the job and the next step. "Conflict" on its own tells a cold
            # operator nothing, and this is the one refusal on the delete path.
            detail=(
                f"A sync is running on this connection (job {live_run}). "
                f"Wait for it to finish — GET /api/runs/{live_run} reports when it has — "
                "then delete the connection."
            ),
        )

    device_ids = select(Device.id).where(Device.mdm_connection_id == connection_id)
    await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(device_ids)))
    await db.execute(
        delete(DeviceExtensionAttribute).where(DeviceExtensionAttribute.device_id.in_(device_ids))
    )
    devices_removed = (
        await db.execute(delete(Device).where(Device.mdm_connection_id == connection_id))
    ).rowcount
    await db.execute(delete(MdmSyncState).where(MdmSyncState.mdm_connection_id == connection_id))
    await db.delete(connection)
    await db.commit()

    audit(
        AuditAction.CONNECTION_DELETED,
        target_type="mdm_connection",
        target_id=connection_id,
        name=name,
        provider=provider,
        # A 204 carries no body, so the size of what went with it is recorded here or
        # nowhere.
        devices_deleted=devices_removed,
    )
