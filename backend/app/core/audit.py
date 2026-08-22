from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from enum import StrEnum
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.context import Actor, get_actor, get_client, get_request_id
from app.core.redact import redact

logger = logging.getLogger(__name__)

# Dedicated logger with propagate=False. Audit records are evidence with their own
# destination and retention — not a severity level of the application log, which gets
# sampled and dropped under pressure.
_audit = logging.getLogger("looninspect.audit")

# One logger, and one file, per tenant. Built on first use rather than at startup,
# because the set of tenants is data and can grow while the process is running.
_audit_loggers: dict[str, logging.Logger] = {}
_audit_lock = threading.Lock()

# Where records that belong to no tenant go: startup, the global catalog refresh, and
# any failed authentication that never got far enough to name one. A directory rather
# than the deployment root, so every audit file sits at the same depth and a log
# shipper can glob one level without special-casing this one.
SYSTEM_AUDIT_KEY = "system"


class AuditAction(StrEnum):
    """Namespaced so a SIEM can alert on a prefix (`auth.login.*`) rather than
    enumerating every action we might add later."""

    LOGIN_SUCCEEDED = "auth.login.succeeded"
    LOGIN_FAILED = "auth.login.failed"
    LOGIN_BLOCKED = "auth.login.blocked"
    LOGOUT = "auth.logout"
    SETUP_COMPLETED = "auth.setup.completed"
    SETUP_REJECTED = "auth.setup.rejected"

    AUTHZ_DENIED = "authz.denied"

    CONNECTION_CREATED = "connection.created"
    CONNECTION_UPDATED = "connection.updated"
    CONNECTION_DELETED = "connection.deleted"
    CONNECTION_CREDENTIALS_UPDATED = "connection.credentials.updated"
    CONNECTION_TESTED = "connection.tested"
    CONNECTION_SYNC_TRIGGERED = "connection.sync.triggered"

    COLLECTION_CREATED = "collection.created"
    COLLECTION_UPDATED = "collection.updated"
    COLLECTION_DELETED = "collection.deleted"
    COLLECTION_RUN_TRIGGERED = "collection.run.triggered"

    CHANGE_POLICY_UPDATED = "change-policy.updated"

    FEATURE_FLAG_UPDATED = "feature-flag.updated"

    SHARING_SETTINGS_UPDATED = "sharing.settings.updated"
    SHARING_UUID_RESET = "sharing.uuid.reset"

    TOKEN_CREATED = "token.created"
    TOKEN_REVOKED = "token.revoked"

    ACCOUNT_CREATED = "account.created"
    ACCOUNT_UPDATED = "account.updated"
    ACCOUNT_DISABLED = "account.disabled"
    ACCOUNT_ENABLED = "account.enabled"
    ACCOUNT_ROLES_CHANGED = "account.roles.changed"
    PASSWORD_CHANGED = "account.password.changed"
    PASSWORD_RESET = "account.password.reset"

    DESTINATION_CREATED = "destination.created"
    DESTINATION_UPDATED = "destination.updated"
    DESTINATION_DELETED = "destination.deleted"
    DELIVERY_DEAD_LETTERED = "destination.delivery.dead_lettered"


class _SecureTimedRotatingFileHandler(TimedRotatingFileHandler):
    """Forces 0600 on the audit file, including the ones rotation creates.

    The data volume is meant to be mountable by a log shipper; that shouldn't make the
    audit trail readable by everything else sharing the volume.
    """

    def _open(self):
        stream = super()._open()
        try:
            os.chmod(self.baseFilename, 0o600)
        except OSError:
            logger.warning(
                "could not restrict audit file permissions",
                extra={"path": self.baseFilename},
            )
        return stream


def audit_path_for(tenant_key: str) -> Path:
    """Where one tenant's audit file lives.

    `audit_log_path` is a template rather than a literal path: the tenant is inserted
    as a directory above the filename, so ./data/audit/audit.jsonl becomes
    ./data/audit/<tenant-id>/audit.jsonl. Splitting by directory rather than by
    filename means a tenant's whole trail — current file and every rotated one — can be
    shipped, exported, or handed over by naming one path.

    The tenant id and not the slug: a slug can be renamed, and an audit trail that
    moves directories when someone edits a display name is not evidence.
    """
    template = Path(settings.audit_log_path)
    return template.parent / tenant_key / template.name


def _build_audit_logger(tenant_key: str) -> logging.Logger:
    path = audit_path_for(tenant_key)

    # Created here because the directory isn't in the image and the data volume mounts
    # empty — without this the first boot dies on a missing path, and it presents as a
    # Docker problem rather than an application one. 0700 so the per-tenant directory
    # is no more readable than the file it holds.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    handler = _SecureTimedRotatingFileHandler(
        filename=str(path),
        when="midnight",
        utc=True,
        # backupCount *is* the retention policy: the handler drops the oldest file on
        # each rotation, so N daily files is a rolling N-day window with no cron job,
        # no cleanup task, and nothing to forget.
        backupCount=settings.audit_retention_days,
        encoding="utf-8",
    )
    # The payload is already JSON by the time it reaches here; re-encoding it would
    # only nest it inside another envelope.
    handler.setFormatter(logging.Formatter("%(message)s"))

    tenant_logger = logging.getLogger(f"{_audit.name}.{tenant_key}")
    tenant_logger.handlers = [handler]
    tenant_logger.setLevel(logging.INFO)
    # Without this a record would also travel up to the parent audit logger, and every
    # tenant's events would land in a shared file as well as their own — which is the
    # thing this split exists to prevent.
    tenant_logger.propagate = False

    logger.info(
        "audit log configured",
        extra={
            "tenant": tenant_key,
            "path": str(path),
            "retention_days": settings.audit_retention_days,
        },
    )
    return tenant_logger


def _audit_logger(tenant_key: str) -> logging.Logger:
    existing = _audit_loggers.get(tenant_key)
    if existing is not None:
        return existing

    with _audit_lock:
        # Re-checked under the lock: two concurrent requests for a tenant seen for the
        # first time both miss above, and two handlers on one file would double-write
        # and fight over rotation.
        existing = _audit_loggers.get(tenant_key)
        if existing is None:
            existing = _build_audit_logger(tenant_key)
            _audit_loggers[tenant_key] = existing
        return existing


def configure_audit_logging() -> None:
    """Prepare audit logging. Called at startup, before anything can emit an event.

    Per-tenant loggers are built on demand, so the only thing set up eagerly is the
    system one — which doubles as the check that the configured path is writable at
    all. Discovering that at the first audit write instead would mean discovering it
    from the one log line that says an audit write failed.

    Idempotent: called twice at startup (see the note in app.main.lifespan), and the
    old handlers are closed rather than leaked.
    """
    with _audit_lock:
        for tenant_logger in _audit_loggers.values():
            for handler in tenant_logger.handlers:
                handler.close()
            tenant_logger.handlers = []
        _audit_loggers.clear()

    _audit.setLevel(logging.INFO)
    _audit.propagate = False

    _audit_logger(SYSTEM_AUDIT_KEY)


def audit(
    action: AuditAction | str,
    *,
    outcome: str = "success",
    target_type: str | None = None,
    target_id: str | int | None = None,
    actor: Actor | None = None,
    **metadata: Any,
) -> None:
    """Append one audit event.

    Actor, tenant, request id, IP, and user agent come from the request context, so
    call sites only supply what's specific to the action. `actor` is an override for
    the one case the context can't cover: a login, where the principal isn't
    established until the event being recorded has already succeeded — and which is
    also why the tenant is read off the actor rather than from context, so that
    override carries it too.
    """
    resolved = actor or get_actor()
    client = get_client()
    tenant_key = str(resolved.tenant_id) if resolved.tenant_id is not None else SYSTEM_AUDIT_KEY

    payload = {
        "occurred_at": datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "action": str(action),
        "outcome": outcome,
        # Written into the record as well as deciding the file. The file answers
        # "whose trail is this" for anyone holding it; the field answers the same
        # question for a SIEM that has already merged every tenant's events into one
        # index, which is the normal end state.
        "tenant_id": str(resolved.tenant_id) if resolved.tenant_id is not None else None,
        "actor_type": resolved.type,
        "actor_id": resolved.id,
        # Captured at the moment of the action rather than resolved on read: a rename,
        # or an IdP rewriting an email during a domain migration, must not retroactively
        # change who a past action appears to have been.
        "actor_label": resolved.label,
        "target_type": target_type,
        "target_id": str(target_id) if target_id is not None else None,
        "request_id": get_request_id(),
        "ip": client.ip,
        "user_agent": client.user_agent,
        # Redacted even though call sites are expected to pass only safe fields — this
        # file is plaintext on a shared volume, and a credential reaching it would be a
        # real incident rather than a cosmetic bug.
        "metadata": redact(metadata),
    }

    try:
        _audit_logger(tenant_key).info(json.dumps(payload, default=str))
    except Exception:
        # An audit write must never take down the action it was recording. Failing loud
        # in the application log is the right trade here; refusing the request instead
        # would turn a full disk into a total outage.
        logger.exception("audit write failed", extra={"audit_action": str(action)})
