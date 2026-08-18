from __future__ import annotations

import json
import logging
import os
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

    FEATURE_FLAG_UPDATED = "feature-flag.updated"

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


def configure_audit_logging() -> None:
    """Attach the rotating JSONL handler. Called once at startup, before anything can
    emit an event."""
    path = Path(settings.audit_log_path)

    # Created here because the directory isn't in the image and the data volume mounts
    # empty — without this the first boot dies on a missing path, and it presents as a
    # Docker problem rather than an application one.
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

    _audit.handlers = [handler]
    _audit.setLevel(logging.INFO)
    _audit.propagate = False

    logger.info(
        "audit log configured",
        extra={"path": str(path), "retention_days": settings.audit_retention_days},
    )


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

    Actor, request id, IP, and user agent come from the request context, so call sites
    only supply what's specific to the action. `actor` is an override for the one case
    the context can't cover: a login, where the principal isn't established until the
    event being recorded has already succeeded.
    """
    resolved = actor or get_actor()
    client = get_client()

    payload = {
        "occurred_at": datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "action": str(action),
        "outcome": outcome,
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
        _audit.info(json.dumps(payload, default=str))
    except Exception:
        # An audit write must never take down the action it was recording. Failing loud
        # in the application log is the right trade here; refusing the request instead
        # would turn a full disk into a total outage.
        logger.exception("audit write failed", extra={"audit_action": str(action)})
