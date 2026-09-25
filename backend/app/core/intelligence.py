"""Tenant-scoped paid intelligence delivery, independent of upload consent (#622)."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.sharing import get_or_create_settings
from app.core.version import get_app_version
from app.core.vuln_library import corpus_pointer, load_epoch_if_new
from app.core.vuln_selection import assess_and_select, record_acquisition
from app.models.schema import DataSharingSettings, VulnCorpusRelease, VulnCorpusSelection

STATES = {"paid", "trial", "cancelled", "grace", "extended"}

logger = logging.getLogger(__name__)


class AccessFailure(ValueError):
    """Safe operator text only: never an upstream response, request, URL or credential."""

    def __init__(self, state: str, message: str):
        super().__init__(message)
        self.state = state


def enabled() -> bool:
    return settings.intelligence_access and settings.vuln_tenant_selection and settings.vuln_release_retention


def endpoint(path: str) -> str:
    base = settings.intelligence_endpoint.rstrip("/")
    parsed = urlsplit(base)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path
    ):
        raise AccessFailure("configuration_error", "Paid access needs an HTTPS service origin. Check INTELLIGENCE_ENDPOINT.")
    return base + "/v2/" + path


def timestamp(value) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp missing")
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError("timezone missing")
    return result.astimezone(UTC)


def refusal(path: str, code: int, raw: bytes) -> AccessFailure:
    """Name the likely cause of a non-200 answer from its status alone.

    Upstream text is never quoted (see `AccessFailure`); the configured origin is ours to
    repeat. The service issues a credential only with a 200, so a refusal in the 4xx range,
    or a 503 in its own JSON shape, left an activation secret unused. Anything else - a
    gateway 5xx, a timeout - may have come after the service finished, which is the one
    case where an activation or rotation can be spent without this instance learning it.
    """
    origin = settings.intelligence_endpoint.rstrip("/")
    try:
        body = json.loads(raw)
    except ValueError:
        body = None
    unused = " The activation secret was not used." if path == "activate" else ""
    if path == "activate":
        spent = (
            " If the service finished the activation first, the secret is spent: when a retry is refused, "
            "ask support for recovery."
        )
    elif path == "rotate":
        spent = (
            " If the service finished the rotation first, the previous credential is retired: when refresh then "
            "fails, ask support for recovery."
        )
    else:
        spent = ""
    if code == 401:
        if path == "activate":
            return AccessFailure(
                "invalid_activation",
                "The intelligence service did not accept this activation secret (HTTP 401). It may be mistyped, "
                "already used, expired or revoked; ask support for a new one.",
            )
        return AccessFailure("credential_invalid", "Credential is invalid or retired. Ask support for a new activation.")
    if code == 403:
        if not isinstance(body, dict) or "state" not in body:
            # The service's own refusals always carry a state. A bare 403 is whatever else
            # answers at that address - the 2024 gateway at api.loonsec.io (the default before
            # 2026-09-25, #650) answers every path with "Missing Authentication Token".
            return AccessFailure(
                "configuration_error",
                f"{origin} refused the request without an intelligence-service answer (HTTP 403), so "
                f"INTELLIGENCE_ENDPOINT probably names something else. Set it to the origin support confirmed.{unused}",
            )
        if body["state"] not in {"expired", "revoked"}:
            raise ValueError("unknown refusal")
        return AccessFailure(
            body["state"], "New updates stopped. Contact support to renew access; held intelligence remains usable."
        )
    if code == 404:
        return AccessFailure(
            "configuration_error",
            f"No paid-access service answers at {origin} (HTTP 404). Check INTELLIGENCE_ENDPOINT: it takes the "
            f"service origin only, with no path, and support confirms which origin is live.{unused}",
        )
    if code == 400:
        return AccessFailure(
            "rejected",
            "The intelligence service rejected the request as outside its contract (HTTP 400). Check that this "
            f"LoonInspect build is current, then contact support.{unused}",
        )
    if code == 409:
        return AccessFailure(
            "unavailable",
            f"The entitlement changed while the service answered (HTTP 409). Retry; if it repeats, contact support.{unused}",
        )
    if code == 503 and isinstance(body, dict):
        return AccessFailure(
            "unavailable",
            "The intelligence service is not serving paid access right now (HTTP 503): its preview may be switched "
            "off, or its entitlement store or corpus is unavailable. This is not an expiry. Retry later or contact "
            f"support; held intelligence remains usable.{unused}",
        )
    return AccessFailure(
        "unavailable",
        f"The intelligence service answered HTTP {code}. Retry later or contact support; held intelligence "
        f"remains usable.{spent}",
    )


async def request(
    path: str, *, credential: str | None = None, activation: str | None = None, transport: httpx.AsyncBaseTransport | None = None
) -> dict:
    body = {"contract": "v2", "client_version": get_app_version()}
    headers = {}
    if activation is not None:
        body["activation_secret"] = activation
    else:
        headers["Authorization"] = f"Bearer {credential}"
        body["channel"] = "stable"
    url = endpoint(path)
    try:
        async with (
            httpx.AsyncClient(transport=transport, timeout=10, follow_redirects=False, trust_env=False) as client,
            client.stream("POST", url, json=body, headers=headers) as response,
        ):
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                if len(raw) > 65536:
                    raise ValueError("oversized reply")
            if response.status_code != 200:
                raise refusal(path, response.status_code, bytes(raw))
            result = json.loads(raw)
        if not isinstance(result, dict) or result.get("contract") != "v2" or result.get("state") not in STATES:
            raise ValueError("invalid response")
        timestamp(result.get("updates_until"))
        if path in {"activate", "rotate"}:
            token = result.get("credential")
            if not isinstance(token, str) or not token.startswith("loon_key_") or len(token) != 52:
                raise ValueError("invalid credential")
        elif corpus_pointer(result.get("corpus")) is None:
            raise ValueError("missing corpus")
        return result
    except httpx.HTTPError:
        raise AccessFailure(
            "unavailable",
            f"Could not reach the intelligence service at {settings.intelligence_endpoint.rstrip('/')}. Check DNS, "
            "network access and INTELLIGENCE_ENDPOINT, then retry; held intelligence remains usable. "
            "Lost activation/rotation responses need support recovery.",
        ) from None
    except (ValueError, TypeError) as exc:
        if isinstance(exc, AccessFailure):
            raise
        raise AccessFailure(
            "invalid_response",
            "Intelligence service returned an invalid reply. Retry or contact support; held intelligence remains usable.",
        ) from None


async def locked_settings(db: AsyncSession) -> DataSharingSettings:
    await get_or_create_settings(db)
    return (
        await db.execute(select(DataSharingSettings).with_for_update().execution_options(populate_existing=True))
    ).scalar_one()


def record(row: DataSharingSettings, **fields) -> None:
    row.intelligence_status = {**(row.intelligence_status or {}), **fields}


async def status(db: AsyncSession) -> dict:
    row = await get_or_create_settings(db)
    selection = (await db.execute(select(VulnCorpusSelection))).scalar_one_or_none()
    release = await db.get(VulnCorpusRelease, selection.signature) if selection else None
    saved = row.intelligence_status or {}
    return {
        "enabled": enabled(),
        "credentialPresent": bool(row.intelligence_credential),
        "state": saved.get("state", "not_activated"),
        "updatesUntil": saved.get("updates_until"),
        "lastAttemptAt": saved.get("last_attempt_at"),
        "lastRefreshAt": saved.get("last_refresh_at"),
        "error": saved.get("error"),
        "selectedCorpus": selection.signature if selection else None,
        "sourceAsOf": release.asof.isoformat() if release else None,
        "sharingTier": row.tier,
    }


async def activate(
    db: AsyncSession, activation: str | None, *, rotate: bool = False, transport: httpx.AsyncBaseTransport | None = None
) -> dict:
    row = await locked_settings(db)
    if not enabled():
        raise AccessFailure(
            "disabled", "Paid access preview is disabled. Ask the instance administrator to check the release settings."
        )
    if rotate and not row.intelligence_credential:
        raise AccessFailure("not_activated", "Activate paid access before rotating a credential.")
    if activation is not None:
        # Copied out of support's file or a message, a secret often arrives wrapped in
        # quotes or trailing whitespace; its own alphabet has neither, so shed them.
        activation = activation.strip().strip("\"'")
    if not rotate and (not activation or not activation.startswith("loon_act_") or len(activation) != 52):
        raise AccessFailure(
            "invalid_activation",
            "Paste only the one-time activation secret from support: 52 characters beginning loon_act_, without "
            "quotes or spaces. Nothing was sent.",
        )
    try:
        answer = await request(
            "rotate" if rotate else "activate",
            credential=row.intelligence_credential,
            activation=None if rotate else activation,
            transport=transport,
        )
    except AccessFailure as exc:
        logger.warning(
            "paid intelligence request failed",
            extra={"operation": "rotate" if rotate else "activate", "reason": exc.state, "detail": str(exc)},
        )
        message = str(exc)
        if row.intelligence_credential and not rotate:
            # Seen on the first dev walk: a second Activate with a spent secret read like an
            # outage while access was fine. Say which access is still in force.
            message += " Current paid access is unchanged."
        record(row, error=message)  # A failed replacement must not revoke an existing working credential.
        await db.commit()
        return await status(db)
    row.intelligence_credential = answer["credential"]
    record(row, state=answer["state"], updates_until=answer["updates_until"], error=None, last_attempt_at=None)
    # Persist the replacement before any download/assessment. No consent or MDM license mutation.
    await db.commit()
    return await status(db)


async def refresh(db: AsyncSession, *, scheduled: bool = False, transport: httpx.AsyncBaseTransport | None = None) -> dict | None:
    if not enabled():
        return None
    row = await locked_settings(db)
    if not row.intelligence_credential:
        return None
    now = datetime.now(UTC)
    last = (row.intelligence_status or {}).get("last_attempt_at")
    if scheduled and last and now - timestamp(last) < timedelta(days=1):
        return None
    credential = row.intelligence_credential
    record(row, last_attempt_at=now.isoformat(), error=None)
    try:
        answer = await request("intelligence", credential=credential, transport=transport)
    except AccessFailure as exc:
        logger.warning(
            "paid intelligence request failed",
            extra={"operation": "refresh", "scheduled": scheduled, "reason": exc.state, "detail": str(exc)},
        )
        # Outage is a separate error, never a fabricated expiry/revocation.
        fields = {"error": str(exc)}
        if exc.state in {"expired", "revoked", "credential_invalid"}:
            fields["state"] = exc.state
        if exc.state == "revoked":
            # The service revokes with no end date; a remembered one would read as a live term.
            fields["updates_until"] = None
        record(row, **fields)
        await db.commit()
        return await status(db)
    record(row, state=answer["state"], updates_until=answer["updates_until"])
    await db.commit()
    pointer = corpus_pointer(answer["corpus"])
    try:
        await load_epoch_if_new(db, pointer, transport=transport)
        if await db.get(VulnCorpusRelease, pointer.signature) is None:
            # load_epoch_if_new never raises: it has already logged why, as a "vulnerability
            # library" warning (docs/troubleshooting.md §5).
            raise AccessFailure(
                "download_failed",
                "The paid corpus could not be downloaded, verified or stored. The container log's "
                '"vulnerability library" warning just before this names why (docs/troubleshooting.md §5); '
                "fix that, then Refresh now. The previous selection remains usable.",
            )
        await record_acquisition(db, pointer.signature)
        await db.commit()
        await assess_and_select(db, pointer.signature)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        # Import/assessment errors may carry URLs or SQL parameters. Never persist or echo them;
        # only this module's own AccessFailure sentences are safe to repeat.
        if isinstance(exc, AccessFailure):
            reason, error = exc.state, str(exc)
        else:
            reason = "assessment_failed"
            error = (
                "The intelligence update could not be assessed. Check database availability and storage, then retry; "
                "the previous selection remains usable."
            )
        logger.warning(
            "paid intelligence update not applied",
            extra={"reason": reason, "error_type": type(exc).__name__, "detail": error},
        )
        row = await locked_settings(db)
        record(row, error=error)
        await db.commit()
    else:
        row = await locked_settings(db)
        record(row, last_refresh_at=datetime.now(UTC).isoformat(), error=None)
        await db.commit()
    return await status(db)
