"""Tenant-scoped paid intelligence delivery, independent of upload consent (#622)."""

from __future__ import annotations

import json
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
            if response.status_code == 401:
                raise AccessFailure("credential_invalid", "Credential is invalid or retired. Ask support for a new activation.")
            if response.status_code == 403:
                failure = json.loads(raw)
                state = failure.get("state") if isinstance(failure, dict) else None
                if state not in {"expired", "revoked"}:
                    raise ValueError("unknown refusal")
                raise AccessFailure(
                    state, "New updates stopped. Contact support to renew access; held intelligence remains usable."
                )
            if response.status_code != 200:
                raise AccessFailure(
                    "unavailable",
                    "Intelligence service could not complete the request. Retry or contact support; "
                    "a lost activation or rotation response may need a new activation.",
                )
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
            "Intelligence service is unreachable. Check network access and retry; "
            "held intelligence remains usable. Lost activation/rotation responses need support recovery.",
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
    if not rotate and (not activation or not activation.startswith("loon_act_") or len(activation) != 52):
        raise AccessFailure("invalid_activation", "Enter the one-time activation secret supplied by support.")
    try:
        answer = await request(
            "rotate" if rotate else "activate",
            credential=row.intelligence_credential,
            activation=None if rotate else activation,
            transport=transport,
        )
    except AccessFailure as exc:
        record(row, error=str(exc))  # A failed replacement must not revoke an existing working credential.
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
        # Outage is a separate error, never a fabricated expiry/revocation.
        fields = {"error": str(exc)}
        if exc.state in {"expired", "revoked", "credential_invalid"}:
            fields["state"] = exc.state
        record(row, **fields)
        await db.commit()
        return await status(db)
    record(row, state=answer["state"], updates_until=answer["updates_until"])
    await db.commit()
    pointer = corpus_pointer(answer["corpus"])
    try:
        await load_epoch_if_new(db, pointer, transport=transport)
        if await db.get(VulnCorpusRelease, pointer.signature) is None:
            raise AccessFailure("download_failed", "The corpus could not be verified or stored. Check storage and retry refresh.")
        await record_acquisition(db, pointer.signature)
        await db.commit()
        await assess_and_select(db, pointer.signature)
        await db.commit()
    except Exception:
        await db.rollback()
        # Import/assessment errors may carry URLs or SQL parameters. Never persist or echo them.
        row = await locked_settings(db)
        record(
            row,
            error="The intelligence update could not be assessed. Check database availability and storage, then retry; "
            "the previous selection remains usable.",
        )
        await db.commit()
    else:
        row = await locked_settings(db)
        record(row, last_refresh_at=datetime.now(UTC).isoformat(), error=None)
        await db.commit()
    return await status(db)
