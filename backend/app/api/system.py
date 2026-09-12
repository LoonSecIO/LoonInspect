from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ai import AI_SHARE_TIER
from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.sharing import (
    ExchangeRefused,
    build_exchange_request,
    get_or_create_settings,
    remember_tier,
    send_exchange_now,
)
from app.core.update_check import get_update_status
from app.core.version import get_app_version
from app.models.schema import ShareLog
from app.schemas.system import (
    DataSharingOut,
    DataSharingUpdate,
    SendExchangeOut,
    ShareLogEntryOut,
    UpdateStatusOut,
    VersionOut,
)

router = APIRouter(prefix="/api/system", tags=["system"])

# A test stands in for the collector by setting this; production leaves it None.
transport_override: httpx.AsyncBaseTransport | None = None


@router.get("/version", response_model=VersionOut)
async def version() -> VersionOut:
    """The build this instance is running. Authenticated but unprivileged: anyone who
    can sign in should be able to answer "what am I running?" when they file a bug.
    Behind-ness stays behind SYSTEM_READ below — that is the sensitive half."""
    return VersionOut(version=get_app_version())


@router.get(
    "/update-status",
    response_model=UpdateStatusOut,
    dependencies=[Depends(require(Permission.SYSTEM_READ))],
)
async def update_status() -> UpdateStatusOut:
    """Whether a newer build of main exists than the one running. Authenticated on
    purpose: the sign-in page must not advertise that an instance is behind."""
    status = await get_update_status()
    return UpdateStatusOut(
        enabled=status.enabled,
        current_version=status.current_version,
        update_available=status.update_available,
        latest_sha=status.latest_sha,
        checked_at=status.checked_at,
    )


async def _sharing_out(db: AsyncSession, row) -> DataSharingOut:
    # AI-inference rows share the log but are not exchanges; "last exchange" must
    # not start reporting an inference call as one.
    last = (
        await db.execute(select(ShareLog).where(ShareLog.tier != AI_SHARE_TIER).order_by(desc(ShareLog.occurred_at)).limit(1))
    ).scalar_one_or_none()
    return DataSharingOut(
        tier=row.tier,
        submission_uuid=str(row.submission_uuid),
        exclude_globs=list(row.exclude_globs or []),
        env_disabled=not settings.community_sharing,
        ai_inference=row.ai_inference,
        last_exchange_at=last.occurred_at if last else None,
        last_exchange_outcome=last.outcome if last else None,
        last_exchange_reveals_shed=bool(last.reveals_shed) if last else False,
        last_exchange_error=last.error if last else None,
    )


@router.get(
    "/data-sharing",
    response_model=DataSharingOut,
    dependencies=[Depends(require(Permission.SYSTEM_READ))],
)
async def get_data_sharing(db: AsyncSession = Depends(get_db)) -> DataSharingOut:
    return await _sharing_out(db, await get_or_create_settings(db))


@router.put(
    "/data-sharing",
    response_model=DataSharingOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def update_data_sharing(payload: DataSharingUpdate, db: AsyncSession = Depends(get_db)) -> DataSharingOut:
    """Persisted even while COMMUNITY_SHARING=false: the env override wins at
    exchange time, but an operator's recorded choice should survive the override
    being lifted rather than silently resetting."""
    row = await get_or_create_settings(db)
    if payload.tier is not None:
        row.tier = payload.tier.value
    if payload.exclude_globs is not None:
        row.exclude_globs = [g.strip() for g in payload.exclude_globs if g.strip()]
    if payload.ai_inference is not None:
        row.ai_inference = payload.ai_inference
    row.updated_at = datetime.now(UTC)
    await db.commit()
    # A tier changed here takes effect on the next page, not at tomorrow's exchange: the
    # corpus gate reads a per-tenant cache and this is one of the two places it moves
    # (#248, docs/vulnerabilities.md §8).
    remember_tier(row)

    audit(
        AuditAction.SHARING_SETTINGS_UPDATED,
        target_type="data_sharing",
        tier=row.tier,
        exclude_glob_count=len(row.exclude_globs or []),
        ai_inference=row.ai_inference,
    )
    return await _sharing_out(db, row)


@router.post(
    "/data-sharing/reset-uuid",
    response_model=DataSharingOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def reset_submission_uuid(db: AsyncSession = Depends(get_db)) -> DataSharingOut:
    """The disclosure page promises the pseudonymous identity is resettable; this is
    that promise. The old UUID's snapshots age out server-side on their own."""
    row = await get_or_create_settings(db)
    row.submission_uuid = uuid.uuid4()
    row.updated_at = datetime.now(UTC)
    await db.commit()

    audit(AuditAction.SHARING_UUID_RESET, target_type="data_sharing")
    return await _sharing_out(db, row)


@router.get(
    "/data-sharing/preview",
    dependencies=[Depends(require(Permission.SYSTEM_READ))],
)
async def preview_exchange(db: AsyncSession = Depends(get_db)) -> dict:
    """The literal next exchange request, from live data, through the same builder
    the exchange job uses — the preview cannot drift from the wire."""
    row = await get_or_create_settings(db)
    return await build_exchange_request(db, row)


@router.post(
    "/data-sharing/send",
    response_model=SendExchangeOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def send_exchange(db: AsyncSession = Depends(get_db)) -> SendExchangeOut:
    """Send now (#408): this organization's exchange, immediately, through the code path
    the daily one uses, answered with the share-log row it wrote — the preview shows the
    future, this shows what just left.

    SYSTEM_WRITE, like the tier and the UUID reset: sending off the box is an
    administrator's decision, while seeing what would go stays SYSTEM_READ. A failed
    exchange is still a 200 — the row is the answer and its `error` says what went wrong.
    A 409 is a refusal before anything was attempted (the environment override, an off
    tier, an exchange already running), with the sentence as its `detail`.
    """
    try:
        row = await send_exchange_now(db, transport=transport_override)
    except ExchangeRefused as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    audit(
        AuditAction.SHARING_EXCHANGE_SENT,
        outcome="success" if row.outcome == "sent" else "failure",
        target_type="data_sharing",
        tier=row.tier,
        endpoint=row.endpoint,
        exchange_outcome=row.outcome,
    )
    return SendExchangeOut(
        exchange=ShareLogEntryOut.model_validate(row),
        settings=await _sharing_out(db, await get_or_create_settings(db)),
    )


@router.get(
    "/share-log",
    response_class=PlainTextResponse,
    dependencies=[Depends(require(Permission.AUDIT_READ))],
)
async def download_share_log(
    days: int = Query(default=90, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
) -> PlainTextResponse:
    """The share log as NDJSON — byte-accurate history of what left this tenant.
    AUDIT_READ on purpose: the auditor role exists precisely for "prove to me what
    this thing does", and nothing in here is secret (it already left)."""
    import json

    since = datetime.now(UTC) - timedelta(days=days)
    rows = (
        (await db.execute(select(ShareLog).where(ShareLog.occurred_at >= since).order_by(ShareLog.occurred_at))).scalars().all()
    )
    lines = [
        json.dumps(
            {
                "occurredAt": row.occurred_at.isoformat(),
                "tier": row.tier,
                # scheduled | manual on exchange rows (#408); null on AI rows, which are
                # not exchanges. Two rows on one day are how a Send now reads here.
                "trigger": row.trigger,
                "endpoint": row.endpoint,
                "outcome": row.outcome,
                "payload": row.payload,
                # True = the 413 path ran, so `payload` above is a superset of the body
                # the server accepted: its reveals never left. The auditor's question
                # ("exactly what left the box") needs this beside the payload, not a
                # rewritten payload — see docs/data-sharing.md, "The share log".
                "revealsShed": row.reveals_shed,
                "revealRequests": row.reveal_requests,
                "error": row.error,
            },
            separators=(",", ":"),
        )
        for row in rows
    ]
    return PlainTextResponse(
        "\n".join(lines) + ("\n" if lines else ""),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="share-log.ndjson"'},
    )
