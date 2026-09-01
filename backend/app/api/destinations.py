from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.database import get_db
from app.core.outbox import send_test_event
from app.core.permissions import Permission
from app.models.schema import Destination, OutboxDelivery
from app.schemas.destinations import (
    DestinationCreate,
    DestinationOut,
    DestinationUpdate,
    resolve_auth_type,
)

router = APIRouter(prefix="/api/destinations", tags=["destinations"])


async def _health(db: AsyncSession, destination_ids: list[int]) -> dict[int, dict]:
    """Per-destination delivery health, in two grouped queries rather than N+1.

    `outbox_deliveries.last_error` carries the exact upstream refusal — "HTTP 403:
    Invalid token", "[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate in
    certificate chain" — and until now no API read it, so the symptom an operator
    experienced was "Splunk is empty and the app says everything is fine".
    """
    if not destination_ids:
        return {}

    counts = await db.execute(
        select(OutboxDelivery.destination_id, OutboxDelivery.status, func.count())
        .where(OutboxDelivery.destination_id.in_(destination_ids))
        .group_by(OutboxDelivery.destination_id, OutboxDelivery.status)
    )
    health: dict[int, dict] = {i: {"last_error": None, "pending_count": 0, "failed_count": 0} for i in destination_ids}
    for destination_id, status_value, count in counts:
        if status_value == "pending":
            health[destination_id]["pending_count"] = count
        elif status_value == "failed":
            health[destination_id]["failed_count"] = count

    # The most recent error per destination: one row each, newest attempt first.
    latest = await db.execute(
        select(OutboxDelivery.destination_id, OutboxDelivery.last_error)
        .where(
            OutboxDelivery.destination_id.in_(destination_ids),
            OutboxDelivery.last_error.is_not(None),
        )
        .distinct(OutboxDelivery.destination_id)
        .order_by(OutboxDelivery.destination_id, OutboxDelivery.last_attempted_at.desc())
    )
    for destination_id, last_error in latest:
        health[destination_id]["last_error"] = last_error
    return health


def _to_out(destination: Destination, health: dict | None = None) -> DestinationOut:
    return DestinationOut(
        id=destination.id,
        name=destination.name,
        type=destination.type,
        url=destination.url,
        auth_type=destination.auth_type,
        auth_header_name=destination.auth_header_name,
        elastic_index=destination.elastic_index,
        has_secret=bool(destination.auth_secret_encrypted),
        enabled=destination.enabled,
        subscribed_events=destination.subscribed_events,
        last_error=(health or {}).get("last_error"),
        pending_count=(health or {}).get("pending_count", 0),
        failed_count=(health or {}).get("failed_count", 0),
        last_success_at=destination.last_success_at,
        last_failure_at=destination.last_failure_at,
        created_at=destination.created_at,
        updated_at=destination.updated_at,
    )


async def _get_or_404(db: AsyncSession, destination_id: int) -> Destination:
    destination = await db.get(Destination, destination_id)
    if destination is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")
    return destination


@router.get(
    "", response_model=list[DestinationOut], dependencies=[Depends(require(Permission.DESTINATION_READ))]
)
async def list_destinations(db: AsyncSession = Depends(get_db)) -> list[DestinationOut]:
    result = await db.execute(select(Destination).order_by(Destination.id))
    destinations = list(result.scalars().all())
    health = await _health(db, [d.id for d in destinations])
    return [_to_out(d, health.get(d.id)) for d in destinations]


@router.post(
    "",
    response_model=DestinationOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.DESTINATION_WRITE))],
)
async def create_destination(payload: DestinationCreate, db: AsyncSession = Depends(get_db)) -> DestinationOut:
    destination = Destination(
        name=payload.name,
        type=payload.type,
        url=payload.url,
        auth_type=payload.auth_type,
        auth_header_name=payload.auth_header_name,
        auth_secret_encrypted=payload.auth_secret,
        elastic_index=payload.elastic_index,
        enabled=payload.enabled,
        subscribed_events=payload.subscribed_events,
    )
    db.add(destination)
    await db.commit()
    await db.refresh(destination)

    audit(
        AuditAction.DESTINATION_CREATED,
        target_type="destination",
        target_id=destination.id,
        name=destination.name,
        type=destination.type,
        url=destination.url,
    )
    return _to_out(destination)


@router.patch(
    "/{destination_id}",
    response_model=DestinationOut,
    dependencies=[Depends(require(Permission.DESTINATION_WRITE))],
)
async def update_destination(
    destination_id: int, payload: DestinationUpdate, db: AsyncSession = Depends(get_db)
) -> DestinationOut:
    destination = await _get_or_404(db, destination_id)
    data = payload.model_dump(exclude_unset=True)

    # `type` is immutable, so only here is the pairing knowable. Without this an
    # operator could PATCH a working splunk_hec destination to authType "none" and
    # silently stop every delivery it makes.
    if "auth_type" in data:
        try:
            data["auth_type"] = resolve_auth_type(destination.type, data["auth_type"])
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc

    if "name" in data:
        destination.name = data["name"]
    if "url" in data:
        destination.url = data["url"]
    if "auth_type" in data:
        destination.auth_type = data["auth_type"]
    if "auth_header_name" in data:
        destination.auth_header_name = data["auth_header_name"]
    if data.get("auth_secret"):
        destination.auth_secret_encrypted = data["auth_secret"]
    if "elastic_index" in data:
        destination.elastic_index = data["elastic_index"]
    if "enabled" in data:
        destination.enabled = data["enabled"]
    if "subscribed_events" in data:
        destination.subscribed_events = data["subscribed_events"]

    await db.commit()
    await db.refresh(destination)

    audit(
        AuditAction.DESTINATION_UPDATED,
        target_type="destination",
        target_id=destination.id,
        changed=sorted(k for k in data if k != "auth_secret"),
        secret_rotated=bool(data.get("auth_secret")),
    )
    return _to_out(destination)


@router.post(
    "/{destination_id}/test",
    dependencies=[Depends(require(Permission.DESTINATION_WRITE))],
)
async def test_destination(destination_id: int, db: AsyncSession = Depends(get_db)) -> dict:
    """Send one synthetic event down the real delivery path and report what came back.

    Closes the setup loop. Before this the only way to learn whether a destination was
    configured correctly was to wait for a sweep, watch nothing arrive in the SIEM, and
    open psql — the product offered no way to prove delivery worked, and the onboarding
    page's own headline is "Get your fleet into Splunk".

    Always 200: the upstream verdict is the payload, not the status of this call. A
    refused delivery is a successful test that reports a refusal.
    """
    destination = await _get_or_404(db, destination_id)
    ok, error = await send_test_event(destination)

    audit(
        AuditAction.DESTINATION_UPDATED,
        target_type="destination",
        target_id=destination.id,
        tested=True,
        delivered=ok,
    )
    if ok:
        return {"ok": True, "detail": "Delivered. The destination accepted a test event."}
    return {"ok": False, "detail": error or "Delivery failed with no detail from the destination."}


@router.delete(
    "/{destination_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.DESTINATION_WRITE))],
)
async def delete_destination(destination_id: int, db: AsyncSession = Depends(get_db)) -> None:
    destination = await _get_or_404(db, destination_id)
    name = destination.name

    # Cascade pending deliveries so a deleted destination stops being retried — the
    # worker also handles a vanished destination defensively, but there's no reason to
    # leave dead rows sitting in the table.
    await db.execute(delete(OutboxDelivery).where(OutboxDelivery.destination_id == destination_id))
    await db.delete(destination)
    await db.commit()

    audit(AuditAction.DESTINATION_DELETED, target_type="destination", target_id=destination_id, name=name)
