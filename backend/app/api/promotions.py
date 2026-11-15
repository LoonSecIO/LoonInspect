"""Promoted applications (#793): the administrator API for `app.core.promotions`.

Under the data-sharing settings because that is what a promotion is: a decision about what
leaves this organization. Reading is SYSTEM_READ, like the preview. Promoting and withdrawing
are SYSTEM_WRITE, like the tier and the exclusions, and both are audited with the title named.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import promotions
from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.sharing import get_or_create_settings
from app.schemas.promotions import PromotionCreate, PromotionOut, PromotionsOut

router = APIRouter(prefix="/api/system/data-sharing/promotions", tags=["system"])


@router.get("", response_model=PromotionsOut, dependencies=[Depends(require(Permission.SYSTEM_READ))])
async def list_promotions(
    q: Annotated[str | None, Query(max_length=100)] = None,
    db: AsyncSession = Depends(get_db),
) -> PromotionsOut:
    """What is promoted, whether it is leaving, and the installed titles that could be promoted,
    the ones no public source here knows first. `q` searches the candidates by name or bundle ID."""
    return PromotionsOut.model_validate(await promotions.list_promotions(db, await get_or_create_settings(db), q))


@router.post(
    "",
    response_model=PromotionOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def promote(
    payload: PromotionCreate,
    response: Response,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> PromotionOut:
    """Promote one installed title: its name, bundle ID and versions leave in plain text with
    each exchange from now on, while sharing is on. A refusal is a 409 whose `detail` is the
    sentence (the flag is off, the title is not installed, an exclusion covers it, the limit).
    Promoting a title already promoted answers 200 with the row that exists."""
    settings_row = await get_or_create_settings(db)
    try:
        row, created = await promotions.promote(db, settings_row, payload.key_title, principal.account.email)
    except promotions.PromotionRefused as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    if created:
        audit(
            AuditAction.SHARING_PROMOTION_ADDED,
            target_type="app_promotion",
            target_id=str(row.id),
            app_name=row.app_name,
            bundle_id=row.bundle_id,
            key_title=row.key_title,
        )
    else:
        response.status_code = status.HTTP_200_OK
    listing = await promotions.list_promotions(db, settings_row)
    return PromotionOut.model_validate(next(item for item in listing["items"] if item["id"] == row.id))


@router.delete(
    "/{promotion_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def withdraw(promotion_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> Response:
    """Withdraw a promotion. Allowed with the flag off, so switching the area off never strands
    a choice someone wants undone."""
    row = await promotions.withdraw(db, promotion_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No promoted application has that id in this organization.")
    audit(
        AuditAction.SHARING_PROMOTION_REMOVED,
        target_type="app_promotion",
        target_id=str(promotion_id),
        app_name=row.app_name,
        bundle_id=row.bundle_id,
        key_title=row.key_title,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
