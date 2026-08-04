from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.database import get_db
from app.core.permissions import Permission, permissions_for
from app.core.security import hash_token
from app.core.tokens import generate_token
from app.models.schema import ApiToken
from app.schemas.tokens import ApiTokenCreated, ApiTokenCreateRequest, ApiTokenOut

router = APIRouter(
    prefix="/api/auth/tokens",
    tags=["tokens"],
    dependencies=[Depends(require(Permission.TOKEN_CREATE))],
)
logger = logging.getLogger(__name__)


def _to_out(token: ApiToken) -> ApiTokenOut:
    return ApiTokenOut(
        id=token.id,
        name=token.name,
        scopes=list(token.scopes or []),
        created_at=token.created_at,
        expires_at=token.expires_at,
        last_used_at=token.last_used_at,
    )


@router.get("", response_model=list[ApiTokenOut])
async def list_tokens(
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> list[ApiTokenOut]:
    """The caller's own tokens. There is no endpoint for reading anyone else's —
    listing another account's credentials isn't an admin convenience worth the blast
    radius, and revoking them belongs with account management."""
    result = await db.execute(
        select(ApiToken)
        .where(ApiToken.account_id == principal.account.id, ApiToken.revoked_at.is_(None))
        .order_by(ApiToken.created_at.desc())
    )
    return [_to_out(token) for token in result.scalars().all()]


@router.post("", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    payload: ApiTokenCreateRequest,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> ApiTokenCreated:
    # Minting requires an interactive session. Without this, a leaked token can issue
    # fresh tokens, and revoking the original no longer contains the compromise —
    # the attacker just keeps the replacement.
    if principal.auth_method != "session":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API tokens can only be created from a signed-in browser session",
        )

    account_permissions = permissions_for(row.role for row in principal.account.roles)
    requested: list[str] = []

    for value in payload.scopes:
        try:
            permission = Permission(value)
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Unknown scope: {value}") from None
        if permission not in account_permissions:
            # Rejected rather than silently dropped: a token quietly weaker than asked
            # for produces a confusing 403 later, far from the cause.
            raise HTTPException(
                status_code=422, detail=f"Your account does not hold the scope: {value}"
            )
        requested.append(permission.value)

    now = datetime.now(timezone.utc)
    minted = generate_token()

    token = ApiToken(
        id=minted.token_id,
        account_id=principal.account.id,
        name=payload.name.strip(),
        token_hash=hash_token(minted.secret),
        scopes=sorted(set(requested)),
        created_at=now,
        expires_at=now + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None,
    )
    db.add(token)
    await db.commit()

    audit(
        AuditAction.TOKEN_CREATED,
        target_type="api_token",
        target_id=token.id,
        name=token.name,
        scopes=token.scopes,
        expires_at=token.expires_at,
    )
    logger.info("api token created", extra={"token_id": token.id, "account_id": principal.account.id})

    # The only time the raw value is ever returned. It is not recoverable afterwards —
    # only the hash was stored.
    return ApiTokenCreated(**_to_out(token).model_dump(), token=minted.raw)


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(
    token_id: str,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> None:
    token = await db.get(ApiToken, token_id)

    # Same 404 whether the token doesn't exist or belongs to someone else — otherwise
    # this endpoint reports which token ids are real.
    if token is None or token.account_id != principal.account.id or token.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")

    token.revoked_at = datetime.now(timezone.utc)
    await db.commit()

    audit(
        AuditAction.TOKEN_REVOKED,
        target_type="api_token",
        target_id=token.id,
        name=token.name,
    )
