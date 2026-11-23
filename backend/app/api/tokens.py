from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import Principal, act_as_tenant, current_principal, require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.security import hash_token
from app.core.tokens import generate_token
from app.mcp.policy import validate_grant
from app.models.schema import ApiToken, ApiTokenTenant
from app.schemas.tokens import ApiTokenCreated, ApiTokenCreateRequest, ApiTokenOut

router = APIRouter(
    prefix="/api/auth/tokens",
    tags=["tokens"],
    dependencies=[Depends(require(Permission.TOKEN_CREATE))],
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def _at_token_home(db: AsyncSession, principal: Principal):
    """Read or write the owner's tokens at home, then restore the active organization."""
    acting = principal.tenant_id
    await act_as_tenant(db, principal.home_tenant_id)
    try:
        yield
    except BaseException:
        await db.rollback()
        raise
    finally:
        await act_as_tenant(db, acting)


def _own_tokens(principal: Principal):
    return (
        select(ApiToken)
        .join(ApiTokenTenant, ApiTokenTenant.token_hash == ApiToken.token_hash)
        .where(
            ApiToken.account_id == principal.account.id,
            ApiToken.revoked_at.is_(None),
            ApiTokenTenant.tenant_id == principal.tenant_id,
        )
    )


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
    expected: UUID | None = Header(default=None, alias="X-Expected-Tenant-ID"),
) -> list[ApiTokenOut]:
    """The caller's own tokens. There is no endpoint for reading anyone else's —
    listing another account's credentials isn't an admin convenience worth the blast
    radius, and revoking them belongs with account management."""
    if expected is not None and expected != principal.tenant_id:
        raise HTTPException(409, "Your active organization changed. Reload before listing connections.")
    query = _own_tokens(principal).order_by(ApiToken.created_at.desc())
    async with _at_token_home(db, principal):
        result = await db.execute(query)
        return [_to_out(token) for token in result.scalars().all()]


@router.post("", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(
    payload: ApiTokenCreateRequest,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
    expected: UUID | None = Header(default=None, alias="X-Expected-Tenant-ID"),
) -> ApiTokenCreated:
    # Minting requires an interactive session. Without this, a leaked token can issue
    # fresh tokens, and revoking the original no longer contains the compromise —
    # the attacker just keeps the replacement.
    if principal.auth_method != "session":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API tokens can only be created from a signed-in browser session",
        )

    if expected is not None and expected != principal.tenant_id:
        raise HTTPException(409, "Your active organization changed. Reload before creating a connection.")
    if Permission.MCP_CONNECT.value in payload.scopes:
        if expected is None:
            raise HTTPException(409, "Reload AI connections to confirm the organization before creating a connection.")
        try:
            validate_grant(payload.scopes, payload.expires_in_days)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    account_permissions = principal.permissions
    requested: list[str] = []

    for value in payload.scopes:
        try:
            permission = Permission(value)
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Unknown scope: {value}") from None
        if permission not in account_permissions:
            # Rejected rather than silently dropped: a token quietly weaker than asked
            # for produces a confusing 403 later, far from the cause.
            raise HTTPException(status_code=422, detail=f"Your account does not hold the scope: {value}")
        requested.append(permission.value)

    now = datetime.now(UTC)
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
    acting, home = principal.tenant_id, principal.home_tenant_id
    async with _at_token_home(db, principal):
        db.add(token)
        await db.flush()
        db.add(ApiTokenTenant(token_hash=token.token_hash, tenant_id=acting, home_tenant_id=home if acting != home else None))
        await db.commit()
        created = ApiTokenCreated(**_to_out(token).model_dump(), token=minted.raw)

    audit(
        AuditAction.TOKEN_CREATED,
        target_type="api_token",
        target_id=created.id,
        name=created.name,
        scopes=created.scopes,
        expires_at=created.expires_at,
    )
    logger.info("api token created", extra={"token_id": created.id, "account_id": principal.account.id})

    # The only time the raw value is ever returned. It is not recoverable afterwards —
    # only the hash was stored.
    return created


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(
    token_id: str,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
    expected: UUID | None = Header(default=None, alias="X-Expected-Tenant-ID"),
) -> None:
    if expected is not None and expected != principal.tenant_id:
        raise HTTPException(409, "Your active organization changed. Reload before revoking a connection.")
    query = _own_tokens(principal).where(ApiToken.id == token_id)
    async with _at_token_home(db, principal):
        token = (await db.execute(query)).scalar_one_or_none()
        # Owner and acting organization are both part of the lookup: a token for a
        # different organization is indistinguishable from an unknown identifier.
        if token is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")
        token.revoked_at = datetime.now(UTC)
        name = token.name
        await db.commit()

    audit(
        AuditAction.TOKEN_REVOKED,
        target_type="api_token",
        target_id=token_id,
        name=name,
    )
