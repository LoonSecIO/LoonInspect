"""Explicit administrator actions; no activation secret or bearer is returned to the browser."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import intelligence
from app.core.audit import AuditAction, audit
from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.sharing import exchange_lock
from app.core.tenancy import get_tenant_id

router = APIRouter(prefix="/api/system/intelligence", tags=["system"])


class Activation(BaseModel):
    secret: SecretStr


@router.get("", dependencies=[Depends(require(Permission.SYSTEM_READ))])
async def access_status(db: AsyncSession = Depends(get_db)) -> dict:
    return await intelligence.status(db)


@router.post("/activate", dependencies=[Depends(require(Permission.SYSTEM_WRITE))])
async def activate(payload: Activation, db: AsyncSession = Depends(get_db)) -> dict:
    async with exchange_lock(get_tenant_id()):
        try:
            result = await intelligence.activate(db, payload.secret.get_secret_value())
            if result["credentialPresent"] and not result["error"]:
                audit(AuditAction.INTELLIGENCE_ACTIVATED, target_type="intelligence")
                return await intelligence.refresh(db) or result
            return result
        except intelligence.AccessFailure as exc:
            raise HTTPException(409, str(exc)) from None


@router.post("/rotate", dependencies=[Depends(require(Permission.SYSTEM_WRITE))])
async def rotate(db: AsyncSession = Depends(get_db)) -> dict:
    async with exchange_lock(get_tenant_id()):
        try:
            result = await intelligence.activate(db, None, rotate=True)
            if not result["error"]:
                audit(AuditAction.INTELLIGENCE_ROTATED, target_type="intelligence")
            return result
        except intelligence.AccessFailure as exc:
            raise HTTPException(409, str(exc)) from None


@router.post("/refresh", dependencies=[Depends(require(Permission.SYSTEM_WRITE))])
async def refresh(db: AsyncSession = Depends(get_db)) -> dict:
    async with exchange_lock(get_tenant_id()):
        if not intelligence.enabled():
            raise HTTPException(409, "Paid access preview is disabled. Check the release settings.")
        return await intelligence.refresh(db) or await intelligence.status(db)


@router.post("/disconnect", dependencies=[Depends(require(Permission.SYSTEM_WRITE))])
async def disconnect(db: AsyncSession = Depends(get_db)) -> dict:
    async with exchange_lock(get_tenant_id()):
        row = await intelligence.locked_settings(db)
        row.intelligence_credential = None
        intelligence.record(row, state="disconnected", updates_until=None, error=None)
        await db.commit()
        audit(AuditAction.INTELLIGENCE_DISCONNECTED, target_type="intelligence")
        return await intelligence.status(db)
