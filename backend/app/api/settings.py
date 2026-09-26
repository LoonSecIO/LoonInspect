"""Tenant settings served as text (#116). Display and evidence context, never thresholds:
docs/v-never.md refuses invented compliance regimes, and an org's stated policy is how an
org-backed target could someday be legitimized — that legitimization is its own ruling. One setting is
enforced rather than displayed: who must sign in with a second factor (#653), read by app.core.auth."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal, require
from app.core.database import get_db
from app.core.permissions import Permission
from app.models.schema import PatchingPolicy, Tenant
from app.schemas.settings import MfaPolicy, PatchingPolicyOut, PatchingPolicyUpdate

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get(
    "/patching-policy",
    response_model=PatchingPolicyOut,
    dependencies=[Depends(require(Permission.APP_READ))],
)
async def get_patching_policy(db: AsyncSession = Depends(get_db)) -> PatchingPolicyOut:
    """The org's stated patching policy, or an empty statement when none has been stated.

    Gated like the Jamf Patch page it is read beside (`app:read`), so the auditor who
    reads the numbers reads the sentence. Reading creates nothing: an unstated policy is
    an absent row, and the page says "no patching policy stated" in words.
    """
    row = (await db.execute(select(PatchingPolicy))).scalar_one_or_none()
    return PatchingPolicyOut.model_validate(row) if row is not None else PatchingPolicyOut()


@router.put(
    "/patching-policy",
    response_model=PatchingPolicyOut,
    dependencies=[Depends(require(Permission.SYSTEM_WRITE))],
)
async def put_patching_policy(
    payload: PatchingPolicyUpdate,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> PatchingPolicyOut:
    """State the policy, or clear it with an empty statement. Audited: who stated what an
    auditor will read is exactly what the audit trail exists for."""
    row = (await db.execute(select(PatchingPolicy))).scalar_one_or_none()
    if row is None:
        row = PatchingPolicy()
        db.add(row)
    row.statement = payload.statement.strip()
    row.updated_at = datetime.now(UTC)
    row.updated_by = principal.account.email
    await db.commit()
    await db.refresh(row)
    audit(
        AuditAction.PATCHING_POLICY_UPDATED,
        target_type="patching_policy",
        statement_length=len(row.statement),
        cleared=row.statement == "",
    )
    return PatchingPolicyOut.model_validate(row)


@router.get("/mfa-policy", response_model=MfaPolicy, dependencies=[Depends(require(Permission.ACCOUNT_READ))])
async def get_mfa_policy(principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> MfaPolicy:
    """Who must sign in with a second factor where this session acts; read by whoever reads Accounts."""
    tenant = await db.get(Tenant, principal.tenant_id)
    return MfaPolicy(mfa_required=tenant.mfa_required)


@router.put("/mfa-policy", response_model=MfaPolicy, dependencies=[Depends(require(Permission.ACCOUNT_WRITE))])
async def put_mfa_policy(
    payload: MfaPolicy,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> MfaPolicy:
    """Administrators only. It applies from each account's next request; nobody is signed out."""
    tenant = await db.get(Tenant, principal.tenant_id)
    before = tenant.mfa_required
    tenant.mfa_required = payload.mfa_required
    await db.commit()
    audit(AuditAction.MFA_POLICY_CHANGED, target_type="tenant", target_id=tenant.id, before=before, after=tenant.mfa_required)
    return MfaPolicy(mfa_required=tenant.mfa_required)
