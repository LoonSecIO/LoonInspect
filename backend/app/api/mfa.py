"""Enrolling a second factor (#653): status, a fresh secret, and the code that proves it.

The sign-in half — the challenge the password step returns and the route that redeems
it — lives in `app.api.auth` beside the lockout it shares. Everything here needs a
signed-in browser session, never a bearer token: a leaked token must not be able to
enrol a factor its owner does not hold.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import mfa
from app.core.audit import AuditAction, audit
from app.core.auth import Principal, current_principal
from app.core.database import get_db
from app.models.schema import AuthIdentity
from app.schemas.mfa import MfaCodeRequest, MfaConfirmOut, MfaEnrolOut, MfaStatusOut

router = APIRouter(prefix="/api/auth/mfa", tags=["auth"])
logger = logging.getLogger(__name__)


def _session_only(principal: Principal) -> None:
    if principal.auth_method != "session":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Two-factor enrolment requires a signed-in browser session"
        )


@router.get("", response_model=MfaStatusOut)
async def mfa_status(principal: Principal = Depends(current_principal)) -> MfaStatusOut:
    identity = mfa.identity_for(principal.account)
    return MfaStatusOut(
        enrolled=identity is not None and identity.confirmed_at is not None,
        pending=identity is not None and identity.confirmed_at is None,
        confirmed_at=identity.confirmed_at if identity else None,
        recovery_codes_remaining=len(identity.recovery_codes or []) if identity and identity.confirmed_at else 0,
    )


@router.post("/enrol", response_model=MfaEnrolOut)
async def enrol(principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)) -> MfaEnrolOut:
    """A fresh secret, shown once. Replaces an unconfirmed enrolment; a confirmed one has to
    be removed first, so a session that was hijacked cannot quietly swap the factor."""
    _session_only(principal)
    account = principal.account
    identity = mfa.identity_for(account)
    if identity is not None and identity.confirmed_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A second factor is already enrolled on this account. Remove it before enrolling another.",
        )
    secret = mfa.mint_secret()
    if identity is None:
        identity = AuthIdentity(account_id=account.id, provider=mfa.PROVIDER, subject=account.id)
        db.add(identity)
    identity.secret_encrypted = secret
    identity.recovery_codes = []
    identity.last_otp_step = None
    await db.commit()
    logger.info("second factor enrolment started", extra={"account_id": account.id})
    return MfaEnrolOut(secret=secret, otpauth_url=mfa.otpauth_url(secret, account.email))


@router.post("/confirm", response_model=MfaConfirmOut)
async def confirm(
    payload: MfaCodeRequest, principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)
) -> MfaConfirmOut:
    """One valid code proves the phone holds the secret; from then on the password alone
    no longer signs this account in. Answers with the recovery codes, once."""
    _session_only(principal)
    account = principal.account
    identity = mfa.identity_for(account)
    if identity is None or identity.confirmed_at is not None or not identity.secret_encrypted:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="There is no enrolment waiting for a code. Start one first."
        )
    now = datetime.now(UTC)
    step = mfa.verify_code(identity.secret_encrypted, payload.code, None, now=now)
    if step is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="That code was not accepted. Scan the QR code again, check the phone's clock, and type the current code.",
        )
    codes, hashes = mfa.mint_recovery_codes()
    identity.confirmed_at = now
    identity.last_otp_step = step
    identity.recovery_codes = hashes
    identity.last_used_at = now
    # This session proved possession just now; say so, the way a code-verified sign-in does.
    if principal.session is not None:
        principal.session.auth_method = mfa.METHOD_TOTP
    await db.commit()
    audit(AuditAction.MFA_ENROLLED, target_type="account", target_id=account.id, email=account.email)
    logger.info("second factor enrolled", extra={"account_id": account.id})
    return MfaConfirmOut(recovery_codes=codes, confirmed_at=now)
