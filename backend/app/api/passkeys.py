"""Passkeys (#955): the two public sign-in routes, and a person's own passkeys on My Account.

A passkey sign-in is two calls from the sign-in page, both public, both in app.core.auth's
`_PUBLIC_EXACT`: a challenge that takes nothing and names nobody, the same for every caller, and the
answer, which mints the session in the same step. The rest needs a signed-in browser session, never a
bearer token, so a leaked token cannot add a way in: the list, adding one (which asks for the current
password first, and counts a wrong one toward the sign-in lockout) and removing one. An administrator's
removal of another account's passkeys is app.api.accounts, beside its second factor's. The checks and
the sentences are app.core.passkeys.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import _account_out, _clear_failures, _client_ip, _get_attempt, _record_failure
from app.core import mfa, passkeys
from app.core.audit import AuditAction, audit
from app.core.auth import (
    Principal,
    act_as_tenant,
    as_utc,
    create_session,
    current_principal,
    memberships_for,
    set_session_cookies,
)
from app.core.context import Actor
from app.core.database import get_db
from app.core.passkeys import PasskeyRefused
from app.core.security import verify_password
from app.models.schema import AuthIdentity
from app.schemas.auth import AccountOut
from app.schemas.passkeys import PasskeyAddRequest, PasskeyOptionsOut, PasskeyOptionsRequest, PasskeyOut, PasskeySignInRequest

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger(__name__)

SESSION_ONLY = "Adding or removing a passkey requires a signed-in browser session"


def _refusal(refused: PasskeyRefused) -> HTTPException:
    return HTTPException(status_code=refused.status, detail=refused.detail)


def _out(identity: AuthIdentity) -> PasskeyOut:
    return PasskeyOut(
        id=identity.id,
        name=identity.name or "",
        host=identity.rp_id or "",
        created_at=identity.created_at,
        last_used_at=identity.last_used_at,
    )


def _session_only(principal: Principal) -> None:
    if principal.auth_method != "session" or principal.session is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=SESSION_ONLY)


def _address(request: Request) -> passkeys.Address:
    """The page's address, or the refusal that says why no passkey can work at it, logged with what to check."""
    try:
        return passkeys.check_address(request)
    except PasskeyRefused as refused:
        logger.warning(
            "no passkey at this address",
            extra={"reason": refused.reason, "client_ip": _client_ip(request), "detail": refused.detail},
        )
        raise _refusal(refused) from None


@router.post("/login/passkey/options", response_model=PasskeyOptionsOut)
async def sign_in_options(request: Request, db: AsyncSession = Depends(get_db)) -> PasskeyOptionsOut:
    """A challenge for a passkey sign-in. Takes nothing, not even an email, and answers every caller alike apart
    from the challenge itself: with no allow-list in it, the answer says nothing about which accounts exist or
    hold a passkey. A browser lists the passkeys it holds for this host, and the answer names the one it used."""
    options = await passkeys.begin_sign_in(db, _address(request))
    await db.commit()
    return PasskeyOptionsOut(public_key=options)


@router.post("/login/passkey", response_model=AccountOut)
async def sign_in(
    payload: PasskeySignInRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AccountOut:
    """A passkey's answer: verified, and the session minted in the same step (#955, default 1: user verification on
    every passkey, so no code follows it). Neither counted toward nor held by the password lockout."""
    ip = _client_ip(request)
    try:
        account, identity = await passkeys.finish_sign_in(db, payload.credential)
    except PasskeyRefused as refused:
        await db.rollback()
        logger.warning("passkey sign-in refused", extra={"reason": refused.reason, "client_ip": ip, "detail": refused.detail})
        audit(
            AuditAction.PASSKEY_REFUSED,
            outcome="failure",
            target_type="account" if refused.account_id else None,
            target_id=refused.account_id,
            reason=refused.reason,
            **({"passkey_id": refused.passkey_id} if refused.passkey_id else {}),
        )
        raise _refusal(refused) from None

    now = datetime.now(UTC)
    session, raw_token = await create_session(
        db,
        account,
        identity_id=identity.id,
        auth_method=passkeys.METHOD,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    account.last_login_at = now
    await db.commit()
    set_session_cookies(response, raw_token, session.csrf_token)

    roles = sorted({row.role for row in account.roles})
    # Break-glass sign-ins are logged at WARNING whichever way they come in: the line a SIEM rule alerts on.
    emit = logger.warning if account.is_break_glass else logger.info
    emit(
        "login succeeded",
        extra={"account_id": account.id, "email": account.email, "client_ip": ip, "auth_method": passkeys.METHOD},
    )
    audit(
        AuditAction.LOGIN_SUCCEEDED,
        actor=Actor(type="account", id=account.id, label=account.email, tenant_id=account.tenant_id),
        target_type="account",
        target_id=account.id,
        auth_method=passkeys.METHOD,
        passkey_id=identity.id,
        break_glass=account.is_break_glass,
        roles=roles,
    )
    owed = await mfa.enrolment_required(db, account, roles, account.tenant_id, passkeys.METHOD)
    return _account_out(account, memberships=await memberships_for(db, account), mfa_enrolment_required=owed)


@router.get("/passkeys", response_model=list[PasskeyOut])
async def list_passkeys(principal: Principal = Depends(current_principal)) -> list[PasskeyOut]:
    """The caller's passkeys, oldest first: each one's name, the host it works at, when it was made and last signed in."""
    return [_out(identity) for identity in passkeys.passkeys_of(principal.account)]


@router.post("/passkeys/options", response_model=PasskeyOptionsOut)
async def registration_options(
    payload: PasskeyOptionsRequest,
    request: Request,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> PasskeyOptionsOut:
    """A challenge for adding a passkey, for the current password (#955, default 4). The address is checked first, so
    a page that can hold no passkey spends no password; a wrong one counts toward the sign-in lockout, as a wrong
    code does on New recovery codes."""
    _session_only(principal)
    account = principal.account
    address = _address(request)
    ip, now = _client_ip(request), datetime.now(UTC)
    attempt = await _get_attempt(db, account.email, ip)
    if attempt is not None and attempt.locked_until is not None and as_utc(attempt.locked_until) > now:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed attempts. Try again later.")
    local = next((row for row in account.identities if row.provider == "local"), None)
    if local is None or not verify_password(local.secret_hash, payload.current_password):
        await _record_failure(db, account.email, ip)
        logger.warning("passkey not started: the current password was wrong", extra={"account_id": account.id, "client_ip": ip})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")
    await _clear_failures(db, account.email, ip)
    # The challenge, like the passkey it leads to, lives with the account at home (#36): the same tenant for every
    # session that never switched, which is every session on every pod today.
    await act_as_tenant(db, account.tenant_id)
    options = await passkeys.begin_registration(db, address, account, principal.session)
    await db.commit()
    return PasskeyOptionsOut(public_key=options)


@router.post("/passkeys", response_model=PasskeyOut, status_code=status.HTTP_201_CREATED)
async def add_passkey(
    payload: PasskeyAddRequest,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> PasskeyOut:
    """The browser's answer to a registration challenge, and the name: the passkey is added to the caller's account."""
    _session_only(principal)
    account, session = principal.account, principal.session
    # Read before anything can roll back, which expires every object the session holds.
    account_id, email = account.id, account.email
    await act_as_tenant(db, account.tenant_id)
    try:
        identity = await passkeys.finish_registration(db, account, session, payload.credential, payload.name)
        # This session just proved the device and the person; say so, as a confirmed code does (#653).
        if session.auth_method == "password":
            session.auth_method = passkeys.METHOD_ADDED
        await db.commit()
    except PasskeyRefused as refused:
        await db.rollback()
        logger.warning("passkey not added", extra={"reason": refused.reason, "account_id": account_id, "detail": refused.detail})
        raise _refusal(refused) from None
    except IntegrityError:
        # Two answers for one credential, landing together: uq_auth_identity_provider_subject is the arbiter.
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=passkeys.ALREADY_ADDED) from None
    audit(
        AuditAction.PASSKEY_ADDED,
        target_type="account",
        target_id=account_id,
        email=email,
        passkey_id=identity.id,
        name=identity.name,
        host=identity.rp_id,
    )
    logger.info("passkey added", extra={"account_id": account_id, "passkey_id": identity.id, "host": identity.rp_id})
    return _out(identity)


@router.delete("/passkeys/{passkey_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_passkey(
    passkey_id: str,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Removes one of the caller's own passkeys, and ends every session it signed in, this one included if it did:
    a passkey removed for a lost device takes that device's sessions with it. The password still signs in."""
    _session_only(principal)
    account = principal.account
    identity = next((row for row in passkeys.passkeys_of(account) if row.id == passkey_id), None)
    if identity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Passkey not found")
    await act_as_tenant(db, account.tenant_id)
    await passkeys.remove(db, [identity], end_their_sessions=True)
    await db.commit()
    audit(
        AuditAction.PASSKEY_REMOVED,
        target_type="account",
        target_id=account.id,
        email=account.email,
        passkey_id=identity.id,
        name=identity.name,
        host=identity.rp_id,
        by_administrator=False,
    )
    logger.info("passkey removed", extra={"account_id": account.id, "passkey_id": identity.id})
