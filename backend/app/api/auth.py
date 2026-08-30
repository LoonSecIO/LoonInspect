from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.auth import (
    SESSION_COOKIE,
    Principal,
    as_utc,
    clear_session_cookies,
    create_session,
    current_principal,
    resolve_session,
    revoke_session,
    set_session_cookies,
)
from app.core.bootstrap import account_count, consume_claim_token, create_account, get_claim_token
from app.core.context import Actor
from app.core.database import get_db
from app.core.permissions import Permission, permissions_for
from app.core.security import hash_password, tokens_equal, verify_password
from app.core.version import get_app_version
from app.models.schema import Account, AuthIdentity, LoginAttempt, UserSession
from app.schemas.accounts import PasswordChangeRequest
from app.schemas.auth import AccountOut, AuthStatusOut, LoginRequest, Role, SetupRequest

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger(__name__)

_LOCKOUT_THRESHOLD = 5
_LOCKOUT_BASE_SECONDS = 60
_LOCKOUT_MAX_SECONDS = 3600
# Bounds the exponent so a long-running attack can't ask Python to compute 2**900.
_LOCKOUT_MAX_EXPONENT = 16


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _account_out(account: Account, permissions: Iterable[Permission] | None = None) -> AccountOut:
    roles = sorted({row.role for row in account.roles})
    effective = permissions if permissions is not None else permissions_for(roles)
    return AccountOut(
        id=account.id,
        email=account.email,
        display_name=account.display_name,
        roles=roles,
        permissions=sorted(permission.value for permission in effective),
        is_break_glass=account.is_break_glass,
    )


async def _get_attempt(db: AsyncSession, identifier: str, ip: str) -> LoginAttempt | None:
    result = await db.execute(
        select(LoginAttempt).where(LoginAttempt.identifier == identifier, LoginAttempt.ip == ip)
    )
    return result.scalar_one_or_none()


async def _record_failure(db: AsyncSession, identifier: str, ip: str) -> None:
    now = datetime.now(timezone.utc)
    attempt = await _get_attempt(db, identifier, ip)

    if attempt is None:
        attempt = LoginAttempt(identifier=identifier, ip=ip, failure_count=0)
        db.add(attempt)

    attempt.failure_count += 1
    attempt.last_failure_at = now

    if attempt.failure_count >= _LOCKOUT_THRESHOLD:
        exponent = min(attempt.failure_count - _LOCKOUT_THRESHOLD, _LOCKOUT_MAX_EXPONENT)
        backoff = min(_LOCKOUT_BASE_SECONDS * (2**exponent), _LOCKOUT_MAX_SECONDS)
        attempt.locked_until = now + timedelta(seconds=backoff)

    await db.commit()


async def _clear_failures(db: AsyncSession, identifier: str, ip: str) -> None:
    attempt = await _get_attempt(db, identifier, ip)
    if attempt is not None:
        await db.delete(attempt)


@router.get("/status", response_model=AuthStatusOut)
async def auth_status(request: Request, db: AsyncSession = Depends(get_db)) -> AuthStatusOut:
    """Unauthenticated probe the SPA calls on load, to decide between the first-run
    wizard, the login screen, and the app itself."""
    total = await account_count(db)

    authenticated = False
    raw_token = request.cookies.get(SESSION_COOKIE)
    if raw_token:
        authenticated = await resolve_session(db, raw_token) is not None

    # Anyone who can reach the port can call this, so the build only rides along for a
    # caller who has signed in — or on an unclaimed instance, which is already offering
    # that caller the first admin account. See GET /api/system/version for the
    # authenticated read, and the image's OCI labels for a host that can't sign in.
    setup_required = total == 0
    version = get_app_version() if (authenticated or setup_required) else None

    return AuthStatusOut(setup_required=setup_required, authenticated=authenticated, version=version)


@router.post("/setup", response_model=AccountOut, status_code=status.HTTP_201_CREATED)
async def setup(
    payload: SetupRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AccountOut:
    """Create the first administrator. Only reachable while zero accounts exist, and
    only with the claim token printed to the container logs at startup."""
    if await account_count(db) > 0:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Setup has already been completed")

    expected = get_claim_token()
    if expected is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Setup is not available")

    if not tokens_equal(payload.claim_token.strip(), expected):
        logger.warning("setup claim rejected", extra={"client_ip": _client_ip(request)})
        audit(AuditAction.SETUP_REJECTED, outcome="failure", reason="invalid_claim_token")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid claim token")

    account, identity = await create_account(
        db,
        email=payload.email,
        display_name=payload.display_name,
        password=payload.password,
        roles=[Role.admin.value],
    )

    session, raw_token = await create_session(
        db,
        account,
        identity_id=identity.id,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    account.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    # `account` was constructed in Python rather than loaded by a query, so its roles
    # relationship has never been populated. Reading it would trigger a lazy load,
    # which under asyncio raises MissingGreenlet instead of quietly issuing a query.
    await db.refresh(account, ["roles"])

    consume_claim_token()
    set_session_cookies(response, raw_token, session.csrf_token)

    logger.info(
        "first administrator created",
        extra={"account_id": account.id, "email": account.email, "client_ip": _client_ip(request)},
    )
    audit(
        AuditAction.SETUP_COMPLETED,
        actor=Actor(type="account", id=account.id, label=account.email, tenant_id=account.tenant_id),
        target_type="account",
        target_id=account.id,
        role=Role.admin.value,
    )
    return _account_out(account)


@router.post("/login", response_model=AccountOut)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AccountOut:
    email = payload.email.strip().lower()
    ip = _client_ip(request)
    now = datetime.now(timezone.utc)

    attempt = await _get_attempt(db, email, ip)
    locked_until = as_utc(attempt.locked_until) if attempt is not None else None
    if locked_until is not None and locked_until > now:
        logger.warning(
            "login blocked by lockout",
            extra={"email": email, "client_ip": ip, "failure_count": attempt.failure_count},
        )
        audit(
            AuditAction.LOGIN_BLOCKED,
            outcome="failure",
            attempted_email=email,
            failure_count=attempt.failure_count if attempt else None,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
        )

    result = await db.execute(select(Account).where(Account.email == email))
    account = result.scalar_one_or_none()

    identity = None
    if account is not None:
        identity = next((row for row in account.identities if row.provider == "local"), None)

    # Runs unconditionally, including when no account matched — verify_password falls
    # back to a dummy hash so an unknown address costs the same time as a real one.
    password_ok = verify_password(identity.secret_hash if identity else None, payload.password)

    if (
        account is None
        or identity is None
        or not password_ok
        or account.status != "active"
        or account.is_service_account
    ):
        await _record_failure(db, email, ip)
        # One message for every failure mode above. Distinguishing "no such account"
        # from "wrong password" from "disabled" hands an attacker a free account
        # enumeration oracle.
        logger.warning("login failed", extra={"email": email, "client_ip": ip})
        # The audit record deliberately does not say *why* it failed. The response
        # doesn't distinguish the cases, and a log an operator can read to learn that
        # an address exists would reintroduce the enumeration oracle by another route.
        audit(AuditAction.LOGIN_FAILED, outcome="failure", attempted_email=email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    await _clear_failures(db, email, ip)

    session, raw_token = await create_session(
        db,
        account,
        identity_id=identity.id,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    account.last_login_at = now
    identity.last_used_at = now
    await db.commit()

    set_session_cookies(response, raw_token, session.csrf_token)

    # Break-glass logins are logged at WARNING so the SSO-enforcement exemption can't
    # be used quietly — this is the line a SIEM rule should alert on.
    emit = logger.warning if account.is_break_glass else logger.info
    emit(
        "login succeeded",
        extra={
            "account_id": account.id,
            "email": account.email,
            "client_ip": ip,
            "break_glass": account.is_break_glass,
        },
    )
    audit(
        AuditAction.LOGIN_SUCCEEDED,
        # Explicit actor: the global dependency skips public paths, so nothing has
        # populated the request context by the time a login is being recorded.
        actor=Actor(type="account", id=account.id, label=account.email, tenant_id=account.tenant_id),
        target_type="account",
        target_id=account.id,
        auth_method="password",
        break_glass=account.is_break_glass,
        roles=sorted({row.role for row in account.roles}),
    )
    return _account_out(account)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    raw_token = request.cookies.get(SESSION_COOKIE)

    if raw_token:
        session = await resolve_session(db, raw_token)
        if session is not None:
            await revoke_session(db, session)
            await db.commit()
            logger.info("logout", extra={"account_id": session.account_id})

            # Fetched only for the label: logout is a public path, so nothing has
            # resolved the principal, and an audit line identifying the actor by UUID
            # alone is unreadable three weeks later.
            account = await db.get(Account, session.account_id)
            audit(
                AuditAction.LOGOUT,
                actor=Actor(
                    type="account",
                    id=session.account_id,
                    label=account.email if account else session.account_id,
                    # From the session rather than the account: the session is what is
                    # being ended, and it may outlive the account row being readable.
                    tenant_id=session.tenant_id,
                ),
                target_type="session",
                target_id=session.id,
            )

    # Cookies are cleared whether or not a session was found, so a stale cookie can
    # always be shed.
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookies(response)
    return response


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    payload: PasswordChangeRequest,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> None:
    # Session only. Allowing a bearer token to change its owner's password would let a
    # leaked token lock the actual owner out of their own account.
    if principal.auth_method != "session":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password changes require a signed-in browser session",
        )

    result = await db.execute(
        select(AuthIdentity).where(
            AuthIdentity.account_id == principal.account.id, AuthIdentity.provider == "local"
        )
    )
    identity = result.scalar_one_or_none()

    if identity is None or not verify_password(identity.secret_hash, payload.current_password):
        audit(
            AuditAction.PASSWORD_CHANGED,
            outcome="failure",
            target_type="account",
            target_id=principal.account.id,
            reason="current_password_incorrect",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")

    now = datetime.now(timezone.utc)
    identity.secret_hash = hash_password(payload.new_password)
    identity.password_changed_at = now

    # Every other session dies; this one survives so the user isn't logged out by their
    # own password change. API tokens are deliberately left alone — a routine rotation
    # shouldn't silently break the macOS client and every CI job. Revoking those is a
    # separate, explicit action on the API Tokens page.
    await db.execute(
        update(UserSession)
        .where(
            UserSession.account_id == principal.account.id,
            UserSession.id != (principal.session.id if principal.session else ""),
            UserSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    await db.commit()

    audit(
        AuditAction.PASSWORD_CHANGED,
        target_type="account",
        target_id=principal.account.id,
        email=principal.account.email,
    )
    logger.info("password changed", extra={"account_id": principal.account.id})


@router.get("/me", response_model=AccountOut)
async def me(principal: Principal = Depends(current_principal)) -> AccountOut:
    # Reports the principal's *effective* permissions, not the account's. A scoped
    # token must see the narrowed set here, or a client would build its UI around
    # capabilities its own credential doesn't carry.
    return _account_out(principal.account, principal.permissions)
