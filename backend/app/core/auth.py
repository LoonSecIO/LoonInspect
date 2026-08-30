from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditAction, audit
from app.core.config import settings
from app.core.context import Actor, set_actor
from app.core.database import get_db, rebind_tenant
from app.core.permissions import Permission, permissions_for
from app.core.security import generate_token, hash_token, tokens_equal
from app.core.tenancy import set_tenant_id
from app.core.tokens import parse_token
from app.models.schema import Account, ApiToken, UserSession

logger = logging.getLogger(__name__)

SESSION_COOKIE = "loon_session"
CSRF_COOKIE = "loon_csrf"
CSRF_HEADER = "X-CSRF-Token"

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Writing last_seen_at on literally every request turns a page load into a dozen
# UPDATEs. Refreshing at most this often keeps the sliding window accurate to within
# a minute, which is far finer than any sane idle timeout needs.
_SESSION_TOUCH_INTERVAL = timedelta(seconds=60)

# Routes reachable without a session. Everything not listed here is denied, so adding
# a router can't accidentally expose it — but *adding to this set* is the one change
# that can, which is why it's a single visible list rather than per-route decorators.
_PUBLIC_EXACT = frozenset(
    {
        "/api/health",
        "/api/auth/status",
        "/api/auth/setup",
        "/api/auth/login",
        # Logout stays public so it works with an already-expired session — clearing
        # cookies should never itself require a valid one.
        "/api/auth/logout",
    }
)

# Webhooks authenticate with their own per-connection credential rather than a session
# (see docs/auth-design.md §4.7 and app.api.webhooks). Exempt from session auth, not
# unauthenticated.
_PUBLIC_PREFIXES = ("/webhooks/",)

# FastAPI's generated docs enumerate the entire API surface, which is free
# reconnaissance for anyone who can reach the port. A signed-in admin's browser sends
# the session cookie, so Swagger still works for them.
_PROTECTED_NON_API = frozenset({"/docs", "/redoc", "/openapi.json"})


def as_utc(value: datetime | None) -> datetime | None:
    """Re-attach UTC to a datetime read back from the database.

    A no-op on Postgres, which has a real timezone type and returns aware values from
    `DateTime(timezone=True)`. Kept because it costs nothing and every comparison
    against a stored timestamp already routes through it — session expiry, the sliding
    refresh, the lockout check — so removing it would be a wide edit that trades a
    guaranteed-aware value for an assumed one.
    """
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def is_public_path(path: str) -> bool:
    if path in _PUBLIC_EXACT:
        return True
    if path.startswith(_PUBLIC_PREFIXES):
        return True
    if path in _PROTECTED_NON_API:
        return False
    # Anything left that isn't an API call is the SPA shell or a static asset, and has
    # to load unauthenticated — otherwise there's no login page to log in from.
    return not path.startswith("/api/")


@dataclass(frozen=True, slots=True)
class Principal:
    account: Account
    # Resolved once at authentication rather than recomputed per check, so token scope
    # narrowing is applied in exactly one place and can't be forgotten by a caller.
    permissions: frozenset[Permission]
    auth_method: str  # "session" | "api_token"
    session: UserSession | None = None
    token: ApiToken | None = None

    @property
    def tenant_id(self) -> uuid.UUID:
        """The tenant this caller acts for.

        Taken from the credential rather than the account, because the credential is
        what the request actually presented — a session or token that outlives a move
        between tenants must keep acting for the one it was issued under until it is
        replaced, not silently follow the account.
        """
        credential = self.session or self.token
        return credential.tenant_id if credential is not None else self.account.tenant_id


def session_expiry(now: datetime) -> datetime | None:
    """None when the operator configured an unlimited lifetime — the session then has
    no passive timer, though revocation still applies."""
    if settings.session_lifetime_seconds == 0:
        return None
    return now + timedelta(seconds=settings.session_lifetime_seconds)


async def create_session(
    db: AsyncSession,
    account: Account,
    *,
    identity_id: str | None,
    auth_method: str = "password",
    ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[UserSession, str]:
    """Returns the persisted session and the raw cookie value, which is the only time
    the raw token exists — only its hash is stored."""
    now = datetime.now(timezone.utc)
    raw_token = generate_token()

    session = UserSession(
        token_hash=hash_token(raw_token),
        account_id=account.id,
        identity_id=identity_id,
        auth_method=auth_method,
        csrf_token=generate_token(),
        ip=ip,
        user_agent=(user_agent or "")[:512] or None,
        created_at=now,
        last_seen_at=now,
        expires_at=session_expiry(now),
    )
    db.add(session)
    await db.flush()
    return session, raw_token


async def revoke_session(db: AsyncSession, session: UserSession) -> None:
    session.revoked_at = datetime.now(timezone.utc)


def scoped_permissions(account: Account, scopes: list[str] | None) -> frozenset[Permission]:
    """Effective permissions for a token: the owner's set, optionally narrowed.

    Always an intersection, never a union. A token cannot outrank its owner, and a
    token minted while its owner was an Admin silently loses that reach the moment the
    account is demoted — the scopes list is a ceiling request, not a grant.
    """
    granted = permissions_for(row.role for row in account.roles)
    if not scopes:
        return granted

    requested: set[Permission] = set()
    for value in scopes:
        try:
            requested.add(Permission(value))
        except ValueError:
            # A scope from an older release that no longer exists. Dropping it degrades
            # to less access, which is the safe direction to fail.
            continue

    return frozenset(granted & requested)


async def revoke_all_tokens(db: AsyncSession, account_id: str) -> None:
    """Companion to revoke_all_sessions for account deactivation. Token auth already
    refuses a non-active account, so this is belt-and-braces — but SCIM deprovisioning
    is expected to sever credentials outright, not merely stop honouring them."""
    await db.execute(
        update(ApiToken)
        .where(ApiToken.account_id == account_id, ApiToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )


async def revoke_all_sessions(db: AsyncSession, account_id: str) -> None:
    """Used on password change, account disable, and (once SCIM lands) deprovisioning.

    A deactivated operator holding a live cookie is the exact scenario deactivation
    exists to prevent, so this has to be synchronous with the status change rather
    than left to expiry.
    """
    await db.execute(
        update(UserSession)
        .where(UserSession.account_id == account_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )


def set_session_cookies(response: Response, raw_token: str, csrf_token: str) -> None:
    max_age = settings.session_lifetime_seconds or None

    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=max_age,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )
    # Readable by JavaScript on purpose: the SPA has to echo it back in a header, which
    # is what proves the request came from our own page rather than a cross-site form.
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=max_age,
        httponly=False,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


async def resolve_session(db: AsyncSession, raw_token: str) -> UserSession | None:
    result = await db.execute(select(UserSession).where(UserSession.token_hash == hash_token(raw_token)))
    session = result.scalar_one_or_none()
    if session is None or session.revoked_at is not None:
        return None

    expires_at = as_utc(session.expires_at)
    if expires_at is not None and expires_at <= datetime.now(timezone.utc):
        return None

    return session


async def account_for_session(db: AsyncSession, session: UserSession) -> Account | None:
    """The account a session may still act as, or None if it may not.

    Split out from _authenticate_session because a live session and an account allowed
    to use it are two different questions, and answering the second one in two places
    is how they drifted: /api/auth/status used to call resolve_session alone and report
    a disabled account as signed in, while every real route revoked the same cookie.

    The consequence is left to the caller. _authenticate_session revokes; auth_status
    only reports, because a public probe should not carry a write. Note this cannot
    move into resolve_session itself — logout resolves deliberately without caring
    whether the account is still active, and must keep clearing a disabled user's
    cookie.
    """
    account = await db.get(Account, session.account_id)
    if account is None or account.status != "active":
        return None
    return account


def _verify_csrf(request: Request, session: UserSession) -> None:
    supplied = request.headers.get(CSRF_HEADER, "")
    if not supplied or not tokens_equal(supplied, session.csrf_token):
        logger.warning(
            "csrf check failed",
            extra={"http": {"method": request.method, "path": request.url.path}},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")


async def authenticate(request: Request, response: Response, db: AsyncSession = Depends(get_db)) -> None:
    """Global dependency: every route is denied unless is_public_path() says otherwise.

    Declared with Depends(get_db) rather than opening its own session so FastAPI's
    dependency cache hands the *same* session to the route below — one session per
    request, not two. The cost is constructing a session object on public requests
    too, which is negligible because SQLAlchemy doesn't acquire a connection until the
    first query.

    The Response parameter is FastAPI's per-request sub-response: headers set on it
    are merged into whatever the route returns, which is how the sliding-session
    cookie re-issue (see _authenticate_session) reaches the browser.
    """
    if is_public_path(request.url.path):
        return

    header = request.headers.get("authorization", "")
    if header[:7].lower() == "bearer ":
        principal = await _authenticate_bearer(db, header[7:].strip())
    else:
        principal = await _authenticate_session(db, request, response)

    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    # CSRF is a cookie problem specifically: the browser attaches cookies to
    # cross-site requests on its own, but never an Authorization header. Requiring the
    # token here would be pure friction for the macOS client and CI.
    if principal.auth_method == "session" and request.method not in _SAFE_METHODS:
        _verify_csrf(request, principal.session)

    request.state.principal = principal

    # The acting tenant, now that it is known. Until this line the request has been
    # scoped to whatever was wide enough to find the credential; from here it is
    # scoped to the tenant that credential names, in the context every later session
    # reads from *and* in the session already open for this request.
    tenant_id = principal.tenant_id
    set_tenant_id(tenant_id)
    await rebind_tenant(db, tenant_id)

    if principal.token is not None:
        set_actor(
            Actor(
                type="api_token",
                id=principal.token.id,
                # Names both the token and its owner: an audit line saying only "a
                # token did this" leaves the reader with more work than it saved.
                label=f"{principal.account.email} via token {principal.token.name!r}",
                tenant_id=tenant_id,
            )
        )
    else:
        set_actor(
            Actor(
                type="account",
                id=principal.account.id,
                label=principal.account.email,
                tenant_id=tenant_id,
            )
        )


async def _authenticate_session(
    db: AsyncSession, request: Request, response: Response
) -> Principal | None:
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not raw_token:
        return None

    session = await resolve_session(db, raw_token)
    if session is None:
        return None

    account = await account_for_session(db, session)
    if account is None:
        # The session outlived the account's ability to use it. Revoke rather than
        # merely rejecting, so a re-enabled account doesn't resurrect old cookies.
        await revoke_session(db, session)
        await db.commit()
        return None

    now = datetime.now(timezone.utc)
    if now - as_utc(session.last_seen_at) > _SESSION_TOUCH_INTERVAL:
        session.last_seen_at = now
        session.expires_at = session_expiry(now)
        await db.commit()

        # The slide has to reach the browser too. Advancing expires_at is worthless
        # once the cookie's own Max-Age — stamped at login — runs out, because the
        # browser then stops presenting a token the server would still accept (#124).
        # Re-issuing here, on the same cadence as the touch above, keeps the cookie's
        # clock in lockstep with the session's at a cost of at most one Set-Cookie
        # per minute per session. Both cookies, always: loon_csrf carries the same
        # Max-Age, and refreshing only loon_session would leave mutations failing
        # CSRF an hour in while reads sail on. Skipped when the lifetime is 0 — the
        # login-time cookies are already browser-session cookies with no clock to
        # wind. (Routes that return a Response object directly bypass FastAPI's
        # sub-response header merge, so a re-issue can miss one; the SPA's next
        # ordinary request carries it, well inside any permitted lifetime.)
        if settings.session_lifetime_seconds != 0:
            set_session_cookies(response, raw_token, session.csrf_token)

    return Principal(
        account=account,
        permissions=permissions_for(row.role for row in account.roles),
        auth_method="session",
        session=session,
    )


async def _authenticate_bearer(db: AsyncSession, raw: str) -> Principal | None:
    parsed = parse_token(raw)
    if parsed is None:
        return None

    token = await db.get(ApiToken, parsed.token_id)
    if token is None or token.revoked_at is not None:
        return None

    # Constant-time even though the id lookup already succeeded: without it, the
    # comparison leaks how much of a guessed secret was correct.
    if not tokens_equal(token.token_hash, hash_token(parsed.secret)):
        return None

    now = datetime.now(timezone.utc)
    expires_at = as_utc(token.expires_at)
    if expires_at is not None and expires_at <= now:
        return None

    account = await db.get(Account, token.account_id)
    if account is None or account.status != "active":
        return None

    if token.last_used_at is None or now - as_utc(token.last_used_at) > _SESSION_TOUCH_INTERVAL:
        token.last_used_at = now
        await db.commit()

    return Principal(
        account=account,
        permissions=scoped_permissions(account, token.scopes),
        auth_method="api_token",
        token=token,
    )


def current_principal(request: Request) -> Principal:
    """For routes that need the caller. Populated by authenticate(), so reaching a
    route without it means the route was wrongly allowlisted as public."""
    principal = getattr(request.state, "principal", None)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return principal


def principal_permissions(principal: Principal) -> frozenset[Permission]:
    return principal.permissions


def require(*permissions: Permission) -> Callable[[Request], Principal]:
    """Build a dependency asserting the caller holds *every* listed permission.

    Authentication is already guaranteed by the global dependency, so this only
    answers the authorization question — and returns 403 rather than 401, since the
    caller is known and re-authenticating wouldn't help.
    """

    def dependency(request: Request) -> Principal:
        principal = current_principal(request)
        granted = principal_permissions(principal)
        missing = sorted(permission.value for permission in permissions if permission not in granted)

        if missing:
            logger.warning(
                "permission denied",
                extra={
                    "account_id": principal.account.id,
                    "email": principal.account.email,
                    "missing_permissions": missing,
                    "http": {"method": request.method, "path": request.url.path},
                },
            )
            audit(
                AuditAction.AUTHZ_DENIED,
                outcome="failure",
                target_type="endpoint",
                target_id=request.url.path,
                method=request.method,
                missing_permissions=missing,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
            )

        return principal

    return dependency
