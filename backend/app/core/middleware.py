from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings
from app.core.context import ClientInfo, reset_client, reset_request_id, set_client, set_request_id
from app.core.tenancy import IDENTITY_RESOLUTION_TENANT_ID, reset_tenant_id, set_tenant_id

logger = logging.getLogger("app.request")

REQUEST_ID_HEADER = "X-Request-ID"

# An inbound id is echoed into every log line for the request, so it can't be trusted
# verbatim — a caller-supplied newline would let anyone forge log entries. Constrain
# the charset and length, and fall back to a generated id if it doesn't fit.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# The container healthcheck hits this on a timer; logging it at INFO would bury real
# traffic in a dev environment that's otherwise idle.
_LOW_INTEREST_PATHS = frozenset({"/api/health"})


def _resolve_request_id(scope: Scope) -> str:
    for key, value in scope.get("headers", []):
        if key == b"x-request-id":
            candidate = value.decode("latin-1", errors="replace")[:64]
            return candidate if _SAFE_REQUEST_ID.match(candidate) else uuid.uuid4().hex
    return uuid.uuid4().hex


def _resolve_client(scope: Scope) -> ClientInfo:
    client = scope.get("client")
    user_agent: str | None = None

    for key, value in scope.get("headers", []):
        if key == b"user-agent":
            user_agent = value.decode("latin-1", errors="replace")[:512]
            break

    return ClientInfo(ip=client[0] if client else None, user_agent=user_agent)


def _level_for(path: str, status_code: int) -> int:
    if status_code >= 500:
        return logging.ERROR
    if status_code >= 400:
        return logging.WARNING
    if path in _LOW_INTEREST_PATHS:
        return logging.DEBUG
    return logging.INFO


class RequestContextMiddleware:
    """Assigns a request id, exposes it on the response, and logs each request.

    Written as pure ASGI rather than subclassing BaseHTTPMiddleware: that base class
    runs the downstream app in a separate anyio task, which makes contextvar
    propagation subtle and adds a buffering penalty on streaming responses. This
    middleware has neither problem and is the outermost layer, so it sees every
    request including CORS preflights and anything a later middleware rejects.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = _resolve_request_id(scope)
        token = set_request_id(request_id)
        client_token = set_client(_resolve_client(scope))
        # The resolution scope, not the acting tenant. Something has to be bound
        # before authenticate() can read the `sessions` table to find out which tenant
        # the caller actually acts for; authentication then replaces this with the one
        # the session row names, for both the context and the open database session.
        #
        # An unauthenticated request keeps this value for its whole life, which is
        # correct: the public routes either touch no tenant-scoped table (health) or
        # are the ones establishing identity in the first place (login, setup).
        tenant_token = set_tenant_id(IDENTITY_RESOLUTION_TENANT_ID)
        started = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        path = scope.get("path", "")
        client = scope.get("client")

        def fields() -> dict[str, Any]:
            return {
                "http": {
                    "method": scope.get("method"),
                    # Path only — query strings are the usual place identifiers leak
                    # into logs, and nothing in this API needs them for debugging.
                    "path": path,
                    "status_code": status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    # Already the X-Forwarded-For client when the peer is in
                    # FORWARDED_ALLOW_IPS (uvicorn's ProxyHeadersMiddleware, app.serve);
                    # otherwise the direct peer, which behind a proxy is the proxy.
                    "client_ip": client[0] if client else None,
                }
            }

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            logger.exception("request failed", extra=fields())
            raise
        else:
            logger.log(_level_for(path, status_code), "request", extra=fields())
        finally:
            reset_tenant_id(tenant_token)
            reset_client(client_token)
            reset_request_id(token)


# Deny what a Jamf console will never ask for. `clipboard-write` is deliberately
# absent: frontend/src/features/tokens/ApiTokensPage.tsx calls
# navigator.clipboard.writeText to hand the operator a freshly minted API token, and
# Permissions-Policy binds the document's own origin — a tidy-looking
# `clipboard-write=()` would break our own feature on the one screen where the value is
# unrecoverable if not copied. See #186 / #133.
_PERMISSIONS_POLICY = (
    "accelerometer=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), "
    "magnetometer=(), microphone=(), midi=(), payment=(), usb=()"
)


# The policy for the artifact the app built (#187). Every subresource in the shell is
# same-origin: Vite's hashed /assets/*, the favicons and logos from frontend/public, the
# theme script in its own file (frontend/public/theme.js — the reason `script-src` needs
# no hash and no nonce). `style-src 'unsafe-inline'` is the one accepted weakness:
# thirteen React `style={{...}}` attributes compute severity and status colours at
# runtime, `'unsafe-hashes'` would need a digest per colour, and omitting it does not
# fail loudly — the dots render colourless while the page otherwise works. `img-src data:`
# because Vite inlines assets under its 4 KB default. `base-uri`, `form-action`,
# `frame-ancestors`, `frame-src` and `object-src` are not covered by `default-src` and
# are stated so widening the default later cannot quietly widen them.
APP_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
    "frame-src 'none'; object-src 'none'"
)

# A second, weaker policy for exactly /docs and /redoc — not an exemption. FastAPI's
# helpers emit an inline init script and an inline style with no nonce hook, and load
# Swagger UI and ReDoc from jsdelivr; main.py passes the arguments that keep the favicon
# and fonts same-origin, so the code and styles come from one CDN. ReDoc's bundle then
# does two things of its own, both verified against the bundle rather than assumed: it
# builds its search index in a Web Worker created from a blob URL
# (`new Worker(URL.createObjectURL(new Blob([...])))`), which `worker-src` allows, and
# it loads its footer logo from cdn.redoc.ly, which `img-src` names — the first console
# pass logged exactly that violation. Both pages sit behind auth (`_PROTECTED_NON_API`
# in app.core.auth), so this policy is only ever served to a signed-in operator.
DOCS_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://cdn.redoc.ly; "
    "font-src 'self'; connect-src 'self'; worker-src 'self' blob:; base-uri 'self'; form-action 'self'; "
    "frame-ancestors 'none'; object-src 'none'"
)

# Exact match on purpose: `startswith("/docs")` also matches /docsomething, which the SPA
# catch-all serves as the shell, and the app's own pages would inherit the CDN policy.
_DOCS_PATHS = frozenset({"/docs", "/redoc"})

# The one word that turns the header off on its own (`CONTENT_SECURITY_POLICY=off`),
# leaving the other headers standing — the four-knob argument's point, answered with a
# value rather than a toggle.
CONTENT_SECURITY_POLICY_OFF = "off"


def content_security_policy_mode() -> str:
    """`default`, `custom` or `off` — what the startup log says about the policy, and
    never its contents: an override string is unreviewable by the app, so the log says
    that one is in force and leaves reading it to the operator who set it."""
    configured = settings.content_security_policy.strip()
    if not configured:
        return "default"
    if configured.lower() == CONTENT_SECURITY_POLICY_OFF:
        return "off"
    return "custom"


def content_security_policy_for(path: str) -> str | None:
    """The header value for one response, or None to send none."""
    configured = settings.content_security_policy.strip()
    if configured:
        return None if configured.lower() == CONTENT_SECURITY_POLICY_OFF else configured
    return DOCS_CONTENT_SECURITY_POLICY if path in _DOCS_PATHS else APP_CONTENT_SECURITY_POLICY


class SecurityHeadersMiddleware:
    """Stamps the four headers the app can be sure of about its own artifact, plus a
    relayed Strict-Transport-Security the operator opts into (#186, the v0 half of the
    #133 rulings), plus the Content-Security-Policy (#187, the v1 half): one policy for
    the shell the app built and a second, page-scoped one for /docs and /redoc.

    Same shape as RequestContextMiddleware just above: pure ASGI wrapping `send`
    rather than BaseHTTPMiddleware, so streaming responses take no buffering penalty
    and every response gets the same treatment — a same-origin route, a 401 from
    auth.py, a CORS preflight, or /docs and /redoc — regardless of which layer
    produced it. Must be registered *after* RequestContextMiddleware in main.py so it
    ends up outermost (Starlette prepends each added middleware) and can stamp
    everything inside it, CORS preflights included.

    Settings are read on every call rather than cached at import, matching every other
    settings-gated behaviour in this module — it keeps tests able to monkeypatch
    `settings.security_headers` / `settings.hsts_max_age` with no reload.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not settings.security_headers:
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "same-origin"
                headers["Permissions-Policy"] = _PERMISSIONS_POLICY
                # Relay only — never on by default. The app cannot know whether this
                # hostname will still terminate valid HTTPS in six months; only the
                # operator can, which is why this is the one header with no default
                # and no scheme gate (browsers ignore HSTS received over plain HTTP by
                # specification, so gating on the request scheme would buy nothing and
                # gating on X-Forwarded-Proto would make a misconfigured
                # FORWARDED_ALLOW_IPS present as "my HSTS setting silently does
                # nothing"). Never includeSubDomains, never preload — ruled out, no
                # code path here can emit either.
                if settings.hsts_max_age:
                    headers["Strict-Transport-Security"] = f"max-age={settings.hsts_max_age}"
                policy = content_security_policy_for(scope.get("path", ""))
                if policy is not None:
                    headers["Content-Security-Policy"] = policy
            await send(message)

        await self.app(scope, receive, send_wrapper)
