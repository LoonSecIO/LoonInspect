from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.context import ClientInfo, reset_client, reset_request_id, set_client, set_request_id
from app.core.tenancy import OPERATIONAL_TENANT_ID, reset_tenant_id, set_tenant_id

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
        # Bound here, once, before anything can open a database session — including
        # the global authenticate() dependency, which queries tenant-scoped tables
        # itself and so cannot be the thing that establishes the tenant.
        #
        # v0 has one operational tenant and no per-session binding yet: #30 resolves
        # the tenant from UserSession at authentication and sets it here instead.
        # Everything downstream already reads it from context rather than choosing
        # one, so that change lands in this line and nowhere else.
        tenant_token = set_tenant_id(OPERATIONAL_TENANT_ID)
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
                    # scope["client"] is the proxy's address behind a reverse proxy.
                    # Trusting X-Forwarded-For requires knowing which hops are ours,
                    # so that's deferred rather than guessed at.
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
