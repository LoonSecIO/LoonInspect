"""Call allowlisted API operations in-process, returning before their background jobs finish."""

import asyncio
import json as jsonlib
import logging
from typing import Any
from urllib.parse import urlencode

from starlette.types import ASGIApp, Message, Scope

from app.core.auth import MCP_DISPATCH_MARKER

logger = logging.getLogger(__name__)
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class APIError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status


class Dispatcher:
    """The ordinary API still performs authentication, validation, RLS and action authorization.

    ASGITransport waits for BackgroundTasks before returning, which would make an inventory
    sweep hold MCP open. This adapter returns at the final response body and retains the app
    task until its background work finishes. It never opens a socket or follows a redirect.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.tasks: set[asyncio.Task] = set()
        self.patch_tasks: dict[str, asyncio.Task] = {}

    async def close(self) -> None:
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)

    async def request(self, scope: Scope, bearer: str, method: str, path: str, *, params=None, json=None) -> Any:
        if not path.startswith("/api/") or "?" in path or "#" in path:
            raise ValueError("MCP dispatch must name a fixed API path")
        patch = method == "POST" and path in {"/api/jamf-patch/sync", "/api/fleet-catalog/refresh"}
        if patch and (active := self.patch_tasks.get(path)) is not None and not active.done():
            raise APIError(409, "A patch catalog refresh is still running. Check the catalog before retrying.")
        body = jsonlib.dumps(json).encode() if json is not None else b""
        headers = [
            (b"host", b"localhost"),
            (b"authorization", f"Bearer {bearer}".encode()),
            (b"content-type", b"application/json"),
            (b"accept", b"application/json"),
        ]
        # Retain the genuine originating request id/client, never client-selected headers.
        headers.extend((k, v) for k, v in scope.get("headers", []) if k in {b"user-agent", b"x-request-id"})
        inner = dict(scope, path=path, raw_path=path.encode(), root_path="", method=method, headers=headers, state={})
        inner["query_string"] = urlencode(params or {}, doseq=True).encode()
        inner["looninspect.mcp_dispatch"] = MCP_DISPATCH_MARKER
        done = asyncio.Event()
        never = asyncio.Event()
        status = 500
        chunks = bytearray()
        failure: Exception | None = None
        consumed = False

        async def receive() -> Message:
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": body, "more_body": False}
            await never.wait()
            return {"type": "http.disconnect"}

        async def send(message: Message) -> None:
            nonlocal status, failure
            if message["type"] == "http.response.start":
                status = message["status"]
            elif message["type"] == "http.response.body":
                part = message.get("body", b"")
                if len(chunks) + len(part) > MAX_RESPONSE_BYTES:
                    failure = APIError(413, "This result is too large. Narrow the filters or request a smaller page.")
                    done.set()
                    raise failure
                chunks.extend(part)
                if not message.get("more_body", False):
                    done.set()

        async def run() -> None:
            nonlocal failure
            try:
                await self.app(inner, receive, send)
            except Exception:
                # Neither arguments nor exception bodies belong in MCP diagnostics.
                if not done.is_set():
                    failure = failure or APIError(
                        503, "The fleet operation failed. Check its run log and LoonInspect's server log."
                    )
                logger.warning("MCP API operation failed; check the run log and server log", extra={"path": path})
            finally:
                done.set()

        task = asyncio.create_task(run(), name=f"mcp-api:{method}:{path}")
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        if patch:
            # The POST owns this slot until it actually ends, even if its caller
            # disconnected or timed out. The tool coroutine's lifetime is shorter.
            self.patch_tasks[path] = task

            def release(completed):
                if self.patch_tasks.get(path) is completed:
                    del self.patch_tasks[path]

            task.add_done_callback(release)
        try:
            await done.wait()
        except asyncio.CancelledError:
            if method == "GET":
                task.cancel()
            # A write may already have started. Keep it alive and never replay it.
            raise
        if failure:
            raise failure
        if status >= 400:
            # REST diagnostics can include mirror URLs or local paths. An MCP
            # credential has no grant to disclose those, including in error text.
            messages = {
                401: "The credential is no longer valid. Create a new connection in AI connections.",
                403: "The fleet operation is not permitted. Review this connection's scopes, roles and feature settings.",
                404: "The selected item was not found in this organization. Check its identifier and active organization.",
                409: "The operation is unavailable or already running. Check the connection, run or catalog in LoonInspect.",
                422: "The fleet API refused these arguments. Check the tool's identifiers, filters and date range.",
                429: "The fleet API is busy. Wait before requesting the operation again.",
            }
            raise APIError(status, messages.get(status, "The fleet operation failed. Check LoonInspect's run and server logs."))
        if not 200 <= status < 300:
            raise APIError(502, "The fleet API returned an unexpected response. Check the LoonInspect server log.")
        try:
            return jsonlib.loads(chunks) if chunks else {}
        except ValueError as exc:
            raise APIError(502, "The fleet API returned an unreadable result. Check the LoonInspect server log.") from exc
