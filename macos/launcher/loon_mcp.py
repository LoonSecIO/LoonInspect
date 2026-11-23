"""The Mac app's stdio MCP adapter, attaching to its already-running local backend.

The signed Swift entry point supplies a Keychain credential through a private pipe.
This adapter validates the app's private runtime descriptor and health identity before
sending that credential. It never launches services, follows redirects, uses proxies,
or retries a request whose outcome might already have changed the fleet.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import httpx
from mcp.shared.inbound import (
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    NAME_BEARING_METHODS,
    encode_header_value,
)
from mcp.shared.jsonrpc_dispatcher import cancelled_request_id_from_params
from mcp_types import PROTOCOL_VERSION_META_KEY, JSONRPCError
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from pydantic import ValidationError

REQUEST_LIMIT = 256 * 1024
RESPONSE_LIMIT = 512 * 1024
REQUEST_SECONDS = 45
PATCH_SYNC_SECONDS = 330
DISCOVERY_SECONDS = 10
MAX_IN_FLIGHT = 8


class BridgeFailure(Exception):
    """An operator-facing transport failure, without response bodies or secrets."""


def read_credential(fd: int) -> str:
    try:
        with os.fdopen(fd, "rb") as pipe:
            raw = pipe.read(4097)
        token = raw.decode("ascii").strip()
    except (OSError, UnicodeError) as error:
        raise BridgeFailure("Could not read the saved MCP credential. Pair this client again.") from error
    if len(raw) > 4096 or not re.fullmatch(r"loon_pat_[a-f0-9]{32}_[A-Za-z0-9_-]+", token):
        raise BridgeFailure("The saved MCP credential is invalid. Pair this client again.")
    return token


def read_runtime(path: Path) -> dict[str, Any]:
    try:
        # Neither a shared descriptor nor a symlink may redirect a bearer credential.
        for directory in (path.parent, path.parent.parent):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise BridgeFailure("LoonInspect's runtime directory is not private. Quit and reopen LoonInspect.")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise BridgeFailure("LoonInspect's runtime file is not private. Quit and reopen LoonInspect.")
            raw = handle.read(4097)
        if len(raw) > 4096:
            raise ValueError("oversized descriptor")
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or value.get("schema") != 1
            or type(value.get("port")) is not int
            or not 1 <= value["port"] <= 65535
            or type(value.get("pid")) is not int
            or value["pid"] <= 1
            or not isinstance(value.get("instance_id"), str)
            or not re.fullmatch(r"[a-fA-F0-9-]{36}", value["instance_id"])
        ):
            raise ValueError("invalid descriptor")
        os.kill(value["pid"], 0)
        return value
    except (OSError, ValueError, TypeError) as error:
        raise BridgeFailure("LoonInspect is not ready. Open the app and wait for its workspace, then retry.") from error


async def read_json(response: httpx.Response, limit: int) -> dict[str, Any]:
    if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise BridgeFailure("LoonInspect returned an unsupported MCP response. Update the app and reconnect this client.")
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > limit:
            raise BridgeFailure("The MCP response exceeded its size limit. Ask for fewer records or a narrower time range.")
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError) as error:
        raise BridgeFailure("LoonInspect returned an invalid MCP response. Reconnect this client.") from error
    if not isinstance(value, dict):
        raise BridgeFailure("LoonInspect returned an invalid MCP response. Reconnect this client.")
    return value


class Bridge:
    def __init__(self, token: str, runtime: Path, client: httpx.AsyncClient):
        self.token = token
        self.runtime = runtime
        self.client = client
        self.protocol: str | None = None
        self.initialized_instance: str | None = None

    def routing_headers(self, message: dict[str, Any]) -> dict[str, str]:
        """Mirror the SDK's transport routing while keeping the stdio envelope intact."""
        if message.get("method") == "initialize":
            # A failed modern discovery can fall back to the legacy handshake. That
            # handshake must not carry the protocol selected by the earlier probe.
            self.protocol = None
            return {}
        params = message.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        version = meta.get(PROTOCOL_VERSION_META_KEY) if isinstance(meta, dict) else None
        headers = {}
        if isinstance(version, str):
            self.protocol = version
            headers[MCP_METHOD_HEADER] = encode_header_value(message["method"])
            name_key = NAME_BEARING_METHODS.get(message["method"])
            if name_key is not None and isinstance(name := params.get(name_key), str):
                headers[MCP_NAME_HEADER] = encode_header_value(name)
        if self.protocol is not None:
            # Unsupported strings reach the server's protocol-negotiation error;
            # control characters can never become raw HTTP header bytes.
            headers[MCP_PROTOCOL_VERSION_HEADER] = encode_header_value(self.protocol)
        return headers

    async def discover(self) -> tuple[str, str]:
        descriptor = read_runtime(self.runtime)
        base = f"http://127.0.0.1:{descriptor['port']}"
        async with asyncio.timeout(DISCOVERY_SECONDS):
            async with self.client.stream("GET", base + "/api/health") as response:
                if response.status_code != 200:
                    raise BridgeFailure("LoonInspect is starting or unavailable. Wait for its workspace, then retry.")
                health = await read_json(response, 16 * 1024)
        if health.get("instanceId") != descriptor["instance_id"]:
            raise BridgeFailure("The local service is not this LoonInspect instance. Quit and reopen LoonInspect.")
        return base, descriptor["instance_id"]

    async def forward(self, message: dict[str, Any], routing_headers: dict[str, str] | None = None) -> dict[str, Any] | None:
        try:
            routing_headers = self.routing_headers(message) if routing_headers is None else routing_headers
            params = message.get("params")
            timeout = (
                PATCH_SYNC_SECONDS
                if (
                    message.get("method") == "tools/call"
                    and isinstance(params, dict)
                    and params.get("name") == "refresh_patch_catalog"
                )
                else REQUEST_SECONDS
            )
            async with asyncio.timeout(timeout):
                base, instance = await self.discover()
                if self.initialized_instance is not None and self.initialized_instance != instance:
                    raise BridgeFailure("LoonInspect restarted. Reconnect this MCP client before sending more requests.")
                headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json, text/event-stream"}
                headers.update(routing_headers)
                async with self.client.stream("POST", base + "/mcp", json=message, headers=headers, timeout=timeout) as response:
                    if response.status_code == 401:
                        raise BridgeFailure(
                            "The MCP credential expired or was revoked. Create a new connection and pair this client again."
                        )
                    if response.status_code == 403:
                        raise BridgeFailure("This MCP connection lacks permission. Review its scopes in LoonInspect Settings.")
                    if response.status_code in (202, 204) and "id" not in message:
                        return None
                    if response.status_code != 200:
                        # Modern discovery/negotiation errors carry meaningful JSON-RPC
                        # codes at HTTP 400/404. Preserve those codes so the client can
                        # choose a supported protocol; never turn them into a retry.
                        if "id" in message:
                            try:
                                answer = await read_json(response, RESPONSE_LIMIT)
                                JSONRPCError.model_validate(answer)
                            except (BridgeFailure, ValidationError):
                                pass
                            else:
                                if answer.get("id") in (None, message["id"]):
                                    return {**answer, "id": message["id"]}
                        if response.status_code == 404:
                            raise BridgeFailure(
                                "MCP is unavailable in this LoonInspect build. Update the app and enable MCP in Settings."
                            )
                        raise BridgeFailure(
                            f"LoonInspect refused the MCP request (HTTP {response.status_code}). "
                            "Check Settings and retry deliberately."
                        )
                    answer = await read_json(response, RESPONSE_LIMIT)
                if "id" not in message:
                    return None
                if answer.get("jsonrpc") != "2.0" or answer.get("id") != message["id"]:
                    raise BridgeFailure("LoonInspect returned a mismatched MCP response. Reconnect this client.")
                if message.get("method") == "initialize" and isinstance(answer.get("result"), dict):
                    protocol = answer["result"].get("protocolVersion")
                    if isinstance(protocol, str):
                        self.protocol = protocol
                        self.initialized_instance = instance
                elif routing_headers.get(MCP_PROTOCOL_VERSION_HEADER) in MODERN_PROTOCOL_VERSIONS:
                    self.initialized_instance = instance
                return answer
        except (httpx.HTTPError, TimeoutError) as error:
            raise BridgeFailure(
                "LoonInspect did not finish the MCP request. Its outcome is unknown; check run status before retrying a sync."
            ) from error


def emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n")
    sys.stdout.flush()


async def serve(token: str, runtime: Path) -> None:
    pending: set[asyncio.Task[None]] = set()
    by_id: dict[str | int, tuple[asyncio.Task[None], bool, str]] = {}
    async with httpx.AsyncClient(timeout=REQUEST_SECONDS, trust_env=False, follow_redirects=False) as client:
        bridge = Bridge(token, runtime, client)

        async def dispatch(message: dict[str, Any], routing_headers: dict[str, str]) -> None:
            try:
                answer = await bridge.forward(message, routing_headers)
                if answer is not None:
                    emit(answer)
            except BridgeFailure as error:
                if "id" in message:
                    emit({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32000, "message": str(error)}})
                else:
                    print(f"LoonInspect MCP: {error}", file=sys.stderr)

        def finished(task: asyncio.Task[None], request_id: str | int) -> None:
            pending.discard(task)
            if request_id in by_id and by_id[request_id][0] is task:
                del by_id[request_id]

        while True:
            line = await asyncio.to_thread(sys.stdin.buffer.readline, REQUEST_LIMIT + 1)
            if not line:
                break
            if len(line) > REQUEST_LIMIT:
                raise BridgeFailure("The MCP request exceeded 256 KiB. Reconnect and send a smaller request.")
            try:
                message = json.loads(line)
            except (ValueError, UnicodeError):
                emit({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Invalid JSON"}})
                continue
            if (
                not isinstance(message, dict)
                or message.get("jsonrpc") != "2.0"
                or not isinstance(message.get("method"), str)
                or ("id" in message and type(message["id"]) not in (str, int))
            ):
                emit({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid JSON-RPC request"}})
                continue
            if message["method"] == "notifications/cancelled" and "id" not in message:
                params = message.get("params")
                cancelled_id = cancelled_request_id_from_params(params if isinstance(params, dict) else None)
                active = by_id.get(cancelled_id) if cancelled_id is not None else None
                modern = active[1] if active else bridge.protocol in MODERN_PROTOCOL_VERSIONS
                if modern:
                    # The SDK translates modern stdio abandonment into closing that
                    # HTTP POST. Modern HTTP has no client-to-server notifications.
                    if active and active[2] not in ("initialize", "server/discover"):
                        active[0].cancel()
                    continue
            routing_headers = bridge.routing_headers(message)
            # Initialization and its notification are ordered; ordinary tool calls may overlap,
            # so cancellation notifications can reach the server during an in-flight operation.
            if message["method"] == "initialize" or "id" not in message:
                await dispatch(message, routing_headers)
            else:
                if len(pending) >= MAX_IN_FLIGHT:
                    emit(
                        {
                            "jsonrpc": "2.0",
                            "id": message["id"],
                            "error": {"code": -32000, "message": "Wait for an MCP request to finish before sending another."},
                        }
                    )
                    continue
                request_id = message["id"]
                if active := by_id.get(request_id):
                    active[0].cancel()
                task = asyncio.create_task(dispatch(message, routing_headers))
                pending.add(task)
                by_id[request_id] = (
                    task,
                    routing_headers.get(MCP_PROTOCOL_VERSION_HEADER) in MODERN_PROTOCOL_VERSIONS,
                    message["method"],
                )
                task.add_done_callback(lambda task, request_id=request_id: finished(task, request_id))
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="LoonInspect's bundled MCP adapter")
    parser.add_argument("--token-fd", required=True, type=int)
    parser.add_argument("--runtime", required=True, type=Path)
    args = parser.parse_args()
    try:
        asyncio.run(serve(read_credential(args.token_fd), args.runtime))
        return 0
    except (BridgeFailure, BrokenPipeError) as error:
        print(f"LoonInspect MCP: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
