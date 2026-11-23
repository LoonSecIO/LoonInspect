"""Run both MCP protocol families through the bundled adapter and the real server transport."""

import asyncio
import importlib.util
import json
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException
from mcp.shared.inbound import MCP_METHOD_HEADER, MCP_NAME_HEADER, MCP_PROTOCOL_VERSION_HEADER, decode_header_value
from mcp_types import CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, PROTOCOL_VERSION_META_KEY, UNSUPPORTED_PROTOCOL_VERSION
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.core.auth import Principal
from app.core.permissions import Permission
from app.mcp import server

SPEC = importlib.util.spec_from_file_location(
    "loon_mcp_protocol_test", Path(__file__).resolve().parents[2] / "macos/launcher/loon_mcp.py"
)
assert SPEC is not None and SPEC.loader is not None
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)
TOKEN = "loon_pat_" + "a" * 32 + "_protocol_test"
INSTANCE = "d322a770-7b20-43c4-b11b-e12d3f252ec7"


def modern(method, request_id, *, version="2026-07-28", **params):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": {
            **params,
            "_meta": {
                PROTOCOL_VERSION_META_KEY: version,
                CLIENT_CAPABILITIES_META_KEY: {},
                CLIENT_INFO_META_KEY: {"name": "protocol-test", "version": "1"},
            },
        },
    }


def initialize(request_id=1):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "clientInfo": {"name": "protocol-test", "version": "1"}, "capabilities": {}},
    }


@pytest.fixture
async def bridge_protocol(monkeypatch, tmp_path):
    tenant_id = uuid4()
    principal = Principal(
        account=SimpleNamespace(id="owner", email="operator@example.test", tenant_id=tenant_id),
        permissions=frozenset({Permission.MCP_CONNECT, Permission.DEVICE_READ}),
        auth_method="api_token",
        token=SimpleNamespace(id="grant", name="Codex", tenant_id=tenant_id, expires_at=datetime.now(UTC) + timedelta(days=1)),
    )

    @asynccontextmanager
    async def session(_):
        yield object()

    async def resolve(db, raw):
        if raw != TOKEN:
            raise HTTPException(401, "Invalid test credential")
        return principal

    monkeypatch.setattr(server, "session_for_tenant", session)
    monkeypatch.setattr(server, "resolve_grant", resolve)
    monkeypatch.setattr(server, "disclose", AsyncMock())
    calls = []

    async def devices(request):
        calls.append(dict(request.query_params))
        assert request.headers["authorization"] == "Bearer " + TOKEN
        return JSONResponse({"items": [{"id": 4, "name": "A fleet Mac"}], "total": 1})

    async def health(request):
        assert "authorization" not in request.headers
        return JSONResponse({"status": "ok", "instanceId": INSTANCE})

    runtime = server.MCPRuntime(Starlette(routes=[Route("/api/devices", devices)]))
    app = Starlette(routes=[Route("/api/health", health), Route("/mcp", runtime, methods=["POST", "GET", "DELETE"])])
    ready, stop = asyncio.Event(), asyncio.Event()

    async def lifetime():
        async with runtime.lifespan():
            ready.set()
            await stop.wait()

    life = asyncio.create_task(lifetime())
    await ready.wait()
    tmp_path.chmod(0o700)
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    descriptor = run / "mcp.json"
    descriptor.write_text(json.dumps({"schema": 1, "port": 49152, "pid": os.getpid(), "instance_id": INSTANCE}))
    descriptor.chmod(0o600)
    sent = []
    asgi = httpx.ASGITransport(app=app)

    async def transmit(request):
        if request.url.path == "/mcp":
            sent.append((dict(request.headers), json.loads(request.content)))
        return await asgi.handle_async_request(request)

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(transmit), trust_env=False, follow_redirects=False) as client:
            yield ADAPTER.Bridge(TOKEN, descriptor, client), sent, calls
    finally:
        stop.set()
        await life


async def test_legacy_initialize_then_list_and_call_through_bridge(bridge_protocol):
    bridge, sent, calls = bridge_protocol
    assert (await bridge.forward(initialize()))["result"]["protocolVersion"] == "2025-11-25"
    listed = await bridge.forward({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert "list_devices" in {tool["name"] for tool in listed["result"]["tools"]}
    result = await bridge.forward(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_devices", "arguments": {"page_size": 1}}}
    )
    assert result["result"]["structuredContent"]["data"]["items"][0]["id"] == 4
    assert calls == [{"page": "1", "pageSize": "1", "osVersionOperator": "eq", "includeDeparted": "False"}]
    assert MCP_PROTOCOL_VERSION_HEADER not in sent[0][0]
    assert sent[1][0][MCP_PROTOCOL_VERSION_HEADER] == "2025-11-25"


@pytest.mark.parametrize("discover_first", [True, False])
async def test_modern_envelope_routes_without_initialize_and_is_preserved(bridge_protocol, discover_first):
    bridge, sent, calls = bridge_protocol
    if discover_first:
        assert "result" in await bridge.forward(modern("server/discover", 1))
    listed = await bridge.forward(modern("tools/list", 2))
    assert "list_devices" in {tool["name"] for tool in listed["result"]["tools"]}
    message = modern("tools/call", 3, name="list_devices", arguments={"page_size": 1})
    result = await bridge.forward(message)
    assert result["result"]["structuredContent"]["data"]["items"][0]["id"] == 4
    assert calls[0]["pageSize"] == "1"
    headers, body = sent[-1]
    assert headers[MCP_PROTOCOL_VERSION_HEADER] == "2026-07-28"
    assert headers[MCP_METHOD_HEADER] == "tools/call"
    assert headers[MCP_NAME_HEADER] == "list_devices"
    assert body == message


async def test_modern_negotiation_error_survives_http_status_and_legacy_fallback(bridge_protocol):
    bridge, sent, _ = bridge_protocol
    answer = await bridge.forward(modern("server/discover", 1, version="future-version"))
    assert answer["error"]["code"] == UNSUPPORTED_PROTOCOL_VERSION
    assert answer["id"] == 1
    answer = await bridge.forward(initialize(2))
    assert answer["result"]["protocolVersion"] == "2025-11-25"
    assert MCP_PROTOCOL_VERSION_HEADER not in sent[-1][0]
    assert "result" in await bridge.forward({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})


async def test_modern_name_header_uses_sdk_encoding_for_non_ascii_and_control_characters(bridge_protocol):
    bridge, sent, calls = bridge_protocol
    name = "unknown\n🍂tool"
    answer = await bridge.forward(modern("tools/call", 1, name=name, arguments={}))
    assert answer["result"]["isError"]
    assert decode_header_value(sent[-1][0][MCP_NAME_HEADER]) == name
    assert sent[-1][1]["params"]["name"] == name
    assert calls == []
