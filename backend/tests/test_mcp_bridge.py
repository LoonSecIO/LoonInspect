"""Exercise the packaged Mac MCP transport with fake HTTP peers, never the user's app or Keychain."""

from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import httpx

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("loon_mcp", ROOT / "macos/launcher/loon_mcp.py")
assert SPEC is not None and SPEC.loader is not None
BRIDGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BRIDGE)
INSTANCE = "d322a770-7b20-43c4-b11b-e12d3f252ec7"
TOKEN = "loon_pat_" + "a" * 32 + "_test_secret"
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}


class MCPBridgeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="looninspect-mcp-test-")
        self.addCleanup(self.temporary.cleanup)
        self.support = Path(self.temporary.name)
        run = self.support / "run"
        run.mkdir(mode=0o700)
        self.runtime = run / "mcp.json"
        self.runtime.write_text(json.dumps({"schema": 1, "port": 49152, "pid": os.getpid(), "instance_id": INSTANCE}))
        self.runtime.chmod(0o600)

    def health(self):
        return httpx.Response(200, json={"status": "ok", "instanceId": INSTANCE})

    def test_runtime_rejects_shared_file_and_directory(self):
        self.runtime.chmod(0o644)
        with self.assertRaisesRegex(BRIDGE.BridgeFailure, "not private"):
            BRIDGE.read_runtime(self.runtime)
        self.runtime.chmod(0o600)
        self.runtime.parent.chmod(0o755)
        with self.assertRaisesRegex(BRIDGE.BridgeFailure, "not private"):
            BRIDGE.read_runtime(self.runtime)

    def test_runtime_rejects_symlinks_and_bad_ports(self):
        real = self.runtime.with_name("real.json")
        self.runtime.rename(real)
        self.runtime.symlink_to(real)
        with self.assertRaises(BRIDGE.BridgeFailure):
            BRIDGE.read_runtime(self.runtime)
        self.runtime.unlink()
        real.rename(self.runtime)
        descriptor = json.loads(self.runtime.read_text())
        descriptor["port"] = 65536
        self.runtime.write_text(json.dumps(descriptor))
        with self.assertRaises(BRIDGE.BridgeFailure):
            BRIDGE.read_runtime(self.runtime)

    def test_credential_arrives_over_private_descriptor(self):
        reader, writer = os.pipe()
        os.write(writer, TOKEN.encode())
        os.close(writer)
        self.assertEqual(BRIDGE.read_credential(reader), TOKEN)
        with self.assertRaises(OSError):
            os.fstat(reader)

    async def test_verified_identity_precedes_bearer_and_negotiated_protocol_is_forwarded(self):
        requests = []

        def reply(request):
            requests.append(request)
            if request.url.path == "/api/health":
                self.assertNotIn("authorization", request.headers)
                return self.health()
            self.assertEqual(request.headers["authorization"], "Bearer " + TOKEN)
            message = json.loads(request.content)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": {"protocolVersion": "2025-11-25"}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
            bridge = BRIDGE.Bridge(TOKEN, self.runtime, client)
            await bridge.forward(INITIALIZE)
            await bridge.forward({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual([request.url.path for request in requests], ["/api/health", "/mcp", "/api/health", "/mcp"])
        self.assertNotIn("mcp-protocol-version", requests[1].headers)
        self.assertEqual(requests[3].headers["mcp-protocol-version"], "2025-11-25")

    async def test_wrong_instance_never_receives_bearer(self):
        requests = []

        def reply(request):
            requests.append(request)
            return httpx.Response(200, json={"instanceId": "another-instance"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
            with self.assertRaisesRegex(BRIDGE.BridgeFailure, "not this LoonInspect"):
                await BRIDGE.Bridge(TOKEN, self.runtime, client).forward(INITIALIZE)
        self.assertEqual(len(requests), 1)
        self.assertNotIn("authorization", requests[0].headers)

    async def test_rejected_credentials_do_not_leak_response_bodies(self):
        def reply(request):
            return self.health() if request.url.path == "/api/health" else httpx.Response(401, text=TOKEN)

        async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
            with self.assertRaises(BRIDGE.BridgeFailure) as failure:
                await BRIDGE.Bridge(TOKEN, self.runtime, client).forward(INITIALIZE)
        self.assertIn("expired or was revoked", str(failure.exception))
        self.assertNotIn(TOKEN, str(failure.exception))

    async def test_sync_timeout_is_not_retried(self):
        calls = []

        def reply(request):
            calls.append(request.url.path)
            if request.url.path == "/api/health":
                return self.health()
            raise httpx.ReadTimeout("private server detail", request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
            with self.assertRaisesRegex(BRIDGE.BridgeFailure, "outcome is unknown"):
                await BRIDGE.Bridge(TOKEN, self.runtime, client).forward(
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "trigger_sync", "arguments": {}}}
                )
        self.assertEqual(calls, ["/api/health", "/mcp"])

    async def test_notifications_accept_empty_202(self):
        def reply(request):
            return self.health() if request.url.path == "/api/health" else httpx.Response(202)

        async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
            result = await BRIDGE.Bridge(TOKEN, self.runtime, client).forward(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )
        self.assertIsNone(result)

    async def test_response_limit_and_unexpected_transport_fail_with_named_diagnostics(self):
        for response, message in (
            (httpx.Response(200, json={"text": "x" * BRIDGE.RESPONSE_LIMIT}), "exceeded its size limit"),
            (httpx.Response(200, text="data: {}\n\n", headers={"content-type": "text/event-stream"}), "unsupported MCP response"),
            (httpx.Response(302, headers={"location": "https://example.invalid/steal"}), "HTTP 302"),
        ):
            requests = []

            def reply(request, requests=requests, response=response):
                requests.append(request)
                return self.health() if request.url.path == "/api/health" else response

            async with httpx.AsyncClient(transport=httpx.MockTransport(reply), follow_redirects=False) as client:
                with self.assertRaisesRegex(BRIDGE.BridgeFailure, message):
                    await BRIDGE.Bridge(TOKEN, self.runtime, client).forward(INITIALIZE)
            self.assertEqual(len(requests), 2)

    async def test_stdio_forwards_cancellation_while_a_call_is_running_and_emits_only_json(self):
        cancelled = asyncio.Event()

        async def reply(request):
            if request.url.path == "/api/health":
                return self.health()
            message = json.loads(request.content)
            if message["method"] == "notifications/cancelled":
                cancelled.set()
                return httpx.Response(202)
            if message["method"] == "notifications/initialized":
                return httpx.Response(202)
            if message["method"] == "tools/call":
                await asyncio.wait_for(cancelled.wait(), timeout=2)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": {"protocolVersion": "2025-11-25"}})

        messages = [
            INITIALIZE,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_run"}},
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2}},
        ]
        stdin = io.TextIOWrapper(io.BytesIO(("\n".join(json.dumps(item) for item in messages) + "\n").encode()))
        stdout = io.StringIO()
        real_client = httpx.AsyncClient
        client = real_client(transport=httpx.MockTransport(reply))
        with (
            mock.patch.object(BRIDGE.sys, "stdin", stdin),
            mock.patch.object(BRIDGE.sys, "stdout", stdout),
            mock.patch.object(BRIDGE.httpx, "AsyncClient", return_value=client) as factory,
        ):
            await BRIDGE.serve(TOKEN, self.runtime)
        factory.assert_called_once_with(timeout=BRIDGE.REQUEST_SECONDS, trust_env=False, follow_redirects=False)
        replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual([item["id"] for item in replies], [1, 2])
        self.assertTrue(cancelled.is_set())
        self.assertNotIn(TOKEN, stdout.getvalue())

    async def test_modern_stdio_cancellation_aborts_post_without_forwarding_a_notification(self):
        started, aborted = threading.Event(), asyncio.Event()
        methods = []

        async def reply(request):
            if request.url.path == "/api/health":
                return self.health()
            message = json.loads(request.content)
            methods.append(message["method"])
            started.set()
            try:
                await asyncio.Future()
            finally:
                aborted.set()

        class Input(io.BytesIO):
            def readline(self, size=-1):
                line = super().readline(size)
                if b"notifications/cancelled" in line and not started.wait(timeout=2):
                    raise AssertionError("The tool HTTP request never started")
                return line

        messages = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "list_devices", "arguments": {}, "_meta": {BRIDGE.PROTOCOL_VERSION_META_KEY: "2026-07-28"}},
            },
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}},
        ]
        stdin = io.TextIOWrapper(Input(("\n".join(json.dumps(item) for item in messages) + "\n").encode()))
        stdout = io.StringIO()
        client = httpx.AsyncClient(transport=httpx.MockTransport(reply))
        with (
            mock.patch.object(BRIDGE.sys, "stdin", stdin),
            mock.patch.object(BRIDGE.sys, "stdout", stdout),
            mock.patch.object(BRIDGE.httpx, "AsyncClient", return_value=client),
        ):
            await BRIDGE.serve(TOKEN, self.runtime)
        self.assertTrue(aborted.is_set())
        self.assertEqual(methods, ["tools/call"])
        self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
