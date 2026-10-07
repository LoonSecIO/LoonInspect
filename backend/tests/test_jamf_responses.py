"""Invalid Jamf replies and failed token refreshes have bounded, safe outcomes."""

import asyncio

import httpx
import pytest

from app.mdm.jamf.client import JamfClient
from app.mdm.jamf.errors import JamfResponseError, JamfSignInError, fetch_error
from app.mdm.jamf.sign_in import TokenState


@pytest.mark.parametrize("body", [None, [], {}, {"id": "2"}, {"general": {"id": []}}, {"id": "1", "general": []}, {"id": "1"}])
async def test_detail_must_name_the_requested_computer(body):
    client = JamfClient("https://jamf.test", "id", "secret")
    client._tokens.token = "token"
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=body))) as http:
        with pytest.raises(JamfResponseError, match="Jamf Pro returned"):
            await client.fetch_computer_detail(http, "1")


@pytest.mark.parametrize("body", [None, [], {}, {"access_token": []}, {"access_token": ""}, {"access_token": "bad\nvalue"}])
async def test_invalid_token_is_not_swallowed_by_optional_reads(body):
    requests = []

    def answer(request):
        requests.append(request.url.path)
        return httpx.Response(200, json=body)

    client = JamfClient("https://jamf.test", "id", "secret")
    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as http:
        with pytest.raises(JamfSignInError, match="invalid token response from /api/oauth/token"):
            await client.fetch_version(http)
        with pytest.raises(JamfSignInError):
            await client.fetch_inventory_collection_settings(http)
    assert requests == ["/api/oauth/token"]


async def test_credential_failure_is_shared_then_retried_after_cooldown(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("app.mdm.jamf.client.clock", lambda: now[0])
    shared = TokenState()
    clients = [JamfClient("https://jamf.test", "id", "secret") for _ in range(12)]
    for client in clients:
        client._tokens = shared
    calls = 0

    async def answer(request):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0)
        return httpx.Response(401) if calls == 1 else httpx.Response(200, json={"access_token": "ok"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as http:
        results = await asyncio.gather(*(client._authenticate(http) for client in clients), return_exceptions=True)
        assert all(isinstance(result, JamfSignInError) for result in results)
        assert calls == 1
        now[0] += 5.0
        assert await clients[0]._authenticate(http) == "ok"
        assert await clients[1]._authenticate(http) == "ok"
    assert calls == 2
    assert shared.failure_message is None


def test_empty_timeout_has_an_operator_diagnostic():
    assert "Timed out reading computer inventory" in fetch_error(httpx.ReadTimeout(""))


async def test_cancelled_webhook_sign_in_leaves_shared_sweep_free_to_try():
    connected, closed = asyncio.Event(), asyncio.Event()

    async def silent(reader, writer):
        try:
            await reader.read(4096)
            connected.set()
            await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()
            closed.set()

    server = await asyncio.start_server(silent, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    client = JamfClient(f"http://127.0.0.1:{port}", "id", "secret")
    try:
        async with server, httpx.AsyncClient(timeout=30, trust_env=False) as http:
            start = asyncio.get_running_loop().time()
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.2):
                    await client._authenticate(http)
            assert connected.is_set()
            assert asyncio.get_running_loop().time() - start < 1
            sweep = JamfClient("https://jamf.test", "id", "secret")
            sweep._tokens = client._tokens
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"access_token": "ok"}))
            ) as healthy:
                assert await sweep._authenticate(healthy) == "ok"
            await asyncio.wait_for(closed.wait(), 1)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("header", ["3600", "Wed, 01 Jan 2031 00:00:00 GMT"])
@pytest.mark.parametrize("budget", [0, 4])
async def test_webhook_deadline_never_retries_before_retry_after(header, budget):
    client = JamfClient("https://jamf.test", "id", "secret")
    client.deadline = asyncio.get_running_loop().time() + (budget or 4)
    client._tokens.token = "token"
    calls = []

    def answer(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": header})

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as http:
        with pytest.raises(httpx.HTTPStatusError) as failure:
            async with asyncio.timeout(0.1):
                await client.fetch_computer_detail(http, "1")
        assert failure.value.response.status_code == 429
    assert len(calls) == 1
    assert client.throttle.throttled_429 == 1
    assert client.throttle.backoff_ms_total == 0


def test_sweep_retry_cap_and_non_decimal_header():
    from app.mdm.jamf.client import _retry_delay

    assert _retry_delay(httpx.Response(429, headers={"Retry-After": "3600"}), 0) == 30
    response = httpx.Response(429, headers=[(b"Retry-After", b"\xb2")])
    assert 1 <= _retry_delay(response, 0) <= 1.5


@pytest.mark.parametrize("failure", [503, httpx.ConnectError(""), httpx.ReadTimeout("")])
async def test_transient_refresh_failure_does_not_refuse_a_shared_sweep(failure):
    webhook = JamfClient("https://jamf.test", "id", "secret")
    sweep = JamfClient("https://jamf.test", "id", "secret")
    sweep._tokens = webhook._tokens

    def fail(request):
        if isinstance(failure, int):
            return httpx.Response(failure)
        raise failure

    async with httpx.AsyncClient(transport=httpx.MockTransport(fail)) as http:
        with pytest.raises(JamfSignInError):
            await webhook._authenticate(http)
    assert webhook._tokens.failure_message is None
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"access_token": "ok"}))
    ) as http:
        assert await sweep._authenticate(http) == "ok"


async def test_invalid_smart_group_id_is_skipped_before_detail_request(caplog):
    client = JamfClient("https://jamf.test", "id", "secret")
    client._tokens.token = "token"
    paths = []

    def answer(request):
        paths.append(request.url.path)
        return httpx.Response(200, json={"results": [{"id": "../invalid-private-value"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as http:
        assert await client.fetch_smart_groups(http) == []
    assert len(paths) == 1 and "invalid smart-group id" in caplog.text
    assert "invalid-private-value" not in caplog.text
