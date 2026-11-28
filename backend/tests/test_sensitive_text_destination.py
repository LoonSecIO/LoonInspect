"""Sensitive text requires a verified host address and a transport pin."""

import asyncio
import socket
from ipaddress import ip_address

import pytest

from app.ai.providers import Provider
from app.core.local_inference import sensitive_text_destination

pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize(
    ("provider", "model", "base", "address", "reason"),
    [
        (Provider.apple_fm, "system", "http://[::1]:1976/v1", "::1", None),
        (Provider.apple_fm, "pcc", "http://127.0.0.1:1976/v1", None, "model_not_on_host"),
        (Provider.openai_compatible, "pcc", "http://127.0.0.1:1976/v1", None, "model_not_on_host"),
        (Provider.openai_compatible, "local", "http://[::ffff:127.0.0.1]/v1", "::ffff:127.0.0.1", None),
        (Provider.anthropic, "model", "http://127.0.0.1", None, "provider_unsupported"),
        (Provider.openai_compatible, "model", "http://10.0.0.2", None, "endpoint_not_on_host"),
        (Provider.apple_fm, "system", "https://192.0.2.1", None, "endpoint_not_on_host"),
        (Provider.openai_compatible, "model", "file:///tmp/model", None, "endpoint_not_on_host"),
    ],
)
async def test_provider_model_and_endpoint_must_all_qualify(provider, model, base, address, reason):
    result = await sensitive_text_destination(provider, base, model)
    assert (result.allowed, result.connect_ip, result.reason) == (
        address is not None,
        str(ip_address(address)) if address else None,
        reason,
    )


@pytest.mark.parametrize(
    ("host", "answers", "pin"),
    [
        ("host.docker.internal", ["192.168.65.254"], "192.168.65.254"),
        ("host.docker.internal", ["192.168.65.254", "192.0.2.1"], None),
        ("model.example", ["127.0.0.7"], "127.0.0.7"),
        ("model.example", ["127.0.0.7", "10.0.0.2"], None),
        ("model.example", [], None),
        ("model.example", None, None),
    ],
)
async def test_dns_checks_every_answer_and_returns_the_adapter_pin(monkeypatch, host, answers, pin):
    async def resolve(*args, **kwargs):
        if answers is None:
            raise socket.gaierror()
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in answers]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
    result = await sensitive_text_destination(Provider.openai_compatible, f"https://{host}/v1", "local")
    assert result.allowed == (pin is not None)
    assert result.connect_ip == pin
    assert result.reason == (None if pin else "endpoint_not_on_host")
