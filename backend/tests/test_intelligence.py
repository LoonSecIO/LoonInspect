"""Paid wire contract, response trust boundary and secret-free failures (#622)."""

import json

import httpx
import pytest

from app.core import intelligence

KEY = "loon_key_" + "x" * 43
ACT = "loon_act_" + "y" * 43
END = "2030-01-01T00:00:00Z"


def answer(**extra):
    return {"contract": "v2", "state": "paid", "updates_until": END, **extra}


@pytest.mark.asyncio
async def test_activation_sends_no_identity_or_inventory(monkeypatch):
    monkeypatch.setattr(intelligence.settings, "intelligence_endpoint", "https://service.example")

    def handler(request):
        assert str(request.url) == "https://service.example/v2/activate"
        assert "authorization" not in request.headers
        assert set(json.loads(request.content)) == {"contract", "client_version", "activation_secret"}
        return httpx.Response(200, json=answer(credential=KEY))

    assert (await intelligence.request("activate", activation=ACT, transport=httpx.MockTransport(handler)))["credential"] == KEY


@pytest.mark.asyncio
async def test_refresh_has_only_reviewed_fields_and_never_follows_redirects(monkeypatch):
    monkeypatch.setattr(intelligence.settings, "intelligence_endpoint", "https://service.example")
    calls = []

    def handler(request):
        calls.append(request)
        assert request.headers["authorization"] == "Bearer " + KEY
        assert set(json.loads(request.content)) == {"contract", "client_version", "channel"}
        return httpx.Response(307, headers={"location": "https://other.example/secret"}, text=KEY)

    with pytest.raises(intelligence.AccessFailure) as error:
        await intelligence.request("intelligence", credential=KEY, transport=httpx.MockTransport(handler))
    assert len(calls) == 1 and KEY not in str(error.value)


@pytest.mark.parametrize(
    "code,body,expected",
    [
        (401, {"error": KEY}, "credential_invalid"),
        (403, {"state": "expired", "error": KEY}, "expired"),
        (403, {"state": "revoked"}, "revoked"),
        (403, {"state": KEY}, "invalid_response"),
        (503, {"error": KEY}, "unavailable"),
        (200, {"contract": "v2", "state": "paid", "updates_until": "no timezone"}, "invalid_response"),
        (200, answer(credential="wrong"), "invalid_response"),
    ],
)
@pytest.mark.asyncio
async def test_failure_text_never_echoes_service_secrets(code, body, expected):
    with pytest.raises(intelligence.AccessFailure) as error:
        await intelligence.request(
            "activate", activation=ACT, transport=httpx.MockTransport(lambda _: httpx.Response(code, json=body))
        )
    assert error.value.state == expected
    assert KEY not in str(error.value) and ACT not in str(error.value)


@pytest.mark.parametrize(
    "origin",
    [
        "http://service.example",
        "https://a:b@service.example",
        "https://service.example/path",
        "https://service.example?secret=abc",
    ],
)
def test_origin_rejects_unsafe_configuration(monkeypatch, origin):
    monkeypatch.setattr(intelligence.settings, "intelligence_endpoint", origin)
    with pytest.raises(intelligence.AccessFailure):
        intelligence.endpoint("activate")


@pytest.mark.asyncio
async def test_response_is_bounded():
    with pytest.raises(intelligence.AccessFailure, match="invalid reply"):
        await intelligence.request(
            "activate", activation=ACT, transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"x" * 65537))
        )


@pytest.mark.asyncio
async def test_failed_corpus_download_does_not_expose_capability():
    from app.core.vuln_library import CorpusRefused, download_bundle

    url = "https://corpus.example.com/epoch.tar.gz?secret=must-not-appear"
    with pytest.raises(CorpusRefused) as failure:
        await download_bundle(url, transport=httpx.MockTransport(lambda _: httpx.Response(403)))
    assert "must-not-appear" not in str(failure.value)
    assert "HTTP 403" in str(failure.value)
