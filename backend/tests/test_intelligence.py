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
        (401, {"error": KEY}, "invalid_activation"),
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


ORIGIN = "https://service.example"
UNUSED = "The activation secret was not used."


@pytest.mark.parametrize(
    "code,body,state,says",
    [
        # A route nobody serves at that origin: the configuration, not the service.
        (404, {"message": "Not Found"}, "configuration_error", ["HTTP 404", ORIGIN, "INTELLIGENCE_ENDPOINT", UNUSED]),
        # Something else answering, such as the 2024 gateway behind the baked default.
        (403, {"message": "Missing Authentication Token"}, "configuration_error", ["HTTP 403", ORIGIN, UNUSED]),
        (403, b"<html>denied</html>", "configuration_error", ["INTELLIGENCE_ENDPOINT", UNUSED]),
        (401, {"error": KEY}, "invalid_activation", ["HTTP 401", "mistyped, already used, expired or revoked"]),
        (400, {"error": KEY}, "rejected", ["HTTP 400", "build is current", UNUSED]),
        (409, {"error": KEY}, "unavailable", ["HTTP 409", "Retry", UNUSED]),
        # The service's own 503 (preview off, store or corpus unavailable) came before redemption.
        (503, {"error": KEY}, "unavailable", ["HTTP 503", "switched off", "not an expiry", UNUSED]),
        # A gateway 5xx may follow a finished activation: never promise the secret is unused.
        (504, b"", "unavailable", ["HTTP 504", "the secret is spent"]),
    ],
)
@pytest.mark.asyncio
async def test_activation_refusals_name_their_cause(monkeypatch, code, body, state, says):
    monkeypatch.setattr(intelligence.settings, "intelligence_endpoint", ORIGIN)
    reply = httpx.Response(code, json=body) if isinstance(body, dict) else httpx.Response(code, content=body)
    with pytest.raises(intelligence.AccessFailure) as error:
        await intelligence.request("activate", activation=ACT, transport=httpx.MockTransport(lambda _: reply))
    assert error.value.state == state
    for phrase in says:
        assert phrase in str(error.value), (phrase, str(error.value))
    if code == 504:
        assert UNUSED not in str(error.value)
    assert KEY not in str(error.value) and ACT not in str(error.value) and "Missing Authentication" not in str(error.value)


@pytest.mark.parametrize(
    "code,state",
    [(401, "credential_invalid"), (404, "configuration_error"), (503, "unavailable"), (502, "unavailable")],
)
@pytest.mark.asyncio
async def test_refresh_refusals_never_mention_an_activation_secret(monkeypatch, code, state):
    monkeypatch.setattr(intelligence.settings, "intelligence_endpoint", ORIGIN)
    with pytest.raises(intelligence.AccessFailure) as error:
        await intelligence.request(
            "intelligence", credential=KEY, transport=httpx.MockTransport(lambda _: httpx.Response(code, json={}))
        )
    assert error.value.state == state
    assert "activation secret" not in str(error.value) and KEY not in str(error.value)


@pytest.mark.asyncio
async def test_unreachable_service_names_the_configured_origin(monkeypatch):
    monkeypatch.setattr(intelligence.settings, "intelligence_endpoint", ORIGIN)

    def refuse(request):
        raise httpx.ConnectError("name resolution failed", request=request)

    with pytest.raises(intelligence.AccessFailure) as error:
        await intelligence.request("intelligence", credential=KEY, transport=httpx.MockTransport(refuse))
    assert error.value.state == "unavailable"
    assert ORIGIN in str(error.value) and "INTELLIGENCE_ENDPOINT" in str(error.value)
    assert "name resolution" not in str(error.value)


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


def test_default_origin_is_production_on_its_interim_name():
    # Ruled 2026-09-25 (#622): api.loonsec.io still answers 403 from an older account, so the
    # baked default must be the service that exists. Read off the field, not the environment.
    from app.core.config import Settings

    assert Settings.model_fields["intelligence_endpoint"].default == "https://api.next.loonsec.io"
