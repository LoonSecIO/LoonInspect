"""Synthetic upstream echoes must not turn wire credentials or fleet data into diagnostics.

No live service or database: the same delivery/adapter functions used by API and worker
callers run against MockTransport. Only status, condition and next checks may escape.
"""

import json
import socket
import ssl
from datetime import UTC, datetime

import httpx
import pytest

from app.ai.adapters import AdapterError, CompletionRequest, complete
from app.ai.providers import Wire
from app.core import sharing, submissions
from app.core.outbound_errors import CONNECTION_REFUSED, NAME_NOT_RESOLVED, TLS_NOT_VERIFIED, transport_failure
from app.core.outbox import _attempt_delivery, _elastic_bulk_error
from app.models.schema import Destination, EventOutbox, SubmissionCase

SECRET = "SYNTHETIC_OUTBOUND_SECRET_NOT_A_CREDENTIAL"
FLEET = "SYNTHETIC_PRIVATE_FLEET_VALUE"
TYPES = [
    ("generic_webhook", "bearer"),
    ("runreveal", "bearer"),
    ("splunk_hec", "splunk_hec"),
    ("elastic", "elastic_api_key"),
]


def assert_private(error: str) -> None:
    assert SECRET not in error and FLEET not in error
    assert "Check" in error


@pytest.mark.parametrize(("kind", "auth"), TYPES)
@pytest.mark.parametrize("failure", ["http", "connection", "timeout"])
async def test_delivery_errors_do_not_copy_bodies_or_transport_text(kind, auth, failure):
    destination = Destination(
        type=kind,
        name="Synthetic test",
        url="https://example.test/ingest",
        auth_type=auth,
        auth_secret_encrypted=SECRET,
    )
    event = EventOutbox(event_type="device.change", payload={"event": "device.change", "subject": FLEET})

    def answer(request):
        # Echo real request bytes, so this proves the diagnostic boundary after egress.
        assert SECRET in request.headers["authorization"]
        if failure == "connection":
            raise httpx.ConnectError(f"Connection refused at https://user:{SECRET}@example.test/{FLEET}")
        if failure == "timeout":
            raise httpx.ReadTimeout(f"Timed out: {SECRET} {FLEET}")
        return httpx.Response(400, json={"error": request.headers["authorization"], "body": FLEET})

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as client:
        ok, error = await _attempt_delivery(client, destination, event)
    assert not ok and error is not None
    assert_private(error)
    if failure == "http":
        assert "HTTP 400" in error and "body withheld" in error
    elif failure == "connection":
        assert "Connection refused" in error


def _closed_port() -> int:
    """A port on 127.0.0.1 with nothing listening: the system picks a free one, then it is let go."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


async def test_a_real_refused_connection_reads_refused():
    """No MockTransport: the async client every caller uses words a refused port "All
    connection attempts failed", and the refusal is only behind it. Through the delivery
    path a webhook destination takes, so the Destinations page reads what this asserts."""
    destination = Destination(type="generic_webhook", name="Closed port", url=f"http://127.0.0.1:{_closed_port()}/ingest")
    event = EventOutbox(event_type="device.change", payload={"event": "device.change"})
    async with httpx.AsyncClient() as client:
        ok, error = await _attempt_delivery(client, destination, event)
    assert (ok, error) == (False, CONNECTION_REFUSED)


def _raised(exc: Exception, cause: BaseException) -> Exception:
    try:
        raise exc from cause
    except Exception as caught:
        return caught


@pytest.mark.parametrize(
    ("cause", "sentence"),
    [
        pytest.param(socket.gaierror(socket.EAI_NONAME, f"Name or service not known: {SECRET}"), NAME_NOT_RESOLVED, id="dns"),
        pytest.param(
            ExceptionGroup("multiple connection attempts failed", [ConnectionRefusedError(61, SECRET), OSError(65, FLEET)]),
            CONNECTION_REFUSED,
            id="refused-on-one-of-two-addresses",
        ),
        pytest.param(ssl.SSLCertVerificationError(1, f"certificate verify failed: {SECRET}"), TLS_NOT_VERIFIED, id="tls"),
    ],
)
def test_a_connect_error_is_read_by_what_is_behind_it(cause, sentence):
    """The shape httpx, httpcore and anyio raise: the words on top name none of the three."""
    behind = _raised(OSError(f"All connection attempts failed {SECRET}"), cause)
    error = transport_failure(_raised(httpx.ConnectError(f"All connection attempts failed {FLEET}"), behind))
    assert error == sentence
    assert_private(error)


@pytest.mark.parametrize("status", [400, f"400 {SECRET} {FLEET}"])
def test_elastic_item_failure_keeps_only_a_validated_status(status):
    response = httpx.Response(
        200, json={"errors": True, "items": [{"create": {"status": status, "error": {"type": SECRET, "reason": FLEET}}}]}
    )
    error = _elastic_bulk_error(response)
    assert error is not None
    assert_private(error)
    assert "status 400" in error if isinstance(status, int) else "status unknown" in error


@pytest.mark.parametrize("wire", [Wire.openai_chat, Wire.anthropic_messages])
@pytest.mark.parametrize("failure", ["http", "connection", "bad_json"])
async def test_ai_errors_never_return_saved_keys_prompt_echoes_or_headers(wire, failure):
    def answer(request):
        assert SECRET in request.headers.get("authorization", "") + request.headers.get("x-api-key", "")
        if failure == "connection":
            raise httpx.ConnectError(f"TLS error for https://user:{SECRET}@example.test/{FLEET}")
        if failure == "bad_json":
            return httpx.Response(200, text=FLEET, headers={"content-type": SECRET})
        return httpx.Response(401, json={"error": {"message": f"{SECRET} {FLEET}"}})

    request = CompletionRequest(base_url="https://example.test/v1", model="synthetic", prompt=FLEET, api_key=SECRET)
    with pytest.raises(AdapterError) as caught:
        await complete(wire, request, transport=httpx.MockTransport(answer))
    assert_private(caught.value.message)
    assert caught.value.kind == {"http": "http_status", "connection": "unreachable", "bad_json": "malformed"}[failure]
    if failure == "http":
        assert caught.value.status == 401


def test_sharing_withholds_body_reason_phrase_redirect_and_exception_text(monkeypatch):
    monkeypatch.setattr(sharing.app_settings, "sharing_endpoint", "https://collector.example.test/exchange")
    request = httpx.Request("POST", "https://collector.example.test/exchange")
    response = httpx.Response(
        302,
        request=request,
        text=FLEET,
        headers={"location": f"https://{SECRET}.example.test/{FLEET}"},
        extensions={"reason_phrase": SECRET.encode()},
    )
    for exc in [
        httpx.HTTPStatusError(SECRET, request=request, response=response),
        httpx.ConnectError(f"Connection refused: {SECRET} {FLEET}"),
        RuntimeError(f"{SECRET} {FLEET}"),
    ]:
        assert_private(sharing._failure_sentence(exc))


async def test_submissions_do_not_log_or_display_a_reflected_case_key(monkeypatch, caplog):
    monkeypatch.setattr(submissions.settings, "intelligence_endpoint", "https://service.example.test")
    case = SubmissionCase(id="synthetic", state="pending", case_key=submissions.mint_case_key())

    def answer(request):
        echoed = json.loads(request.content)
        return httpx.Response(400, json={"error": f"{echoed['case_key']} {echoed['text']}"})

    code, _, detail = await submissions._post(case, "", {"case_key": case.case_key, "text": FLEET}, httpx.MockTransport(answer))
    submissions._refused(case, code, detail)
    assert detail and "HTTP 400" in case.last_error
    assert case.case_key not in case.last_error and FLEET not in case.last_error
    assert case.case_key not in caplog.text and FLEET not in caplog.text


async def test_submissions_quote_the_services_rule_without_the_key_or_what_was_written(monkeypatch, caplog):
    """The refusal names the rule a field broke, which only the service can say; an echo of the
    case key or the administrator's words inside it is withheld, and the rule still reads."""
    monkeypatch.setattr(submissions.settings, "intelligence_endpoint", "https://service.example.test")
    case = SubmissionCase(id="synthetic", state="pending", case_key=submissions.mint_case_key())
    body = {"case_key": case.case_key, "public_url": f"https://{FLEET}.local/", "contact": SECRET}
    rule = "public_url must name a public host: no IP address and no .local or .localhost name"

    def answer(request):
        echoed = json.loads(request.content)
        return httpx.Response(400, json={"error": f"{rule} (got {echoed['public_url']} for {echoed['case_key']}, {SECRET})"})

    code, _, said = await submissions._post(case, "", body, httpx.MockTransport(answer))
    submissions._refused(case, code, said)
    assert f'It said: "{rule} (got [withheld] for [case key withheld], [withheld])"' in case.last_error
    for private in (case.case_key, FLEET, SECRET):
        assert private not in case.last_error and private not in caplog.text


def test_submissions_keep_successful_explanations_but_remove_capabilities():
    case = SubmissionCase(state="received", case_key=submissions.mint_case_key())
    another_key = submissions.mint_case_key()
    answer = {
        "contract": "v2",
        "state": "reviewing",
        "received_at": datetime.now(UTC).isoformat(),
        "coverage": f"Coverage explanation {case.case_key}",
        "note": f"Review explanation {another_key}",
    }
    assert submissions._settled(case, answer)
    assert case.coverage == "Coverage explanation [case key withheld]"
    assert case.note == "Review explanation [case key withheld]"
