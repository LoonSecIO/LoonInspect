"""`send_test_event`: the status code the test button reports, and where it comes from.

The button's result used to be `(ok, error)`, and the HTTP status lived only inside
`error` as prose — "HTTP 403: …" — so on a refusal it was parseable and on success it was
gone (#305). Now it is the third field of `DeliveryOutcome`, read off the response by a
client hook so `_attempt_delivery` — the path the scheduler runs — is not changed to
carry it. These tests pin the four answers that field can give: the code of an accepted
request, the code of a refused one, null when nothing answered, and Elastic's 200 that
still refused the item.

No database: the outbound client is replaced at the same seam `test_hec_fanout` uses.
"""

from __future__ import annotations

import httpx
import pytest

from app.core import outbox
from app.core.outbox import DeliveryOutcome, send_test_event
from app.models.schema import Destination


def _webhook() -> Destination:
    return Destination(name="hook", type="generic_webhook", url="https://receiver.example/hook", auth_type="none")


def _elastic() -> Destination:
    return Destination(
        name="elastic",
        type="elastic",
        url="https://cluster.es.example:9243",
        auth_type="elastic_api_key",
        auth_secret_encrypted="aWQ6a2V5",
        elastic_index=None,
    )


@pytest.fixture
def answering(monkeypatch):
    """Installs `handler` as every outbox client's transport. The subclass forwards the
    keyword arguments, which is what lets the response hook survive the swap."""

    def install(handler):
        class _Mocked(httpx.AsyncClient):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        monkeypatch.setattr(outbox.httpx, "AsyncClient", _Mocked)

    return install


async def test_an_accepted_test_carries_the_status_the_destination_answered_with(answering) -> None:
    answering(lambda request: httpx.Response(202, json={"queued": True}))

    outcome = await send_test_event(_webhook())

    assert outcome == DeliveryOutcome(ok=True, error=None, status_code=202)


async def test_a_refusal_carries_its_status_as_a_number_and_still_as_the_sentence(answering) -> None:
    answering(lambda request: httpx.Response(403, json={"text": "Invalid token", "code": 4}))

    outcome = await send_test_event(_webhook())

    assert outcome.ok is False
    assert outcome.status_code == 403
    assert outcome.error is not None and outcome.error.startswith("HTTP 403: ")


async def test_no_response_is_a_null_status_not_a_fabricated_one(answering) -> None:
    def refuse_connection(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[Errno 61] Connection refused")

    answering(refuse_connection)

    outcome = await send_test_event(_webhook())

    assert outcome.ok is False
    assert outcome.status_code is None
    assert outcome.error is not None and "Connection refused" in outcome.error


async def test_elastic_can_answer_200_and_still_refuse_which_is_reported_as_both(answering) -> None:
    """The bulk API's trap (`_elastic_bulk_error`): HTTP 200 with the item rejected in the
    body. The verdict is a refusal and the status is 200 — both true, both reported."""
    answering(
        lambda request: httpx.Response(
            200,
            json={
                "errors": True,
                "items": [{"create": {"status": 403, "error": {"type": "security_exception", "reason": "no permission"}}}],
            },
        )
    )

    outcome = await send_test_event(_elastic())

    assert outcome.ok is False
    assert outcome.status_code == 200
    assert outcome.error is not None and outcome.error.startswith("bulk item rejected (status 403)")


async def test_the_hook_changes_nothing_about_what_is_sent(answering) -> None:
    """Observing the response must not alter the request: the test event still travels
    as the one identifiable object it always was."""
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    answering(record)
    destination = _webhook()
    destination.id = 7

    await send_test_event(destination)

    (request,) = seen
    assert request.method == "POST" and str(request.url) == "https://receiver.example/hook"
    body = request.read()
    assert b'"destinationId": 7' in body or b'"destinationId":7' in body
