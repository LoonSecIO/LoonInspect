"""Contribution receipts (#622): opt-in, the receipt block, withdrawal words. No database."""

import json
import logging

import httpx
import pytest

from app.core import participation
from app.models.schema import DataSharingSettings

RECEIPT = "loon_rcpt_" + "r" * 43
ORIGIN = "https://service.example"


@pytest.fixture
def receipts_on(monkeypatch):
    for flag in ("contribution_receipts", "vuln_tenant_selection", "vuln_release_retention"):
        monkeypatch.setattr(participation.settings, flag, True)
    monkeypatch.setattr(participation.settings, "sharing_endpoint", ORIGIN + "/v1/exchange")


def block(**changes):
    return {"receipt": RECEIPT, "accepted_at": "2026-09-21T12:00:00Z", "updates_until": "2026-10-21T12:00:00Z", **changes}


def asked(row: DataSharingSettings) -> dict:
    body: dict = {}
    participation.opt_in(row, body)
    return body


def test_opt_in_is_the_literal_boolean_and_only_when_everything_allows_it(receipts_on, monkeypatch):
    row = DataSharingSettings(participation_status={})
    assert asked(row) == {"participation_receipt": True}

    # Nothing is asked while a withdrawal waits: the contract serializes re-consent.
    row.participation_status = {"state": "withdrawal_pending"}
    assert asked(row) == {}

    row.participation_status = {}
    monkeypatch.setattr(participation.settings, "sharing_endpoint", "http://collector.example/v1/exchange")
    assert asked(row) == {}, "a bearer is never requested over plain HTTP"

    monkeypatch.setattr(participation.settings, "sharing_endpoint", ORIGIN + "/v1/exchange")
    monkeypatch.setattr(participation.settings, "contribution_receipts", False)
    assert asked(row) == {}


def test_receipts_need_the_v2_corpus_flags(receipts_on, monkeypatch):
    monkeypatch.setattr(participation.settings, "vuln_tenant_selection", False)
    assert asked(DataSharingSettings(participation_status={})) == {}


def test_a_valid_block_is_normalized():
    parsed = participation.parse({"participation": block()})
    assert parsed["receipt"] == RECEIPT
    assert parsed["accepted_at"] == "2026-09-21T12:00:00+00:00"
    assert parsed["updates_until"] == "2026-10-21T12:00:00+00:00"
    assert participation.parse({}) is None
    assert participation.parse({"participation": None}) is None


@pytest.mark.parametrize(
    "changes",
    [
        {"receipt": "loon_key_" + "x" * 43},  # a paid credential is never a receipt
        {"receipt": RECEIPT[:-1]},
        {"receipt": None},
        {"accepted_at": "2026-09-21T12:00:00"},  # no timezone
        {"updates_until": "2026-09-20T12:00:00Z"},  # ends before it starts
    ],
)
def test_a_malformed_block_is_ignored_and_never_quoted(changes, caplog):
    with caplog.at_level(logging.WARNING, logger="app.core.participation"):
        assert participation.parse({"participation": block(**changes)}) is None
    assert "contribution receipt ignored" in caplog.text
    assert RECEIPT not in caplog.text and "loon_key_" not in caplog.text


def test_mark_withdrawal_keeps_a_live_receipt_until_it_is_withdrawn():
    live = DataSharingSettings(
        participation_receipt=RECEIPT,
        participation_status={"state": "contributing", "updates_until": "2999-01-01T00:00:00+00:00"},
    )
    participation.mark_withdrawal(live)
    assert live.participation_receipt == RECEIPT
    assert live.participation_status["state"] == "withdrawal_pending"
    assert live.participation_status["withdrawal_requested_at"]

    ended = DataSharingSettings(
        participation_receipt=RECEIPT,
        participation_status={"state": "contributing", "updates_until": "2000-01-01T00:00:00+00:00"},
    )
    participation.mark_withdrawal(ended)
    assert ended.participation_receipt is None and ended.participation_status["state"] == "ended"

    none = DataSharingSettings(participation_receipt=None, participation_status={})
    participation.mark_withdrawal(none)
    assert none.participation_status == {}


@pytest.mark.parametrize(
    "code,body,outcome",
    [
        (200, {"contract": "v2", "state": "withdrawn"}, "withdrawn"),
        (401, {"error": "Receipt unknown"}, "ended"),
        (403, {"state": "expired", "error": "ended"}, "ended"),
    ],
)
async def test_withdrawal_answers_that_settle_it(code, body, outcome):
    seen = []

    def service(request):
        seen.append(request)
        return httpx.Response(code, json=body)

    assert await participation._post_withdrawal(ORIGIN, RECEIPT, httpx.MockTransport(service)) == outcome
    (request,) = seen
    assert str(request.url) == ORIGIN + "/v2/contribution/withdraw"
    assert request.headers["authorization"] == "Bearer " + RECEIPT
    # The contract's minimal body: no inventory, no submission UUID, no paid credential.
    assert set(json.loads(request.content)) == {"contract", "client_version"}


@pytest.mark.parametrize(
    "code,body,says",
    [
        (404, {"message": "Not Found"}, "HTTP 404"),
        (403, {"message": "Missing Authentication Token"}, "HTTP 403"),
        (409, {"error": RECEIPT}, "HTTP 409"),
        (400, {"error": RECEIPT}, "HTTP 400"),
        (503, {"error": RECEIPT}, "HTTP 503"),
        (502, None, "HTTP 502"),
    ],
)
async def test_withdrawal_answers_that_do_not_settle_it_name_the_cause(code, body, says):
    reply = httpx.Response(code, json=body) if body is not None else httpx.Response(code, content=b"")
    with pytest.raises(participation.Unresolved) as error:
        await participation._post_withdrawal(ORIGIN, RECEIPT, httpx.MockTransport(lambda _: reply))
    assert says in str(error.value) and ORIGIN in str(error.value)
    assert RECEIPT not in str(error.value)


async def test_an_unreachable_service_leaves_the_withdrawal_pending():
    def refuse(request):
        raise httpx.ConnectError("name resolution failed", request=request)

    with pytest.raises(participation.Unresolved, match="Could not reach") as error:
        await participation._post_withdrawal(ORIGIN, RECEIPT, httpx.MockTransport(refuse))
    assert "name resolution" not in str(error.value)


def test_the_summary_never_carries_the_receipt_or_the_service(receipts_on):
    row = DataSharingSettings(
        participation_receipt=RECEIPT,
        participation_status={"state": "contributing", "accepted_at": "a", "updates_until": "b", "service": ORIGIN},
    )
    summary = participation.summary(row)
    assert summary["enabled"] is True and summary["receipt_present"] is True and summary["state"] == "contributing"
    assert RECEIPT not in json.dumps(summary) and "service" not in summary
    assert participation.summary(DataSharingSettings(participation_status={}))["state"] == "none"
