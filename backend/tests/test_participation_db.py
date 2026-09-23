"""Contribution receipts (#622) under real PostgreSQL row-level security.

Pinned here: a consenting exchange asks for a receipt and stores it encrypted, never in
the share log or a log line; turning sharing off (or resetting the submission UUID)
marks it for withdrawal in the same transaction; an unacknowledged withdrawal holds the
next upload, and the upload proceeds once the service acknowledges it; consent that
ends while an exchange is in flight still gets the new receipt withdrawn; and nothing
crosses tenants. The service is an `httpx.MockTransport`; nothing reaches a network.
"""

from __future__ import annotations

import json
import logging
import os

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text

from tests.test_sharing_send_now_db import ADMIN, _signed_in, accounts  # noqa: F401
from tests.test_vuln_library import BUNDLE, CORPUS_URL, SIGNATURE
from tests.test_vuln_library_db import acting_tenant, empty, foreign_tenant  # noqa: F401
from tests.test_vuln_retention_db import retained  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ORIGIN = "https://service.example"
RECEIPTS = ["loon_rcpt_" + letter * 43 for letter in "abcdefgh"]


class Service:
    """The Support service: the exchange mints a new receipt per opted-in upload, and the
    withdrawal answers with `withdraw_status`. Records every call in order."""

    def __init__(self, withdraw_status: int = 200) -> None:
        self.withdraw_status = withdraw_status
        self.exchange_status = 200
        self.redeem_status = 200
        self.redeem_state: str | None = None
        self.calls: list[tuple[str, dict, str | None]] = []
        self.minted = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            assert str(request.url) == CORPUS_URL and "authorization" not in request.headers
            return httpx.Response(200, content=BUNDLE)
        body = json.loads(request.content)
        self.calls.append((request.url.path, body, request.headers.get("authorization")))
        if request.url.path == "/v1/exchange" and self.exchange_status != 200:
            return httpx.Response(self.exchange_status, json={"error": "collector unavailable"})
        if request.url.path == "/v2/contribution/intelligence":
            if self.redeem_status != 200:
                return httpx.Response(self.redeem_status, json={"state": self.redeem_state, "error": "no"})
            return httpx.Response(
                200,
                json={
                    "contract": "v2",
                    "state": "contributing",
                    "accepted_at": "2026-09-23T03:00:00Z",
                    "updates_until": "2999-10-23T03:00:00Z",
                    "corpus": {"url": CORPUS_URL, "signature": SIGNATURE, "asof": "2026-09-10T20:00:00Z"},
                },
            )
        if request.url.path == "/v1/exchange":
            answer: dict = {"contract": "v1"}
            if body.get("participation_receipt") is True:
                answer["participation"] = {
                    "receipt": RECEIPTS[self.minted],
                    "accepted_at": "2026-09-23T03:00:00Z",
                    "updates_until": "2999-10-23T03:00:00Z",
                }
                self.minted += 1
            return httpx.Response(200, json=answer)
        if request.url.path == "/v2/contribution/withdraw":
            if self.withdraw_status == 200:
                return httpx.Response(200, json={"contract": "v2", "state": "withdrawn"})
            return httpx.Response(self.withdraw_status, json={"error": "Participation service unavailable"})
        raise AssertionError(f"unexpected call to {request.url}")

    @property
    def uploads(self) -> list[dict]:
        return [body for path, body, _ in self.calls if path == "/v1/exchange"]

    @property
    def withdrawals(self) -> list[str | None]:
        return [bearer for path, _, bearer in self.calls if path == "/v2/contribution/withdraw"]

    @property
    def redemptions(self) -> list[tuple[dict, str | None]]:
        return [(body, bearer) for path, body, bearer in self.calls if path == "/v2/contribution/intelligence"]


@pytest_asyncio.fixture(loop_scope="session")
async def receipts(db, monkeypatch):
    """A consenting tenant with receipts on, no receipt held and no exchange rows."""
    from app.core import participation, sharing
    from app.core.sharing import get_or_create_settings
    from app.models.schema import ShareLog

    for flag in ("contribution_receipts", "vuln_tenant_selection", "vuln_release_retention", "community_sharing"):
        monkeypatch.setattr(participation.settings, flag, True)
    monkeypatch.setattr(participation.settings, "sharing_endpoint", ORIGIN + "/v1/exchange")
    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))

    async def reset(tier: str) -> None:
        await db.rollback()
        await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
        row = await get_or_create_settings(db)
        row.tier = tier
        row.pending_reveal_keys = []
        row.participation_receipt = None
        row.participation_status = {}
        await db.commit()

    original = (await get_or_create_settings(db)).tier
    await reset("keys")
    yield
    await reset(original)


async def held(db):
    from app.core.sharing import get_or_create_settings

    await db.rollback()
    return await get_or_create_settings(db)


async def test_a_consenting_exchange_earns_a_receipt_stored_encrypted_and_never_logged(db, receipts, caplog):
    from app.api.system import get_data_sharing
    from app.core.sharing import run_exchange

    service = Service()
    with caplog.at_level(logging.DEBUG):
        log = await run_exchange(db, transport=httpx.MockTransport(service))

    assert log.outcome == "sent"
    assert service.uploads[0]["participation_receipt"] is True
    row = await held(db)
    assert row.participation_receipt == RECEIPTS[0] and row.participation_status["state"] == "contributing"
    assert row.participation_status["service"] == ORIGIN
    raw = await db.scalar(text("SELECT participation_receipt FROM data_sharing_settings"))
    assert raw.startswith("k1:") and RECEIPTS[0] not in raw
    # The share log proves the request asked for a receipt, and never holds the receipt.
    assert log.payload["participation_receipt"] is True
    assert RECEIPTS[0] not in json.dumps(log.payload) and RECEIPTS[0] not in json.dumps(log.reveal_requests)
    assert RECEIPTS[0] not in caplog.text
    shown = (await get_data_sharing(db)).model_dump(mode="json", by_alias=True)
    assert shown["participation"]["receiptPresent"] is True and shown["participation"]["state"] == "contributing"
    assert RECEIPTS[0] not in json.dumps(shown)


async def test_receipts_off_sends_the_legacy_body_and_keeps_nothing(db, receipts, monkeypatch):
    from app.core import participation
    from app.core.sharing import run_exchange

    monkeypatch.setattr(participation.settings, "contribution_receipts", False)
    service = Service()
    await run_exchange(db, transport=httpx.MockTransport(service))
    assert "participation_receipt" not in service.uploads[0]
    assert (await held(db)).participation_receipt is None


async def test_turning_sharing_off_marks_the_receipt_and_the_withdrawal_clears_it(db, receipts, accounts):  # noqa: F811
    from app.core import participation
    from app.core.sharing import run_exchange

    service = Service()
    await run_exchange(db, transport=httpx.MockTransport(service))
    client = await _signed_in(*ADMIN)
    try:
        answer = await client.put("/api/system/data-sharing", json={"tier": "off"})
    finally:
        await client.aclose()
    assert answer.status_code == 200, answer.text
    assert answer.json()["participation"]["state"] == "withdrawal_pending"
    assert RECEIPTS[0] not in answer.text

    row = await held(db)
    assert participation.pending(row) and row.participation_receipt == RECEIPTS[0]
    assert await participation.withdrawal_due(db)
    assert await participation.withdraw(db, transport=httpx.MockTransport(service)) is True
    assert service.withdrawals == ["Bearer " + RECEIPTS[0]]
    row = await held(db)
    assert row.participation_receipt is None and row.participation_status["state"] == "withdrawn"
    assert row.participation_status["withdrawal_outcome"] == "withdrawn"


async def test_an_unacknowledged_withdrawal_holds_the_next_upload_until_it_is_acknowledged(db, receipts, accounts):  # noqa: F811
    from app.core import participation
    from app.core.sharing import run_exchange

    service = Service(withdraw_status=503)
    await run_exchange(db, transport=httpx.MockTransport(service))
    client = await _signed_in(*ADMIN)
    try:
        assert (await client.put("/api/system/data-sharing", json={"tier": "off"})).status_code == 200
        assert await participation.withdraw(db, transport=httpx.MockTransport(service)) is False
        row = await held(db)
        assert participation.pending(row) and "HTTP 503" in row.participation_status["error"]
        # Re-consent while the service has not acknowledged the withdrawal.
        assert (await client.put("/api/system/data-sharing", json={"tier": "keys"})).status_code == 200
    finally:
        await client.aclose()

    # The tick and Send now each run on a fresh session; this one read the row before the
    # re-consent above, so start its next transaction the way theirs start.
    await db.rollback()
    stopped = await run_exchange(db, transport=httpx.MockTransport(service))
    assert stopped.outcome == "failed" and stopped.error == participation.HELD and stopped.payload is None
    assert len(service.uploads) == 1, "nothing may upload while a withdrawal is unresolved"

    service.withdraw_status = 200
    await db.rollback()
    sent = await run_exchange(db, transport=httpx.MockTransport(service))
    assert sent.outcome == "sent" and len(service.uploads) == 2
    paths = [path for path, _, _ in service.calls]
    assert paths.index("/v1/exchange", 1) > max(i for i, p in enumerate(paths) if p == "/v2/contribution/withdraw")
    row = await held(db)
    assert row.participation_receipt == RECEIPTS[1] and row.participation_status["state"] == "contributing"


async def test_consent_ending_mid_exchange_withdraws_the_receipt_that_exchange_earned(db, receipts):
    from app.core import participation
    from app.core.database import session_for_tenant
    from app.core.sharing import run_exchange
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import DataSharingSettings

    service = Service()

    async def switched_off_during_the_upload(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/exchange":
            async with session_for_tenant(OPERATIONAL_TENANT_ID) as other:
                row = (await other.execute(select(DataSharingSettings))).scalar_one()
                row.tier = "off"
                await other.commit()
        return service(request)

    await run_exchange(db, transport=httpx.MockTransport(switched_off_during_the_upload))
    row = await held(db)
    assert row.tier == "off"
    assert row.participation_receipt == RECEIPTS[0] and participation.pending(row)


async def test_a_submission_uuid_reset_withdraws_the_old_identity(db, receipts, accounts):  # noqa: F811
    from app.core import participation
    from app.core.sharing import run_exchange

    await run_exchange(db, transport=httpx.MockTransport(Service()))
    client = await _signed_in(*ADMIN)
    try:
        assert (await client.post("/api/system/data-sharing/reset-uuid")).status_code == 200
    finally:
        await client.aclose()
    row = await held(db)
    assert participation.pending(row) and row.participation_receipt == RECEIPTS[0]


async def test_another_tenant_never_sees_the_receipt(db, receipts, foreign_tenant):  # noqa: F811
    from app.core.sharing import get_or_create_settings, run_exchange

    await run_exchange(db, transport=httpx.MockTransport(Service()))
    other = await get_or_create_settings(foreign_tenant)
    assert other.participation_receipt is None and (other.participation_status or {}).get("state") is None


@pytest_asyncio.fixture(loop_scope="session")
async def delivery(db, retained):  # noqa: F811
    """A retained-release store, left as found: grants and selections go before releases."""
    from app.models.schema import VulnCorpusAcquisition, VulnCorpusSelection

    yield
    await db.rollback()
    await db.execute(delete(VulnCorpusSelection))
    await db.execute(delete(VulnCorpusAcquisition))
    await db.commit()


async def _earned_then_failed(db, service: Service) -> None:
    """One accepted exchange that earns RECEIPTS[0], then a day whose upload fails."""
    from app.core.sharing import run_exchange

    await run_exchange(db, transport=httpx.MockTransport(service))
    service.exchange_status = 503
    await db.rollback()
    failed = await run_exchange(db, transport=httpx.MockTransport(service))
    assert failed.outcome == "failed"


async def test_a_failed_upload_is_fetched_with_the_receipt_alone(db, receipts, delivery):
    from app.core import participation
    from app.core.sharing import deliver_corpus
    from app.models.schema import VulnCorpusAcquisition

    service = Service()
    await _earned_then_failed(db, service)
    row = await held(db)
    assert row.participation_status["retry_reason"] == "upload_failed"
    assert await participation.redemption_due(db)

    pointer = await participation.redeem(db, transport=httpx.MockTransport(service))
    assert pointer is not None and pointer.signature == SIGNATURE
    ((body, bearer),) = service.redemptions
    # The contract's two fields and the receipt: no inventory, no submission UUID, no paid credential.
    assert set(body) == {"contract", "client_version"} and bearer == "Bearer " + RECEIPTS[0]
    assert await deliver_corpus(db, pointer, transport=httpx.MockTransport(service)) is True
    await participation.after_delivery(db, None)

    acquired = (await db.execute(select(VulnCorpusAcquisition))).scalars().all()
    assert [a.signature for a in acquired] == [SIGNATURE]
    row = await held(db)
    assert "retry_after" not in row.participation_status and row.participation_status["last_redeemed_at"]
    assert not await participation.redemption_due(db)


async def test_no_redemption_while_consent_is_off_a_withdrawal_waits_or_the_kill_switch_is_on(db, receipts, monkeypatch):
    from app.core import participation

    service = Service()
    await _earned_then_failed(db, service)
    assert await participation.redemption_due(db)

    monkeypatch.setattr(participation.settings, "community_sharing", False)
    assert not await participation.redemption_due(db)
    monkeypatch.setattr(participation.settings, "community_sharing", True)

    row = await participation.locked_row(db)
    participation.mark_withdrawal(row)
    await db.commit()
    assert not await participation.redemption_due(db)
    assert await participation.redeem(db, transport=httpx.MockTransport(service)) is None
    assert service.redemptions == []


async def test_a_withdrawn_generation_drops_the_receipt_and_leaves_consent_alone(db, receipts):
    from app.core import participation

    service = Service()
    await _earned_then_failed(db, service)
    service.redeem_status, service.redeem_state = 403, "withdrawn"
    assert await participation.redeem(db, transport=httpx.MockTransport(service)) is None
    row = await held(db)
    assert row.participation_receipt is None and row.participation_status["state"] == "withdrawn"
    assert row.tier == "keys"
    assert RECEIPTS[0] not in row.participation_status["error"]


async def test_an_unavailable_service_keeps_the_receipt_and_backs_off_an_hour(db, receipts):
    from datetime import UTC, datetime, timedelta

    from app.core import participation

    service = Service()
    await _earned_then_failed(db, service)
    service.redeem_status = 503
    assert await participation.redeem(db, transport=httpx.MockTransport(service)) is None
    row = await held(db)
    assert row.participation_receipt == RECEIPTS[0] and "HTTP 503" in row.participation_status["error"]
    retry = datetime.fromisoformat(row.participation_status["retry_after"])
    assert retry - datetime.now(UTC) > timedelta(minutes=55)
    assert not await participation.redemption_due(db)
