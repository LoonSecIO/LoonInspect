"""Send now (#408): POST /api/system/data-sharing/send through the whole door.

The route runs the exchange the tick runs, so what is pinned here is what the button adds
around it: the row it answers with is the row the run wrote, byte for byte what the
collector received; a failure is still an answer and says why in words; the three
refusals write nothing and dial nothing; a read-only role cannot send; the lock keeps the
button and the tick from overlapping for one tenant, without either waiting on the other;
and the download says which kind of send each row was.

The collector is stood in for by an `httpx.MockTransport` on
`app.api.system.transport_override`, and nothing in this file reaches a real network.
Needs a real Postgres: the consent row and the share log are tenant-scoped rows.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

ADMIN = ("send-now-admin@example.com", "send-now-admin-password")
AUDITOR = ("send-now-auditor@example.com", "send-now-auditor-password")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def accounts(tenant_ready) -> None:
    from app.core.bootstrap import create_account
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID
    from app.models.schema import Account

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as db:
        for (email, password), role in ((ADMIN, "admin"), (AUDITOR, "auditor")):
            if (await db.execute(select(Account).where(Account.email == email))).scalars().first() is None:
                await create_account(db, email=email, display_name=role, password=password, roles=(role,))
        await db.commit()


async def _signed_in(email: str, password: str) -> httpx.AsyncClient:
    from app.main import app

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://send-now.example.com")
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, f"login failed: {response.status_code} {response.text}"
    client.headers["X-CSRF-Token"] = client.cookies.get("loon_csrf", "")
    return client


@pytest_asyncio.fixture(loop_scope="session")
async def client(accounts):
    signed_in = await _signed_in(*ADMIN)
    try:
        yield signed_in
    finally:
        await signed_in.aclose()


async def _exchange_rows(db) -> list:
    from app.models.schema import ShareLog

    await db.rollback()
    return (await db.execute(select(ShareLog).where(ShareLog.tier != "ai").order_by(ShareLog.occurred_at))).scalars().all()


@pytest_asyncio.fixture(loop_scope="session")
async def clean(db, monkeypatch):
    """A consenting tenant with no exchange rows, no backoff, and the override lifted —
    then the tier this suite found, put back, and its rows removed. Other suites share
    the tenant; the AI rows that share the log are left alone."""
    from app.core import sharing
    from app.core.config import settings as app_settings
    from app.core.sharing import get_or_create_settings
    from app.models.schema import ShareLog

    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(app_settings, "community_sharing", True)

    await db.rollback()
    row = await get_or_create_settings(db)
    original = row.tier
    await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
    row.tier = "reveal"
    row.pending_reveal_keys = []
    await db.commit()
    yield
    await db.rollback()
    await db.execute(delete(ShareLog).where(ShareLog.tier != "ai"))
    row = await get_or_create_settings(db)
    row.tier = original
    await db.commit()


class Collector:
    """The far end: records every body it was sent, and answers with `status`."""

    def __init__(self, status: int = 200, body: bytes = b'{"contract":"v1"}') -> None:
        self.status = status
        self.body = body
        self.received: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.received.append(json.loads(request.content))
        return httpx.Response(self.status, content=self.body, headers={"Content-Type": "application/json"})


def _never_dials(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"a refused send must not dial anything; it dialled {request.url}")


def _audit_events(action: str) -> list[dict]:
    from app.core.audit import audit_path_for
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    path = audit_path_for(str(OPERATIONAL_TENANT_ID))
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return [row for row in rows if row.get("action") == action]


async def test_send_now_answers_with_the_row_it_wrote_and_the_row_is_what_left(client, db, clean, monkeypatch) -> None:
    from app.core.config import settings as app_settings

    collector = Collector()
    monkeypatch.setattr("app.api.system.transport_override", httpx.MockTransport(collector))
    audited_before = len(_audit_events("sharing.exchange.sent"))

    response = await client.post("/api/system/data-sharing/send")

    assert response.status_code == 200, response.text
    exchange = response.json()["exchange"]
    assert exchange["outcome"] == "sent"
    assert exchange["trigger"] == "manual"
    assert exchange["endpoint"] == app_settings.sharing_endpoint
    assert exchange["error"] is None
    assert exchange["revealsShed"] is False
    # What the box shows is what the collector received: one body, and the same one.
    assert collector.received == [exchange["payload"]]
    assert exchange["payload"]["contract"] == "v1"

    settings_out = response.json()["settings"]
    assert settings_out["lastExchangeOutcome"] == "sent"
    assert settings_out["lastExchangeError"] is None
    assert datetime.fromisoformat(settings_out["lastExchangeAt"]) == datetime.fromisoformat(exchange["occurredAt"])
    assert exchange["payload"]["submission"] == settings_out["submissionUuid"]

    (row,) = await _exchange_rows(db)
    assert (row.trigger, row.outcome) == ("manual", "sent")

    audited = _audit_events("sharing.exchange.sent")
    assert len(audited) == audited_before + 1
    assert audited[-1]["outcome"] == "success"
    assert audited[-1]["metadata"]["exchange_outcome"] == "sent"


async def test_a_failed_send_is_still_an_answer_and_says_why(client, db, clean, monkeypatch) -> None:
    """The default endpoint with no collector behind it answers API Gateway's 403 today.
    That is a 200 from Send now — the row is the answer — whose error is a sentence the
    page can show, and the settings the page re-reads carry the same sentence."""
    collector = Collector(status=403, body=b'{"message":"Missing Authentication Token"}')
    monkeypatch.setattr("app.api.system.transport_override", httpx.MockTransport(collector))

    response = await client.post("/api/system/data-sharing/send")

    assert response.status_code == 200, response.text
    exchange = response.json()["exchange"]
    assert exchange["outcome"] == "failed"
    assert "answered 403 Forbidden" in exchange["error"]
    assert "Missing Authentication Token" in exchange["error"]
    assert exchange["error"].endswith("Tried 4 times.")
    assert len(collector.received) == 4
    assert response.json()["settings"]["lastExchangeError"] == exchange["error"]

    audited = _audit_events("sharing.exchange.sent")
    assert audited[-1]["outcome"] == "failure"


async def test_an_off_tier_is_refused_and_nothing_is_written(client, db, clean, monkeypatch) -> None:
    from app.core.sharing import REFUSED_OFF, get_or_create_settings

    row = await get_or_create_settings(db)
    row.tier = "off"
    await db.commit()
    monkeypatch.setattr("app.api.system.transport_override", httpx.MockTransport(_never_dials))

    response = await client.post("/api/system/data-sharing/send")

    assert response.status_code == 409
    assert response.json()["detail"] == REFUSED_OFF
    assert await _exchange_rows(db) == []


async def test_the_override_refuses_without_writing_a_skipped_row(client, db, clean, monkeypatch) -> None:
    """Under COMMUNITY_SHARING=false nothing is attempted, so nothing is logged: the daily
    `skipped_env` row stays that day's record, and a click does not add a second."""
    from app.core.config import settings as app_settings
    from app.core.sharing import REFUSED_ENV

    monkeypatch.setattr(app_settings, "community_sharing", False)
    monkeypatch.setattr("app.api.system.transport_override", httpx.MockTransport(_never_dials))

    response = await client.post("/api/system/data-sharing/send")

    assert response.status_code == 409
    assert response.json()["detail"] == REFUSED_ENV
    assert await _exchange_rows(db) == []


async def test_a_send_while_one_is_running_is_refused_not_queued(client, db, clean, monkeypatch) -> None:
    from app.core.sharing import REFUSED_BUSY, exchange_lock
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    monkeypatch.setattr("app.api.system.transport_override", httpx.MockTransport(_never_dials))

    async with exchange_lock(OPERATIONAL_TENANT_ID):
        response = await client.post("/api/system/data-sharing/send")

    assert response.status_code == 409
    assert response.json()["detail"] == REFUSED_BUSY
    assert await _exchange_rows(db) == []


async def test_a_read_only_role_sees_what_would_be_sent_but_cannot_send(accounts, db, clean, monkeypatch) -> None:
    monkeypatch.setattr("app.api.system.transport_override", httpx.MockTransport(_never_dials))
    auditor = await _signed_in(*AUDITOR)
    try:
        assert (await auditor.get("/api/system/data-sharing/preview")).status_code == 200
        assert (await auditor.post("/api/system/data-sharing/send")).status_code == 403
    finally:
        await auditor.aclose()
    assert await _exchange_rows(db) == []


async def test_the_tick_skips_a_tenant_whose_send_is_in_flight_and_runs_once_it_lands(db, clean, monkeypatch) -> None:
    """Neither caller waits on the lock. While it is held the tick passes the tenant over
    — the send in flight writes the row that decides the day — and the next tick, with
    the lock free and the slot owed, runs the scheduled exchange."""
    from app import main
    from app.core import sharing
    from app.core.sharing import ExchangeResult, exchange_lock
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    # Only this tenant, and a midnight slot so "due" is decided by the log alone.
    async def only_this_tenant() -> list:
        return [OPERATIONAL_TENANT_ID]

    monkeypatch.setattr(main, "operational_tenant_ids", only_this_tenant)
    monkeypatch.setattr(sharing, "_jitter_minute_of_day", lambda _row: 0)
    posted: list[dict] = []

    async def fake_post(body: dict, *, transport=None) -> ExchangeResult:
        posted.append(body)
        return ExchangeResult({"contract": "v1"})

    monkeypatch.setattr(sharing, "post_exchange", fake_post)

    async with exchange_lock(OPERATIONAL_TENANT_ID):
        await main.sharing_exchange_tick()
    assert posted == []
    assert await _exchange_rows(db) == []

    await main.sharing_exchange_tick()
    assert len(posted) == 1
    (row,) = await _exchange_rows(db)
    assert (row.trigger, row.outcome) == ("scheduled", "sent")


async def test_the_download_says_which_kind_of_send_each_row_was(client, db, clean, monkeypatch) -> None:
    from app.core.sharing import run_exchange

    monkeypatch.setattr("app.api.system.transport_override", httpx.MockTransport(Collector()))
    await run_exchange(db, transport=httpx.MockTransport(Collector()))
    assert (await client.post("/api/system/data-sharing/send")).status_code == 200

    response = await client.get("/api/system/share-log")
    assert response.status_code == 200, response.text
    lines = [json.loads(line) for line in response.text.splitlines()]
    assert [line["trigger"] for line in lines if line["tier"] != "ai"] == ["scheduled", "manual"]
