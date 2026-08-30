"""The exchange half of docs/data-sharing.md, tested without a database: response
semantics against a plain settings object, transport behavior against a mock
endpoint, and the due-ness rule as pure time arithmetic. Snapshot assembly is SQL
and is exercised against the live schema by the preview endpoint instead."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import httpx
import pytest

from app.core import sharing
from app.core.sharing import _due, apply_response, post_exchange
from app.models.schema import DataSharingSettings


def _row(tier: str = "reveal") -> DataSharingSettings:
    row = DataSharingSettings()
    row.tier = tier
    row.submission_uuid = uuid.uuid4()
    row.pending_reveal_keys = []
    return row


# --- apply_response ---------------------------------------------------------------


def test_reveal_requests_are_stored_for_the_next_exchange() -> None:
    row = _row("reveal")
    apply_response(row, {"reveal_requests": ["v1:aa", "v1:bb"]})
    assert row.pending_reveal_keys == ["v1:aa", "v1:bb"]


def test_keys_tier_never_stores_requests() -> None:
    """The tier is the client-side enforcement of "never answers reveals" — a server
    request must not be able to queue one anyway."""
    row = _row("keys")
    apply_response(row, {"reveal_requests": ["v1:aa"]})
    assert row.pending_reveal_keys == []


def test_answered_requests_are_cleared_by_an_empty_response() -> None:
    row = _row("reveal")
    row.pending_reveal_keys = ["v1:aa"]
    apply_response(row, {})
    assert row.pending_reveal_keys == []


def test_revoke_flips_the_tier_off() -> None:
    """The server-side kill switch: stop sharing until an admin re-consents."""
    row = _row("reveal")
    row.pending_reveal_keys = ["v1:aa"]
    apply_response(row, {"revoke": True, "reveal_requests": ["v1:bb"]})
    assert row.tier == "off"
    assert row.pending_reveal_keys == []


def test_unknown_fields_and_garbage_are_ignored() -> None:
    """A collector answering {} — or a future server speaking a richer v1 — is a
    valid peer; nothing in the response may be load-bearing."""
    row = _row("reveal")
    apply_response(row, {"verdicts": [{"whatever": 1}], "future_field": True, "reveal_requests": "not-a-list"})
    assert row.tier == "reveal"
    assert row.pending_reveal_keys == []


# --- post_exchange ----------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sharing, "_RETRY_DELAYS", (0, 0, 0))


@pytest.mark.asyncio
async def test_successful_exchange_returns_the_response_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"contract": "v1", "reveal_requests": []})

    result = await post_exchange({"contract": "v1"}, transport=httpx.MockTransport(handler))
    assert result == {"contract": "v1", "reveal_requests": []}


@pytest.mark.asyncio
async def test_413_drops_reveals_and_retries_once() -> None:
    """The contract's halving rule: too large → resend keys-only."""
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        body = json.loads(request.content)
        seen.append(body)
        if body["reveals"]:
            return httpx.Response(413)
        return httpx.Response(200, json={})

    result = await post_exchange(
        {"contract": "v1", "reveals": [{"title": "v1:aa"}]},
        transport=httpx.MockTransport(handler),
    )
    assert result == {}
    assert [bool(b["reveals"]) for b in seen] == [True, False]


@pytest.mark.asyncio
async def test_persistent_failure_raises_after_the_delays() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    with pytest.raises(httpx.HTTPError):
        await post_exchange({"contract": "v1"}, transport=httpx.MockTransport(handler))
    assert calls == 4  # the initial attempt plus one per delay


@pytest.mark.asyncio
async def test_a_200_that_is_not_json_is_a_failed_attempt_not_an_escape() -> None:
    """A captive portal or a misconfigured CDN answering 200 text/html. The decode
    error is a ValueError, not an httpx.HTTPError, so it used to sail past the retry
    loop and out of run_exchange before the share-log row was written. It is a
    failed attempt like any other now: retried, then raised to the caller to log."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, text="<html>Sign in to the guest network</html>")

    with pytest.raises(ValueError):
        await post_exchange({"contract": "v1"}, transport=httpx.MockTransport(handler))
    assert calls == 4


# --- due-ness ---------------------------------------------------------------------


def _at(hour: int, minute: int) -> datetime:
    return datetime(2026, 8, 20, hour, minute, tzinfo=timezone.utc)


def test_not_due_before_the_jittered_minute() -> None:
    assert _due(_at(9, 0), None, minute_of_day=10 * 60) is False


def test_due_at_first_tick_past_the_slot_even_hours_late() -> None:
    """A container that was down at its slot sends at the first tick after it."""
    assert _due(_at(23, 55), None, minute_of_day=10 * 60) is True


def test_one_attempt_per_day_regardless_of_outcome() -> None:
    assert _due(_at(14, 0), _at(10, 5), minute_of_day=10 * 60) is False


def test_yesterdays_attempt_does_not_satisfy_today() -> None:
    yesterday = datetime(2026, 8, 19, 10, 5, tzinfo=timezone.utc)
    assert _due(_at(10, 30), yesterday, minute_of_day=10 * 60) is True
