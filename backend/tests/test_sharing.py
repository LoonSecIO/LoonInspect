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
    assert result.response == {"contract": "v1", "reveal_requests": []}
    # Nothing was given up to earn that 200, and the share log must be able to say so.
    assert result.reveals_shed is False


@pytest.mark.asyncio
async def test_413_sheds_the_reveals_and_resends_the_same_snapshot() -> None:
    """The contract's 413 rule, as implemented: the reveals are shed and the snapshot
    is resent byte-for-byte. Nothing halves the snapshot — docs/data-sharing.md used
    to say it did (INSPECT-0083), and this is the shape it now describes."""
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        body = json.loads(request.content)
        seen.append(body)
        if body["reveals"]:
            return httpx.Response(413)
        return httpx.Response(200, json={})

    snapshot = {"apps": [{"title": "v1:aa", "full": "v1:bb", "count": 2}]}
    result = await post_exchange(
        {"contract": "v1", "snapshot": snapshot, "reveals": [{"title": "v1:aa"}]},
        transport=httpx.MockTransport(handler),
    )
    assert result.response == {}
    assert [bool(b["reveals"]) for b in seen] == [True, False]
    # The snapshot is untouched by the shed: only the reveals were given up.
    assert [b["snapshot"] for b in seen] == [snapshot, snapshot]


@pytest.mark.asyncio
async def test_a_shed_is_reported_to_the_caller() -> None:
    """A 200 to a reveal-less retry is byte-identical to a 200 to the whole
    submission, so the response cannot carry this — the result object does, and the
    share log row is the thing that would otherwise overclaim."""

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        return httpx.Response(413 if json.loads(request.content)["reveals"] else 200, json={})

    result = await post_exchange(
        {"contract": "v1", "reveals": [{"title": "v1:aa"}]},
        transport=httpx.MockTransport(handler),
    )
    assert result.reveals_shed is True


@pytest.mark.asyncio
async def test_a_413_against_a_reveal_less_body_is_an_ordinary_failure() -> None:
    """The container has nothing left to give up, which is why the contract requires
    the server never to 413 a reveal-less snapshot: the run burns its remaining
    attempts and the day is lost rather than degraded."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(413)

    with pytest.raises(httpx.HTTPError):
        await post_exchange(
            {"contract": "v1", "reveals": [{"title": "v1:aa"}]},
            transport=httpx.MockTransport(handler),
        )
    # Four attempts total: the shed consumes one of them rather than adding a fifth.
    assert calls == 4


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
