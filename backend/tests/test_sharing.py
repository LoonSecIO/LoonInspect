"""The exchange half of docs/data-sharing.md, tested without a database: response
semantics against a plain settings object, transport behavior against a mock
endpoint, and the due-ness rule as pure time arithmetic. Snapshot assembly is SQL and is
exercised against the live schema by the preview endpoint instead — except for the shape
of the rows the builder wraps around those query results, which is contract and is pinned
here (#231) against a stub session."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

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


# --- the consent default ----------------------------------------------------------
#
# The database-backed half of this property — what a real INITIAL_ADMIN_* install ends
# up sharing, and what the wizard records — is in test_sharing_consent_db.py. These two
# need no database and so run in every lane, which is the point: they are the cheapest
# possible tripwire on a default that must never drift back.


def test_an_unanswered_install_defaults_to_off() -> None:
    """The regression guard. Sharing must be something an operator turned on, so the
    tier a row is born with is `off` — an absent or freshly-materialized row is an
    install nobody has answered for, and this used to be `reveal`, the most permissive
    tier. Anything that flips this literal back re-opens the finding: bootstrap through
    INITIAL_ADMIN_* never renders the wizard, so on that path a permissive default is
    egress of employee device inventory that nobody was ever asked about.
    """
    assert DataSharingSettings.__table__.c.tier.default.arg == "off"


def test_a_setup_request_that_omits_the_choice_does_not_share() -> None:
    """The wire's own fail-safe. An older UI build, or somebody's script written
    against last month's API, sends no sharing field at all; the answer to a question
    that was never asked is no."""
    from app.schemas.auth import SetupRequest

    payload = SetupRequest(
        claim_token="t",
        email="admin@example.com",
        display_name="Admin",
        password="correct-horse-battery",
    )
    assert payload.share_community_data is False


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
    return datetime(2026, 8, 20, hour, minute, tzinfo=UTC)


def test_not_due_before_the_jittered_minute() -> None:
    assert _due(_at(9, 0), None, minute_of_day=10 * 60) is False


def test_due_at_first_tick_past_the_slot_even_hours_late() -> None:
    """A container that was down at its slot sends at the first tick after it."""
    assert _due(_at(23, 55), None, minute_of_day=10 * 60) is True


def test_one_attempt_per_day_regardless_of_outcome() -> None:
    assert _due(_at(14, 0), _at(10, 5), minute_of_day=10 * 60) is False


def test_yesterdays_attempt_does_not_satisfy_today() -> None:
    yesterday = datetime(2026, 8, 19, 10, 5, tzinfo=UTC)
    assert _due(_at(10, 30), yesterday, minute_of_day=10 * 60) is True


def test_a_send_now_before_the_slot_leaves_the_slot_owed() -> None:
    """Send now (#408) does not move the schedule. Its row counts like any attempt, so one
    sent at 09:00 for a 10:00 slot does not stand in for the scheduled exchange."""
    assert _due(_at(10, 5), _at(9, 0), minute_of_day=10 * 60) is True


def test_a_send_now_after_the_slot_is_that_days_exchange() -> None:
    assert _due(_at(14, 0), _at(11, 30), minute_of_day=10 * 60) is False


# --- the failure sentence (#408) --------------------------------------------------
#
# Send now puts a failed row's `error` on the page, so it is written for an operator, not
# as httpx's own text. Each shape below is produced the way the exchange produces it —
# post_exchange against a mock endpoint, every retry spent — rather than constructed by
# hand, so a change in what httpx raises shows up here first.

ENDPOINT = "https://collector.example.test/v1/exchange"


@pytest.fixture
def endpoint(monkeypatch: pytest.MonkeyPatch) -> str:
    from app.core.config import settings as app_settings

    monkeypatch.setattr(app_settings, "sharing_endpoint", ENDPOINT)
    return ENDPOINT


async def _sentence_for(handler) -> str:
    with pytest.raises((httpx.HTTPError, ValueError)) as caught:
        await post_exchange({"contract": "v1"}, transport=httpx.MockTransport(handler))
    return sharing._failure_sentence(caught.value)


@pytest.mark.asyncio
async def test_a_refusal_names_the_host_the_status_and_the_collectors_reason(endpoint) -> None:
    """The shape a default endpoint with no collector behind it answers today: API
    Gateway's 403 for a route that does not exist."""

    def handler(request: httpx.Request) -> httpx.Response:
        # The bytes API Gateway sends, verbatim, rather than json= and whatever
        # separators this httpx happens to encode with.
        return httpx.Response(
            403,
            content=b'{"message":"Missing Authentication Token"}',
            headers={"Content-Type": "application/json"},
        )

    assert await _sentence_for(handler) == (
        'The collector at collector.example.test answered 403 Forbidden: {"message":"Missing Authentication Token"}. '
        "Tried 4 times."
    )


@pytest.mark.asyncio
async def test_a_long_html_error_page_is_one_bounded_line(endpoint) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="<html>\n  <body>\n" + "Bad gateway. " * 400 + "</body></html>")

    sentence = await _sentence_for(handler)
    assert sentence.startswith("The collector at collector.example.test answered 502 Bad Gateway: <html> <body> Bad")
    assert "\n" not in sentence
    assert len(sentence) < 300


@pytest.mark.asyncio
async def test_a_redirect_names_where_to_by_host_and_nothing_else(endpoint) -> None:
    """A captive portal's redirect: the host says who is answering; its query string may
    carry a session and has no business in the share log."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://portal.example.net/login?session=s3cr3t"})

    sentence = await _sentence_for(handler)
    assert sentence == (
        "The collector at collector.example.test answered 302 Found, redirecting to portal.example.net. Tried 4 times."
    )
    assert "s3cr3t" not in sentence


@pytest.mark.asyncio
async def test_no_answer_says_how_long_it_waited(endpoint) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    assert await _sentence_for(handler) == "No answer from collector.example.test within 10 seconds. Tried 4 times."


@pytest.mark.asyncio
async def test_an_unreachable_host_keeps_the_reason_httpx_gave(endpoint) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[Errno -2] Name or service not known", request=request)

    assert await _sentence_for(handler) == (
        "Could not connect to collector.example.test: [Errno -2] Name or service not known. Tried 4 times."
    )


@pytest.mark.asyncio
async def test_a_200_that_is_not_json_says_something_else_answered(endpoint) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>Sign in to the guest network</html>")

    sentence = await _sentence_for(handler)
    assert sentence.startswith("collector.example.test answered 200 with a body that is not JSON")
    assert "captive portal" in sentence


def test_every_failure_shape_has_its_line_in_the_step_through(endpoint) -> None:
    """`docs/diagnosability.md` rule 4: the words ship with their step-through. Each shape
    the sentence can take is looked for, by its opening words, in troubleshooting.md §5
    step 6 — so rewording the code without the document fails here, and so does the
    reverse."""
    from pathlib import Path

    document = (Path(__file__).resolve().parents[2] / "docs" / "troubleshooting.md").read_text()
    marker = "6. **Settings › Data Sharing says the last exchange *failed*.**"
    assert marker in document
    step = document.split(marker, 1)[1].split("\n**H.**", 1)[0]

    request = httpx.Request("POST", ENDPOINT)
    for exc, words in (
        (httpx.HTTPStatusError("refused", request=request, response=httpx.Response(403, request=request)), "The collector at"),
        (httpx.ReadTimeout("timed out", request=request), "No answer from"),
        (httpx.ConnectError("[Errno -2] Name or service not known", request=request), "Could not connect to"),
        (ValueError("Expecting value"), "answered 200 with a body that is not JSON"),
    ):
        sentence = sharing._failure_sentence(exc)
        assert words in sentence, f"the sentence no longer says {words!r}: {sentence}"
        assert words in step, f"troubleshooting.md §5 step 6 has no line for: {sentence}"


# --- the exchange lock (#408) -----------------------------------------------------


def test_one_lock_per_tenant_shared_by_every_caller() -> None:
    """The tick and Send now must reach the same lock for a tenant, and different
    tenants must never share one — one tenant's slow collector would stall the rest."""
    first, second = uuid.uuid4(), uuid.uuid4()
    assert sharing.exchange_lock(first) is sharing.exchange_lock(uuid.UUID(str(first)))
    assert sharing.exchange_lock(first) is not sharing.exchange_lock(second)


# --- the snapshot names its platform (#231) ---------------------------------------
#
# Assembly is SQL, but the property under test is not: it is what the builder puts in the
# dicts around the query results. A stub session that answers the two aggregates with fixed
# rows pins that down in the lane that runs everywhere, which is the point — this key can
# only be added before the first exchange, and a tripwire that needs a Postgres is a
# tripwire that is not watching on the day someone deletes the key.


class _StubResult:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def all(self) -> list:
        return self._rows


class _StubSession:
    """Answers `build_exchange_request`'s two aggregates in order: apps, then os."""

    def __init__(self, app_rows: list, os_rows: list) -> None:
        self._results = [app_rows, os_rows]

    async def execute(self, _statement):
        return _StubResult(self._results.pop(0))


def _app_row(title: str, full: str, bundle_id: str, count: int) -> SimpleNamespace:
    # `platform` is what the join on `devices.platform` hands the builder per row (#233).
    return SimpleNamespace(key_title=title, key_full=full, bundle_id=bundle_id, count=count, platform="macos")


async def _snapshot(*, exclude_globs: list[str] | None = None) -> dict:
    row = _row("reveal")
    row.exclude_globs = exclude_globs or []
    db = _StubSession(
        [
            _app_row("v1:title-chrome", "v1:full-chrome", "com.google.Chrome", 412),
            _app_row("v1:title-tool", "v1:full-tool", "com.vendor.tool", 31),
            _app_row("v1:title-acme", "v1:full-acme", "com.acme.payroll", 7),
        ],
        [
            SimpleNamespace(platform="macos", os_version="14.6.1", count=380),
            SimpleNamespace(platform="macos", os_version="15.0", count=12),
        ],
    )
    return await sharing.build_exchange_request(db, row)


@pytest.mark.asyncio
async def test_every_app_row_names_the_platform_it_was_counted_on() -> None:
    """The cloud corpus is partitioned by platform (R4), so a row that does not carry one
    cannot be routed — and rows already summed cloud-side can never be told afterwards
    which fleet they came from. Every row, not the envelope: one container will read
    computers and mobile from one connection."""
    apps = (await _snapshot())["snapshot"]["apps"]
    assert apps, "the fixture must produce rows, or this asserts nothing"
    assert all(app["platform"] == "macos" for app in apps), apps
    # The rest of the row is untouched — this is an additive key, not a reshape.
    assert apps[0] == {
        "title": "v1:title-chrome",
        "full": "v1:full-chrome",
        "count": 412,
        "platform": "macos",
    }


@pytest.mark.asyncio
async def test_an_excluded_app_is_still_excluded() -> None:
    """The added key must not have moved the exclude filter's ground: the operator's
    globs run on the bundle id, which no longer sits beside it in the emitted dict."""
    apps = (await _snapshot(exclude_globs=["com.acme.*"]))["snapshot"]["apps"]
    assert [app["title"] for app in apps] == ["v1:title-chrome", "v1:title-tool"]


@pytest.mark.asyncio
async def test_os_rows_state_the_platform_they_already_hash() -> None:
    """`os_key` hashes the platform, but a sha256 is not a routing token — a reader would
    have to guess-and-check the whole OS vocabulary to partition on it. Both rows come from
    the one constant, so a submission can never claim two platforms."""
    os_rows = (await _snapshot())["snapshot"]["os"]
    assert all(row["platform"] == "macos" for row in os_rows), os_rows
    assert [row["count"] for row in os_rows] == [380, 12]


@pytest.mark.asyncio
async def test_the_platform_rides_the_rows_and_not_the_envelope() -> None:
    """The recorded decision on #231. A submission-level field is cheaper today and wrong
    the day one container sweeps both platforms — and a field in a frozen v1 contract has
    to be deprecated rather than extended. Guarding the negative is the only way that
    decision survives the next person who finds the per-row key repetitive."""
    body = await _snapshot()
    assert "platform" not in body
    assert "platform" not in body["snapshot"]


def test_replacing_the_os_literal_did_not_move_a_hash() -> None:
    """#231 changes what the submission *says*, never what it hashes. The platform the os
    key hashes is read off `devices.platform` per row since #233 — the constant that stood
    in until then was deleted, as its comment promised — so the value every existing row
    carries is asserted against the published vector from docs/data-sharing.md, not
    against a literal that would only prove the two agree with each other."""
    from app.core.content_keys import os_key
    from app.models.schema import Device

    assert not hasattr(sharing, "SNAPSHOT_PLATFORM"), "deleted with #233, not renamed"
    assert Device.__table__.c.platform.server_default.arg == "macos"
    assert os_key("macos", "14.6.1", "23G93") == "v1:f74565fbdda8b8036799e1e3a67b22ee909acac8840f2a6ae040b3d5a4e18867"
