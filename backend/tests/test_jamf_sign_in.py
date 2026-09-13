"""What a connection keeps of its Jamf Pro sign-in between runs (#412), in the pure lane.

Three modes, and the property each one is worth: No cache signs in per run, as before;
Cache and hold shares one token (and one pooled connection) across runs while it lives;
Perpetual cache keeps one ready with no traffic at all. Around them, the guarantees that
make sharing safe: a sign-in built from settings that have since changed is retired, not
reused; each run keeps its own throttle counters; a pool is closed only when its last run
lets go; and a pooled connection Jamf closed costs one retry, not a failure.

Every request goes to `tests.jamf_fake.FakeJamf`, which records them, so "one token
request" is counted rather than inferred. The perpetual renewal runs on a fake clock
through the module's own seams (`sign_in._sleep`, `sign_in._now`), so a day of renewals
takes a moment.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from types import SimpleNamespace

import httpx
import pytest

from app.mdm.jamf import sign_in
from app.mdm.jamf.client import JamfClient
from app.mdm.jamf.sign_in import (
    DEFAULT_TOKEN_CACHE_MODE,
    MODE_CACHE_AND_HOLD,
    MODE_NO_CACHE,
    MODE_PERPETUAL,
    RENEWAL_BACKOFF_START_SECONDS,
    HeldSignIn,
    SignIns,
    clock,
    stamp,
)
from tests.jamf_fake import HOST, FakeJamf

TENANT = uuid.UUID("00000000-0000-0000-0000-0000000004a2")
CREDENTIALS = SimpleNamespace(client_id="client", client_secret="secret")
VERSION = "/api/v1/jamf-pro-version"
TOKEN = "POST /api/oauth/token"


def _connection(mode: str = MODE_CACHE_AND_HOLD, **overrides) -> SimpleNamespace:
    fields = {
        "tenant_id": TENANT,
        "id": 7,
        "token_cache_mode": mode,
        "base_url": HOST,
        "user_agent_override": None,
    }
    return SimpleNamespace(**(fields | overrides))


def _build(held: HeldSignIn | None = None) -> JamfClient:
    return JamfClient(base_url=HOST, client_id="client", client_secret="secret", held=held)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeJamf:
    """FakeJamf behind every pool a held sign-in opens."""
    tenant = FakeJamf()
    monkeypatch.setattr(sign_in, "new_http_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(tenant.handler)))
    return tenant


async def _read(client: JamfClient) -> None:
    async with client.http() as http:
        response = await client._get(http, VERSION, comment="test")
    assert response.status_code == 200


async def _settle() -> None:
    """Let retirements scheduled from synchronous code run."""
    for _ in range(3):
        await asyncio.sleep(0)


class TestModes:
    async def test_no_cache_holds_nothing_and_every_run_signs_in(self, fake: FakeJamf) -> None:
        registry = SignIns()
        assert registry.held_for(_connection(MODE_NO_CACHE), CREDENTIALS, _build) is None

        # Today's behaviour: a run's client owns its own HTTP client, so FakeJamf is
        # mounted the way test_jamf_client.py mounts it.
        for _ in range(2):
            client = _build()
            async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as http:
                assert (await client._get(http, VERSION, comment="test")).status_code == 200

        assert fake.requests.count(TOKEN) == 2

    async def test_cache_and_hold_shares_one_token_across_runs(self, fake: FakeJamf) -> None:
        registry = SignIns()
        held = registry.held_for(_connection(), CREDENTIALS, _build)
        assert held is not None

        await _read(held.client())
        await _read(held.client())  # a second run: a second, fresh client

        assert fake.requests == [TOKEN, f"GET {VERSION}", f"GET {VERSION}"]
        await registry.close_all()

    async def test_cache_and_hold_asks_again_once_the_token_is_spent(self, fake: FakeJamf) -> None:
        registry = SignIns()
        held = registry.held_for(_connection(), CREDENTIALS, _build)

        await _read(held.client())
        held.tokens.expires_at = clock() - 1  # the lifetime Jamf named has run out
        await _read(held.client())

        assert fake.requests.count(TOKEN) == 2
        await registry.close_all()

    async def test_cache_and_hold_starts_no_renewal(self, fake: FakeJamf) -> None:
        registry = SignIns()
        held = registry.held_for(_connection(), CREDENTIALS, _build)
        await _settle()

        assert not held.renewing
        assert fake.requests == []  # nothing is spent while nothing happens
        await registry.close_all()

    def test_the_default_is_cache_and_hold(self) -> None:
        """Ruled by Kyle, 2026-09-12 (#412)."""
        assert DEFAULT_TOKEN_CACHE_MODE == MODE_CACHE_AND_HOLD

    async def test_a_row_with_no_mode_gets_the_default(self, fake: FakeJamf) -> None:
        registry = SignIns()
        held = registry.held_for(_connection(None), CREDENTIALS, _build)

        assert held is not None and held.mode == MODE_CACHE_AND_HOLD
        await registry.close_all()


class TestNothingStaleIsReused:
    async def test_the_same_row_keeps_the_same_sign_in(self, fake: FakeJamf) -> None:
        registry = SignIns()
        first = registry.held_for(_connection(), CREDENTIALS, _build)

        assert registry.held_for(_connection(), CREDENTIALS, _build) is first
        await registry.close_all()

    @pytest.mark.parametrize(
        ("connection", "credentials"),
        [
            (_connection(base_url="https://moved.jamfcloud.com"), CREDENTIALS),
            (_connection(), SimpleNamespace(client_id="client", client_secret="rotated")),
            (_connection(), SimpleNamespace(client_id="another-client", client_secret="secret")),
            (_connection(user_agent_override="Acme"), CREDENTIALS),
            (_connection(MODE_PERPETUAL), CREDENTIALS),
        ],
    )
    async def test_a_changed_setting_retires_the_held_sign_in(
        self, fake: FakeJamf, connection: SimpleNamespace, credentials: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rotated secret must never keep signing in as the old one."""
        monkeypatch.setattr(sign_in, "_sleep", _parked_sleep)  # a perpetual one must not loop here
        registry = SignIns()
        old = registry.held_for(_connection(), CREDENTIALS, _build)

        new = registry.held_for(connection, credentials, _build)
        await _settle()

        assert new is not old
        assert old.retired
        await registry.close_all()

    async def test_switching_to_no_cache_retires_it(self, fake: FakeJamf) -> None:
        registry = SignIns()
        old = registry.held_for(_connection(), CREDENTIALS, _build)

        assert registry.held_for(_connection(MODE_NO_CACHE), CREDENTIALS, _build) is None
        await _settle()

        assert old.retired
        assert registry.get(str(TENANT), 7) is None

    async def test_tenants_never_share_a_sign_in(self, fake: FakeJamf) -> None:
        """Keyed by tenant and connection (#143): the same id in another tenant is another
        connection."""
        registry = SignIns()
        ours = registry.held_for(_connection(), CREDENTIALS, _build)
        theirs = registry.held_for(_connection(tenant_id=uuid.uuid4()), CREDENTIALS, _build)

        assert ours is not theirs
        await registry.close_all()

    def test_the_stamp_never_carries_the_secret(self) -> None:
        secret = "a-secret-that-must-not-appear"
        value = stamp(HOST, SimpleNamespace(client_id="client", client_secret=secret), None, MODE_CACHE_AND_HOLD)

        assert secret not in value
        assert value != stamp(HOST, SimpleNamespace(client_id="client", client_secret="other"), None, MODE_CACHE_AND_HOLD)
        # The trailing slash is the one spelling the client itself erases.
        assert value == stamp(f"{HOST}/", SimpleNamespace(client_id="client", client_secret=secret), None, MODE_CACHE_AND_HOLD)

    async def test_retire_absent_keeps_only_whats_asked_for(self, fake: FakeJamf) -> None:
        registry = SignIns()
        kept = registry.held_for(_connection(id=1), CREDENTIALS, _build)
        gone = registry.held_for(_connection(id=2), CREDENTIALS, _build)
        elsewhere = registry.held_for(_connection(id=2, tenant_id=uuid.uuid4()), CREDENTIALS, _build)

        await registry.retire_absent(str(TENANT), {1})

        assert not kept.retired and gone.retired and not elsewhere.retired
        await registry.close_all()


class TestSharingIsSafe:
    async def test_each_run_keeps_its_own_throttle_counters(self, fake: FakeJamf) -> None:
        """The run copies these onto its own row; a shared client would mix one sweep's
        throttling into a concurrent webhook's."""
        registry = SignIns()
        held = registry.held_for(_connection(), CREDENTIALS, _build)
        throttled, clean = held.client(), held.client()
        throttled._sleep = _no_wait
        fake.transient.append((VERSION, 429, {"Retry-After": "0"}))

        await _read(throttled)
        await _read(clean)

        assert throttled.throttle.throttled_429 == 1
        assert clean.throttle.throttled_429 == 0
        assert throttled._tokens is clean._tokens  # while sharing one sign-in
        assert fake.requests.count(TOKEN) == 1
        await registry.close_all()

    async def test_a_retired_pool_closes_only_when_its_last_run_lets_go(self, fake: FakeJamf) -> None:
        """A settings change in the middle of a sweep must not pull the connection out
        from under it."""
        held = HeldSignIn((str(TENANT), 7), "stamp", MODE_CACHE_AND_HOLD, _build)
        async with held.lease() as http:
            await held.retire()
            assert not http.is_closed  # the run in flight keeps its connection
            assert (await http.get(f"{HOST}/api/oauth/token")).status_code in (200, 405)
        assert http.is_closed

    async def test_a_pooled_connection_jamf_dropped_costs_one_retry(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/oauth/token":
                return httpx.Response(200, json={"access_token": "tok", "expires_in": 179})
            calls["n"] += 1
            if calls["n"] == 1:
                raise httpx.RemoteProtocolError("Server disconnected without sending a response.", request=request)
            return httpx.Response(200, json={"version": "11.31.1"})

        client = _build()
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            response = await client._get(http, VERSION, comment="test")

        assert response.status_code == 200
        assert calls["n"] == 2

    async def test_a_second_drop_is_a_real_failure(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/oauth/token":
                return httpx.Response(200, json={"access_token": "tok", "expires_in": 179})
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.", request=request)

        client = _build()
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(httpx.RemoteProtocolError):
                await client._get(http, VERSION, comment="test")


async def _no_wait(_seconds: float) -> None:
    return None


async def _parked_sleep(_seconds: float) -> None:
    """A renewal that sleeps forever — for tests that start one only to retire it."""
    await asyncio.Event().wait()


class _FakeClock:
    """Time for the renewal, moved only by the test. A zero wait passes at once; any other
    parks until `advance()`, which moves the clock by exactly that wait — so a token is
    live while the test reads, and expires when the test says the time has passed."""

    def __init__(self) -> None:
        self.now = 1_000.0
        self.waits: list[float] = []
        self._pending: float | None = None
        self._gate: asyncio.Event | None = None

    def monotonic(self) -> float:
        return self.now

    @property
    def parked(self) -> bool:
        return self._gate is not None and not self._gate.is_set()

    async def sleep(self, seconds: float) -> None:
        self.waits.append(seconds)
        if seconds <= 0:
            await asyncio.sleep(0)
            return
        self._pending, self._gate = seconds, asyncio.Event()
        await self._gate.wait()

    def advance(self) -> None:
        assert self._pending is not None and self._gate is not None, "nothing is waiting"
        self.now += self._pending
        self._pending = None
        self._gate.set()


@pytest.fixture
def fake_clock(monkeypatch: pytest.MonkeyPatch) -> _FakeClock:
    time = _FakeClock()
    monkeypatch.setattr(sign_in, "_now", time.monotonic)
    monkeypatch.setattr(sign_in, "_sleep", time.sleep)
    return time


async def _until(condition, *, turns: int = 500) -> None:
    for _ in range(turns):
        if condition():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition never held")


async def _let_time_pass(clock: _FakeClock, times: int) -> None:
    """Wait for the renewal to park, let its wait elapse; `times` over."""
    for _ in range(times):
        await _until(lambda: clock.parked)
        clock.advance()


class TestPerpetualCache:
    async def test_it_renews_before_each_expiry_with_no_traffic(self, fake: FakeJamf, fake_clock: _FakeClock) -> None:
        registry = SignIns()
        held = registry.held_for(_connection(MODE_PERPETUAL), CREDENTIALS, _build)
        assert held.renewing

        await _let_time_pass(fake_clock, 3)
        await _until(lambda: fake_clock.parked)
        await registry.close_all()

        # The first sign-in at once; then each renewal when the token enters its 30-second
        # margin: expires_in=179 is 149 seconds of use, read off Jamf's response.
        assert fake_clock.waits[:5] == [0.0, 149.0, 149.0, 149.0, 149.0]
        assert fake.requests.count(TOKEN) == 4
        assert fake.requests.count(f"GET {VERSION}") == 0  # tokens only: nothing is read

    async def test_a_webhook_after_a_quiet_spell_finds_a_token_ready(self, fake: FakeJamf, fake_clock: _FakeClock) -> None:
        registry = SignIns()
        held = registry.held_for(_connection(MODE_PERPETUAL), CREDENTIALS, _build)
        await _let_time_pass(fake_clock, 5)  # most of a quarter hour with no traffic at all
        await _until(lambda: fake_clock.parked)
        fake.requests.clear()

        await _read(held.client())

        assert fake.requests == [f"GET {VERSION}"]  # no token request of its own
        await registry.close_all()

    async def test_a_failed_renewal_is_logged_waited_out_and_retried(
        self, fake: FakeJamf, fake_clock: _FakeClock, caplog: pytest.LogCaptureFixture
    ) -> None:
        fake.transient.append(("/api/oauth/token", 401, {}))
        registry = SignIns()

        with caplog.at_level(logging.WARNING, logger="app.mdm.jamf.sign_in"):
            held = registry.held_for(_connection(MODE_PERPETUAL), CREDENTIALS, _build)
            await _let_time_pass(fake_clock, 1)  # the backoff after the refusal
            await _until(lambda: held.tokens.token is not None and fake_clock.parked)
        await registry.close_all()

        assert fake_clock.waits == [0.0, RENEWAL_BACKOFF_START_SECONDS, 0.0, 149.0]
        [line] = [r for r in caplog.records if r.getMessage().startswith("could not renew the Jamf Pro sign-in")]
        assert "Jamf Pro answered 401 on /api/oauth/token" in line.getMessage()
        assert "Test connection" in line.getMessage()
        assert line.connection_id == 7
        assert "client_secret" not in caplog.text

    async def test_a_failed_renewal_never_blocks_a_read(self, fake: FakeJamf, fake_clock: _FakeClock) -> None:
        """Until a renewal succeeds, each read signs in as it needs to — Cache and hold."""
        fake.transient.append(("/api/oauth/token", 401, {}))
        registry = SignIns()
        held = registry.held_for(_connection(MODE_PERPETUAL), CREDENTIALS, _build)
        await _until(lambda: fake_clock.parked)  # the renewal failed and is backing off

        await _read(held.client())

        assert fake.requests[-2:] == [TOKEN, f"GET {VERSION}"]
        await registry.close_all()

    async def test_backoff_doubles_to_its_cap(self, fake_clock: _FakeClock, monkeypatch: pytest.MonkeyPatch) -> None:
        def refuse(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"httpStatus": 401})

        monkeypatch.setattr(sign_in, "new_http_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(refuse)))
        registry = SignIns()
        registry.held_for(_connection(MODE_PERPETUAL), CREDENTIALS, _build)

        await _let_time_pass(fake_clock, 7)
        await registry.close_all()

        backoffs = [wait for wait in fake_clock.waits if wait > 0]
        assert backoffs[:7] == [30.0, 60.0, 120.0, 240.0, 480.0, 600.0, 600.0]

    async def test_retiring_stops_the_renewal(self, fake: FakeJamf, fake_clock: _FakeClock) -> None:
        registry = SignIns()
        held = registry.held_for(_connection(MODE_PERPETUAL), CREDENTIALS, _build)
        await _let_time_pass(fake_clock, 1)
        await _until(lambda: fake_clock.parked)

        await registry.forget(str(TENANT), 7)
        issued = fake.requests.count(TOKEN)
        for _ in range(20):
            await asyncio.sleep(0)

        assert held.retired and not held.renewing
        assert fake.requests.count(TOKEN) == issued == 2

    async def test_no_lifetime_means_hold_rather_than_renew(
        self, fake_clock: _FakeClock, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        requests: list[str] = []

        def no_lifetime(request: httpx.Request) -> httpx.Response:
            requests.append(request.url.path)
            return httpx.Response(200, json={"access_token": "tok"})

        monkeypatch.setattr(sign_in, "new_http_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(no_lifetime)))
        registry = SignIns()

        with caplog.at_level(logging.INFO, logger="app.mdm.jamf.sign_in"):
            held = registry.held_for(_connection(MODE_PERPETUAL), CREDENTIALS, _build)
            await _until(lambda: not held.renewing and held.tokens.token is not None)
        await registry.close_all()

        assert requests == ["/api/oauth/token"]
        assert any("named no lifetime" in r.getMessage() for r in caplog.records)


class TestTheFactory:
    """`get_mdm_client` is where every run gets its client; the process registry is where
    the held sign-ins live."""

    @staticmethod
    def _row(mode: str):
        from app.models.schema import MdmConnection

        return MdmConnection(
            id=412,
            tenant_id=TENANT,
            base_url=HOST,
            credentials_encrypted=json.dumps({"clientId": "client", "clientSecret": "secret"}),
            token_cache_mode=mode,
            user_agent_override=None,
        )

    async def test_runs_of_one_connection_share_its_sign_in(self, fake: FakeJamf) -> None:
        from app.mdm.factory import get_mdm_client

        try:
            first, second = get_mdm_client(self._row(MODE_CACHE_AND_HOLD)), get_mdm_client(self._row(MODE_CACHE_AND_HOLD))
            assert first is not second  # a fresh client per run...
            assert first._tokens is second._tokens  # ...borrowing one sign-in
        finally:
            await sign_in.SIGN_INS.forget(str(TENANT), 412)

    async def test_no_cache_runs_share_nothing(self) -> None:
        from app.mdm.factory import get_mdm_client

        first, second = get_mdm_client(self._row(MODE_NO_CACHE)), get_mdm_client(self._row(MODE_NO_CACHE))
        assert first._tokens is not second._tokens
        assert sign_in.SIGN_INS.get(str(TENANT), 412) is None
