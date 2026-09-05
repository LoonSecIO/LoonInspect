"""The Jamf client's transport behavior, against the fake tenant and no database:
the wave pager (#71), the totalCount floor, and the transient retry with counters.

Pure in the conftest's sense — no session, no RUN_DB_TESTS gate. The client talks to
FakeJamf through httpx.MockTransport directly rather than through the monkeypatched
`http()` seam the e2e suite uses, because these tests are about the transport itself.
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from app.core.wire import instance_label
from app.mdm.jamf.client import JamfClient, _token_lifetime
from tests.jamf_fake import HOST, FakeJamf


def make_client() -> JamfClient:
    return JamfClient(base_url=HOST, client_id="client", client_secret="secret")


async def sweep(fake: FakeJamf, *, page_size: int, use_async_handler: bool = False) -> tuple[list[dict], JamfClient]:
    client = make_client()
    handler = fake.async_handler if use_async_handler else fake.handler
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        computers = [computer async for computer in client.iter_computers(http, page_size=page_size)]
    return computers, client


@pytest.fixture
def recorded_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Retry waits recorded instead of slept, so a scripted 429 costs no wall time."""
    delays: list[float] = []

    async def _instant(seconds: float) -> None:
        delays.append(seconds)

    monkeypatch.setattr(JamfClient, "_sleep", staticmethod(_instant))
    return delays


async def test_wave_pager_yields_every_device_exactly_once() -> None:
    fake = FakeJamf()
    fake.seed(6)  # 8 devices at page_size=1: page 0 alone, then waves over pages 1-7

    computers, _ = await sweep(fake, page_size=1)

    ids = [computer["id"] for computer in computers]
    assert sorted(ids) == sorted(computer["id"] for computer in fake.computers)
    assert len(ids) == len(set(ids)) == 8
    # 8 known pages, all full, plus the serial tail's one empty probe past totalCount.
    assert len(fake.page_sizes) == 9
    assert all(size == 1 for size in fake.page_sizes)


async def test_waves_actually_overlap_and_respect_the_bound() -> None:
    fake = FakeJamf()
    fake.seed(10)  # 12 devices: waves of 4 over pages 1-11

    computers, _ = await sweep(fake, page_size=1, use_async_handler=True)

    assert len(computers) == 12
    # Overlap proves the fan-out is real; the ceiling proves the wave is the limiter.
    assert 2 <= fake.max_in_flight <= 4


async def test_totalcount_is_a_floor_not_gospel() -> None:
    fake = FakeJamf()
    late = fake.synthetic | {"id": "late999", "udid": "F0000000-0000-4000-8000-00000000LATE"}
    fake.appear_after_first_page.append(late)

    computers, _ = await sweep(fake, page_size=1)

    ids = [computer["id"] for computer in computers]
    # Page 0 promised totalCount=2; the device that enrolled right after it was served
    # is still found by the serial tail, exactly once.
    assert "late999" in ids
    assert len(ids) == len(set(ids)) == 3


async def test_429_is_retried_honoring_retry_after(recorded_sleeps: list[float]) -> None:
    fake = FakeJamf()
    fake.transient.append(("/api/v4/computers-inventory", 429, {"Retry-After": "7"}))

    computers, client = await sweep(fake, page_size=100)

    assert len(computers) == 2
    assert recorded_sleeps == [7.0]
    assert client.throttle.throttled_429 == 1
    assert client.throttle.backoff_ms_total == 7000
    assert client.throttle.observations() == {"throttled_429": 1, "backoff_ms_total": 7000}


async def test_502_is_retried_with_backoff_and_jitter(recorded_sleeps: list[float]) -> None:
    fake = FakeJamf()
    fake.transient.append(("/api/v4/computers-inventory", 502, {}))

    computers, client = await sweep(fake, page_size=100)

    assert len(computers) == 2
    assert client.throttle.retried_5xx == 1
    assert client.throttle.throttled_429 == 0
    (delay,) = recorded_sleeps
    assert 1.0 <= delay < 1.6  # base 1s * 2^0, plus up to half a second of jitter


async def test_transients_exhaust_and_the_real_failure_propagates(recorded_sleeps: list[float]) -> None:
    fake = FakeJamf()
    fake.transient.extend([("/api/v4/computers-inventory", 502, {})] * 4)

    with pytest.raises(httpx.HTTPStatusError):
        await sweep(fake, page_size=100)

    # Three waits, and the fourth answer propagates as the sweep's failure.
    assert len(recorded_sleeps) == 3


async def test_an_expired_token_reauthenticates_once_mid_sweep() -> None:
    fake = FakeJamf()
    client = make_client()
    # A token the tenant no longer accepts and whose deadline this client never saw —
    # revoked, or issued before a restart. The 401 backstop is the only thing that can
    # find that out, which is why proactive refresh does not replace it.
    client._token = "stale"

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as http:
        computers = [computer async for computer in client.iter_computers(http, page_size=100)]

    assert len(computers) == 2
    assert fake.requests.count("POST /api/oauth/token") == 1
    assert client.throttle.observations() == {}  # a 401 is not a transient


# --- the token, and the lock around issuing one ---------------------------------------


def test_token_lifetime_comes_from_the_response_and_never_from_a_default() -> None:
    """The number this module used to assert in a comment ("30 minutes by default")
    is now nobody's business but the tenant's: `expires_in` decides, and the margin is
    the only constant."""
    # What one production tenant (Jamf Pro 11.31.1) actually returned, less the margin.
    assert _token_lifetime({"expires_in": 179}) == 149.0
    assert _token_lifetime({"expires_in": "179"}) == 149.0
    # A lifetime shorter than the margin is halved, never driven negative: a deadline
    # in the past would re-authenticate before every single request.
    assert _token_lifetime({"expires_in": 20}) == 10.0
    # Nothing usable said: no proactive refresh, and the 401 retry carries the client.
    assert _token_lifetime({"token_type": "Bearer"}) is None
    assert _token_lifetime({"expires_in": "soon"}) is None
    assert _token_lifetime({"expires_in": 0}) is None


async def test_a_token_is_replaced_before_it_expires_rather_than_after_a_401() -> None:
    """Proactive refresh: at the measured lifetime a long sweep crosses many expiries,
    and each one used to cost a wasted 401 per request in flight."""
    fake = FakeJamf()
    client = make_client()
    client._token = "expired"
    client._token_expires_at = time.monotonic() - 1  # the deadline expires_in named has passed

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as http:
        response = await client._get(http, "/api/v1/jamf-pro-version", comment="aperture")

    assert response.status_code == 200
    # One GET, not two: the expiry was known, so no round trip was spent discovering it.
    assert fake.requests == ["POST /api/oauth/token", "GET /api/v1/jamf-pro-version"]
    assert client._token == "tok"
    # The fake answers expires_in=179, as the real tenant does; the deadline is that
    # less the 30-second margin, read off the response rather than assumed.
    assert 148.0 < client._token_expires_at - time.monotonic() <= 149.0


async def test_one_expiry_produces_one_token_request_however_many_race() -> None:
    """The whole point: a wave's worth of coroutines meeting a dead token together
    issue one token between them, not one each."""
    fake = FakeJamf()
    client = make_client()
    client._token = "revoked"  # every request in flight will 401 at the same moment

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake.async_handler)) as http:
        responses = await asyncio.gather(
            *(client._get(http, "/api/v1/jamf-pro-version", comment="race") for _ in range(4))
        )

    assert [response.status_code for response in responses] == [200, 200, 200, 200]
    assert fake.requests.count("POST /api/oauth/token") == 1
    # Four 401s and four retries — the wasted GETs are the 401 backstop working, and
    # the amplification that was fixed is in the POST count above.
    assert fake.requests.count("GET /api/v1/jamf-pro-version") == 8


async def test_a_coroutine_waiting_on_the_lock_takes_the_peers_token() -> None:
    """The classic double-fetch. A coroutine that blocks on the lock re-checks after
    acquiring it; without that re-check it would POST for a token it already has."""
    fake = FakeJamf()
    client = make_client()

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake.async_handler)) as http:
        await client._auth_lock.acquire()  # stand in for a peer mid-refresh
        waiter = asyncio.create_task(client._authenticate(http))
        await asyncio.sleep(0)
        assert not waiter.done()  # it is on the lock, not on the network

        client._token = "peer-token"  # the peer's refresh lands
        client._auth_lock.release()

        assert await waiter == "peer-token"

    assert fake.requests == []  # nothing was asked of the tenant at all


def test_a_late_401_does_not_wipe_a_peers_fresh_token() -> None:
    """`self._token = None` was the old invalidation, and a 401 carrying an already
    replaced token would clear the replacement — sending the next wave unauthenticated
    for one round trip each. Invalidation is now by value."""
    client = make_client()
    client._token = "fresh"
    client._token_expires_at = time.monotonic() + 100

    client._forget("expired")  # a slow coroutine's 401, carrying the dead token
    assert client._token == "fresh"

    client._forget("fresh")  # the cached token itself failing is a real invalidation
    assert client._token is None
    assert client._token_expires_at is None


async def test_a_second_401_is_a_real_failure_and_does_not_authenticate_for_ever() -> None:
    """One retry, not a loop. An API client disabled mid-sweep fails the run instead of
    hammering the token endpoint — the behavior this change had to leave alone."""
    posts = 0
    gets = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal posts, gets
        if request.url.path == "/api/oauth/token":
            posts += 1
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 179})
        gets += 1
        return httpx.Response(401, json={"httpStatus": 401})

    client = make_client()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        response = await client._get(http, "/api/v1/jamf-pro-version", comment="aperture")

    # The 401 is returned for the caller to raise on, after exactly one re-auth: two
    # POSTs proves the failing token was invalidated, two GETs that it stopped there.
    assert response.status_code == 401
    assert (posts, gets) == (2, 2)


async def test_aimd_halves_the_width_on_429_and_earns_it_back(recorded_sleeps: list[float]) -> None:
    fake = FakeJamf()
    fake.seed(30)  # 32 devices at page_size=1: pages 0..31, waves over 1..31
    fake.transient.append(("&page=1", 429, {"Retry-After": "0"}))

    computers, client = await sweep(fake, page_size=1)

    assert len(computers) == 32
    # One throttled wave halved 4 → 2; three clean waves stepped 2 → 3, three more
    # 3 → 4 — recovered to the ceiling by the end of the sweep.
    assert client.adaptive.changes == ["4 → 2"]
    assert client.adaptive.reductions == 1
    assert client.adaptive.floor_seen == 2
    assert client.adaptive.width == 4
    assert client.adaptive.observations() == {"concurrency_reductions": 1, "concurrency_floor": 2}
    assert recorded_sleeps == [0.0]  # the 429 itself was still rescued by retry


async def test_aimd_floor_is_one_and_sustained_429s_stay_there(recorded_sleeps: list[float]) -> None:
    fake = FakeJamf()
    fake.seed(8)  # 10 devices at page_size=1: pages 0..9
    fake.transient.extend(
        [
            ("&page=1", 429, {"Retry-After": "0"}),
            ("&page=5", 429, {"Retry-After": "0"}),
            ("&page=7", 429, {"Retry-After": "0"}),
        ]
    )

    computers, client = await sweep(fake, page_size=1)

    # Every page still lands — retry rescues each request while AIMD narrows the next
    # wave: 4 → 2 → 1, and a 429 at width 1 has nothing left to halve.
    assert len(computers) == 10
    assert client.adaptive.changes == ["4 → 2", "2 → 1"]
    assert client.adaptive.reductions == 2
    assert client.adaptive.floor_seen == 1
    assert client.adaptive.width == 1  # only two clean waves ran after the floor
    assert len(recorded_sleeps) == 3


async def test_departments_and_buildings_are_fetched_as_id_and_name() -> None:
    """The two catalogs that make `departmentId: "7"` mean something."""
    fake = FakeJamf()
    client = make_client()
    async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as http:
        departments = await client.fetch_departments(http, page_size=1)
        buildings = await client.fetch_buildings(http)

    # page_size=1 over two departments: the pager runs until a short page, so the
    # second department is only here if it paged.
    assert departments == [{"id": "7", "name": "Engineering"}, {"id": "9", "name": "Sales"}]
    assert buildings == [{"id": "2", "name": "Bletchley Park"}]


async def test_a_catalog_without_the_privilege_is_empty_not_fatal() -> None:
    """No "Read Departments" privilege: ids stay unresolved, and the sweep that came
    for inventory still gets it. A missing label may never cost a device read."""
    fake = FakeJamf()
    fake.departments = None
    client = make_client()
    async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as http:
        assert await client.fetch_departments(http) == []
        assert await client.fetch_buildings(http) == [{"id": "2", "name": "Bletchley Park"}]


async def test_a_catalog_that_errors_is_empty_not_fatal(recorded_sleeps: list[float]) -> None:
    """Same promise for a hard failure, not just a missing privilege: the label read
    fails, the run's inventory is unaffected. Four 503s — one more than the transient
    budget — so the retry is exhausted and the failure is real."""
    fake = FakeJamf()
    fake.transient.extend([("/api/v1/departments", 503, {}) for _ in range(4)])
    client = make_client()
    async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as http:
        assert await client.fetch_departments(http) == []
        computers = [computer async for computer in client.iter_computers(http)]

    assert len(computers) == 2
    assert client.throttle.retried_5xx == 3  # the budget, spent on the catalog and no further


def test_parse_webhook_event_unwraps_the_checkin_nesting() -> None:
    from app.mdm.jamf.client import parse_webhook_event

    payload = {
        "webhook": {"webhookEvent": "ComputerCheckIn"},
        "event": {"trigger": "CLIENT_CHECKIN", "computer": {"jssID": 7, "udid": "U-1", "serialNumber": "S-1"}},
    }
    event = parse_webhook_event(payload)
    # The one payload shape that buries the computer a level deeper — parsed so the
    # drop (#76) can name what it dropped.
    assert event.event_name == "ComputerCheckIn"
    assert event.jamf_id == "7"
    assert event.udid == "U-1"
    assert event.serial_number == "S-1"


def test_host_keeps_a_non_default_port_the_aperture_must_not_drop() -> None:
    """`.host` feeds the read aperture's collector identity (app.mdm.service.
    capture_aperture -> build_aperture). It must agree with instance_label, the value
    HEC ships as `source`, or two Jamf Pro instances behind one hostname on different
    ports are two `source` values in Splunk but merge into one collector identity here
    (#226)."""
    client = JamfClient(base_url="https://jamf.corp.local:8443", client_id="client", client_secret="secret")
    assert client.host == instance_label("https://jamf.corp.local:8443") == "jamf.corp.local:8443"


def test_host_still_drops_a_default_port_like_instance_label_does() -> None:
    client = JamfClient(base_url="https://acme.jamfcloud.com:443", client_id="client", client_secret="secret")
    assert client.host == instance_label("https://acme.jamfcloud.com:443") == "acme.jamfcloud.com"
