"""The Jamf client's transport behavior, against the fake tenant and no database:
the wave pager (#71), the totalCount floor, and the transient retry with counters.

Pure in the conftest's sense — no session, no RUN_DB_TESTS gate. The client talks to
FakeJamf through httpx.MockTransport directly rather than through the monkeypatched
`http()` seam the e2e suite uses, because these tests are about the transport itself.
"""

from __future__ import annotations

import httpx
import pytest

from app.mdm.jamf.client import JamfClient
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
    client._token = "stale"  # as if the sweep outlived the token's 30 minutes

    async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as http:
        computers = [computer async for computer in client.iter_computers(http, page_size=100)]

    assert len(computers) == 2
    assert fake.requests.count("POST /api/oauth/token") == 1
    assert client.throttle.observations() == {}  # a 401 is not a transient


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
