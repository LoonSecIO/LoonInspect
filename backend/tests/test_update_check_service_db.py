"""The update check asking LoonSec's update service (#819), answered by a mock transport: nothing leaves the test."""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, update

from tests.test_update_check import SHORT, _stamp, _timeout
from tests.test_update_check_db import DUE, HOUR, _row, _served, github  # noqa: F401 — a fixture

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

SERVICE, ELSEWHERE = "https://api.next.loonsec.io/v1/update", "https://elsewhere.example/v1/update"
PAGE = "https://github.com/LoonSecIO/LoonInspect/releases/tag/v1.2.1"
TENANTS = (uuid.UUID("08190000-0000-4000-8000-00000000000a"), uuid.UUID("08190000-0000-4000-8000-00000000000b"))


def _answer(**changes) -> httpx.Response:  # LoonSec's 200, keys changed, or dropped when None
    body = {"contract": "v1", "day": 20776, "latest": {"tag": "v1.2.1", "url": PAGE}} | changes
    return httpx.Response(200, json={key: value for key, value in body.items() if value is not None})


@pytest_asyncio.fixture(loop_scope="session")
async def service(github, monkeypatch):  # noqa: F811 — the fixture above, with UPDATE_CHECK_URL unset and RELEASE held
    from app.core import update_check
    from app.core.config import settings

    monkeypatch.setattr(settings, "update_check_url", "")
    monkeypatch.setattr(update_check, "RELEASE", "v1.2.0")
    github.handler = lambda request: _answer()
    return github


def _sent(service, index: int = -1) -> dict:
    return json.loads(service.requests[index].content)


async def test_the_request_is_five_keys_and_last_is_the_day_it_was_given(service, monkeypatch) -> None:
    from app.core.config import settings
    from app.core.update_check import provider, stage, tick

    first = {"contract": "v1", "release": "v1.2.0", "kind": "container", "stage": await stage(DUE)}
    assert await tick(DUE) is True  # UPDATE_CHECK_URL unset: LoonSec's update service
    request = service.requests[0]
    assert (request.method, str(request.url), request.headers["content-type"]) == ("POST", SERVICE, "application/json")
    assert request.headers["user-agent"] == "LoonSecIO/v1.2.0 update-check"  # the release: not the stamp, not the setting
    assert _sent(service) == (await _row()).last_sent == first  # no `last` before the first answer, and never null

    service.handler = lambda request: _answer(day=20770)  # lower than the day held, and stored as given
    assert await tick((await _row()).next_check_at) is True
    monkeypatch.setattr(settings, "instance_kind", "mac-app")
    monkeypatch.setattr(settings, "update_check_url", "https://updates.example.test/v1/update/")  # sent without the slash
    assert await tick((await _row()).next_check_at) is True
    assert [_sent(service, 1), _sent(service, 2)] == [first | {"last": 20776}, first | {"kind": "mac-app", "last": 20770}]
    assert str(service.requests[2].url) == "https://updates.example.test/v1/update"
    monkeypatch.setattr(settings, "update_check_url", "https://mirror.example/v1/update/x")  # anything else: GitHub-shaped
    assert provider() == ("github", "https://mirror.example/v1/update/x")


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        pytest.param(_timeout, "unreachable", id="no response"),
        pytest.param(lambda request: httpx.Response(502, text="bad gateway"), "unreachable", id="a 502"),
        pytest.param(lambda request: httpx.Response(429, json={}), "refused", id="the throttle's 429"),
        pytest.param(lambda request: httpx.Response(307, headers={"location": ELSEWHERE}), "unreachable", id="a redirect"),
        pytest.param(lambda request: httpx.Response(200, text="<html>sign in</html>"), "unreachable", id="a page"),
        pytest.param(lambda request: httpx.Response(200, json=[20777]), "unreachable", id="not an object"),
        pytest.param(lambda request: _answer(day="20777"), "unreachable", id="a day that is a string"),
        pytest.param(lambda request: _answer(day=-1), "unreachable", id="a negative day"),
        pytest.param(lambda request: _answer(day=True), "unreachable", id="a day that is true"),
        pytest.param(lambda request: _answer(day=20777.0), "unreachable", id="a day with a fraction"),
    ],
)
async def test_an_unanswered_check_keeps_what_it_held_and_retries_with_the_same_last(service, reply, reason) -> None:
    from app.core.update_check import tick

    assert await tick(DUE) is True  # answered: day 20776, and v1.2.1
    owed = (await _row()).next_check_at
    service.handler = lambda request: _answer(day=20777) if str(request.url) == ELSEWHERE else reply(request)
    assert await tick(owed) is True
    row, served = await _row(), await _served()
    assert (row.reason, row.last_day, row.latest_tag, row.release_url) == (reason, 20776, "v1.2.1", PAGE)
    assert (served.update_available, served.reason, served.latest_tag) == (None, reason, "v1.2.1")  # no notice
    assert [str(request.url) for request in service.requests] == [SERVICE, SERVICE]  # a redirect is not followed

    service.handler = lambda request: _answer(day=20777)
    assert await tick(owed + HOUR) is True
    assert [_sent(service, index).get("last") for index in (0, 1, 2)] == [None, 20776, 20776]
    assert ((await _row()).last_day, (await _served()).update_available) == (20777, True)


@pytest.mark.parametrize(
    ("release", "latest", "read"),
    [
        pytest.param("v1.2.0", {"tag": "v1.2.1", "url": PAGE}, (True, None, PAGE), id="another build of the same release"),
        pytest.param("v1.2.1", {"tag": "v1.2.1", "url": PAGE}, (False, None, PAGE), id="a build of the newer release"),
        pytest.param("v1.9.0", {"tag": "v1.10.0", "url": PAGE}, (True, None, PAGE), id="v1.10.0 is higher than v1.9.0"),
        pytest.param("v1.10.0", {"tag": "v1.9.0", "url": PAGE}, (False, None, PAGE), id="v1.9.0 is not"),
        pytest.param("v1.2.0", None, (None, "no_release", None), id="no latest"),
        pytest.param("v1.2.0", {"tag": "v1.3", "url": PAGE}, (None, "unreachable", PAGE), id="a tag of another form"),
        pytest.param("v1.2.0", {"tag": "v1.3.0-rc.1", "url": PAGE}, (None, "unreachable", PAGE), id="a prerelease tag"),
        pytest.param("v1.2.0", {"tag": "v1.2.1", "url": "http://github.com/x"}, (True, None, None), id="a url not https"),
    ],
)
async def test_the_answer_is_judged_by_the_build_that_reads_it(service, monkeypatch, release, latest, read) -> None:
    from app.core import update_check

    service.handler = lambda request: _answer(latest=latest)
    assert await update_check.tick(DUE) is True  # asked by a v1.2.0 build
    _stamp(monkeypatch, "2026.11.20+0123abc")  # and read by another build, which is never told `not_checked`
    monkeypatch.setattr(update_check, "RELEASE", release)
    served = await _served()
    assert (served.update_available, served.reason, served.release_url, served.latest_sha) == (*read, None)
    assert len(service.requests) == 1


ASKING = [(False, SHORT, False), (True, "0.0.0-dev+local", False), (True, "2026.11.19+unknown", True)]


@pytest.mark.parametrize(("on", "stamp", "asks"), ASKING, ids=["UPDATE_CHECK=false", "no build_info.json", "no GIT_SHA"])
async def test_what_asks_and_what_says_so_at_startup(service, monkeypatch, on, stamp, asks) -> None:
    from app.core.config import settings
    from app.core.update_check import startup_line, tick

    monkeypatch.setattr(settings, "update_check", on)
    _stamp(monkeypatch, stamp)
    assert (await tick(DUE), len(service.requests)) == (asks, int(asks))
    said = "update check on: it asks api.next.loonsec.io once a day; UPDATE_CHECK=false turns it off"
    assert startup_line() == (said if asks else None)


async def test_each_stage_from_a_database_in_that_state(tenant_ready, monkeypatch) -> None:
    from app.core import update_check
    from app.core.database import session_for_tenant, unscoped_session
    from app.models.schema import Account, Collection, MdmConnection, Tenant

    async def write(tenant_id, *rows, statements=()):
        async with session_for_tenant(tenant_id) as session:
            for statement in statements:
                await session.execute(statement)
            session.add_all(rows)
            await session.commit()

    now, (first, second), stage = datetime.now(UTC), TENANTS, update_check.stage
    async with unscoped_session() as session:  # two tenants of this test's own; the second is not operational
        for tenant_id, kind in ((first, "operational"), (second, "root")):
            if await session.get(Tenant, tenant_id) is None:
                session.add(Tenant(id=tenant_id, slug=f"update-check-stage-{kind}", name="update check stage", kind=kind))
        await session.commit()
    empty = (delete(MdmConnection), delete(Account))  # a connection's collections go with it
    for tenant_id in TENANTS:  # what a run before this one left
        await write(tenant_id, statements=empty)
    assert await stage(now, TENANTS) == "unclaimed"
    await write(first, Account(email="update-check-stage@example.test", display_name="stage"))
    assert await stage(now, TENANTS) == "claimed"
    connection = MdmConnection(name="stage", provider="jamf", base_url="https://jamf.example.test")
    await write(second, connection)
    late = now - timedelta(days=7, minutes=1)  # its one collection run completed 7 days and a minute ago
    await write(second, Collection(mdm_connection_id=connection.id, name="sweep", kind="device_sweep", last_success_at=late))
    assert await stage(now, TENANTS) == "connected"  # an account in one tenant, a connection in the other
    await write(second, statements=[update(Collection).values(last_success_at=now - timedelta(days=6))])
    assert await stage(now, TENANTS) == "collecting"
    visited = []  # and with no tenants named, every one is read, the one that is not operational included
    monkeypatch.setattr(update_check, "session_for_tenant", lambda tenant: visited.append(tenant) or session_for_tenant(tenant))
    assert await stage(now) == "collecting" and set(TENANTS) <= set(visited)
    for tenant_id in TENANTS:
        await write(tenant_id, statements=empty)
