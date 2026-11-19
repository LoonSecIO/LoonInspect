"""The update check on the scheduler (#819), against a mock GitHub: each promise is a request count."""

from __future__ import annotations

import asyncio
import importlib
import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete

from tests.test_update_check import SHORT, TAG, _github, _serve, _stamp

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

MINUTE = datetime(2026, 11, 19, 10, 0, tzinfo=UTC)  # the minute the `github` fixture's row keeps
CHECK = 2  # an answered check's requests: the release, then the compare


@pytest_asyncio.fixture(loop_scope="session")
async def github(db, monkeypatch):
    """`handler` answers, and a test swaps it; `requests` is every request it was sent."""
    from app.core.config import settings
    from app.models.schema import UpdateCheckState

    await db.execute(delete(UpdateCheckState))
    db.add(UpdateCheckState(id=1, check_minute=600))
    await db.commit()
    monkeypatch.setattr(settings, "update_check", True)
    monkeypatch.setattr(settings, "update_check_url", "")
    _stamp(monkeypatch, SHORT)
    github = SimpleNamespace(handler=_github())
    github.requests = _serve(monkeypatch, lambda request: github.handler(request))
    return github


async def _row():
    from app.core.database import unscoped_session
    from app.models.schema import UpdateCheckState

    async with unscoped_session() as session:
        return await session.get(UpdateCheckState, 1)


async def _served():  # the route, on a request's own session, as a web-only process serves it
    from app.api.system import update_status
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        return await update_status(db=session)


async def test_one_instance_asks_once_a_utc_day_across_a_restart_and_two_scheduler_processes(github, monkeypatch) -> None:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.core import update_check

    async def two_processes(now):  # each reads the row before either claims: the claim alone decides
        barrier, read = asyncio.Barrier(2), AsyncSession.get

        async def get(session, *args, **kwargs):
            row = await read(session, *args, **kwargs)
            await barrier.wait()
            return row

        with monkeypatch.context() as patch:
            patch.setattr(AsyncSession, "get", get)
            return sorted(await asyncio.gather(update_check.tick(now), update_check.tick(now)))

    assert await two_processes(MINUTE) == [False, True]
    importlib.reload(update_check)  # a restart: nothing this module held in memory survives
    _stamp(monkeypatch, SHORT)
    for later in (MINUTE + timedelta(minutes=1), MINUTE.replace(hour=23, minute=59)):
        assert await asyncio.gather(update_check.tick(later), update_check.tick(later)) == [False, False]
    assert len(github.requests) == CHECK

    tomorrow = MINUTE + timedelta(days=1)
    assert await two_processes(tomorrow) == [False, True]
    assert len(github.requests) == 2 * CHECK
    row = await _row()
    assert (row.answered_on, row.attempted_at, row.update_available, row.latest_tag) == (tomorrow.date(), tomorrow, False, TAG)


@pytest.mark.parametrize(
    ("answer", "reason", "retried"),
    [
        pytest.param(_github(release=httpx.Response(403, headers={"x-ratelimit-remaining": "0"})), "refused", True, id="refused"),
        pytest.param(_github(release=httpx.Response(502, text="bad gateway")), "unreachable", True, id="unreachable"),
        pytest.param(_github(release=httpx.Response(404, json={})), "no_release", False, id="no release is an answer"),
    ],
)
async def test_a_check_with_no_answer_is_asked_again_after_an_hour_and_not_before(github, answer, reason, retried) -> None:
    from app.core.update_check import tick

    github.handler = answer
    assert await tick(MINUTE) is True
    row = await _row()
    assert (row.reason, row.attempted_at, row.answered_on) == (reason, MINUTE, None if retried else MINUTE.date())

    github.handler = _github()
    assert await tick(MINUTE + timedelta(minutes=59)) is False
    assert await tick(MINUTE + timedelta(hours=1)) is retried
    assert await tick(MINUTE + timedelta(hours=3)) is False  # answered: nothing more that day
    assert len(github.requests) == (1 + CHECK if retried else 1)


async def test_nothing_is_asked_before_the_kept_minute(github) -> None:
    from app.core.update_check import tick

    assert [await tick(MINUTE.replace(hour=0)), await tick(MINUTE - timedelta(minutes=1)), await tick(MINUTE)] == [0, 0, 1]
    assert len(github.requests) == CHECK  # the third alone asked


@pytest.mark.parametrize(("on", "stamp", "reason"), [(False, SHORT, "disabled"), (True, "0.0.0-dev+local", "dev_build")])
async def test_update_check_false_and_a_build_with_no_stamp_dial_nothing(github, monkeypatch, on, stamp, reason) -> None:
    from app.core.config import settings
    from app.core.update_check import tick

    monkeypatch.setattr(settings, "update_check", on)
    _stamp(monkeypatch, stamp)
    assert await tick(MINUTE) is False
    assert (await _served()).reason == reason
    assert github.requests == [] and (await _row()).attempted_at is None


async def test_the_status_route_serves_the_stored_answer_and_dials_nothing(github, monkeypatch) -> None:
    from app.core.update_check import tick

    before = await _served()
    assert (before.reason, before.checked_at, before.update_available, github.requests) == ("not_checked", None, None, [])
    assert await tick(MINUTE) is True
    served = await _served()
    assert (served.update_available, served.latest_tag, served.checked_at, served.reason) == (False, TAG, MINUTE, None)
    _stamp(monkeypatch, "2026.11.20+0123abc")  # updated since: the answer stored was the previous build's
    assert (await _served()).reason == "not_checked"
    assert len(github.requests) == CHECK  # the tick's, and none of the route's
