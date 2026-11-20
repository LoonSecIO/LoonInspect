"""The update check on the scheduler (#819), against a mock GitHub: each promise is a request count.

No time of day belongs to an instance. `tick` takes the clock and the draw, so every moment here is one a
test chose; a draw left to the OS's generator is held to its range.
"""

from __future__ import annotations

import asyncio
import importlib
import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, text, update

from tests.test_update_check import API, SHORT, TAG, _github, _serve, _stamp

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

DUE = datetime(2026, 11, 19, 10, 0, tzinfo=UTC)  # the moment the `github` fixture's row owes its check
LATE = datetime(2026, 11, 19, 23, 30, tzinfo=UTC)  # half an hour before UTC midnight
CHECK = 2  # an answered check's requests: the release, then the compare
HOUR, DAY, TICK = timedelta(hours=1), timedelta(days=1), timedelta(microseconds=1)


@pytest_asyncio.fixture(loop_scope="session")
async def github(db, monkeypatch):
    """`handler` answers, and a test swaps it; `requests` is every request it was sent."""
    from app.core.config import settings
    from app.models.schema import UpdateCheckState

    await db.execute(delete(UpdateCheckState))
    db.add(UpdateCheckState(id=1, next_check_at=DUE))
    await db.commit()
    monkeypatch.setattr(settings, "update_check", True)
    monkeypatch.setattr(settings, "update_check_url", API)  # GitHub-shaped; tests/test_update_check_service_db.py has LoonSec's
    _stamp(monkeypatch, SHORT)
    github = SimpleNamespace(handler=_github())
    github.requests = _serve(monkeypatch, lambda request: github.handler(request))
    return github


async def _row(next_check_at: datetime | None = None):
    """The row, after owing its next check at `next_check_at` when one is given."""
    from app.core.database import unscoped_session
    from app.models.schema import UpdateCheckState

    async with unscoped_session() as session:
        if next_check_at is not None:
            await session.execute(update(UpdateCheckState).values(next_check_at=next_check_at))
            await session.commit()
        return await session.get(UpdateCheckState, 1)


async def _served():  # the route, on a request's own session, as a web-only process serves it
    from app.api.system import update_status
    from app.core.database import session_for_tenant
    from app.core.tenancy import OPERATIONAL_TENANT_ID

    async with session_for_tenant(OPERATIONAL_TENANT_ID) as session:
        return await update_status(db=session)


async def test_a_new_instance_waits_for_a_moment_drawn_in_its_first_day(github, db) -> None:
    from app.core.update_check import tick
    from app.models.schema import UpdateCheckState

    spans = []

    def draw(span):
        spans.append(span)
        return span * 3 / 4

    await db.execute(delete(UpdateCheckState))  # no row: the first look makes it, and asks nothing yet
    await db.commit()
    assert await tick(DUE, draw) is False
    assert (spans, (await _row()).next_check_at) == ([DAY], DUE + 18 * HOUR)
    assert [await tick(DUE + 18 * HOUR - TICK, draw), await tick(DUE + 18 * HOUR, draw)] == [False, True]
    assert len(github.requests) == CHECK

    await db.execute(delete(UpdateCheckState))  # the OS's draw lands in the first 24 hours
    await db.commit()
    assert await tick(DUE) is False
    assert DUE <= (await _row()).next_check_at < DUE + DAY


async def test_an_answer_owes_the_next_check_20_to_23_hours_on_drawn_afresh(github) -> None:
    from app.core.update_check import tick

    asked, offsets = DUE, []
    for _ in range(2):
        assert await tick(asked) is True
        owed = (await _row()).next_check_at
        assert await tick(owed - TICK) is False  # nothing is asked before it
        offsets.append(owed - asked)
        asked = owed
    assert all(20 * HOUR <= offset < 23 * HOUR for offset in offsets) and offsets[0] != offsets[1]
    assert len(github.requests) == 2 * CHECK


async def test_a_check_owed_while_nothing_ran_is_asked_at_the_next_look_past_midnight(github) -> None:
    from app.core.update_check import tick

    await _row(LATE)  # owed at 23:30, and nothing ran until 03:00 the next UTC day
    assert await tick(LATE + 3.5 * HOUR) is True
    assert len(github.requests) == CHECK


@pytest.mark.parametrize(
    ("answer", "reason", "retried"),
    [
        pytest.param(_github(release=httpx.Response(403, headers={"x-ratelimit-remaining": "0"})), "refused", True, id="refused"),
        pytest.param(_github(release=httpx.Response(502, text="bad gateway")), "unreachable", True, id="unreachable"),
        pytest.param(_github(release=httpx.Response(404, json={})), "no_release", False, id="no release is an answer"),
    ],
)
async def test_a_check_with_no_answer_is_asked_again_an_hour_on_across_midnight(github, answer, reason, retried) -> None:
    from app.core.update_check import tick

    await _row(LATE)
    github.handler = answer
    assert await tick(LATE) is True
    row = await _row()
    assert (row.reason, row.attempted_at) == (reason, LATE)

    github.handler = _github()
    assert await tick(LATE + HOUR - TICK) is False
    assert await tick(LATE + HOUR) is retried  # 00:30, the next UTC day
    assert await tick(LATE + 3 * HOUR) is False  # answered: the next is 20 hours on at least
    assert len(github.requests) == (1 + CHECK if retried else 1)


UNREADABLE = [
    "https://[fe80::1/repos/LoonSecIO/LoonInspect",  # httpx.InvalidURL, which is neither an HTTPError nor a ValueError
    "https://api.github.com:abc/repos/LoonSecIO/LoonInspect",
    "https://127.0.0.1:65536/repos/LoonSecIO/LoonInspect",  # read, and no host has the port: an OverflowError at connect
    "https://xn--.test/repos/LoonSecIO/LoonInspect",  # read, and the name does not decode when the client asks
    "ftp://127.0.0.1/repos/LoonSecIO/LoonInspect",
    "https://[fe80::1/v1/update",  # the same in the shape of LoonSec's update service
    "https://127.0.0.1:abc/v1/update",
    "https://127.0.0.1:99999/v1/update",
    "https://xn--.test/v1/update",
    "https://user:SECRET/tail@127.0.0.1/v1/update",  # httpx takes the password for a port and quotes it
]


@pytest.mark.parametrize("address", UNREADABLE)
async def test_an_address_that_cannot_be_asked_is_unreachable_says_so_and_is_owed_an_hour_on(
    github, monkeypatch, caplog, address
) -> None:
    from app.core.config import settings
    from app.core.update_check import _unreadable, startup_line, tick

    assert [_unreadable(f"https://127.0.0.1:{port}/v1/update") is None for port in (0, 65535, 65536)] == [True, True, False]
    monkeypatch.setattr(settings, "update_check_url", address)
    with caplog.at_level("WARNING", logger="app.core.update_check"):
        assert await tick(DUE) is True  # asked, not raised: the scheduler's "could not run" line would name the database
    row, served = await _row(), await _served()
    assert (row.reason, row.next_check_at, github.requests) == ("unreachable", DUE + HOUR, [])
    assert (served.reason, served.provider_host) == ("unreachable", None) and "unreadable address" in startup_line()
    assert [record.levelname for record in caplog.records] == ["WARNING"]
    assert "UPDATE_CHECK_URL cannot be asked" in caplog.text and "SECRET" not in caplog.text


async def test_a_next_moment_more_than_a_day_ahead_is_owed_at_once(github) -> None:
    from app.core.update_check import tick

    await _row(DUE + DAY)
    assert await tick(DUE) is False  # a day ahead: not yet
    await _row(DUE + DAY + TICK)
    assert await tick(DUE) is True  # further: the clock went back, and the check is owed now
    assert await tick((await _row()).next_check_at - 2 * DAY) is True  # set back two days after an answer
    assert len(github.requests) == 2 * CHECK


async def test_two_scheduler_processes_never_both_ask_and_a_restart_asks_nothing_more(github, monkeypatch) -> None:
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

    assert await two_processes(DUE) == [False, True]
    owed = (await _row()).next_check_at
    importlib.reload(update_check)  # a restart: nothing this module held in memory survives
    _stamp(monkeypatch, SHORT)
    for later in (DUE + timedelta(minutes=1), owed - TICK):
        assert await asyncio.gather(update_check.tick(later), update_check.tick(later)) == [False, False]
    assert len(github.requests) == CHECK

    assert await two_processes(owed) == [False, True]
    assert len(github.requests) == 2 * CHECK
    row = await _row()
    assert (row.attempted_at, row.update_available, row.latest_tag) == (owed, False, TAG)


@pytest.mark.parametrize(("on", "stamp", "reason"), [(False, SHORT, "disabled"), (True, "0.0.0-dev+local", "dev_build")])
async def test_update_check_false_and_a_build_with_no_stamp_dial_nothing(github, monkeypatch, on, stamp, reason) -> None:
    from app.core.config import settings
    from app.core.update_check import tick

    monkeypatch.setattr(settings, "update_check", on)
    _stamp(monkeypatch, stamp)
    assert await tick(DUE) is False
    assert (await _served()).reason == reason
    assert github.requests == [] and (await _row()).attempted_at is None


async def test_the_status_route_serves_the_stored_answer_and_dials_nothing(github, monkeypatch) -> None:
    from app.core.update_check import tick

    before = await _served()
    assert (before.reason, before.checked_at, before.update_available, github.requests) == ("not_checked", None, None, [])
    assert await tick(DUE) is True
    served = await _served()
    assert (served.update_available, served.latest_tag, served.checked_at, served.reason) == (False, TAG, DUE, None)
    _stamp(monkeypatch, "2026.11.20+0123abc")  # updated since: the answer stored was the previous build's
    assert (await _served()).reason == "not_checked"
    assert len(github.requests) == CHECK  # the tick's, and none of the route's


@pytest.mark.skipif(not os.environ.get("ADMIN_DATABASE_URL"), reason="set ADMIN_DATABASE_URL to a role that may create databases")
async def test_the_migration_owes_a_fresh_install_its_first_check_within_a_day(monkeypatch) -> None:
    import secrets

    from tests.test_migration_round_trip_db import _alembic, _database

    bounds = []
    monkeypatch.setattr(secrets, "randbelow", lambda bound: bounds.append(bound) or bound - 1)  # its latest moment
    async with _database() as (url, engine):
        before = datetime.now(UTC)
        await _alembic(url, "upgrade", "e819a4c2f6b3")
        after = datetime.now(UTC)
        async with engine.connect() as connection:
            row = (await connection.execute(text("SELECT next_check_at, notice_pending FROM update_check_state"))).one()
    assert bounds == [DAY // TICK] and before + DAY - TICK <= row.next_check_at <= after + DAY - TICK
    assert row.notice_pending is False


async def test_deciding_the_notice_leaves_no_tenant_bound(db) -> None:
    """The migration reads each tenant's accounts in the upgrade's one transaction; a tenant bound on the way
    in, as 28b0d447bc53 leaves one, is not bound on the way out."""
    from alembic.script import ScriptDirectory

    from app.core.database import _alembic_config
    from app.core.tenancy import TENANT_GUC

    migration = ScriptDirectory.from_config(_alembic_config()).get_revision("e819a4c2f6b3").module
    connection = await db.connection()  # the operational tenant's session: one is bound
    await connection.run_sync(migration._an_account_exists)
    assert await connection.scalar(text("SELECT current_setting(:guc, true)"), {"guc": TENANT_GUC}) == ""
    await db.rollback()
