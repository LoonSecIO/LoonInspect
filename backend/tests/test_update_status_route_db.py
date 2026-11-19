"""What `/api/system/update-status` says the check sends (#819), and the notice an administrator dismisses.

Every check here is answered by a mock transport, which also counts the route's own requests: none.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import delete, update

from tests.test_sharing_send_now_db import ADMIN, AUDITOR, _audit_events, _signed_in, accounts  # noqa: F401 — a fixture
from tests.test_update_check import SHORT, _stamp
from tests.test_update_check_db import DAY, DUE, HOUR, _row, _served, github  # noqa: F401 — a fixture
from tests.test_update_check_service_db import PAGE, service  # noqa: F401 — a fixture

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

DISMISS = "/api/system/update-status/dismiss-notice"


async def test_the_route_shows_what_a_check_sent_its_answer_and_what_the_next_will_carry(service) -> None:  # noqa: F811
    from app.core.update_check import request_body, stage, tick

    first = await _served()  # before the first answer: the next body has no `last`
    assert (first.provider, first.provider_host, first.kind) == ("loonsec", "api.next.loonsec.io", "container")
    assert first.next_body == request_body(await stage(datetime.now(UTC)), None) and "last" not in first.next_body
    assert (first.last_body, first.next_check_at) == (None, DUE)

    assert await tick(DUE) is True  # answered: day 20776, and v1.2.1
    served = await _served()
    assert list(served.last_body.items()) == list(json.loads(service.requests[0].content).items())  # as sent, in order
    assert (served.update_available, served.latest_tag, served.release_url, served.checked_at) == (True, "v1.2.1", PAGE, DUE)
    assert served.next_body == request_body(await stage(datetime.now(UTC)), 20776)  # the day given comes back as `last`
    assert served.next_check_at == (await _row()).next_check_at
    assert len(service.requests) == 1  # the tick's: the route asked no one


async def test_the_next_check_is_owed_at_its_moment_or_now_when_that_is_over_a_day_ahead(service) -> None:  # noqa: F811
    now = datetime.now(UTC)
    for moment in (now - HOUR, now + 2 * HOUR):  # owed since, and owed later
        await _row(moment)
        assert (await _served()).next_check_at == moment
    await _row(now + 3 * DAY)  # the clock went back: the scheduler's next look asks
    assert now <= (await _served()).next_check_at <= datetime.now(UTC)
    assert service.requests == []


async def test_the_github_shaped_provider_shows_no_body_and_names_its_shape(github, db) -> None:  # noqa: F811
    from app.core.update_check import tick
    from app.models.schema import UpdateCheckState

    assert await tick(DUE) is True  # v1.1.0's two GETs, no body
    await db.execute(update(UpdateCheckState).values(last_sent={"contract": "v1"}))  # left by LoonSec's, before a switch
    await db.commit()
    served = await _served()
    assert (served.provider, served.provider_host, served.last_body, served.next_body) == ("github", "api.github.com", None, None)
    assert served.next_check_at == (await _row()).next_check_at and len(github.requests) == 2


async def test_an_address_that_cannot_be_read_names_no_host_and_the_route_still_answers(service, monkeypatch) -> None:  # noqa: F811
    from app.core.config import settings

    monkeypatch.setattr(settings, "update_check_url", "https://[fe80::1/v1/update")  # urlsplit refuses the host
    served = await _served()
    assert (served.provider, served.provider_host, served.reason) == ("loonsec", None, "not_checked")
    assert served.next_body is not None and service.requests == []


OFF = [(False, SHORT, "disabled"), (True, "0.0.0-dev+local", "dev_build")]


@pytest.mark.parametrize(("on", "stamp", "reason"), OFF, ids=["UPDATE_CHECK=false", "a development tree"])
async def test_the_check_off_and_a_development_tree_show_no_next_body(service, monkeypatch, on, stamp, reason) -> None:  # noqa: F811
    from app.core.config import settings
    from app.core.update_check import tick

    assert await tick(DUE) is True
    monkeypatch.setattr(settings, "update_check", on)
    _stamp(monkeypatch, stamp)
    served = await _served()
    assert (served.reason, served.next_body, served.next_check_at) == (reason, None, None)
    assert served.last_body == json.loads(service.requests[0].content) and len(service.requests) == 1  # it stays said


@pytest_asyncio.fixture(loop_scope="session")
async def notice(db, accounts, monkeypatch):  # noqa: F811 — the row, its notice pending; nothing patched to answer
    from app.core.config import settings
    from app.models.schema import UpdateCheckState

    await db.execute(delete(UpdateCheckState))
    db.add(UpdateCheckState(id=1, next_check_at=DUE, notice_pending=True))
    await db.commit()
    monkeypatch.setattr(settings, "update_check", True)
    monkeypatch.setattr(settings, "update_check_url", "")
    _stamp(monkeypatch, SHORT)


async def test_an_administrator_dismisses_the_notice_for_good_and_a_reader_cannot(notice) -> None:
    admin, auditor = await _signed_in(*ADMIN), await _signed_in(*AUDITOR)
    try:
        read, refused = (await auditor.get("/api/system/update-status")).json(), await auditor.post(DISMISS)
        still = (await _row()).notice_pending
        answers = [await admin.post(DISMISS), await admin.post(DISMISS)]  # the second changes nothing
    finally:
        await admin.aclose()
        await auditor.aclose()
    assert {"provider", "providerHost", "kind", "lastBody", "nextBody", "nextCheckAt", "noticePending"} <= set(read)
    assert (read["noticePending"], refused.status_code, still) == (True, 403, True)
    assert [(answer.status_code, answer.json()["noticePending"]) for answer in answers] == [(200, False), (200, False)]
    assert (await _row()).notice_pending is False
    assert [event["metadata"]["cleared"] for event in _audit_events("update-check.notice.dismissed")[-2:]] == [True, False]
