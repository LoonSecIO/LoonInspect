"""Fleet's version history (#838), end to end against a fake GitHub: what the background reads
and when, what it dates, the reserve it leaves, and what a person's read and the tab answer.

`HistoryGitHub` is `FakeGitHub` with each manifest's changes behind it: the commits API lists
them, newest first and a page at a time, the raw host serves the manifest as of each, and
every API answer carries GitHub's allowance headers, counting down. Three of the feature's
promises are request counts: a title costs one API request per page of changes, an instance
holding the reserve makes no API request, and **an instance where no organization has the
flag on asks GitHub nothing**.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from tests import test_fleet_catalog_db as catalog
from tests import test_patching_policy_db as policy
from tests.test_fleet_catalog_db import ALPHA, BETA, GAMMA, FakeGitHub, _sha, _titles, rate_limited

# The catalogue's fixtures, shared by name: pytest finds a fixture by the module attribute.
accounts, admin, viewer = policy.accounts, policy.admin, policy.viewer
flag_off, flag_on, macs = catalog.flag_off, catalog.flag_on, catalog.macs

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

OUTPUTS = "ee/maintained-apps/outputs/"


class HistoryGitHub(FakeGitHub):
    """Fleet's catalogue with the changes behind each manifest. `change` is Fleet committing
    to one title's manifest: a version, `ABSENT` for a commit that removed it, or None for a
    manifest this build cannot read."""

    def __init__(self) -> None:
        super().__init__()
        self.changes: dict[str, list[tuple[str, datetime, str | None]]] = {}
        self.remaining = 60
        self.reset_at = int((datetime.now(UTC) + timedelta(minutes=40)).timestamp())
        self.broken_commits: Callable[[], httpx.Response] | None = None

    def change(self, slug: str, version: str | None, *, days_ago: float) -> str:
        from app.core import fleet_history as fh

        held = self.changes.setdefault(slug, [])
        sha = _sha("change", slug, str(version), str(days_ago), str(len(held)))
        held.append((sha, datetime.now(UTC) - timedelta(days=days_ago), version))
        if version not in (None, fh.ABSENT):
            name, bundle_id, _ = self.titles[slug]
            self.titles[slug] = (name, bundle_id, version)
        return sha

    def handler(self, request: httpx.Request) -> httpx.Response:
        host, path = request.url.host, request.url.path
        if host == "api.github.com":
            if path == "/repos/fleetdm/fleet/commits":
                self.requests.append(request)
                response = self.broken_commits() if self.broken_commits else self._commits(request)
            else:
                response = super().handler(request)
            if "x-ratelimit-remaining" not in response.headers:
                self.remaining = max(self.remaining - 1, 0)
                response.headers["x-ratelimit-remaining"] = str(self.remaining)
                response.headers["x-ratelimit-reset"] = str(self.reset_at)
            return response
        prefix = "/fleetdm/fleet/"
        if host == "raw.githubusercontent.com" and path.startswith(prefix):
            ref, _, rest = path.removeprefix(prefix).partition("/")
            if ref != "main":
                self.requests.append(request)
                return self._at(ref, rest)
        return super().handler(request)

    def _commits(self, request: httpx.Request) -> httpx.Response:
        params = request.url.params
        slug = params["path"].removeprefix(OUTPUTS).removesuffix("/darwin.json")
        per_page, page = int(params.get("per_page", "30")), int(params.get("page", "1"))
        rows = sorted(self.changes.get(slug, []), key=lambda change: change[1], reverse=True)
        if since := params.get("since"):
            cutoff = datetime.fromisoformat(since.replace("Z", "+00:00"))
            rows = [row for row in rows if row[1] >= cutoff]
        window = rows[(page - 1) * per_page : page * per_page]
        return httpx.Response(
            200,
            json=[
                {"sha": sha, "commit": {"committer": {"date": at.strftime("%Y-%m-%dT%H:%M:%SZ")}, "message": "FMA updates"}}
                for sha, at, _ in window
            ],
        )

    def _at(self, sha: str, rest: str) -> httpx.Response:
        from app.core import fleet_history as fh

        slug = rest.removeprefix(OUTPUTS).removesuffix("/darwin.json")
        for held, _, version in self.changes.get(slug, []):
            if held == sha:
                if version == fh.ABSENT:
                    break
                if version is None:
                    return httpx.Response(200, content=b"<<not a manifest>>")
                return httpx.Response(200, json={"versions": [{"version": version, "installer_url": "https://x"}]})
        return httpx.Response(404, text="404: Not Found")

    def listed(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == "api.github.com" and r.url.path.endswith("/commits")]

    def read_at(self) -> list[str]:
        return [r.url.path for r in self.requests if r.url.host == "raw.githubusercontent.com" and "/main/" not in r.url.path]


@pytest.fixture(autouse=True)
def _fresh_history_state(monkeypatch: pytest.MonkeyPatch):
    from app.core import fleet_history as fh

    fh.reset_for_tests()
    monkeypatch.setattr(fh, "BACKGROUND_PACE_SECONDS", 0.0)
    yield
    fh.reset_for_tests()


@pytest_asyncio.fixture(loop_scope="session")
async def fleet(db):
    """Three titles with their changes, oldest first, and nothing stored before or after.
    Alpha: 1.0 three hundred days ago, a change that kept 1.0, 1.5, then 2.0 fifty days ago.
    Beta: 0.9, then 1.0. Gamma: one change."""
    from app.models.schema import FleetCatalogState, FleetMaintainedApp

    async def clear() -> None:
        await db.rollback()
        await db.execute(delete(FleetMaintainedApp))  # the versions go with their titles
        await db.execute(delete(FleetCatalogState))
        await db.commit()

    await clear()
    fake = HistoryGitHub()
    fake.put("alpha", "Alpha", ALPHA, "2.0")
    fake.put("beta", "Beta", BETA, "1.0")
    fake.put("gamma", "Gamma", GAMMA, "7.1.3")
    for version, days in (("1.0", 300), ("1.0", 200), ("1.5", 150), ("2.0", 50)):
        fake.change("alpha", version, days_ago=days)
    for version, days in (("0.9", 100), ("1.0", 20)):
        fake.change("beta", version, days_ago=days)
    fake.change("gamma", "7.1.3", days_ago=10)
    yield fake
    await clear()


async def _versions(db, slug: str) -> dict[str, tuple[int, str | None]]:
    """version -> (whole days ago it was dated, the version it replaced)."""
    from app.models.schema import FleetAppVersion

    rows = (
        (await db.execute(select(FleetAppVersion).where(FleetAppVersion.slug == slug).execution_options(populate_existing=True)))
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    return {row.version: (round((now - row.seen_at) / timedelta(days=1)), row.previous_version) for row in rows}


async def _state(db):
    from app.models.schema import FleetCatalogState

    return await db.get(FleetCatalogState, 1, populate_existing=True)


# --- the background ---------------------------------------------------------------------------


async def test_the_background_reads_titles_on_a_mac_one_at_a_time_most_installed_first(db, fleet, flag_on, macs) -> None:
    from app.core import fleet_catalog as fc
    from app.core import fleet_history as fh

    await fc.check(db, transport=fleet.transport)
    fleet.requests.clear()

    # Alpha is on three Macs, Beta on one, Gamma on none.
    assert await fh.tick(transport=fleet.transport) == "alpha"
    assert len(fleet.listed()) == 1 and len(fleet.read_at()) == 4  # one page of changes, a manifest per change
    assert await _versions(db, "alpha") == {"1.0": (300, None), "1.5": (150, "1.0"), "2.0": (50, "1.5")}
    alpha = (await _titles(db))["alpha"]
    assert alpha.history_complete is True and alpha.history_detail is None and alpha.history_read_at is not None
    assert round((datetime.now(UTC) - alpha.history_since) / timedelta(days=1)) == 300
    assert alpha.history_last_sha == fleet.changes["alpha"][-1][0]
    assert (await _state(db)).history_outcome == fh.OUTCOME_OK

    assert await fh.tick(transport=fleet.transport) == "beta"
    assert await _versions(db, "beta") == {"0.9": (100, None), "1.0": (20, "0.9")}

    fleet.requests.clear()
    assert await fh.tick(transport=fleet.transport) is None  # Gamma is on no Mac: never read in the background
    assert fleet.requests == []
    assert (await _titles(db))["gamma"].history_read_at is None


async def test_with_the_flag_off_nothing_is_read_and_the_routes_refuse(db, fleet, flag_off, macs, admin) -> None:
    from app.core import fleet_catalog as fc
    from app.core import fleet_history as fh

    await fc.check(db, transport=fleet.transport)  # the instance holds titles, for whoever asked
    fleet.requests.clear()

    assert await fh.tick(transport=fleet.transport) is None
    for method in ("get", "post"):
        refused = await getattr(admin, method)("/api/fleet-catalog/alpha/history")
        assert refused.status_code == 409 and refused.json()["detail"] == fc.FLAG_OFF
    assert fleet.requests == []


async def test_the_reserve_leaves_githubs_last_requests_alone_until_the_hour_resets(
    db,
    fleet,
    flag_on,
    macs,
    admin,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core import fleet_catalog as fc
    from app.core import fleet_history as fh

    real = fh.read_now
    monkeypatch.setattr(fh, "read_now", lambda session, slug: real(session, slug, transport=fleet.transport))

    # The daily check's own two requests are what bring the allowance down to the reserve.
    fleet.remaining = 22
    await fc.check(db, transport=fleet.transport)
    assert fc.ALLOWANCE.left(datetime.now(UTC)) == fh.RESERVE
    fleet.requests.clear()

    assert await fh.tick(transport=fleet.transport) is None
    assert fleet.requests == []
    state = await _state(db)
    assert state.history_outcome == fh.OUTCOME_WAITING and state.history_detail.startswith("Paused until")
    waiting_since = state.history_checked_at
    assert await fh.tick(transport=fleet.transport) is None
    assert (await _state(db)).history_checked_at == waiting_since  # written once per pause, not every tick

    # A person is held to the same reserve, in words.
    held = await admin.post("/api/fleet-catalog/alpha/history")
    assert held.status_code == 409 and held.json()["detail"].startswith("Not read:")
    assert fleet.requests == []
    assert (await _state(db)).history_detail.startswith("Paused until")  # a person's 409 is not the instance's state

    fc.ALLOWANCE.reset_at = datetime.now(UTC) - timedelta(seconds=1)  # the hour reset
    assert await fh.tick(transport=fleet.transport) == "alpha"


async def test_a_title_that_moved_is_read_again_from_its_last_change(db, fleet, flag_on, macs) -> None:
    from app.core import fleet_catalog as fc
    from app.core import fleet_history as fh

    await fc.check(db, transport=fleet.transport)
    assert await fh.tick(transport=fleet.transport) == "alpha"
    assert await fh.tick(transport=fleet.transport) == "beta"
    assert await fh.tick(transport=fleet.transport) is None  # nothing moved: nothing to read

    fleet.change("alpha", "2.1", days_ago=0.01)
    await fc.check(db, transport=fleet.transport)  # the daily check sees the move
    fleet.requests.clear()

    assert await fh.tick(transport=fleet.transport) == "alpha"
    (listed,) = fleet.listed()
    assert "since" in listed.url.params  # from a week before the last change read, not the beginning
    assert len(fleet.read_at()) == 2  # that change, to know what 2.1 replaced, and the new one
    assert await _versions(db, "alpha") == {"1.0": (300, None), "1.5": (150, "1.0"), "2.0": (50, "1.5"), "2.1": (0, "2.0")}
    alpha = (await _titles(db))["alpha"]
    assert alpha.history_complete is True  # a resumed read does not undo the first one's reach
    assert round((datetime.now(UTC) - alpha.history_since) / timedelta(days=1)) == 300


async def test_a_long_history_is_read_page_by_page_and_a_capped_one_leaves_its_oldest_undated(
    db,
    fleet,
    flag_on,
    macs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core import fleet_catalog as fc
    from app.core import fleet_history as fh

    monkeypatch.setattr(fh, "PAGE_SIZE", 2)
    monkeypatch.setattr(fh, "MAX_PAGES", 2)
    await fc.check(db, transport=fleet.transport)
    fleet.requests.clear()

    # Alpha's four changes fill both pages: the read stops at the cap, so the change it starts
    # at is not where 1.0 arrived, and 1.0 has no date.
    assert await fh.tick(transport=fleet.transport) == "alpha"
    assert len(fleet.listed()) == 2
    assert await _versions(db, "alpha") == {"1.5": (150, "1.0"), "2.0": (50, "1.5")}
    alpha = (await _titles(db))["alpha"]
    assert alpha.history_complete is False and "Only the newest 4 changes were read" in alpha.history_detail

    # Beta's two fill the first page, so the second is asked for, comes back empty, and the
    # history is whole.
    fleet.requests.clear()
    assert await fh.tick(transport=fleet.transport) == "beta"
    assert len(fleet.listed()) == 2
    assert (await _titles(db))["beta"].history_complete is True


async def test_a_manifest_that_cannot_be_read_at_one_change_is_named_and_the_rest_are_dated(db, fleet, flag_on, macs) -> None:
    from app.core import fleet_catalog as fc
    from app.core import fleet_history as fh

    fleet.changes["alpha"].insert(3, (_sha("unreadable"), datetime.now(UTC) - timedelta(days=100), None))
    fleet.changes["alpha"].insert(4, (_sha("1.9"), datetime.now(UTC) - timedelta(days=90), "1.9"))
    await fc.check(db, transport=fleet.transport)

    assert await fh.tick(transport=fleet.transport) == "alpha"
    # 1.9 arrived at the unreadable change or the one after it: no date for it. 2.0 replaced it.
    assert await _versions(db, "alpha") == {"1.0": (300, None), "1.5": (150, "1.0"), "2.0": (50, "1.9")}
    assert "1 of the 6 changes did not carry a manifest" in (await _titles(db))["alpha"].history_detail


async def test_a_failure_pauses_the_background_marks_nothing_read_and_sets_only_its_title_aside(db, fleet, flag_on, macs) -> None:
    from app.core import fleet_catalog as fc
    from app.core import fleet_history as fh

    await fc.check(db, transport=fleet.transport)

    fleet.broken_commits = rate_limited
    assert await fh.tick(transport=fleet.transport) is None
    state = await _state(db)
    assert state.history_outcome == fc.OUTCOME_REFUSED and "60 an hour for each address" in state.history_detail
    assert (await _titles(db))["alpha"].history_read_at is None  # read again later

    fleet.broken_commits = None
    fleet.requests.clear()
    assert await fh.tick(transport=fleet.transport) is None and fleet.requests == []  # paused, not hammering

    # A proxy answering in GitHub's place: every title would fail the same way, so none is marked read.
    fh._paused_until = None
    fh._skipped.clear()
    fleet.broken_commits = lambda: httpx.Response(200, content=b"<html>Sign in to your proxy</html>")
    assert await fh.tick(transport=fleet.transport) is None
    assert (await _titles(db))["alpha"].history_read_at is None
    assert (await _state(db)).history_outcome == fc.OUTCOME_UNEXPECTED

    # Once it is fixed, the next title is read while the one that failed waits its hour, and then it is read too.
    fleet.broken_commits = None
    fh._paused_until = None
    assert await fh.tick(transport=fleet.transport) == "beta"
    fh._skipped.clear()  # the hour is over
    assert await fh.tick(transport=fleet.transport) == "alpha"
    assert (await _state(db)).history_outcome == fh.OUTCOME_OK


async def test_a_pause_comes_off_the_status_line_once_the_hour_resets_with_nothing_left_to_read(db, fleet, flag_on, macs) -> None:
    from app.core import fleet_catalog as fc
    from app.core import fleet_history as fh

    await fc.check(db, transport=fleet.transport)
    assert await fh.tick(transport=fleet.transport) == "alpha"
    assert await fh.tick(transport=fleet.transport) == "beta"

    # GitHub's allowance down to the reserve with nothing left to read: no pause is written.
    fc.ALLOWANCE.remaining, fc.ALLOWANCE.reset_at = fh.RESERVE, datetime.now(UTC) + timedelta(minutes=30)
    assert await fh.tick(transport=fleet.transport) is None
    assert (await _state(db)).history_outcome == fh.OUTCOME_OK

    # A pause written while a title was waiting goes once there is nothing left and the hour has reset.
    state = await _state(db)
    state.history_outcome, state.history_detail = fh.OUTCOME_WAITING, "Paused until 14:05 UTC: …"
    await db.commit()
    fc.ALLOWANCE.reset_at = datetime.now(UTC) - timedelta(seconds=1)
    assert await fh.tick(transport=fleet.transport) is None
    cleared = await _state(db)
    assert cleared.history_outcome is None and cleared.history_detail is None


async def test_a_version_that_came_back_shows_the_move_seen_here_not_its_first_date(db, fleet, flag_on, macs, viewer) -> None:
    from app.core import fleet_catalog as fc
    from app.core import fleet_history as fh

    await fc.check(db, transport=fleet.transport)
    assert await fh.tick(transport=fleet.transport) == "alpha"
    fleet.change("alpha", "1.5", days_ago=0.01)  # Fleet went back from 2.0 to 1.5
    await fc.check(db, transport=fleet.transport)
    assert await fh.tick(transport=fleet.transport) == "alpha"  # moved, and on the most Macs: before beta's first read
    assert (await _versions(db, "alpha"))["1.5"] == (150, "1.0")  # the first arrival keeps its date

    alpha = (await viewer.get("/api/fleet-catalog")).json()["items"][0]
    assert alpha["latestVersion"] == "1.5"
    assert alpha["inCatalogSince"] is None and alpha["versionBefore"] is None  # not 150 days ago
    assert alpha["previousVersion"] == "2.0" and alpha["versionChangedAt"] is not None


# --- a person's read, and the tab ---------------------------------------------------------------


async def test_a_persons_read_is_the_sync_permission_for_any_title_and_answers_newest_first(
    db,
    fleet,
    flag_on,
    admin,
    viewer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core import fleet_catalog as fc
    from app.core import fleet_history as fh

    real = fh.read_now
    monkeypatch.setattr(fh, "read_now", lambda session, slug: real(session, slug, transport=fleet.transport))
    await fc.check(db, transport=fleet.transport)
    fleet.requests.clear()

    assert (await viewer.post("/api/fleet-catalog/alpha/history")).status_code == 403
    never = (await viewer.get("/api/fleet-catalog/alpha/history")).json()
    assert never["historyReadAt"] is None and never["versions"] == [] and never["latestVersion"] == "2.0"
    assert fleet.requests == []

    # Gamma is on no Mac, which the background never reads; a person can.
    read = await admin.post("/api/fleet-catalog/gamma/history")
    assert read.status_code == 200, read.text
    body = read.json()
    assert body["historyComplete"] is True and body["historyDetail"] is None
    assert [(v["version"], v["previousVersion"]) for v in body["versions"]] == [("7.1.3", None)]
    assert (await viewer.get("/api/fleet-catalog/gamma/history")).json()["versions"] == body["versions"]

    alpha = (await admin.post("/api/fleet-catalog/alpha/history")).json()
    assert [v["version"] for v in alpha["versions"]] == ["2.0", "1.5", "1.0"]  # newest first
    assert alpha["versions"][0]["commitSha"] == fleet.changes["alpha"][-1][0]

    missing = await admin.post("/api/fleet-catalog/nope/history")
    assert missing.status_code == 404 and "holds no Mac title nope" in missing.json()["detail"]
    assert (await admin.get("/api/fleet-catalog/..%2Fetc/history")).status_code in (404, 422)

    async with fh._lock:
        busy = await admin.post("/api/fleet-catalog/alpha/history")
    assert busy.status_code == 409 and busy.json()["detail"] == fh.BUSY


async def test_the_tab_shows_when_fleets_catalog_took_the_latest_version(db, fleet, flag_on, macs, viewer) -> None:
    from app.core import fleet_catalog as fc
    from app.core import fleet_history as fh

    await fc.check(db, transport=fleet.transport)
    assert await fh.tick(transport=fleet.transport) == "alpha"

    body = (await viewer.get("/api/fleet-catalog")).json()
    assert body["installedTitles"] == 2 and body["installedTitlesWithHistory"] == 1
    assert body["state"]["historyOutcome"] == "ok"
    alpha, beta = body["items"]
    since = datetime.fromisoformat(alpha["inCatalogSince"])
    assert round((datetime.now(UTC) - since) / timedelta(days=1)) == 50 and alpha["versionBefore"] == "1.5"
    assert alpha["historyReadAt"] is not None
    assert beta["inCatalogSince"] is None and beta["versionBefore"] is None and beta["historyReadAt"] is None
