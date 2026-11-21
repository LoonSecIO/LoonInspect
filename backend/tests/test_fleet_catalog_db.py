"""Fleet's maintained-apps catalogue (#794), end to end against a fake GitHub: what a check
does to the stored titles, who makes one happen, and what the tab's read answers.

`FakeGitHub` answers the four addresses a check reads, over an httpx mock transport, and
records every request, because three of this feature's promises are request counts: an
unchanged catalogue costs one request, a changed title costs that title's manifest and not
the others, and **an instance where no organization has the flag on asks GitHub nothing**.

The titles are global rows, so every test starts from none and the file leaves none. The
Macs are this file's own, tagged, and removed on the way out as well as on the way in.

Gated on RUN_DB_TESTS like the other database-backed suites.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid as uuidlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from tests.test_patching_policy_db import accounts, admin, viewer  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

SUFFIX = uuidlib.uuid4().hex[:6]
TAG = "fleetcat-"
ALPHA, BETA, GAMMA = f"com.example{SUFFIX}.alpha", f"com.example{SUFFIX}.beta", f"com.example{SUFFIX}.gamma"


def _sha(*parts: str) -> str:
    return hashlib.sha1("\x1f".join(parts).encode()).hexdigest()


class FakeGitHub:
    """Fleet's catalogue as GitHub serves it: the folder listing, the tree, the index and the
    manifests. `put` and `drop` are Fleet committing; `broken` answers in a file's place."""

    def __init__(self) -> None:
        self.titles: dict[str, tuple[str, str, str]] = {}  # slug -> (name, bundle id, version)
        self.requests: list[httpx.Request] = []
        # "contents" | "tree" | "index" | a slug -> what answers in its place, made fresh per request
        self.broken: dict[str, Callable[[], httpx.Response]] = {}

    def put(self, slug: str, name: str, bundle_id: str, version: str) -> None:
        self.titles[slug] = (name, bundle_id, version)

    def drop(self, slug: str) -> None:
        del self.titles[slug]

    def _broken(self, key: str) -> httpx.Response | None:
        answer = self.broken.get(key)
        return answer() if answer is not None else None

    def _manifest(self, slug: str) -> dict:
        _, bundle_id, version = self.titles[slug]
        return {
            "versions": [
                {
                    "version": version,
                    "queries": {"exists": f"SELECT 1 FROM apps WHERE bundle_identifier = '{bundle_id}';"},
                    "installer_url": f"https://downloads.example.com/{slug}.pkg",
                    "install_script_ref": "ab3f7792",
                    "sha256": "no_check",
                }
            ],
            "refs": {"ab3f7792": '#!/bin/bash\ninstaller -pkg "$INSTALLER_PATH" -target /\n'},
        }

    def _blob(self, slug: str) -> str:
        return _sha(json.dumps(self._manifest(slug), sort_keys=True))

    def _index(self) -> dict:
        apps = []
        for slug, (name, bundle_id, _) in sorted(self.titles.items()):
            apps.append({"name": name, "slug": f"{slug}/darwin", "platform": "darwin", "unique_identifier": bundle_id})
            apps.append({"name": name, "slug": f"{slug}/windows", "platform": "windows", "unique_identifier": name})
        return {"version": 2, "apps": apps}

    @property
    def tree_sha(self) -> str:
        return _sha(json.dumps(self._index(), sort_keys=True), *(self._blob(slug) for slug in sorted(self.titles)))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host, path = request.url.host, request.url.path
        if host == "api.github.com" and path == "/repos/fleetdm/fleet/contents/ee/maintained-apps":
            return self._broken("contents") or httpx.Response(
                200,
                json=[
                    {"name": "README.md", "type": "file", "sha": _sha("readme")},
                    {"name": "outputs", "type": "dir", "sha": self.tree_sha},
                ],
            )
        if host == "api.github.com" and path == f"/repos/fleetdm/fleet/git/trees/{self.tree_sha}":
            entries = [{"path": "apps.json", "type": "blob", "sha": _sha("index")}]
            for slug in sorted(self.titles):
                entries.append({"path": slug, "type": "tree", "sha": _sha("dir", slug)})
                entries.append({"path": f"{slug}/darwin.json", "type": "blob", "sha": self._blob(slug)})
                entries.append({"path": f"{slug}/windows.json", "type": "blob", "sha": _sha("windows", slug)})
            return self._broken("tree") or httpx.Response(200, json={"sha": self.tree_sha, "tree": entries, "truncated": False})
        outputs = "/fleetdm/fleet/main/ee/maintained-apps/outputs/"
        if host == "raw.githubusercontent.com" and path.startswith(outputs):
            rest = path.removeprefix(outputs)
            if rest == "apps.json":
                return self._broken("index") or httpx.Response(200, json=self._index())
            slug, _, name = rest.partition("/")
            if name == "darwin.json" and slug in self.titles:
                return self._broken(slug) or httpx.Response(200, json=self._manifest(slug))
        return httpx.Response(404, json={"message": "Not Found"})

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def asked(self, host: str) -> list[str]:
        return [request.url.path for request in self.requests if request.url.host == host]

    def manifests_read(self) -> list[str]:
        return sorted(path.split("/")[-2] for path in self.asked("raw.githubusercontent.com") if path.endswith("/darwin.json"))


def rate_limited() -> httpx.Response:
    """GitHub's primary limit, as it answers it: a 403 with the remaining budget at zero."""
    return httpx.Response(403, headers={"x-ratelimit-remaining": "0"}, json={"message": "API rate limit exceeded"})


@pytest_asyncio.fixture(loop_scope="session")
async def github(db):
    """A fake GitHub holding three titles, and no title or state stored before or after."""
    from app.models.schema import FleetCatalogState, FleetMaintainedApp

    async def clear() -> None:
        await db.rollback()
        await db.execute(delete(FleetMaintainedApp))
        await db.execute(delete(FleetCatalogState))
        await db.commit()

    await clear()
    fake = FakeGitHub()
    fake.put("alpha", "Alpha", ALPHA, "2.0")
    fake.put("beta", "Beta", BETA, "1.0")
    fake.put("gamma", "Gamma", GAMMA, "7.1.3")
    yield fake
    await clear()


async def _flag(db, enabled: bool) -> None:
    from app.core.feature_flags import FLEET_MAINTAINED_APPS_FLAG
    from app.models.schema import FeatureFlag

    await db.execute(delete(FeatureFlag).where(FeatureFlag.key == FLEET_MAINTAINED_APPS_FLAG))
    if enabled:
        db.add(FeatureFlag(key=FLEET_MAINTAINED_APPS_FLAG, enabled=True))
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def flag_off(db):
    await _flag(db, False)


@pytest_asyncio.fixture(loop_scope="session")
async def flag_on(db):
    await _flag(db, True)
    yield
    await db.rollback()
    await _flag(db, False)


async def _titles(db) -> dict:
    from app.models.schema import FleetMaintainedApp

    # Read fresh from the database, without expiring the state row a test still holds.
    rows = await db.execute(select(FleetMaintainedApp).execution_options(populate_existing=True))
    return {row.slug: row for row in rows.scalars().all()}


# --- what a check does ----------------------------------------------------------------------


async def test_the_first_check_reads_every_mac_title_and_keeps_three_facts_of_each(db, github) -> None:
    from app.core import fleet_catalog as fc
    from app.models.schema import FleetMaintainedApp

    state = await fc.check(db, transport=github.transport)

    assert (state.outcome, state.detail, state.app_count) == (fc.OUTCOME_OK, None, 3)
    assert state.tree_sha == github.tree_sha and state.checked_at is not None and state.changed_at == state.checked_at
    titles = await _titles(db)
    assert {slug: (t.name, t.bundle_id, t.latest_version) for slug, t in titles.items()} == {
        "alpha": ("Alpha", ALPHA, "2.0"),
        "beta": ("Beta", BETA, "1.0"),
        "gamma": ("Gamma", GAMMA, "7.1.3"),
    }
    # The first reading of a title is not a move.
    assert all(t.previous_version is None and t.version_changed_at is None for t in titles.values())
    # Two requests to the API, whatever the catalogue's size; the index and each manifest from raw.
    assert len(github.asked("api.github.com")) == 2
    assert github.manifests_read() == ["alpha", "beta", "gamma"]
    # The installer address, the script and the query have no column to be kept in. The
    # history columns are what the version history read reached (#838), not the manifest.
    assert set(FleetMaintainedApp.__table__.columns.keys()) == {
        "slug",
        "name",
        "bundle_id",
        "latest_version",
        "previous_version",
        "version_changed_at",
        "first_seen_at",
        "manifest_sha",
        "updated_at",
        "history_read_at",
        "history_since",
        "history_through",
        "history_last_sha",
        "history_complete",
        "history_detail",
    }


async def test_a_catalogue_that_has_not_moved_costs_one_request(db, github) -> None:
    from app.core import fleet_catalog as fc

    first = await fc.check(db, transport=github.transport)
    changed_at, checked_at = first.changed_at, first.checked_at
    github.requests.clear()

    second = await fc.check(db, transport=github.transport)

    assert second.outcome == fc.OUTCOME_UNCHANGED and second.detail is None
    assert len(github.requests) == 1  # the folder listing, and nothing after it
    assert second.changed_at == changed_at and second.checked_at > checked_at


async def test_a_version_move_reads_one_manifest_and_keeps_the_version_before(db, github) -> None:
    from app.core import fleet_catalog as fc

    await fc.check(db, transport=github.transport)
    github.put("alpha", "Alpha", ALPHA, "2.1")
    github.requests.clear()

    state = await fc.check(db, transport=github.transport)

    assert state.outcome == fc.OUTCOME_OK
    assert github.manifests_read() == ["alpha"]  # beta and gamma did not change and were not read
    titles = await _titles(db)
    alpha = titles["alpha"]
    assert (alpha.latest_version, alpha.previous_version) == ("2.1", "2.0")
    assert alpha.version_changed_at == state.checked_at
    assert titles["beta"].version_changed_at is None and titles["beta"].previous_version is None


async def test_a_title_fleet_drops_is_removed_a_new_one_is_added_and_a_rename_follows_the_index(db, github) -> None:
    from app.core import fleet_catalog as fc

    await fc.check(db, transport=github.transport)
    github.drop("gamma")
    github.put("delta", "Delta", f"com.example{SUFFIX}.delta", "0.9")
    github.put("beta", "Beta Pro", BETA, "1.0")  # the index renames it; its manifest does not move
    github.requests.clear()

    state = await fc.check(db, transport=github.transport)

    assert (state.outcome, state.app_count) == (fc.OUTCOME_OK, 3)
    titles = await _titles(db)
    assert sorted(titles) == ["alpha", "beta", "delta"]
    assert titles["beta"].name == "Beta Pro" and titles["beta"].version_changed_at is None
    assert github.manifests_read() == ["delta"]


@pytest.mark.parametrize(
    ("where", "answer", "outcome", "said"),
    [
        ("contents", rate_limited, "refused", "60 an hour for each address"),
        ("tree", rate_limited, "refused", "60 an hour for each address"),
        ("contents", lambda: httpx.Response(200, text="<html>Sign in to the guest network</html>"), "unexpected", "not JSON"),
        (
            "contents",
            lambda: httpx.Response(404, json={"message": "Not Found"}),
            "unexpected",
            "answered 404 for the folder ee/maintained-apps",
        ),
        ("contents", lambda: httpx.Response(502, text="Bad Gateway"), "unreachable", "answered 502"),
        ("index", lambda: httpx.Response(200, json={"version": 2, "apps": []}), "unexpected", "lists no Mac app"),
        ("index", lambda: httpx.Response(429), "refused", "raw.githubusercontent.com refused"),
    ],
    ids=["api-limit", "api-limit-at-the-tree", "captive-portal", "folder-gone", "bad-gateway", "empty-index", "raw-limit"],
)
async def test_a_check_that_fails_says_which_failure_and_leaves_the_catalogue(db, github, where, answer, outcome, said) -> None:
    from app.core import fleet_catalog as fc

    held = await fc.check(db, transport=github.transport)
    tree_sha, changed_at = held.tree_sha, held.changed_at
    github.put("alpha", "Alpha", ALPHA, "3.0")  # there is something new to read, and it is not read
    github.broken[where] = answer

    state = await fc.check(db, transport=github.transport)

    assert state.outcome == outcome and state.outcome in fc.FAILED
    assert state.detail is not None and said in state.detail and "Nothing was changed" in state.detail
    assert (state.tree_sha, state.changed_at, state.app_count) == (tree_sha, changed_at, 3)
    assert (await _titles(db))["alpha"].latest_version == "2.0"


async def test_a_check_cut_short_keeps_what_it_read_and_the_next_one_reads_the_rest(db, github) -> None:
    from app.core import fleet_catalog as fc

    first = await fc.check(db, transport=github.transport)
    github.put("alpha", "Alpha", ALPHA, "2.1")
    github.put("beta", "Beta", BETA, "1.1")
    github.put("gamma", "Gamma", GAMMA, "7.2")
    github.put("zeta", "Zeta", f"com.example{SUFFIX}.zeta", "1.0")
    github.broken["zeta"] = lambda: httpx.Response(429)  # the last one asked for, so the three before it are read

    cut = await fc.check(db, transport=github.transport)

    assert cut.outcome == fc.OUTCOME_REFUSED
    assert cut.detail is not None and "3 of the 4 manifests that had changed were read and kept" in cut.detail
    assert "Nothing was changed" not in cut.detail  # something was, and the sentence does not say otherwise
    assert cut.tree_sha == first.tree_sha  # not moved, so the next check does not call this one complete
    titles = await _titles(db)
    assert {slug: t.latest_version for slug, t in titles.items()} == {"alpha": "2.1", "beta": "1.1", "gamma": "7.2"}

    del github.broken["zeta"]
    github.requests.clear()
    done = await fc.check(db, transport=github.transport)

    assert (done.outcome, done.app_count, done.tree_sha) == (fc.OUTCOME_OK, 4, github.tree_sha)
    assert github.manifests_read() == ["zeta"]  # the three it kept are not read twice


async def test_a_manifest_that_cannot_be_read_is_skipped_by_name_and_the_rest_land(db, github) -> None:
    from app.core import fleet_catalog as fc

    github.broken["beta"] = lambda: httpx.Response(200, json={"versions": []})

    state = await fc.check(db, transport=github.transport)

    assert state.outcome == fc.OUTCOME_OK and state.app_count == 2
    assert state.detail is not None and state.detail.startswith("1 of Fleet's Mac manifests could not be read")
    assert "left as held: beta." in state.detail
    assert sorted(await _titles(db)) == ["alpha", "gamma"]


# --- who makes a check happen ---------------------------------------------------------------


async def test_no_organization_with_the_flag_on_means_no_request_at_all(db, github, flag_off) -> None:
    from app.core import fleet_catalog as fc

    assert await fc.any_organization_enabled() is False
    assert await fc.tick(transport=github.transport) is None
    assert github.requests == []
    assert await _titles(db) == {}


async def test_the_tick_checks_when_one_is_due_and_not_again_that_day(db, github, flag_on) -> None:
    from app.core import fleet_catalog as fc
    from app.models.schema import FleetCatalogState

    state = await fc.tick(transport=github.transport)
    assert state is not None and state.outcome == fc.OUTCOME_OK and len(await _titles(db)) == 3

    github.requests.clear()
    assert await fc.tick(transport=github.transport) is None  # an hour later: not due
    assert github.requests == []

    # A day later it is due again, and an unchanged catalogue is one request.
    row = await db.get(FleetCatalogState, 1)
    row.checked_at = datetime.now(UTC) - timedelta(hours=24)
    await db.commit()
    again = await fc.tick(transport=github.transport)
    assert again is not None and again.outcome == fc.OUTCOME_UNCHANGED and len(github.requests) == 1


async def test_a_failed_check_is_tried_again_within_the_hour_not_the_minute(db, github, flag_on) -> None:
    from app.core import fleet_catalog as fc
    from app.models.schema import FleetCatalogState

    github.broken["contents"] = rate_limited
    failed = await fc.tick(transport=github.transport)
    assert failed is not None and failed.outcome == fc.OUTCOME_REFUSED

    github.requests.clear()
    assert await fc.tick(transport=github.transport) is None and github.requests == []

    row = await db.get(FleetCatalogState, 1)
    row.checked_at = datetime.now(UTC) - timedelta(hours=1)
    await db.commit()
    del github.broken["contents"]
    retried = await fc.tick(transport=github.transport)
    assert retried is not None and retried.outcome == fc.OUTCOME_OK


# --- the tab's read, and the button -----------------------------------------------------------


@pytest_asyncio.fixture(loop_scope="session")
async def macs(db):
    """Three Macs and an iPad. Alpha (Fleet's latest 2.0) is on all three Macs: at the latest,
    one behind, one ahead. Beta (1.0) is on one Mac twice, once current and once stale. Gamma
    is on none. The iPad carries Alpha's bundle identifier at an old version and is not a Mac."""
    from app.core.content_keys import app_full_key, app_title_key
    from app.models.schema import Device, InstalledApp

    async def clear() -> None:
        await db.rollback()
        ours = select(Device.id).where(Device.external_id.like(f"{TAG}%"))
        await db.execute(delete(InstalledApp).where(InstalledApp.device_id.in_(ours)))
        await db.execute(delete(Device).where(Device.external_id.like(f"{TAG}%")))
        await db.commit()

    await clear()
    devices = [
        Device(mdm_provider="jamf", external_id=f"{TAG}{SUFFIX}{n}", serial_number=f"F{SUFFIX}{n}", hostname=f"fleet{SUFFIX}{n}")
        for n in range(3)
    ]
    ipad = Device(
        mdm_provider="jamf", external_id=f"{TAG}{SUFFIX}pad", serial_number=f"F{SUFFIX}P", hostname="pad", platform="ipados"
    )
    db.add_all([*devices, ipad])
    await db.commit()

    def app(device, name, bundle_id, version):
        return InstalledApp(
            device_id=device.id,
            name=name,
            bundle_id=bundle_id,
            version=version,
            app_hash=uuidlib.uuid4().hex,
            version_hash=uuidlib.uuid4().hex,
            key_title=app_title_key(name, bundle_id),
            key_full=app_full_key(name, bundle_id, version, None),
        )

    db.add_all(
        [
            app(devices[0], "Alpha", ALPHA, "2.0"),
            app(devices[1], "Alpha", ALPHA, "1.9.4"),
            app(devices[2], "Alpha", ALPHA, "2.0.1"),
            app(ipad, "Alpha", ALPHA, "1.0"),
            app(devices[0], "Beta", BETA, "1.0"),
            app(devices[0], "Beta (old copy)", BETA, "0.9"),
        ]
    )
    await db.commit()
    yield
    await clear()


async def test_with_the_flag_off_the_read_answers_nothing_another_flag_fetched(db, github, flag_off, admin) -> None:  # noqa: F811
    from app.core import fleet_catalog as fc

    await fc.check(db, transport=github.transport)  # the instance holds titles, for whoever asked
    github.requests.clear()

    body = (await admin.get("/api/fleet-catalog")).json()

    assert body["enabled"] is False and body["state"] is None and body["items"] == [] and body["total"] == 0
    refused = await admin.post("/api/fleet-catalog/refresh")
    assert refused.status_code == 409 and refused.json()["detail"] == fc.FLAG_OFF
    assert github.requests == []  # neither route asked GitHub anything


async def test_the_read_counts_this_organizations_macs_against_fleets_latest(db, github, flag_on, macs, viewer) -> None:  # noqa: F811
    from app.core import fleet_catalog as fc

    await fc.check(db, transport=github.transport)
    github.requests.clear()

    response = await viewer.get("/api/fleet-catalog")
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["enabled"] is True and body["source"] == "fleetdm/fleet"
    assert body["state"]["outcome"] == "ok" and body["state"]["appCount"] == 3
    # Installed only, by default: Gamma is on no Mac and is not listed.
    assert [item["slug"] for item in body["items"]] == ["alpha", "beta"]
    assert body["total"] == 2 and body["installedTitles"] == 2
    alpha, beta = body["items"]
    # Three Macs, not four: the iPad shares the bundle identifier and is not a Mac. One is
    # behind (1.9.4); the Mac on 2.0.1 is ahead of Fleet and is not behind.
    assert (alpha["deviceCount"], alpha["devicesBehind"], alpha["devicesCurrent"]) == (3, 1, 2)
    assert alpha["latestVersion"] == "2.0" and alpha["previousVersion"] is None and alpha["versionChangedAt"] is None
    # One Mac with two copies is one Mac, and its stale copy makes it behind.
    assert (beta["deviceCount"], beta["devicesBehind"], beta["devicesCurrent"]) == (1, 1, 0)

    everything = (await viewer.get("/api/fleet-catalog", params={"installedOnly": "false"})).json()
    assert [item["slug"] for item in everything["items"]] == ["alpha", "beta", "gamma"]
    assert everything["items"][2]["deviceCount"] == 0 and everything["installedTitles"] == 2

    searched = (await viewer.get("/api/fleet-catalog", params={"q": BETA.upper()})).json()
    assert [item["slug"] for item in searched["items"]] == ["beta"] and searched["installedTitles"] == 2

    paged = (await viewer.get("/api/fleet-catalog", params={"installedOnly": "false", "pageSize": 2, "page": 2})).json()
    assert [item["slug"] for item in paged["items"]] == ["gamma"] and paged["total"] == 3

    assert github.requests == []  # a page load is not a check


async def test_before_the_first_check_the_read_says_so_with_no_state(db, github, flag_on, admin) -> None:  # noqa: F811
    body = (await admin.get("/api/fleet-catalog")).json()
    assert body["enabled"] is True and body["state"] is None and body["items"] == [] and body["installedTitles"] == 0


async def test_check_now_is_the_sync_permissions_and_answers_what_it_found(
    db,
    github,
    flag_on,
    admin,  # noqa: F811
    viewer,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core import fleet_catalog as fc

    real = fc.check_now
    monkeypatch.setattr(fc, "check_now", lambda session: real(session, transport=github.transport))

    assert (await viewer.post("/api/fleet-catalog/refresh")).status_code == 403
    assert github.requests == []

    answered = await admin.post("/api/fleet-catalog/refresh")
    assert answered.status_code == 200, answered.text
    assert answered.json()["outcome"] == "ok" and answered.json()["appCount"] == 3

    # GitHub refusing is a 409 with the sentence, and the same sentence is the stored state.
    github.put("alpha", "Alpha", ALPHA, "2.1")
    github.broken["contents"] = rate_limited
    refused = await admin.post("/api/fleet-catalog/refresh")
    assert refused.status_code == 409 and "60 an hour for each address" in refused.json()["detail"]
    state = (await admin.get("/api/fleet-catalog")).json()["state"]
    assert state["outcome"] == "refused" and state["detail"] == refused.json()["detail"] and state["appCount"] == 3


async def test_a_second_check_does_not_wait_on_the_one_running(db, github, flag_on, admin) -> None:  # noqa: F811
    from app.core import fleet_catalog as fc

    async with fc._lock:
        busy = await admin.post("/api/fleet-catalog/refresh")
        assert await fc.tick(transport=github.transport) is None
    assert busy.status_code == 409 and busy.json()["detail"] == fc.BUSY
    assert github.requests == []
