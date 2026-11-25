"""`GET /api/patch-policy/walk` and the sources `GET /api/patch-policy/apps` reports, against a real
Postgres (#614).

`test_patch_policy_timelines.py` proves the adapters and the trim without a database. What needs
one is the route end to end: the held copy behind the tier gate, this instance's copy of Jamf's
catalog and Fleet's history read from their own tables, the Fleet flag per organization, parity
per app, `align=common`, the 409 sentences, the copy's `as_of` deciding `stale` and LoonSec's
`built_at` naming its cause, and that none of it reads a device. Gated on RUN_DB_TESTS like the
other database suites.

The tables are global, so the document's apps carry bundle ids no other test or catalog uses, the
rows written here have ids of their own, and every fixture removes what it wrote.
"""

from __future__ import annotations

import copy
import gzip
import json
import os
from datetime import UTC, date, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, event

from app.core import fleet_catalog
from app.core import patch_policy_feed as feed
from app.core import patch_policy_timelines as timelines
from app.core import patch_policy_views as views
from app.core import patch_policy_walk as walk
from app.core.config import settings
from app.core.tenancy import OPERATIONAL_TENANT_ID, reset_tenant_id, set_tenant_id
from app.models.schema import (
    FleetAppVersion,
    FleetCatalogState,
    FleetMaintainedApp,
    JamfPatchTitle,
    PatchPolicyDoc,
    PatchPolicyFeedState,
)
from tests.test_patch_policy_feed import DOC, LINK
from tests.test_patching_policy_db import accounts, viewer  # noqa: F401

pytestmark = [
    pytest.mark.skipif(not os.environ.get("RUN_DB_TESTS"), reason="needs Postgres; set RUN_DB_TESTS=1"),
    pytest.mark.asyncio(loop_scope="session"),
]

# Bundle ids nothing else on a test database names, so the global catalogs answer only these rows.
WIRESHARK = "io.loonsec.test.patch-policy-walk.wireshark"
CHROME = "io.loonsec.test.patch-policy-walk.chrome"
VLC = "io.loonsec.test.patch-policy-walk.vlc"
JAMF_IDS = ("PPW-661", "PPW-817")
FLEET_SLUG = "ppw-wireshark-app"


def _document(*, tamper: bool = False) -> dict:
    """The fixture document with this file's bundle ids, and the totals LoonVD publishes with it:
    each track's `check` from the walk of its public dates (2 and 3 years for Wireshark's held
    track, 2 for its newest line, so that window's 3 years has none, and 2 for Chrome)."""
    doc = copy.deepcopy(DOC)
    for app, bundle in zip(doc["apps"], (CHROME, WIRESHARK, VLC), strict=True):
        app["bundle_ids"] = [bundle]
    spans = {"chrome/stable": (2,), "wireshark/4.4": (2, 3), "wireshark/newest": (2,)}
    for app in doc["apps"][:2]:
        for track in app["tracks"]:
            timeline = timelines.public(doc, app["app"], track["track"]).walk_input()
            track["check"] = {}
            for years in spans[track["track"]]:
                result = walk.walk(doc, app=app["app"], track=track["track"], timeline=timeline, years=years)
                track["check"][f"{years}y"] = {stop: walk.check_totals(result, stop) for stop in walk.STOPS}
    if tamper:
        doc["apps"][1]["tracks"][1]["check"]["2y"]["never"]["exposed"] += 1
    doc["doc_id"] = feed.canonical_doc_id(doc)
    return doc


def _serving(payload: bytes) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(200, content=payload))


def _offer(doc: dict, **extra) -> feed.Offer:
    return feed.read_offer({"patch_walk/1": {"signature": doc["doc_id"], "asof": "2026-11-23T20:00:00Z", "url": LINK, **extra}})


async def _hold(db, doc: dict, **extra) -> None:
    payload = gzip.compress(json.dumps(doc).encode(), mtime=0)
    assert await feed.deliver_from_exchange(db, _offer(doc, **extra), transport=_serving(payload)) in ("stored", "unchanged")


async def _empty(db) -> None:
    await db.rollback()
    await db.execute(delete(PatchPolicyDoc))
    await db.execute(delete(PatchPolicyFeedState))
    await db.commit()
    feed._parsed.clear()
    views.reset_for_tests()


async def _tier(db, tier: str) -> str:
    from app.core.sharing import get_or_create_settings

    row = await get_or_create_settings(db)
    before = row.tier
    row.tier = tier
    await db.commit()
    return before


async def _flag(db, enabled: bool) -> None:
    from app.core.feature_flags import FLEET_MAINTAINED_APPS_FLAG
    from app.models.schema import FeatureFlag

    await db.execute(delete(FeatureFlag).where(FeatureFlag.key == FLEET_MAINTAINED_APPS_FLAG))
    if enabled:
        db.add(FeatureFlag(key=FLEET_MAINTAINED_APPS_FLAG, enabled=True))
    await db.commit()


@pytest_asyncio.fixture(loop_scope="session")
async def held(db, monkeypatch):
    """The document held and current, a consenting organization in context, the Fleet flag off."""
    monkeypatch.setattr(settings, "patch_policy_feed_file", "")
    token = set_tenant_id(OPERATIONAL_TENANT_ID)
    await _empty(db)
    before = await _tier(db, "keys")
    await _flag(db, False)
    doc = _document()
    await _hold(db, doc)
    try:
        yield doc
    finally:
        await _empty(db)
        await _tier(db, before)
        await _flag(db, False)
        reset_tenant_id(token)


def _jamf_row(title_id: str, name: str, versions: list[tuple[str, str]], bundle: str = WIRESHARK) -> JamfPatchTitle:
    """A title as the hourly sync writes it: patches newest first, Jamf dating each release a day
    after the vendor's tag."""
    patches = [
        {"version": v, "releaseDate": f"{(date.fromisoformat(d) + timedelta(days=1)).isoformat()}T17:00:00Z"}
        for v, d in sorted(versions, key=lambda pair: pair[1], reverse=True)
    ]
    return JamfPatchTitle(
        id=title_id,
        name=name,
        bundle_id=bundle,
        current_version=patches[0]["version"],
        last_modified="2026-11-23T10:00:00Z",
        patches=patches,
        requirements=[],
        synced_at=datetime.now(UTC),
    )


@pytest_asyncio.fixture(loop_scope="session")
async def jamf(db):
    """Two of this instance's Jamf titles for the test bundle id: Wireshark's 4.4 line and its 4.6 line."""

    async def clear() -> None:
        await db.rollback()
        await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id.in_(JAMF_IDS)))
        await db.commit()
        timelines._jamf_index = None

    await clear()
    db.add(
        _jamf_row(
            "PPW-661",
            "Wireshark 4.4",
            [("4.4.0", "2024-08-28"), ("4.4.1", "2024-10-09"), ("4.4.2", "2024-11-20"), ("4.4.3", "2025-01-08")],
        )
    )
    db.add(_jamf_row("PPW-817", "Wireshark 4.6", [("4.6.0", "2025-10-08"), ("4.6.1", "2025-11-05")]))
    await db.commit()
    timelines._jamf_index = None
    yield
    await clear()


@pytest_asyncio.fixture(loop_scope="session")
async def fleet(db):
    """A Fleet title for the test bundle id that carries only Wireshark's newest line, its history read."""

    async def clear() -> None:
        await db.rollback()
        await db.execute(delete(FleetAppVersion).where(FleetAppVersion.slug == FLEET_SLUG))
        await db.execute(delete(FleetMaintainedApp).where(FleetMaintainedApp.slug == FLEET_SLUG))
        await db.commit()

    await clear()
    db.add(
        FleetMaintainedApp(
            slug=FLEET_SLUG,
            name="Wireshark",
            bundle_id=WIRESHARK,
            latest_version="4.6.1",
            manifest_sha="0" * 40,
            history_read_at=datetime.now(UTC),
        )
    )
    await db.flush()
    for version, seen in (("4.6.0", datetime(2025, 10, 9, 3, tzinfo=UTC)), ("4.6.1", datetime(2025, 11, 6, 3, tzinfo=UTC))):
        db.add(FleetAppVersion(slug=FLEET_SLUG, version=version, seen_at=seen, commit_sha="1" * 40))
    await db.commit()
    yield
    await clear()


@pytest_asyncio.fixture(loop_scope="session")
async def snapshot(db):
    """Sets this instance's one Fleet catalog state row for a test (`put(**columns)`), and puts
    back whatever was there before. The row is global, so a test that reads the Fleet source says
    which snapshot it means rather than inheriting another file's."""
    before = await db.get(FleetCatalogState, 1)
    kept = None if before is None else {c.key: getattr(before, c.key) for c in FleetCatalogState.__table__.columns}

    async def put(**columns) -> None:
        await db.rollback()
        await db.execute(delete(FleetCatalogState))
        db.add(FleetCatalogState(id=1, **columns))
        await db.commit()

    try:
        yield put
    finally:
        await db.rollback()
        await db.execute(delete(FleetCatalogState))
        if kept is not None:
            db.add(FleetCatalogState(**kept))
        await db.commit()


async def _walk(client, expect: int = 200, **query) -> dict:
    response = await client.get("/api/patch-policy/walk", params=query)
    assert response.status_code == expect, response.text
    return response.json()


# --- the public source -----------------------------------------------------------------------------


async def test_a_public_walk_is_served_whole_in_its_totals_and_paged_in_its_rows(held, viewer) -> None:  # noqa: F811
    body = await _walk(viewer, app="wireshark")
    assert (body["kind"], body["schema"], body["algorithm"]) == ("patch_policy_walk", 1, "patch_walk/1")
    assert body["inputs"]["track"] == "wireshark/4.4"  # the default track
    assert body["inputs"]["doc_id"] == held["doc_id"]
    assert body["inputs"]["timeline"]["source"] == "public" and body["inputs"]["timeline"]["ids"] == ["wireshark-tags"]
    assert body["check"] == {
        "state": "matched",
        "detail": "Matches the totals LoonSec published for a 2-year window of Wireshark.",
    }
    assert (body["window"]["since"], body["window"]["until"]) == ("2024-11-22", "2026-11-22")
    assert set(body["policies"]) == set(walk.STOPS) and len(body["policies"]["60d"]["series"]["open"]) == body["window"]["days"]
    assert body["cves_page"] == {"page": 1, "page_size": views.PAGE_SIZE, "pages": 1, "total": len(body["cves"])}
    assert body["intervals_for"] is None
    assert all("intervals" not in outcome for row in body["cves"] for outcome in row["outcomes"].values())

    with_days = await _walk(viewer, app="wireshark", track="wireshark/4.4", stop="never")
    assert with_days["run_id"] == body["run_id"] and with_days["input_id"] == body["input_id"]
    exposed = [row["outcomes"]["never"] for row in with_days["cves"] if row["outcomes"]["never"]["outcome"] == "exposed"]
    assert exposed and all("intervals" in outcome for outcome in exposed)

    three = await _walk(viewer, app="wireshark", years=3)
    assert three["check"]["state"] == "matched" and three["window"]["since"] == "2024-10-26"


async def test_a_window_with_no_published_totals_is_shown_only_because_another_matched(held, viewer) -> None:  # noqa: F811
    body = await _walk(viewer, app="wireshark", track="wireshark/newest", years=3)
    assert body["check"] == {
        "state": "unchecked_window",
        "detail": "LoonSec has no check for a 3-year window of Wireshark; it is shown because the 2-year walk matched.",
    }


async def test_an_app_with_no_public_dates_has_nothing_to_check_and_is_refused_in_words(held, viewer) -> None:  # noqa: F811
    for source in ("public", "jamf", "fleet"):
        body = await _walk(viewer, 409, app="vlc", source=source)
        assert body["reason"] == "no_public_dates" and body["source"] == source
        assert body["detail"].startswith(
            "LoonSec holds no public release dates for VLC media player yet, so no walk of VLC media player can be "
            "checked against the totals LoonSec publishes, and no view of it is shown from any source"
        )
        assert body["facts"]["windows"] == {"vlc/latest 2y": "no_public_dates", "vlc/latest 3y": "no_public_dates"}


async def test_an_unknown_app_and_bad_requests_are_refused(held, viewer) -> None:  # noqa: F811
    unknown = await _walk(viewer, 409, app="nothing-here")
    assert (unknown["reason"], unknown["detail"]) == (
        "app_unknown",
        "No reference yet for nothing-here. That is not a count of zero.",
    )
    track = await _walk(viewer, 409, app="wireshark", track="wireshark/3.6")
    assert track["reason"] == "track_unknown" and "it has wireshark/4.4, wireshark/newest" in track["detail"]
    for query in ({"years": 4}, {"stop": "90d"}, {"source": "homebrew"}, {"page": 0}, {"align": "everything"}):
        response = await viewer.get("/api/patch-policy/walk", params={"app": "wireshark", **query})
        assert response.status_code == 422, query


# --- the instance's own catalogs -----------------------------------------------------------------


async def test_jamf_dates_walk_the_track_and_the_other_lines_versions_are_set_aside(held, jamf, viewer) -> None:  # noqa: F811
    body = await _walk(viewer, app="wireshark", track="wireshark/4.4", source="jamf")
    joined = body["inputs"]["timeline"]
    assert joined["source"] == "jamf" and joined["ids"] == list(JAMF_IDS)
    assert joined["name"] == "this instance's copy of Jamf's public patch catalog (Wireshark 4.4, Wireshark 4.6)"
    assert (joined["other_track"], joined["other_track_versions"], joined["unmatched"]) == (2, ["4.6.0", "4.6.1"], [])
    # The app's public walk matched, which unlocks Jamf; the Jamf numbers themselves are not checked.
    assert body["check"] == {
        "state": "matched",
        "detail": "The walk of LoonSec's published dates for a 2-year window of Wireshark matches the totals LoonSec "
        "published. This view's dates come from this instance's copy of Jamf's public patch catalog, and its own "
        "numbers are not checked.",
    }
    assert body["clocks"]["release_date"] == timelines.JAMF_CLOCK
    # Jamf dated 4.4.3 a day after the tag, so the 1-day stop installs it a day later than on Public.
    public = await _walk(viewer, app="wireshark", track="wireshark/4.4")
    installs = {row["version"]: row["date"] for row in body["policies"]["1d"]["installs"]}
    public_installs = {row["version"]: row["date"] for row in public["policies"]["1d"]["installs"]}
    assert date.fromisoformat(installs["4.4.3"]) - date.fromisoformat(public_installs["4.4.3"]) == timedelta(days=1)

    newest = await _walk(viewer, app="wireshark", track="wireshark/newest", source="jamf")
    assert newest["inputs"]["timeline"]["other_track"] == 0 and newest["inputs"]["timeline"]["matched"] == 6


async def test_a_channel_the_data_names_and_does_not_walk_is_set_aside_and_counted_per_channel(db, held, viewer) -> None:  # noqa: F811
    """The fixture names Chrome's extended stable channel under `other_channels`. A Jamf title that
    dates stable and extended builds walks the stable track with the extended ones set aside, per
    channel, and counts them; 141.0.7390.108 is on both lists and is the stable track's. A
    version neither list names still counts against the 5% limit, with the set-aside beside it."""
    stable = [("141.0.7390.54", "2025-09-30"), ("141.0.7390.66", "2025-10-07"), ("141.0.7390.108", "2025-10-21")]
    stable.append(("142.0.7444.59", "2025-10-28"))
    extended = [("140.0.7339.207", "2025-09-23"), ("140.0.7339.213", "2025-10-14")]
    title = "PPW-CHROME"
    db.add(_jamf_row(title, "Google Chrome", stable + extended, bundle=CHROME))
    await db.commit()
    try:
        body = await _walk(viewer, app="chrome", source="jamf")
        joined = body["inputs"]["timeline"]
        assert (joined["matched"], joined["unmatched"], joined["other_track"], joined["other_channel"]) == (4, [], 0, 2)
        assert joined["other_channels"] == [
            {
                "channel": "extended",
                "label": "Google Chrome (extended stable)",
                "source": held["apps"][0]["other_channels"][0]["source"],
                "count": 2,
                "versions": ["140.0.7339.207", "140.0.7339.213"],
            }
        ]
        # Counted, never worded in the note: the page says it once, in the reader's language.
        assert joined["note"] is None
        apps = {app["app"]: app for app in (await viewer.get("/api/patch-policy/apps")).json()["apps"]}
        chrome = apps["chrome"]["sources"]["jamf"]
        assert chrome["available"] is True and chrome["note"] is None
        (stable_track,) = chrome["tracks"]
        assert (stable_track["matched"], stable_track["otherChannel"], stable_track["unmatched"]) == (4, 2, 0)

        # A build no list names is still unmatched, and the refusal carries what was set aside.
        await db.rollback()
        await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id == title))
        db.add(_jamf_row(title, "Google Chrome", [*stable, *extended, ("143.0.7499.40", "2025-11-04")], bundle=CHROME))
        await db.commit()
        refused = await _walk(viewer, 409, app="chrome", source="jamf")
        assert refused["reason"] == "too_many_unmatched"
        assert refused["facts"]["in_reach"]["unmatched"] == ["143.0.7499.40"]
        assert [(c["channel"], c["count"]) for c in refused["facts"]["other_channels"]] == [("extended", 2)]
    finally:
        await db.rollback()
        await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id == title))
        await db.commit()


async def test_a_jamf_catalog_with_no_title_for_the_app_says_so(held, jamf, viewer) -> None:  # noqa: F811
    body = await _walk(viewer, 409, app="chrome", source="jamf")
    assert (body["reason"], body["source"]) == ("no_title", "jamf")
    assert body["detail"].startswith(
        f"This instance's copy of Jamf's public patch catalog has no title for Google Chrome (bundle id {CHROME})"
    )


async def test_fleet_is_read_only_while_the_flag_is_on_and_follows_only_the_newest_line(db, held, fleet, viewer) -> None:  # noqa: F811
    off = await _walk(viewer, 409, app="wireshark", track="wireshark/newest", source="fleet")
    assert (off["reason"], off["detail"]) == ("flag_off", fleet_catalog.FLAG_OFF)

    await _flag(db, True)
    line = await _walk(viewer, 409, app="wireshark", track="wireshark/4.4", source="fleet")
    assert line["reason"] == "line_not_followed" and line["detail"].startswith(
        f"This instance's Fleet history ({FLEET_SLUG}) dates no Wireshark 4.4 release, so the Wireshark 4.4 device has no "
        "line to hold"
    )
    body = await _walk(viewer, app="wireshark", track="wireshark/newest", source="fleet")
    assert body["inputs"]["timeline"]["ids"] == [FLEET_SLUG] and body["inputs"]["timeline"]["note"] == timelines.FLEET_CLOCK
    # Fleet carried 4.6.0 from 2025-10-09: the 60-day stop needs 59 days of it.
    assert body["window"]["since"] == "2025-12-07"
    assert [row["reason"] for row in body["window"]["shortened_by"]] == ["timeline_coverage"]


async def test_a_fleet_title_whose_history_is_unread_says_how_to_read_it(db, held, fleet, viewer) -> None:  # noqa: F811
    from sqlalchemy import update

    await _flag(db, True)
    await db.execute(update(FleetMaintainedApp).where(FleetMaintainedApp.slug == FLEET_SLUG).values(history_read_at=None))
    await db.commit()
    body = await _walk(viewer, 409, app="wireshark", track="wireshark/newest", source="fleet")
    assert body["reason"] == "history_unread"
    assert "Read history on the Fleet catalog tab (docs/troubleshooting.md §27)" in body["detail"]


async def test_align_common_cuts_every_view_to_the_days_all_the_sources_share(db, held, jamf, fleet, viewer) -> None:  # noqa: F811
    await _flag(db, True)
    body = await _walk(viewer, app="wireshark", track="wireshark/newest", align="common")
    aligned = body["window"]["aligned"]
    assert aligned["sources"] == ["public", "jamf", "fleet"] and aligned["left_out"] == []
    assert (aligned["since"], aligned["until"]) == ("2025-12-07", "2026-11-22")
    assert (body["window"]["since"], body["window"]["until"]) == ("2025-12-07", "2026-11-22")
    assert "common_window" in [row["reason"] for row in body["window"]["shortened_by"]]

    await _flag(db, False)
    views.reset_for_tests()
    without_fleet = await _walk(viewer, app="wireshark", track="wireshark/newest", source="jamf", align="common")
    left = without_fleet["window"]["aligned"]["left_out"]
    assert [(row["source"], row["reason"]) for row in left] == [("fleet", "flag_off")]
    assert without_fleet["window"]["aligned"]["sources"] == ["public", "jamf"]


async def test_a_title_the_hourly_sync_adds_is_read_on_the_next_walk(db, held, jamf, viewer) -> None:  # noqa: F811
    """The titles' bundle ids are parsed once per state of the catalog. A sync that writes a title
    moves that state, so the next walk reads the new title without a restart."""
    first = await _walk(viewer, app="wireshark", track="wireshark/newest", source="jamf")
    assert first["inputs"]["timeline"]["ids"] == list(JAMF_IDS)
    added = _jamf_row("PPW-612", "Wireshark", [("4.6.1", "2025-11-09")])
    added.synced_at = datetime.now(UTC) + timedelta(seconds=1)
    db.add(added)
    await db.commit()
    try:
        again = await _walk(viewer, app="wireshark", track="wireshark/newest", source="jamf")
        assert again["inputs"]["timeline"]["ids"] == sorted([*JAMF_IDS, "PPW-612"])
        assert again["inputs"]["timeline"]["digest"] != first["inputs"]["timeline"]["digest"]
    finally:
        await db.rollback()
        await db.execute(delete(JamfPatchTitle).where(JamfPatchTitle.id == "PPW-612"))
        await db.commit()


async def test_a_fleet_history_is_confirmed_past_its_read_only_by_a_complete_check(db, held, fleet, snapshot, viewer) -> None:  # noqa: F811
    """A daily check that answered confirms an unmoved title up to the check; one that skipped
    manifests (`partial`) left some titles as held and confirms nothing past the history read, and
    the view's note says that is why it ends sooner. A title's own history sentence travels with
    the view either way."""
    from sqlalchemy import update

    await _flag(db, True)
    read_at = datetime(2026, 11, 20, 8, tzinfo=UTC)
    await db.execute(update(FleetMaintainedApp).where(FleetMaintainedApp.slug == FLEET_SLUG).values(history_read_at=read_at))
    await db.commit()
    checked = datetime(2026, 11, 22, 9, 20, tzinfo=UTC)
    await snapshot(outcome="ok", checked_at=checked, snapshot_status="complete")
    complete = await _walk(viewer, app="wireshark", track="wireshark/newest", source="fleet")
    assert complete["inputs"]["timeline"]["as_of"] == "2026-11-22"
    assert complete["inputs"]["timeline"]["note"] == timelines.FLEET_CLOCK

    skipped = "1 Mac manifest could not be read and was left as held: example-app (unrecognized Mac manifest path)."
    await snapshot(outcome="ok", checked_at=checked, snapshot_status="partial", detail=skipped)
    partial = await _walk(viewer, app="wireshark", track="wireshark/newest", source="fleet")
    assert partial["inputs"]["timeline"]["as_of"] == "2026-11-20"
    assert partial["inputs"]["timeline"]["note"] == timelines.FLEET_CLOCK + (
        " Fleet's catalog was read only in part, so the last check (2026-11-22) confirms no title's history past the day "
        "it was read (2026-11-20), and this view ends the day before; a check that reads the whole catalog carries it to "
        "that check's day (docs/troubleshooting.md §33 step 5)."
    )
    assert partial["window"]["until"] == "2026-11-19"
    # The note is not walked: the same days, the same digest, whichever snapshot.
    assert partial["inputs"]["timeline"]["digest"] == complete["inputs"]["timeline"]["digest"]

    # A check that did not get an answer confirms nothing either way, and says nothing about it.
    await snapshot(outcome="unreachable", checked_at=checked, snapshot_status="partial", detail="No answer from api.github.com.")
    failed = await _walk(viewer, app="wireshark", track="wireshark/newest", source="fleet")
    assert failed["inputs"]["timeline"]["as_of"] == "2026-11-20"
    assert failed["inputs"]["timeline"]["note"] == timelines.FLEET_CLOCK

    # The title's history read left a version undated: its own words travel with the view.
    gap = (
        "2 of the 40 changes did not carry a manifest this build could read, so a version that arrived at one of them has "
        "no date."
    )
    await db.execute(update(FleetMaintainedApp).where(FleetMaintainedApp.slug == FLEET_SLUG).values(history_detail=gap))
    await db.commit()
    await snapshot(outcome="ok", checked_at=checked, snapshot_status="complete")
    gappy = await _walk(viewer, app="wireshark", track="wireshark/newest", source="fleet")
    assert gappy["inputs"]["timeline"]["note"] == timelines.FLEET_CLOCK + (
        f" Fleet's version history for {FLEET_SLUG}: {gap} A version left undated there is not in this view, and a fix it "
        "carried is dated by the next version this history dates (docs/troubleshooting.md §27 step 10, §33 step 10)."
    )


async def test_a_catalog_read_only_in_part_does_not_say_fleet_holds_no_title(db, held, fleet, snapshot, viewer) -> None:  # noqa: F811
    """Chrome has no Fleet title here. Only a complete read lets the source say Fleet does not
    maintain it (`not_held`); a partial or unread one says the title may be one not read yet, in
    the walk route's 409 and in the apps route (through `_for_app`) alike."""
    await _flag(db, True)
    checked = datetime(2026, 11, 22, 9, 20, tzinfo=UTC)
    await snapshot(outcome="ok", checked_at=checked, snapshot_status="complete")
    complete = await _walk(viewer, 409, app="chrome", source="fleet")
    assert (complete["reason"], complete["source"]) == ("not_held", "fleet")

    skipped = "1 Mac manifest could not be read and was left as held: example-app (unrecognized Mac manifest path)."
    await snapshot(outcome="ok", checked_at=checked, snapshot_status="partial", detail=skipped)
    partial = await _walk(viewer, 409, app="chrome", source="fleet")
    assert (partial["reason"], partial["source"]) == ("catalog_partial", "fleet")
    opening = (
        f"Fleet's catalog, as this instance holds it, has no Mac title for Google Chrome (bundle id {CHROME}), but this "
        "instance has read that catalog only in part, so the title may be one it has not read yet."
    )
    closing = (
        " Once a check reads the whole catalog, this source dates the track or says Fleet holds no title for the app; "
        "until then, choose another source (docs/troubleshooting.md §33 step 5)."
    )
    assert partial["detail"] == f"{opening} The last check said: {skipped}{closing}"
    apps = {app["app"]: app for app in (await viewer.get("/api/patch-policy/apps")).json()["apps"]}
    chrome = apps["chrome"]["sources"]["fleet"]
    assert (chrome["available"], chrome["state"], chrome["sentence"]) == (False, "catalog_partial", partial["detail"])
    # The held Wireshark title still walks; a refusal concluded from what was read says the read was partial.
    line = await _walk(viewer, 409, app="wireshark", track="wireshark/4.4", source="fleet")
    assert line["reason"] == "line_not_followed" and line["detail"].endswith(timelines.PARTIAL_TAIL)
    assert (await _walk(viewer, app="wireshark", track="wireshark/newest", source="fleet"))["inputs"]["timeline"]["ids"] == [
        FLEET_SLUG
    ]

    # A check cut short after it had read some titles: failed, partial, and the sentence is that
    # check's own, as the status line has it (§27 step 3), not the skipped-titles case.
    cut = (
        "No answer from raw.githubusercontent.com. 3 of the 9 manifests that had changed were read and kept; the next "
        "check reads the rest."
    )
    await snapshot(outcome="unreachable", checked_at=checked, snapshot_status="partial", detail=cut)
    stopped = await _walk(viewer, 409, app="chrome", source="fleet")
    assert stopped["reason"] == "catalog_partial"
    assert stopped["detail"] == f"{opening} The last check did not get an answer: {cut}{closing}"
    # The 1.3.0 upgrade marks a read catalog partial and leaves the last check's line without words.
    await snapshot(outcome="ok", checked_at=checked, snapshot_status="partial", detail=None)
    upgraded = await _walk(viewer, 409, app="chrome", source="fleet")
    assert upgraded["detail"] == opening + timelines.PARTIAL_NO_WORDS + closing

    # No state row at all: nothing has said the catalog is whole.
    await db.rollback()
    await db.execute(delete(FleetCatalogState))
    await db.commit()
    unread = await _walk(viewer, 409, app="chrome", source="fleet")
    assert unread["reason"] == "catalog_partial" and "The last check said" not in unread["detail"]
    assert unread["detail"] == opening + timelines.PARTIAL_NO_WORDS + closing


# --- what refuses every source ---------------------------------------------------------------------


async def test_totals_that_disagree_refuse_every_source_of_the_app(db, held, jamf, viewer) -> None:  # noqa: F811
    await _hold(db, _document(tamper=True))
    for query in ({"source": "public"}, {"source": "jamf"}, {"track": "wireshark/newest", "years": 3}):
        body = await _walk(viewer, 409, app="wireshark", **query)
        assert body["reason"] == "parity", query
        assert body["detail"].startswith("The walk of LoonSec's published dates for Wireshark (newest line) over 2 years")
        # The totals that disagreed, as the walk found them: the page lists them beside the sentence.
        assert (body["facts"]["stop"], body["facts"]["key"]) == ("never", "exposed")
        assert body["facts"]["published"] == body["facts"]["walked"] + 1
    # The apps route still answers, and offers no source of the app, in the walk route's words.
    apps = {app["app"]: app for app in (await viewer.get("/api/patch-policy/apps")).json()["apps"]}
    assert list(apps) == ["chrome", "wireshark", "vlc"]
    for name, source in apps["wireshark"]["sources"].items():
        assert (source["available"], source["state"]) == (False, "parity"), name
        assert source["sentence"].startswith("The walk of LoonSec's published dates for Wireshark (newest line)"), name
        assert all(track["state"] == "parity" and not track["available"] for track in source["tracks"]), name
    # The timeline's own facts are still reported: what Jamf holds is not a walk.
    assert apps["wireshark"]["sources"]["jamf"]["ids"] == list(JAMF_IDS)
    assert apps["chrome"]["sources"]["public"]["available"] is True


async def test_an_organization_whose_tier_is_off_reads_the_tier_sentence(db, held, viewer) -> None:  # noqa: F811
    await _tier(db, "off")
    body = await _walk(viewer, 409, app="wireshark")
    assert (body["reason"], body["detail"], body["source"]) == ("tier_off", feed.TIER_OFF_SENTENCE, None)


# --- which sources can date each app --------------------------------------------------------------


async def test_the_apps_route_says_per_source_and_track_whether_a_walk_can_be_shown(
    db,
    held,
    jamf,
    fleet,
    snapshot,
    viewer,  # noqa: F811
) -> None:
    await _flag(db, True)
    await snapshot(outcome="ok", checked_at=datetime(2026, 11, 22, 9, 20, tzinfo=UTC), snapshot_status="complete")
    body = (await viewer.get("/api/patch-policy/apps")).json()
    apps = {app["app"]: app for app in body["apps"]}
    jamf_source = apps["wireshark"]["sources"]["jamf"]
    assert (jamf_source["available"], jamf_source["state"], jamf_source["ids"]) == (True, "available", list(JAMF_IDS))
    assert (jamf_source["first"], jamf_source["last"], jamf_source["matched"]) == ("2024-08-29", "2025-11-06", 6)
    held_track, newest_track = jamf_source["tracks"]
    assert (held_track["track"], held_track["matched"], held_track["otherTrack"], held_track["unmatched"]) == (
        "wireshark/4.4",
        4,
        2,
        0,
    )
    assert (held_track["since"], held_track["until"]) == ("2024-11-22", "2026-11-22")
    assert newest_track["matched"] == 6

    fleet_source = apps["wireshark"]["sources"]["fleet"]
    assert fleet_source["available"] is True and fleet_source["note"] == timelines.FLEET_CLOCK
    assert [(t["track"], t["state"]) for t in fleet_source["tracks"]] == [
        ("wireshark/4.4", "line_not_followed"),
        ("wireshark/newest", "available"),
    ]
    assert apps["chrome"]["sources"]["jamf"]["state"] == "no_title"
    assert apps["chrome"]["sources"]["fleet"]["state"] == "not_held"
    # Nothing of VLC can be checked against LoonSec's totals, so no source of it is offered.
    assert {name: source["state"] for name, source in apps["vlc"]["sources"].items()} == {
        "public": "no_public_dates",
        "jamf": "no_public_dates",
        "fleet": "no_public_dates",
    }

    await _flag(db, False)
    fleet_off = (await viewer.get("/api/patch-policy/apps")).json()["apps"][1]["sources"]["fleet"]
    assert (fleet_off["available"], fleet_off["state"], fleet_off["sentence"]) == (False, "flag_off", fleet_catalog.FLAG_OFF)


async def test_neither_route_reads_a_device(db, held, jamf, fleet, viewer) -> None:  # noqa: F811
    """A reference analysis reads LoonSec's document and the instance's catalogs, never inventory."""
    from app.core.database import engine

    await _flag(db, True)
    seen: list[str] = []

    def record(_conn, _cursor, statement, *_args) -> None:
        seen.append(statement.lower())

    event.listen(engine.sync_engine, "before_cursor_execute", record)
    try:
        await _walk(viewer, app="wireshark", track="wireshark/newest", source="fleet", align="common")
        assert (await viewer.get("/api/patch-policy/apps")).status_code == 200
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", record)
    touched = [s for s in seen if "jamf_patch_titles" in s or "fleet_app_versions" in s]
    assert touched, "the statements were not captured"
    for statement in seen:
        for table in ("installed_apps", " devices", "app_catalog"):
            assert table not in statement, statement


# --- the copy's own date decides stale; LoonSec's last build names the cause -----------------------


async def test_stale_is_judged_from_the_copys_date_and_loonsecs_last_build_names_the_cause(db, held, viewer) -> None:  # noqa: F811
    await _empty(db)
    # A copy dated 2026-11-23, and a publisher that finished a build over it on the 29th.
    await _hold(db, held, built_at="2026-11-29T07:12:03Z")
    young = await feed.feed_view(db, now=datetime(2026, 11, 25, tzinfo=UTC))
    assert young.state == "current" and young.built_at == datetime(2026, 11, 29, 7, 12, 3, tzinfo=UTC)
    assert young.publisher_running is True
    # On the 30th the copy is more than three days old, though the build is a day old: stale, and
    # the publisher is running over NVD data that has not advanced.
    running = await feed.feed_view(db, now=datetime(2026, 11, 30, tzinfo=UTC))
    assert running.state == "stale" and running.publisher_running is True
    assert running.sentence == (
        "Showing patch-policy data dated 2026-11-23, more than three days old: LoonSec's publisher last ran on 2026-11-29, "
        "but its NVD data has not advanced since 2026-11-23, and the walk ends 2026-11-22."
    )
    # On 3 December the build is more than three days old too: the publisher has stopped.
    stopped = await feed.feed_view(db, now=datetime(2026, 12, 3, tzinfo=UTC))
    assert stopped.state == "stale" and stopped.publisher_running is False
    assert stopped.sentence == (
        "Showing patch-policy data dated 2026-11-23, more than three days old: LoonSec's publisher last ran on 2026-11-29, "
        "more than three days ago, and the walk ends 2026-11-22."
    )
    # The next exchange finds the copy unchanged and a newer build: still stale, running again.
    await _hold(db, held, built_at="2026-12-02T07:00:00Z")
    again = await feed.feed_view(db, now=datetime(2026, 12, 3, tzinfo=UTC))
    assert again.state == "stale" and "LoonSec's publisher last ran on 2026-12-02, but its NVD data" in again.sentence
    body = (await viewer.get("/api/patch-policy/apps")).json()
    assert body["feed"]["builtAt"] == "2026-12-02T07:00:00Z"

    # An exchange that does not say leaves it unknown, and the sentence names only the copy's date.
    await _hold(db, held)
    unknown = await feed.feed_view(db, now=datetime(2026, 12, 3, tzinfo=UTC))
    assert unknown.built_at is None and unknown.state == "stale" and unknown.publisher_running is None
    assert unknown.sentence == "Showing patch-policy data dated 2026-11-23, more than three days old; the walk ends 2026-11-22."


async def test_the_route_sends_the_cause_this_instance_judged_so_the_page_names_the_same(db, held, viewer) -> None:  # noqa: F811
    """`publisherRunning` is the instance's own judgement, by its clock, of the cause its sentence
    names; the page names the cause from it rather than from the browser's clock (LI-5). Built a
    day and five days before the instance's now, so it holds whatever day the suite runs."""
    await _empty(db)
    now = datetime.now(UTC)
    await _hold(db, held, built_at=(now - timedelta(days=1)).isoformat())
    body = (await viewer.get("/api/patch-policy/apps")).json()
    assert body["feed"]["publisherRunning"] is True
    await _hold(db, held, built_at=(now - timedelta(days=5)).isoformat())
    body = (await viewer.get("/api/patch-policy/apps")).json()
    assert body["feed"]["publisherRunning"] is False
    await _hold(db, held)
    body = (await viewer.get("/api/patch-policy/apps")).json()
    assert body["feed"]["builtAt"] is None and body["feed"]["publisherRunning"] is None
