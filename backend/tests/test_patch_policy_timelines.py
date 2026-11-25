"""Patch policy's three timelines (`app.core.patch_policy_timelines`, #614) and what the walk route
makes of them (`app.core.patch_policy_views`), without a database.

The Jamf rows are shaped like `jamf_patch_titles.patches` as the hourly sync stores them (newest
first, `version` and `releaseDate`), and the cases are the ones the plan names: Firefox and
Firefox ESR as two titles under one bundle id, and Thunderbird's one title with both channels
interleaved. The adapter keeps only the track's channel, by membership in the document's version
keys, and reports the rest as `other_track`; it compares no versions. The Fleet rows are shaped
like `fleet_maintained_apps` with their `fleet_app_versions`, with the flag off and on.
"""

from __future__ import annotations

import copy
import datetime as dt
from typing import Any

import pytest

from app.core import fleet_catalog
from app.core import patch_policy_timelines as timelines
from app.core import patch_policy_views as views
from app.core import patch_policy_walk as walk

UTC = dt.UTC


def day(text: str) -> dt.date:
    return dt.date.fromisoformat(text)


def at(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text).replace(tzinfo=UTC)


def _every(start: str, count: int, step: int = 28) -> list[dt.date]:
    return [day(start) + dt.timedelta(days=step * index) for index in range(count)]


# --- A Mozilla-shaped document: a release track and an ESR track per app -----------------------

RELEASES = [(f"{major}.0", when) for major, when in zip(range(128, 147), _every("2024-07-09", 19), strict=True)]
ESR = (
    [("128.0", day("2024-07-09"))]
    + [(f"128.{minor}.0", when) for minor, when in zip(range(1, 13), _every("2024-08-06", 12), strict=True)]
    + [("140.0", day("2025-06-24"))]
    + [(f"140.{minor}.0", when) for minor, when in zip(range(1, 7), _every("2025-07-22", 6), strict=True)]
)


def _version(v: str, when: dt.date | None, line: str, esr: bool = False) -> dict[str, Any]:
    keys = [v] + ([f"{v}esr"] if esr and v.count(".") == 2 else [])
    return {"v": v, "keys": keys, "line": line, "train": v.split(".")[0], "date": when.isoformat() if when else None}


def _release_index(v: str) -> int:
    return [name for name, _ in RELEASES].index(v)


def mozilla_document(app: str = "firefox", name: str = "Mozilla Firefox", *, esr_track: bool = True) -> dict[str, Any]:
    release = {
        "track": f"{app}/release",
        "label": f"{name} (release)",
        "default": True,
        "channel": "release",
        "edition": "release",
        "path": {"kind": "latest"},
        "promotions": None,
        "timeline": f"mozilla-{app}",
        "versions": [_version(v, when, "") for v, when in RELEASES],
        "cves": [
            {
                "cve_id": "CVE-2025-0001",
                "published": "2025-03-01",
                "detectable_at": "2025-03-02",
                "affected": [[0, _release_index("135.0")]],
                "fixes": [{"line": "", "index": _release_index("136.0")}],
            },
            {
                "cve_id": "CVE-2025-0002",
                "published": "2025-09-10",
                "detectable_at": None,
                "affected": [[0, _release_index("142.0")]],
                "fixes": [{"line": "", "index": _release_index("143.0")}],
            },
        ],
        "exclusions": {"by_reason": {}, "cves": []},
        "not_detectable": {"count": 0, "cves": []},
    }
    tracks = [release]
    if esr_track:
        tracks.append(
            {
                "track": f"{app}/esr",
                "label": f"{name} ESR",
                "default": False,
                "channel": "esr",
                "edition": "esr",
                "path": {"kind": "latest"},
                "promotions": None,
                "timeline": f"mozilla-{app}",
                "versions": [_version(v, when, v.split(".")[0], esr=True) for v, when in ESR],
                "cves": [],
                "exclusions": {"by_reason": {}, "cves": []},
                "not_detectable": {"count": 0, "cves": []},
            }
        )
    return {
        "kind": "patch_policy_reference",
        "schema": 1,
        "doc_id": f"doc-{app}",
        "as_of": "2026-11-23T20:00:00Z",
        "algorithm": "patch_walk/1",
        "definitions_version": "2",
        "definitions": {},
        "clocks": {},
        "sources": {
            "detectable": {"coverage_since": "2024-05-21"},
            "timelines": {
                f"mozilla-{app}": {
                    "name": "Mozilla product-details",
                    "fetched_at": "2026-11-23T18:00:00Z",
                    "clock": "The release date product-details gives the version.",
                }
            },
        },
        "apps": [{"app": app, "name": name, "bundle_ids": [f"org.mozilla.{app}"], "tracks": tracks}],
    }


def jamf_title(title_id: str, name: str, bundle: str, versions: list[tuple[str, dt.date]], *, late: int = 1) -> dict[str, Any]:
    """A `jamf_patch_titles` row as the sync stores it: patches newest first, each a version and a
    `releaseDate` stamp (here a day after the vendor's, at 17:00Z, as Jamf's often trail)."""
    patches = [
        {"version": v, "releaseDate": f"{(when + dt.timedelta(days=late)).isoformat()}T17:00:00Z"}
        for v, when in sorted(versions, key=lambda pair: pair[1], reverse=True)
    ]
    return {"id": title_id, "name": name, "bundle_id": bundle, "requirements": [], "patches": patches}


def catalog(*rows: dict[str, Any], size: int | None = None, refreshed: str = "2026-11-23T10:00:00") -> timelines.JamfCatalog:
    """What `read_jamf` answers for the rows given: each title's patches parsed by `jamf_patches`."""
    return timelines.JamfCatalog(
        size=len(rows) if size is None else size,
        refreshed_at=at(refreshed),
        titles=tuple(
            timelines.JamfTitle(
                id=row["id"],
                name=row["name"],
                bundle_ids=(row["bundle_id"].casefold(),),
                patches=timelines.jamf_patches(row["patches"]),
            )
            for row in rows
        ),
    )


FIREFOX_0B3 = jamf_title("0B3", "Mozilla Firefox", "org.mozilla.firefox", RELEASES)
FIREFOX_ESR_0B4 = jamf_title("0B4", "Mozilla Firefox ESR", "org.mozilla.firefox", ESR)


# --- Jamf ------------------------------------------------------------------------------------------


def test_jamf_patches_reads_each_version_and_its_release_day_in_utc() -> None:
    parsed = timelines.jamf_patches(
        [
            {"version": "133.0.3", "releaseDate": "2024-12-10T23:30:00-05:00"},
            {"version": " 133.0 ", "releaseDate": "2024-11-26T17:00:00Z"},
            {"version": "132.0", "releaseDate": None},
            {"version": "131.0", "releaseDate": "not a date"},
            {"version": "", "releaseDate": "2024-10-01T00:00:00Z"},
            "not a patch",
        ]
    )
    assert parsed == (
        ("133.0.3", day("2024-12-11")),
        ("133.0", day("2024-11-26")),
        ("132.0", None),
        ("131.0", None),
    )


def test_firefox_and_firefox_esr_share_a_bundle_id_and_the_release_track_keeps_only_its_channel() -> None:
    """Jamf's "Mozilla Firefox" and "Mozilla Firefox ESR" are two titles under org.mozilla.firefox. The
    release track's timeline keeps every version the release track lists (128.0 and 140.0 are on
    both lists, and both titles date them) and sets every ESR-only build aside as another track's."""
    doc = mozilla_document()
    timeline = timelines.jamf(catalog(FIREFOX_0B3, FIREFOX_ESR_0B4), doc, "firefox", "firefox/release")

    assert timeline.source == "jamf" and timeline.ids == ("0B3", "0B4")
    assert timeline.name == "this instance's copy of Jamf's public patch catalog (Mozilla Firefox, Mozilla Firefox ESR)"
    assert timeline.as_of == day("2026-11-23") and timeline.clock == timelines.JAMF_CLOCK
    esr_only = sorted(v for v, _ in ESR if v not in {"128.0", "140.0"})
    assert list(timeline.other_track) == esr_only
    kept = {key for key, _ in timeline.observations}
    assert kept == {v for v, _ in RELEASES}
    # Ordered by day: the walk reads them in any order, a reader of the evidence in this one.
    assert [when for _, when in timeline.observations] == sorted(when for _, when in timeline.observations)
    # The digest is the walk's own over the same observations.
    result = walk.walk(doc, app="firefox", track="firefox/release", timeline=timeline.walk_input())
    assert result["inputs"]["timeline"]["digest"] == timeline.digest
    joined = result["inputs"]["timeline"]
    assert (joined["matched"], joined["unmatched"], joined["other_track"]) == (len(RELEASES), [], 0)
    # Jamf dates the release a day after the vendor, and the walk installs on Jamf's day.
    first_install = result["policies"]["1d"]["installs"][0]
    assert first_install["date"] == (dict(RELEASES)[first_install["version"]] + dt.timedelta(days=1)).isoformat()


def test_the_esr_track_keeps_esr_builds_and_sets_the_release_channel_aside() -> None:
    doc = mozilla_document()
    timeline = timelines.jamf(catalog(FIREFOX_0B3, FIREFOX_ESR_0B4), doc, "firefox", "firefox/esr")
    assert {key for key, _ in timeline.observations} == {v for v, _ in ESR}
    assert set(timeline.other_track) == {v for v, _ in RELEASES} - {"128.0", "140.0"}


def test_thunderbirds_one_title_with_both_channels_interleaved_is_split_by_membership() -> None:
    """Jamf's Thunderbird title lists release and ESR builds under one title, newest first,
    interleaved. Each version goes to the track whose list holds it; nothing is read from its shape."""
    doc = mozilla_document("thunderbird", "Mozilla Thunderbird")
    interleaved = jamf_title("0E1", "Mozilla Thunderbird", "org.mozilla.thunderbird", RELEASES + ESR)
    versions = [patch["version"] for patch in interleaved["patches"]]
    assert versions[:4] == ["140.6.0", "146.0", "140.5.0", "145.0"]  # interleaved, as Jamf lists it

    release = timelines.jamf(catalog(interleaved), doc, "thunderbird", "thunderbird/release")
    esr = timelines.jamf(catalog(interleaved), doc, "thunderbird", "thunderbird/esr")
    assert {key for key, _ in release.observations} == {v for v, _ in RELEASES}
    assert {key for key, _ in esr.observations} == {v for v, _ in ESR}
    assert set(release.other_track) | {"128.0", "140.0"} == {v for v, _ in ESR}

    result = walk.walk(doc, app="thunderbird", track="thunderbird/release", timeline=release.walk_input())
    served = views.served(result, release, check={"state": "matched", "detail": "."}, stop=None, page=1)
    assert served["inputs"]["timeline"]["other_track"] == len(release.other_track)
    assert served["inputs"]["timeline"]["other_track_versions"] == list(release.other_track)
    assert served["inputs"]["timeline"]["ids"] == ["0E1"]


def test_without_an_esr_track_in_the_document_esr_builds_are_unmatched_and_refuse_the_view_above_five_percent() -> None:
    """Membership needs both lists. A document that lists only the release channel cannot tell an
    ESR build from a version it has never heard of, so every ESR build in reach counts against the
    5% limit, and the walk is refused in words rather than walked over a device that skips them."""
    doc = mozilla_document("thunderbird", "Mozilla Thunderbird", esr_track=False)
    interleaved = jamf_title("0E1", "Mozilla Thunderbird", "org.mozilla.thunderbird", RELEASES + ESR)
    timeline = timelines.jamf(catalog(interleaved), doc, "thunderbird", "thunderbird/release")
    assert timeline.other_track == ()
    with pytest.raises(walk.WalkRefused) as refused:
        walk.walk(doc, app="thunderbird", track="thunderbird/release", timeline=timeline.walk_input())
    assert refused.value.reason == walk.REFUSED_UNMATCHED
    assert "match no version LoonSec's patch-policy data lists for Mozilla Thunderbird" in refused.value.sentence
    assert "Choose Public as the source" in refused.value.sentence


def test_a_catalog_never_synced_and_a_catalog_with_no_title_say_which() -> None:
    doc = mozilla_document()
    with pytest.raises(timelines.Unavailable) as never:
        timelines.jamf(timelines.JamfCatalog(size=0, refreshed_at=None, titles=()), doc, "firefox", "firefox/release")
    assert (never.value.state, never.value.sentence) == ("never_synced", timelines.JAMF_NEVER_SYNCED_SENTENCE)
    assert "needs no Jamf Pro connection" in never.value.sentence

    with pytest.raises(timelines.Unavailable) as none:
        timelines.jamf(catalog(size=1554), doc, "firefox", "firefox/release")
    assert none.value.state == "no_title"
    assert none.value.sentence.startswith(
        "This instance's copy of Jamf's public patch catalog has no title for Mozilla Firefox (bundle id org.mozilla.firefox)"
    )


def test_a_title_that_names_only_another_channel_leaves_the_track_with_no_jamf_timeline() -> None:
    doc = mozilla_document()
    with pytest.raises(timelines.Unavailable) as empty:
        timelines.jamf(catalog(FIREFOX_ESR_0B4), doc, "firefox", "firefox/release")
    assert empty.value.state == "channel_empty"
    assert empty.value.sentence == (
        "This instance's copy of Jamf's public patch catalog lists no Mozilla Firefox release on the release channel (0B4): "
        "every version it names is on another track's list, so Mozilla Firefox (release) has no Jamf timeline. Choose "
        "another track or source."
    )

    with pytest.raises(timelines.Unavailable) as nothing:
        timelines.jamf(
            catalog(jamf_title("0B3", "Mozilla Firefox", "org.mozilla.firefox", [])), doc, "firefox", "firefox/release"
        )
    assert nothing.value.state == "no_versions"


# --- Fleet -----------------------------------------------------------------------------------------


def fleet_title(slug: str, bundle: str, versions: list[tuple[str, dt.date]], **extra: Any) -> timelines.FleetTitle:
    fields = {"name": slug, "history_read_at": at("2026-11-20T08:00:00"), "version_changed_at": None}
    fields.update(extra)
    return timelines.FleetTitle(
        slug=slug,
        bundle_id=bundle,
        versions=tuple((v, dt.datetime.combine(when, dt.time(12), tzinfo=UTC)) for v, when in versions),
        **fields,
    )


def history(*titles: timelines.FleetTitle, enabled: bool = True, **extra: Any) -> timelines.FleetHistory:
    fields = {"catalog_read": True, "checked_ok_at": None, "catalog_detail": None, "history_failure": None}
    fields.update(extra)
    return timelines.FleetHistory(enabled=enabled, titles=tuple(titles), **fields)


FLEET_FIREFOX = fleet_title("firefox", "org.mozilla.firefox", RELEASES[12:])


def test_fleet_with_the_flag_off_says_the_flags_own_sentence() -> None:
    doc = mozilla_document()
    with pytest.raises(timelines.Unavailable) as off:
        timelines.fleet(history(FLEET_FIREFOX, enabled=False), doc, "firefox", "firefox/release")
    assert (off.value.state, off.value.sentence) == ("flag_off", fleet_catalog.FLAG_OFF)


def test_fleet_with_the_flag_on_dates_the_track_by_the_day_fleet_first_carried_each_version() -> None:
    doc = mozilla_document()
    timeline = timelines.fleet(history(FLEET_FIREFOX), doc, "firefox", "firefox/release")
    assert timeline.source == "fleet" and timeline.ids == ("firefox",)
    assert timeline.observations == tuple((v, when) for v, when in RELEASES[12:])
    assert timeline.note == timelines.FLEET_CLOCK and "Fleet's dates, not the vendor's" in timeline.note
    assert timeline.as_of == day("2026-11-20")  # the history was read then, and no later check confirmed it

    result = walk.walk(doc, app="firefox", track="firefox/release", timeline=timeline.walk_input())
    # Fleet's history starts at 140.0 (2025-06-10): the window starts 59 days after, not two years back.
    assert result["window"]["since"] == "2025-08-08"
    assert "timeline_coverage" in [row["reason"] for row in result["window"]["shortened_by"]]
    assert result["clocks"]["release_date"] == timelines.FLEET_CLOCK


def test_a_fleet_history_is_known_up_to_the_last_answered_check_that_saw_no_move() -> None:
    doc = mozilla_document()
    confirmed = history(FLEET_FIREFOX, checked_ok_at=at("2026-11-23T09:20:00"))
    assert timelines.fleet(confirmed, doc, "firefox", "firefox/release").as_of == day("2026-11-23")
    moved = history(
        fleet_title("firefox", "org.mozilla.firefox", RELEASES[12:], version_changed_at=at("2026-11-22T09:20:00")),
        checked_ok_at=at("2026-11-23T09:20:00"),
    )
    assert timelines.fleet(moved, doc, "firefox", "firefox/release").as_of == day("2026-11-20")


@pytest.mark.parametrize(
    ("held", "state", "opening"),
    [
        (history(catalog_read=False), "catalog_unread", "Fleet's catalog has not been read on this instance yet"),
        (
            history(catalog_read=False, catalog_detail="GitHub refused the request (rate limit)."),
            "catalog_unread",
            "Fleet's catalog has not been read on this instance yet, so there is no Fleet history to walk. The last "
            "check did not get an answer: GitHub refused the request (rate limit).",
        ),
        (history(), "not_held", "Fleet's catalog, as this instance last read it, holds no Mac title for Mozilla Firefox"),
        (
            history(fleet_title("firefox", "org.mozilla.firefox", [], history_read_at=None)),
            "history_unread",
            "Fleet's version history for firefox has not been read on this instance yet.",
        ),
        (
            history(
                fleet_title("firefox", "org.mozilla.firefox", [], history_read_at=None),
                history_failure="GitHub did not answer.",
            ),
            "history_failed",
            "Fleet's version history for firefox has not been read on this instance, and the last history read did not "
            "get an answer: GitHub did not answer.",
        ),
    ],
)
def test_each_fleet_state_says_which_it_is(held: timelines.FleetHistory, state: str, opening: str) -> None:
    with pytest.raises(timelines.Unavailable) as unavailable:
        timelines.fleet(held, mozilla_document(), "firefox", "firefox/release")
    assert unavailable.value.state == state
    assert unavailable.value.sentence.startswith(opening)


def test_fleets_catalog_has_no_esr_title_and_follows_only_the_newest_line() -> None:
    doc = mozilla_document()
    with pytest.raises(timelines.Unavailable) as esr:
        timelines.fleet(history(FLEET_FIREFOX), doc, "firefox", "firefox/esr")
    assert esr.value.state == "esr_missing"
    assert esr.value.sentence.startswith("Fleet's catalog has no Mozilla Firefox ESR title (firefox is the release channel)")


def test_fleet_follows_only_wiresharks_newest_line_so_the_held_line_has_no_fleet_timeline() -> None:
    """Fleet's `wireshark-app` carries only the newest line. In a document whose held track lists
    its own line alone (Wireshark 4.4's versions, inside the newest track's), every version Fleet
    names is the newest track's, and the held track says so. (A document whose held track lists
    the newer lines too reaches the walk, which refuses with `ceiling_line_undated`.)"""
    from tests.test_patch_policy_feed import DOC

    wireshark = fleet_title(
        "wireshark-app", "org.wireshark.Wireshark", [("4.6.0", day("2025-10-09")), ("4.6.1", day("2025-11-06"))]
    )
    with pytest.raises(timelines.Unavailable) as line:
        timelines.fleet(history(wireshark), DOC, "wireshark", "wireshark/4.4")
    assert line.value.state == "line_not_followed"
    assert line.value.sentence == (
        "This instance's Fleet history follows only Wireshark's newer lines (wireshark-app) and dates no Wireshark 4.4 "
        "release, so Wireshark 4.4 has no Fleet timeline. Choose a track that follows the newest line, or another source."
    )
    newest = timelines.fleet(history(wireshark), DOC, "wireshark", "wireshark/newest")
    assert [key for key, _ in newest.observations] == ["4.6.0", "4.6.1"] and newest.ids == ("wireshark-app",)


# --- public ----------------------------------------------------------------------------------------


def test_the_public_timeline_is_the_documents_own_dates_and_says_so_when_there_are_none() -> None:
    doc = mozilla_document()
    timeline = timelines.public(doc, "firefox", "firefox/release")
    assert timeline.ids == ("mozilla-firefox",) and timeline.as_of == day("2026-11-23")
    assert timeline.observations == tuple(RELEASES)
    assert timeline.other_track == ()

    undated = copy.deepcopy(doc)
    undated["apps"][0]["tracks"][0]["timeline"] = None
    with pytest.raises(timelines.Unavailable) as none:
        timelines.public(undated, "firefox", "firefox/release")
    assert none.value.state == "no_public_dates"
    assert none.value.sentence == (
        "LoonSec holds no public release dates for Mozilla Firefox yet. Jamf or Fleet may: they are read from this instance."
    )


def test_every_state_has_its_step_in_the_runbook() -> None:
    """docs/diagnosability.md rule 4: each source state's word is walked in §33."""
    from pathlib import Path

    runbook = (Path(__file__).resolve().parents[2] / "docs" / "troubleshooting.md").read_text()
    section = runbook.split('\n## 33. "', 1)[1].split("\n## ", 1)[0]
    for state in timelines.STATES:
        assert f"`{state}`" in section, f"§33 does not walk {state}"


def test_every_refusal_the_walk_route_can_answer_has_its_step_in_the_runbook() -> None:
    """Each `reason` a 409 from `GET /api/patch-policy/walk` can carry is walked in §33, the feed's
    own states aside (§32 walks those). Three of the walk's cannot reach the route: the copy's own
    check refuses a document of another kind or algorithm before it is stored, and the public
    timeline's absence is answered as `no_public_dates`."""
    from pathlib import Path

    runbook = (Path(__file__).resolve().parents[2] / "docs" / "troubleshooting.md").read_text()
    section = runbook.split('\n## 33. "', 1)[1].split("\n## ", 1)[0]
    unreachable = {walk.REFUSED_DOCUMENT_KIND, walk.REFUSED_ALGORITHM, walk.REFUSED_NO_PUBLIC_TIMELINE}
    reasons = {getattr(walk, name) for name in dir(walk) if name.startswith("REFUSED_")} - unreachable
    for reason in sorted(reasons | {views.REFUSED_UNCHECKED, walk.REFUSED_PARITY}):
        assert f"`{reason}`" in section, f"§33 does not walk {reason}"


# --- what the walk route makes of a walk -------------------------------------------------------


def _with_checks(doc: dict[str, Any], years: tuple[int, ...] = (2,)) -> dict[str, Any]:
    """The document as LoonVD publishes it: each track's `check` from the walk of its public dates."""
    done = copy.deepcopy(doc)
    done["doc_id"] = f"{doc['doc_id']}-checked"  # a content hash in life: another document, another id
    app = done["apps"][0]
    for track in app["tracks"]:
        timeline = timelines.public(done, app["app"], track["track"])
        track["check"] = {}
        for span in years:
            result = walk.walk(done, app=app["app"], track=track["track"], timeline=timeline.walk_input(), years=span)
            track["check"][f"{span}y"] = {stop: walk.check_totals(result, stop) for stop in walk.STOPS}
    return done


@pytest.fixture(autouse=True)
def _fresh_memo():
    views.reset_for_tests()
    yield
    views.reset_for_tests()


async def test_parity_matched_unchecked_and_refused_per_app() -> None:
    doc = _with_checks(mozilla_document(), years=(2,))
    app_row = doc["apps"][0]
    states = await views.app_parity(doc, app_row)
    assert states[("firefox/release", 2)] == ("matched", None, None)
    assert states[("firefox/release", 3)] == ("no_entry", None, None)

    assert views.check_for(states, app_row, "firefox/release", 2)["state"] == "matched"
    unchecked = views.check_for(states, app_row, "firefox/release", 3)
    assert unchecked == {
        "state": "unchecked_window",
        "detail": "LoonSec has no check for a 3-year window of Mozilla Firefox; it is shown because the 2-year walk matched.",
    }

    # No window of the app has published totals: nothing is shown, in words.
    bare = mozilla_document()
    with pytest.raises(views.Refused) as unchecked_everywhere:
        views.check_for(await views.app_parity(bare, bare["apps"][0]), bare["apps"][0], "firefox/release", 2)
    assert unchecked_everywhere.value.reason == "unchecked"
    assert unchecked_everywhere.value.sentence.startswith(
        "LoonSec has published no totals this build could match for any window of Mozilla Firefox"
    )
    assert unchecked_everywhere.value.facts["windows"] == {
        "firefox/release 2y": "no_entry",
        "firefox/release 3y": "no_entry",
        "firefox/esr 2y": "no_entry",
        "firefox/esr 3y": "no_entry",
    }

    # When the reason nothing matched is that the data fails the walk's own check, that is said instead.
    malformed = copy.deepcopy(bare)
    malformed["doc_id"] = "doc-firefox-malformed"
    for track in malformed["apps"][0]["tracks"]:
        track["not_detectable"] = {"count": "n/a"}
    with pytest.raises(views.Refused) as invalid:
        views.check_for(await views.app_parity(malformed, malformed["apps"][0]), malformed["apps"][0], "firefox/release", 2)
    assert invalid.value.reason == "document_invalid"
    assert invalid.value.sentence.startswith("LoonSec's patch-policy data for Mozilla Firefox")

    # One window that disagrees refuses every source and window of the app, the ESR track's too.
    broken = copy.deepcopy(doc)
    broken["doc_id"] = "doc-firefox-broken"
    broken["apps"][0]["tracks"][0]["check"]["2y"]["60d"]["exposed"] += 1
    states = await views.app_parity(broken, broken["apps"][0])
    with pytest.raises(views.Refused) as disagrees:
        views.check_for(states, broken["apps"][0], "firefox/esr", 2)
    assert disagrees.value.reason == "parity"
    assert "does not match the totals LoonSec published with the data (60d: exposed is" in disagrees.value.sentence


async def test_a_served_walk_keeps_every_total_and_series_and_trims_intervals_to_the_stop_asked_for(monkeypatch) -> None:
    doc = mozilla_document()
    timeline = timelines.public(doc, "firefox", "firefox/release")
    result = await views._walked(doc, app="firefox", track="firefox/release", timeline=timeline, years=2)
    monkeypatch.setattr(views, "PAGE_SIZE", 1)
    check = {"state": "matched", "detail": "."}

    first = views.served(result, timeline, check=check, stop="60d", page=1)
    assert first["policies"] == result["policies"] and first["counts"] == result["counts"]
    assert first["run_id"] == result["run_id"] and first["input_id"] == result["input_id"]
    assert first["cves_page"] == {"page": 1, "page_size": 1, "pages": 2, "total": 2}
    assert [row["cve_id"] for row in first["cves"]] == ["CVE-2025-0001"]
    outcomes = first["cves"][0]["outcomes"]
    assert set(outcomes) == set(walk.STOPS)
    assert "intervals" in outcomes["60d"] and all("intervals" not in outcomes[s] for s in walk.STOPS if s != "60d")
    assert first["intervals_for"] == "60d"
    # The walk held in memory is untouched by the trim: every stop that saw the CVE open keeps its days.
    held = next(row for row in result["cves"] if row["cve_id"] == "CVE-2025-0001")["outcomes"]
    assert [s for s in walk.STOPS if "intervals" in held[s]] == [s for s in walk.STOPS if held[s]["outcome"] == "exposed"]
    assert any("intervals" in held[s] for s in walk.STOPS if s != "60d")

    second = views.served(result, timeline, check=check, stop=None, page=2)
    assert [row["cve_id"] for row in second["cves"]] == ["CVE-2025-0002"]
    assert all("intervals" not in outcome for outcome in second["cves"][0]["outcomes"].values())
    past = views.served(result, timeline, check=check, stop=None, page=3)
    assert past["cves"] == [] and past["cves_page"]["pages"] == 2


async def test_the_same_input_is_walked_once() -> None:
    doc = mozilla_document()
    timeline = timelines.public(doc, "firefox", "firefox/release")
    first = await views._walked(doc, app="firefox", track="firefox/release", timeline=timeline, years=2)
    again = await views._walked(doc, app="firefox", track="firefox/release", timeline=timeline, years=2)
    assert again is first and len(views._walks) == 1
