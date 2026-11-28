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


def mozilla_document(
    app: str = "firefox", name: str = "Mozilla Firefox", *, esr_track: bool = True, esr_channel: bool = False
) -> dict[str, Any]:
    """A release track, with an ESR track beside it (`esr_track`), or the ESR channel named under
    the app's `other_channels` and not walked (`esr_channel`), as LoonVD emits Firefox and
    Thunderbird: versions spelled as an instance sees them (lowercase, no `esr` suffix), sorted,
    unique. 128.0 and 140.0 are on both the release list and the ESR one."""
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
    app_row: dict[str, Any] = {"app": app, "name": name, "bundle_ids": [f"org.mozilla.{app}"], "tracks": tracks}
    if esr_channel:
        app_row["other_channels"] = [
            {
                "channel": "esr",
                "label": f"{name} ESR",
                "source": f"https://product-details.mozilla.org/1.0/{app}.json",
                "versions": sorted({v for v, _ in ESR}),
            }
        ]
    return {
        "kind": "patch_policy_reference",
        "schema": 1,
        "doc_id": f"doc-{app}",
        "as_of": "2026-11-23T20:00:00Z",
        "algorithm": walk.ALGORITHM,
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
        "apps": [app_row],
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
    # Jamf dates the release a day after the vendor, and the 0-day stop installs on Jamf's day.
    first_install = result["policies"]["0d"]["installs"][0]
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
    """Membership needs both lists. A document that names the ESR channel neither as a track nor
    under `other_channels` cannot tell an ESR build from a version it has never heard of, so every
    ESR build in reach counts against the 5% limit, and the walk is refused in words rather than
    walked over a device that skips them."""
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
    # 128.0 and 140.0 are on both lists, so the sentence names them rather than claim every version
    # is another track's.
    assert empty.value.sentence == (
        "This instance's copy of Jamf's public patch catalog lists no Mozilla Firefox release on the release channel (0B4): "
        "none of the versions it names is this track's alone. It names versions on another track's list and numbers "
        "this track shares with another list (128.0, 140.0), so Mozilla Firefox (release) has no Jamf timeline. Choose "
        "another track or source."
    )

    with pytest.raises(timelines.Unavailable) as nothing:
        timelines.jamf(
            catalog(jamf_title("0B3", "Mozilla Firefox", "org.mozilla.firefox", [])), doc, "firefox", "firefox/release"
        )
    assert nothing.value.state == "no_versions"


# --- Fleet -----------------------------------------------------------------------------------------


def fleet_title(slug: str, bundle: str, versions: list[tuple[str, dt.date]], **extra: Any) -> timelines.FleetTitle:
    fields = {"name": slug, "history_read_at": at("2026-11-20T08:00:00"), "version_changed_at": None, "history_detail": None}
    fields.update(extra)
    return timelines.FleetTitle(
        slug=slug,
        bundle_id=bundle,
        versions=tuple((v, dt.datetime.combine(when, dt.time(12), tzinfo=UTC)) for v, when in versions),
        **fields,
    )


def history(*titles: timelines.FleetTitle, enabled: bool = True, **extra: Any) -> timelines.FleetHistory:
    """A complete snapshot unless the test says otherwise: `FleetHistory` itself has no default for
    it, so every other caller has to say."""
    fields = {
        "catalog_read": True,
        "checked_ok_at": None,
        "catalog_detail": None,
        "history_failure": None,
        "snapshot": "complete",
        "snapshot_detail": None,
        "answered_at": None,
    }
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
    # Fleet's history starts at 140.0 (2025-06-10): the window starts 60 days after, the 60-day stop's
    # wait, not two years back.
    assert result["window"]["since"] == "2025-08-09"
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


def test_a_fleet_title_read_for_the_esr_track_that_names_no_esr_build_says_what_was_read() -> None:
    doc = mozilla_document()
    with pytest.raises(timelines.Unavailable) as esr:
        timelines.fleet(history(FLEET_FIREFOX), doc, "firefox", "firefox/esr")
    assert esr.value.state == "esr_missing"
    assert esr.value.sentence == (
        "This instance's Fleet history (firefox) names no Mozilla Firefox ESR release: none of the versions it names is "
        "this track's alone. It names versions on another track's list and a number this track shares with another list "
        "(140.0), so Mozilla Firefox ESR has no Fleet timeline. Choose another source."
    )


def _esr_title(read: bool) -> timelines.FleetTitle:
    """Fleet's `firefox@esr`, under the same bundle id as `firefox`, spelling ESR builds as Homebrew does."""
    return fleet_title(
        "firefox@esr",
        "org.mozilla.firefox",
        [(f"{v}esr" if v.count(".") == 2 else v, when) for v, when in ESR[13:]],
        history_read_at=at("2026-11-21T08:00:00") if read else None,
    )


def test_a_held_fleet_title_whose_history_is_unread_is_named_never_dropped_in_silence() -> None:
    """Fleet holds `firefox@esr` beside `firefox`. Before its history is read, the ESR track says
    that history is unread (not that Fleet has no ESR title), and the release track's view, walked
    on what was read, names the title it could not include."""
    doc = mozilla_document()
    unread = history(FLEET_FIREFOX, _esr_title(read=False))
    with pytest.raises(timelines.Unavailable) as esr:
        timelines.fleet(unread, doc, "firefox", "firefox/esr")
    assert esr.value.state == "history_unread"
    assert esr.value.sentence.startswith(
        "Fleet's version history for firefox@esr has not been read on this instance yet, and the history read so far "
        "(firefox) dates nothing this track can walk."
    )
    with pytest.raises(timelines.Unavailable) as failed:
        failing = history(FLEET_FIREFOX, _esr_title(read=False), history_failure="GitHub did not answer.")
        timelines.fleet(failing, doc, "firefox", "firefox/esr")
    assert failed.value.state == "history_failed"

    release = timelines.fleet(unread, doc, "firefox", "firefox/release")
    assert release.ids == ("firefox",)
    assert release.note.startswith(timelines.FLEET_CLOCK)
    assert release.note.endswith(
        "Fleet's version history for firefox@esr has not been read on this instance, so its versions are not in this "
        "view; Read history on the Fleet catalog tab reads it (docs/troubleshooting.md §27)."
    )

    # Once it is read, the ESR track walks Fleet's ESR builds, and the release track sets them aside.
    both = history(FLEET_FIREFOX, _esr_title(read=True))
    assert {key for key, _ in timelines.fleet(both, doc, "firefox", "firefox/esr").observations} == {
        f"{v}esr" for v, _ in ESR[13:] if v.count(".") == 2
    } | {"140.0"}
    after = timelines.fleet(both, doc, "firefox", "firefox/release")
    assert after.ids == ("firefox", "firefox@esr") and after.note == timelines.FLEET_CLOCK
    assert {key for key, _ in after.observations} == {v for v, _ in RELEASES[12:]}


def test_two_read_fleet_titles_are_known_only_up_to_the_earlier_read() -> None:
    """A history is known up to the moment it was read; two titles walked together are known up
    to the earlier of the two, or the later one's versions would be walked past what the other
    knows."""
    doc = mozilla_document()
    later = fleet_title("firefox", "org.mozilla.firefox", RELEASES[12:], history_read_at=at("2026-11-22T08:00:00"))
    earlier = _esr_title(read=True)  # read 2026-11-21
    assert timelines.fleet(history(later, earlier), doc, "firefox", "firefox/release").as_of == day("2026-11-21")
    assert timelines.fleet(history(later), doc, "firefox", "firefox/release").as_of == day("2026-11-22")


# --- Fleet's catalog read only in part (`snapshot_status`, docs/fleet-catalog.md) -----------------

# The last check's own words while the titles held are partial (invented, in the shape the check
# writes them).
SKIPPED = "1 Mac manifest could not be read and was left as held: example-app (unrecognized Mac manifest path)."


def test_a_catalog_read_only_in_part_does_not_say_fleet_holds_no_title() -> None:
    """`not_held` concludes Fleet does not maintain the app, which only a complete read can show:
    a title missing from a partial or unread snapshot may be one this instance has not read."""
    doc = mozilla_document()
    with pytest.raises(timelines.Unavailable) as partial:
        timelines.fleet(history(snapshot="partial", snapshot_detail=SKIPPED), doc, "firefox", "firefox/release")
    assert partial.value.state == "catalog_partial"
    opening = (
        "Fleet's catalog, as this instance holds it, has no Mac title for Mozilla Firefox (bundle id org.mozilla.firefox), "
        "but this instance has read that catalog only in part, so the title may be one it has not read yet."
    )
    closing = (
        " Once a check reads the whole catalog, this source dates the track or says Fleet holds no title for the app; "
        "until then, choose another source (docs/troubleshooting.md §33 step 5)."
    )
    assert partial.value.sentence == f"{opening} The last check said: {SKIPPED}{closing}"
    # A check cut short after it had read some titles fails, and leaves them partial: its own words,
    # as the status line has them (§27 step 3, walked from §33 step 5), not the skipped-titles case.
    stopped = (
        "api.github.com refused the request (HTTP 403). 3 of the 9 manifests that had changed were read and kept; the "
        "next check reads the rest."
    )
    with pytest.raises(timelines.Unavailable) as cut:
        timelines.fleet(
            history(snapshot="partial", snapshot_detail=stopped, catalog_detail=stopped), doc, "firefox", "firefox/release"
        )
    assert cut.value.state == "catalog_partial"
    assert cut.value.sentence == f"{opening} The last check did not get an answer: {stopped}{closing}"
    # The 1.3.0 upgrade marks a catalog already read as partial and leaves no words: the sentence
    # says so rather than pointing at a status line with nothing on it.
    with pytest.raises(timelines.Unavailable) as upgraded:
        timelines.fleet(history(snapshot="partial"), doc, "firefox", "firefox/release")
    assert upgraded.value.sentence == opening + timelines.PARTIAL_NO_WORDS + closing
    assert timelines.PARTIAL_NO_WORDS == (
        " The last check left no words for it, which is how the 1.3.0 upgrade leaves a catalog it marked partial; the "
        "next check, within the hour, or Check now on the Fleet catalog tab reads it again."
    )
    # Titles held (of other bundle ids) under a snapshot still marked unread: the same.
    with pytest.raises(timelines.Unavailable) as unread:
        timelines.fleet(history(snapshot="unread"), doc, "firefox", "firefox/release")
    assert unread.value.state == "catalog_partial"
    assert "The last check said" not in unread.value.sentence
    assert unread.value.sentence == opening + timelines.PARTIAL_NO_WORDS + closing
    # Nothing held at all is still `catalog_unread`, whatever the snapshot says; a complete read is `not_held`.
    with pytest.raises(timelines.Unavailable) as nothing:
        timelines.fleet(history(catalog_read=False, snapshot="unread"), doc, "firefox", "firefox/release")
    assert nothing.value.state == "catalog_unread"
    with pytest.raises(timelines.Unavailable) as complete:
        timelines.fleet(history(snapshot_detail=SKIPPED), doc, "firefox", "firefox/release")
    assert complete.value.state == "not_held" and SKIPPED not in complete.value.sentence


PARTIAL_CUT = (
    " Fleet's catalog was read only in part, so the last check (2026-11-23) confirms no title's history past the day it "
    "was read (2026-11-20), and this view ends the day before; a check that reads the whole catalog carries it to that "
    "check's day (docs/troubleshooting.md §33 step 5)."
)


def test_a_held_title_under_a_partial_catalog_ends_at_its_read_and_the_note_says_why() -> None:
    """A partial check confirms nothing past a history's read, so the view ends the day before the
    read; the note says that the partial catalog is why, only when a complete check would have
    carried it further. The walk is unchanged: only the note grows."""
    doc = mozilla_document()
    answered = at("2026-11-23T09:20:00")
    partial = timelines.fleet(history(FLEET_FIREFOX, snapshot="partial", answered_at=answered), doc, "firefox", "firefox/release")
    assert partial.as_of == day("2026-11-20")
    assert partial.note == timelines.FLEET_CLOCK + PARTIAL_CUT
    result = walk.walk(doc, app="firefox", track="firefox/release", timeline=partial.walk_input())
    assert result["window"]["until"] == "2026-11-19"
    assert "timeline_as_of" in [row["reason"] for row in result["window"]["shortened_by"]]

    # The same check, complete: confirmed to its day, and nothing to say.
    complete = timelines.fleet(
        history(FLEET_FIREFOX, checked_ok_at=answered, answered_at=answered), doc, "firefox", "firefox/release"
    )
    assert complete.as_of == day("2026-11-23") and complete.note == timelines.FLEET_CLOCK
    # The sentence is about a partial catalog and is said of nothing else, whatever the other
    # fields hold: a complete history built with no confirming check ends at the read, silently.
    unconfirmed = timelines.fleet(history(FLEET_FIREFOX, answered_at=answered), doc, "firefox", "firefox/release")
    assert unconfirmed.as_of == day("2026-11-20") and unconfirmed.note == timelines.FLEET_CLOCK

    # Partial, and nothing a complete check would have changed: no answered check, one on the day of
    # the read, or a title whose version moved after its read (that view ends at the read anyway).
    moved = fleet_title("firefox", "org.mozilla.firefox", RELEASES[12:], version_changed_at=at("2026-11-21T09:20:00"))
    for held in (
        history(FLEET_FIREFOX, snapshot="partial"),
        history(FLEET_FIREFOX, snapshot="partial", answered_at=at("2026-11-20T09:20:00")),
        history(FLEET_FIREFOX, snapshot="partial", answered_at=at("2026-11-19T09:20:00")),
        history(moved, snapshot="partial", answered_at=answered),
    ):
        quiet = timelines.fleet(held, doc, "firefox", "firefox/release")
        assert quiet.as_of == day("2026-11-20") and quiet.note == timelines.FLEET_CLOCK


def test_a_titles_history_sentence_travels_with_the_view() -> None:
    """The history read's own words for a version it left undated: the version is not in the view,
    and a fix it carried counts from the next version the history dates."""
    doc = mozilla_document()
    detail = (
        "2 of the 40 changes did not carry a manifest this build could read, so a version that arrived at one of them has "
        "no date."
    )
    gappy = fleet_title("firefox", "org.mozilla.firefox", RELEASES[12:], history_detail=detail)
    timeline = timelines.fleet(history(gappy), doc, "firefox", "firefox/release")
    assert timeline.note == (
        timelines.FLEET_CLOCK + f" Fleet's version history for firefox: {detail} A version left undated there is not in "
        "this view, and a fix it carried is dated by the next version this history dates (docs/troubleshooting.md §27 "
        "step 10, §33 step 12)."
    )
    # The note is not walked: the walk's input is the same with or without it.
    plain = timelines.fleet(history(FLEET_FIREFOX), doc, "firefox", "firefox/release")
    assert timeline.walk_input() == plain.walk_input() and timeline.digest == plain.digest


def test_a_refusal_concluded_from_the_titles_read_says_the_catalog_was_read_only_in_part() -> None:
    """`firefox` read alone names no ESR build. Under a partial catalog Fleet's ESR title may be one
    this instance has not read, so the sentence says so; under a complete one it does not."""
    doc = mozilla_document()
    with pytest.raises(timelines.Unavailable) as complete:
        timelines.fleet(history(FLEET_FIREFOX), doc, "firefox", "firefox/esr")
    with pytest.raises(timelines.Unavailable) as partial:
        timelines.fleet(history(FLEET_FIREFOX, snapshot="partial"), doc, "firefox", "firefox/esr")
    assert (complete.value.state, partial.value.state) == ("esr_missing", "esr_missing")
    assert timelines.PARTIAL_TAIL not in complete.value.sentence
    assert partial.value.sentence == complete.value.sentence + timelines.PARTIAL_TAIL
    assert timelines.PARTIAL_TAIL == (
        " This instance has read Fleet's catalog only in part, so another Fleet title under this bundle id may be among "
        "those not read (docs/troubleshooting.md §33 step 5)."
    )
    # The same for `no_versions`; a history not read yet is about that title, and says only that.
    empty = fleet_title("firefox", "org.mozilla.firefox", [])
    with pytest.raises(timelines.Unavailable) as none:
        timelines.fleet(history(empty, snapshot="partial"), doc, "firefox", "firefox/release")
    assert none.value.state == "no_versions" and none.value.sentence.endswith(timelines.PARTIAL_TAIL)
    with pytest.raises(timelines.Unavailable) as unread:
        timelines.fleet(history(FLEET_FIREFOX, _esr_title(read=False), snapshot="partial"), doc, "firefox", "firefox/esr")
    assert unread.value.state == "history_unread" and timelines.PARTIAL_TAIL not in unread.value.sentence


def test_catalog_partial_is_a_state_with_its_step() -> None:
    assert timelines.FLEET_CATALOG_PARTIAL == "catalog_partial"
    states = list(timelines.STATES)
    assert states.index("catalog_partial") == states.index("not_held") + 1


def _held_lists_every_line(doc: dict[str, Any]) -> dict[str, Any]:
    """The fixture's Wireshark as LoonVD emits it: the held track lists every line, the newest
    track's list, and holds the device to its ceiling line by `path`, not by what it lists."""
    shaped = copy.deepcopy(doc)
    app = next(app for app in shaped["apps"] if app["app"] == "wireshark")
    held, newest = app["tracks"]
    held["versions"] = copy.deepcopy(newest["versions"])
    held["counts"] = {**held["counts"], "versions": len(held["versions"]), "versions_dated": len(held["versions"])}
    return shaped


def test_fleet_follows_only_wiresharks_newest_line_so_the_held_line_has_no_fleet_timeline() -> None:
    """Fleet's `wireshark-app` carries only the newest line. The held track holds the device to
    Wireshark 4.4 (`path.ceiling_line`), and Fleet dates no release the document puts on that line,
    so the held track says so: whether its list is 4.4's alone (the fixture) or every line (as
    LoonVD emits it, where the walk would otherwise refuse with `nothing_to_install`)."""
    from tests.test_patch_policy_feed import DOC

    wireshark = fleet_title(
        "wireshark-app", "org.wireshark.Wireshark", [("4.6.0", day("2025-10-09")), ("4.6.1", day("2025-11-06"))]
    )
    for doc in (DOC, _held_lists_every_line(DOC)):
        with pytest.raises(timelines.Unavailable) as line:
            timelines.fleet(history(wireshark), doc, "wireshark", "wireshark/4.4")
        assert line.value.state == "line_not_followed"
        assert line.value.sentence == (
            "This instance's Fleet history (wireshark-app) dates no Wireshark 4.4 release, so the Wireshark 4.4 device has "
            "no line to hold and there is no Fleet timeline for it. Fleet's catalog carries only an app's newest line. "
            "Choose a track that follows the newest line, or another source."
        )
        newest = timelines.fleet(history(wireshark), doc, "wireshark", "wireshark/newest")
        assert [key for key, _ in newest.observations] == ["4.6.0", "4.6.1"] and newest.ids == ("wireshark-app",)

    # A Jamf catalog that holds the 4.4 title walks the held track either way.
    held_line = [("4.4.0", day("2024-08-28")), ("4.4.1", day("2024-10-09"))]
    titles = catalog(
        jamf_title("661", "Wireshark 4.4", "org.wireshark.Wireshark", held_line),
        jamf_title("817", "Wireshark 4.6", "org.wireshark.Wireshark", [("4.6.0", day("2025-10-08"))]),
    )
    for doc in (DOC, _held_lists_every_line(DOC)):
        assert {key for key, _ in timelines.jamf(titles, doc, "wireshark", "wireshark/4.4").observations} >= {"4.4.0", "4.4.1"}


def test_no_versions_says_what_to_check_for_each_source() -> None:
    doc = mozilla_document()
    empty = catalog(jamf_title("0B3", "Mozilla Firefox", "org.mozilla.firefox", []))
    with pytest.raises(timelines.Unavailable) as jamf:
        timelines.jamf(empty, doc, "firefox", "firefox/release")
    assert jamf.value.state == "no_versions"
    assert "Sync now on Devices › Applications › Jamf Patch reads the catalog again (docs/troubleshooting.md §6)" in (
        jamf.value.sentence
    )
    with pytest.raises(timelines.Unavailable) as fleet:
        timelines.fleet(history(fleet_title("firefox", "org.mozilla.firefox", [])), doc, "firefox", "firefox/release")
    assert fleet.value.state == "no_versions"
    assert fleet.value.sentence == (
        "This instance's Fleet history names no Mozilla Firefox version (firefox), so there is nothing to walk. The "
        "title's history on the Fleet catalog tab says why a version is left out (docs/troubleshooting.md §27 step 10); "
        "if it reads the same after Read again, choose another source."
    )


# --- other channels: named by LoonSec's document, set aside, never walked -------------------------

ESR_ONLY = sorted({v for v, _ in ESR} - {v for v, _ in RELEASES})


def test_the_documents_other_channels_are_read_lowercased_in_order_and_anything_malformed_is_skipped() -> None:
    row = {
        "other_channels": [
            {"channel": "esr", "label": "Firefox ESR", "source": "https://example.test/esr", "versions": ["128.5.1", "128.5.0"]},
            {"channel": "beta", "label": "Firefox Beta", "source": "https://example.test/beta", "versions": [" 147.0B1 "]},
            "not a channel",
            {"label": "no id"},
        ]
    }
    channels = timelines.other_channels(row)
    assert [(c.channel, c.label, c.versions) for c in channels] == [
        ("esr", "Firefox ESR", ("128.5.0", "128.5.1")),
        ("beta", "Firefox Beta", ("147.0b1",)),
    ]
    for absent in ({}, {"other_channels": None}, {"other_channels": []}, {"other_channels": "esr"}):
        assert timelines.other_channels(absent) == ()


def test_jamfs_firefox_and_firefox_esr_titles_walk_the_release_track_with_the_esr_builds_set_aside() -> None:
    """The e2e defect: LoonSec's document lists the release track only, and Jamf's 0B3 and 0B4 share
    org.mozilla.firefox. With the ESR channel named under `other_channels`, its builds are set aside
    before the walk, so the release track walks instead of being refused for them as unmatched."""
    refused_before = mozilla_document(esr_track=False)
    with pytest.raises(walk.WalkRefused) as before:
        timeline = timelines.jamf(catalog(FIREFOX_0B3, FIREFOX_ESR_0B4), refused_before, "firefox", "firefox/release")
        walk.walk(refused_before, app="firefox", track="firefox/release", timeline=timeline.walk_input())
    assert before.value.reason == walk.REFUSED_UNMATCHED

    doc = mozilla_document(esr_track=False, esr_channel=True)
    timeline = timelines.jamf(catalog(FIREFOX_0B3, FIREFOX_ESR_0B4), doc, "firefox", "firefox/release")
    assert {key for key, _ in timeline.observations} == {v for v, _ in RELEASES}
    assert timeline.other_track == ()
    assert [(c.channel, c.label, c.versions) for c in timeline.other_channel] == [("esr", "Mozilla Firefox ESR", tuple(ESR_ONLY))]
    # Counted, never worded in the note: the page says it once, in the reader's language.
    assert timeline.note is None

    result = walk.walk(doc, app="firefox", track="firefox/release", timeline=timeline.walk_input())
    joined = result["inputs"]["timeline"]
    assert (joined["matched"], joined["unmatched"], joined["other_track"]) == (len(RELEASES), [], 0)
    assert joined["in_reach"]["unmatched"] == []

    whole = views.served(result, timeline, check={"state": "matched", "detail": "."}, stop=None, page=1)
    # The walk's `join` says a version no track lists is unmatched; the definition served after it
    # says what was set aside first, and the walk's own words are left as they are.
    keys = list(whole["definitions"])
    assert keys[keys.index("join") + 1] == "other_channel"
    assert whole["definitions"]["join"] == walk.DEFINITIONS["join"]
    assert whole["definitions"]["other_channel"] == views.OTHER_CHANNEL_DEFINITION
    assert "other_channel" not in walk.DEFINITIONS and "other_channel" not in result["definitions"]
    served = whole["inputs"]["timeline"]
    assert (served["other_track"], served["other_track_versions"]) == (0, [])
    assert served["other_channel"] == len(ESR_ONLY)
    assert served["other_channels"] == [
        {
            "channel": "esr",
            "label": "Mozilla Firefox ESR",
            "source": "https://product-details.mozilla.org/1.0/firefox.json",
            "count": len(ESR_ONLY),
            "versions": ESR_ONLY,
        }
    ]
    assert served["note"] is None


def test_thunderbirds_interleaved_title_walks_the_release_track_with_the_esr_builds_set_aside() -> None:
    doc = mozilla_document("thunderbird", "Mozilla Thunderbird", esr_track=False, esr_channel=True)
    interleaved = jamf_title("0E1", "Mozilla Thunderbird", "org.mozilla.thunderbird", RELEASES + ESR)
    timeline = timelines.jamf(catalog(interleaved), doc, "thunderbird", "thunderbird/release")
    assert {key for key, _ in timeline.observations} == {v for v, _ in RELEASES}
    assert [c.versions for c in timeline.other_channel] == [tuple(ESR_ONLY)]
    assert timeline.note is None
    result = walk.walk(doc, app="thunderbird", track="thunderbird/release", timeline=timeline.walk_input())
    assert result["inputs"]["timeline"]["unmatched"] == []


def test_fleets_firefox_esr_title_read_beside_firefox_is_set_aside_and_the_release_track_walks() -> None:
    """Fleet holds `firefox@esr` beside `firefox` under one bundle id, and spells its builds as
    Jamf does (153.7.0, no `esr` suffix: what the e2e stack read). Once its history is read, the
    release track's Fleet view sets those builds aside; before this, the view flipped to refused."""
    doc = mozilla_document(esr_track=False, esr_channel=True)
    esr = fleet_title("firefox@esr", "org.mozilla.firefox", ESR[13:], history_read_at=at("2026-11-21T08:00:00"))
    timeline = timelines.fleet(history(FLEET_FIREFOX, esr), doc, "firefox", "firefox/release")
    assert timeline.ids == ("firefox", "firefox@esr")
    assert {key for key, _ in timeline.observations} == {v for v, _ in RELEASES[12:]}
    assert [c.versions for c in timeline.other_channel] == [tuple(sorted(v for v, _ in ESR[14:]))]
    # The note is Fleet's own, and says nothing of the set-aside builds: the page says that once.
    assert timeline.note == timelines.FLEET_CLOCK
    result = walk.walk(doc, app="firefox", track="firefox/release", timeline=timeline.walk_input())
    assert result["inputs"]["timeline"]["unmatched"] == []

    # Without the channel named, the same history refuses the view, as the e2e stack saw.
    bare = mozilla_document(esr_track=False)
    with pytest.raises(walk.WalkRefused) as refused:
        unnamed = timelines.fleet(history(FLEET_FIREFOX, esr), bare, "firefox", "firefox/release")
        walk.walk(bare, app="firefox", track="firefox/release", timeline=unnamed.walk_input())
    assert refused.value.reason == walk.REFUSED_UNMATCHED


def test_a_version_a_track_lists_is_the_tracks_whatever_channel_also_lists_it() -> None:
    """Track membership wins: 140.0 is on the release list and on the ESR channel's (ESR 153.0
    shares its number with release 153.0 the same way), so it is matched to the release track and
    walked, never set aside. A version another track lists is that track's before any channel's."""
    doc = mozilla_document(esr_track=False, esr_channel=True)
    app_row = doc["apps"][0]
    observations = [("140.0", day("2025-06-24")), ("140.1.0", day("2025-07-22")), ("147.0b1", day("2026-01-01"))]
    joined = timelines.split(observations, app_row, "firefox/release")
    assert joined.matched == ("140.0",) and ("140.0", day("2025-06-24")) in joined.kept
    assert [(c.channel, c.versions) for c in joined.other_channel] == [("esr", ("140.1.0",))]
    assert joined.unmatched == ("147.0b1",) and joined.other == ()

    # With an ESR track and the same channel named too, the track takes its builds first.
    both = mozilla_document(esr_track=True, esr_channel=True)
    joined = timelines.split(observations, both["apps"][0], "firefox/release")
    assert joined.other == ("140.1.0",) and joined.other_channel == ()


def _channels_app(*channels: tuple[str, list[str]], release: list[str]) -> dict[str, Any]:
    """A bare app row: one release track listing `release`, and each channel named with its versions."""
    return {
        "app": "demo",
        "name": "Demo",
        "tracks": [{"track": "demo/release", "versions": [{"v": v, "keys": [v]} for v in release]}],
        "other_channels": [
            {"channel": channel, "label": f"Demo {channel}", "source": "https://example.test/demo.json", "versions": versions}
            for channel, versions in channels
        ],
    }


def test_a_track_whose_every_version_a_channel_also_lists_still_walks_what_it_matches() -> None:
    """`lists_exclusive` counts the channels as well as the other tracks (w3 review, mutant M5). Every
    version of this release track is on the ESR channel's list too, so the track lists nothing of its
    own alone, and a timeline naming one of them is the track's: the view walks rather than being
    refused for naming no version only this track lists."""
    app_row = _channels_app(("esr", ["1.0", "1.5.0", "2.0"]), release=["1.0", "2.0"])
    joined = timelines.split([("1.0", day("2026-01-01")), ("1.5.0", day("2026-02-01"))], app_row, "demo/release")
    assert (joined.matched, joined.exclusive, joined.lists_exclusive) == (("1.0",), (), False)
    assert [(c.channel, c.versions) for c in joined.other_channel] == [("esr", ("1.5.0",))]
    assert joined.channel_missing is False


def test_a_version_two_channels_list_is_set_aside_as_the_first_listed_channels() -> None:
    """The first channel the document lists wins a version two channels share (w3 review, mutant M7),
    as `split` documents and the copy's check accepts."""
    app_row = _channels_app(("esr", ["1.5.0"]), ("beta", ["1.5.0", "1.6b1"]), release=["1.0"])
    joined = timelines.split(
        [("1.0", day("2026-01-01")), ("1.5.0", day("2026-02-01")), ("1.6b1", day("2026-02-02"))], app_row, "demo/release"
    )
    assert [(c.channel, c.versions) for c in joined.other_channel] == [("esr", ("1.5.0",)), ("beta", ("1.6b1",))]


def test_a_timeline_that_spells_mozillas_esr_suffix_is_matched_without_it_and_a_track_still_wins() -> None:
    """LoonSec lists a channel's versions without Mozilla's `esr` suffix; Jamf and Fleet spell them
    without it today, and a timeline that spells it is matched by its spelling without it, after its
    spelling as given. Track membership still wins: `140.0esr` is the release track's 140.0 (the
    number both lists share), kept under the spelling the track lists. `128.5.0esr` is set aside as
    the ESR channel's 128.5.0. A spelling nobody lists either way stays unmatched as given."""
    doc = mozilla_document(esr_track=False, esr_channel=True)
    observations = [
        ("140.0esr", day("2025-06-25")),
        ("129.0", day("2024-08-06")),
        ("128.5.0esr", day("2024-11-26")),
        ("9.9esr", day("2024-01-01")),
        ("esr", day("2024-01-02")),
    ]
    joined = timelines.split(observations, doc["apps"][0], "firefox/release")
    assert joined.matched == ("129.0", "140.0")
    assert ("140.0", day("2025-06-25")) in joined.kept and ("140.0esr", day("2025-06-25")) not in joined.kept
    assert [(c.channel, c.versions) for c in joined.other_channel] == [("esr", ("128.5.0",))]
    assert joined.unmatched == ("9.9esr", "esr") and joined.other == ()

    # A track that lists the suffixed spelling itself takes it as given: here the ESR track's keys
    # carry `128.5.0esr`, so the release view sets it aside as that track's, before any channel.
    both = mozilla_document(esr_track=True, esr_channel=True)
    joined = timelines.split(observations, both["apps"][0], "firefox/release")
    assert joined.other == ("128.5.0esr",) and joined.other_channel == ()
    esr = timelines.split(observations, both["apps"][0], "firefox/esr")
    assert "128.5.0esr" in esr.matched
    # The spelling as given is tried against every track before the one without the suffix: another
    # track listing `2.0esr` takes it, though this track lists `2.0`.
    two = {
        "app": "demo",
        "tracks": [
            {"track": "demo/release", "versions": [{"v": "2.0", "keys": ["2.0"]}]},
            {"track": "demo/esr", "versions": [{"v": "2.0", "keys": ["2.0esr"]}]},
        ],
    }
    joined = timelines.split([("2.0esr", day("2026-01-01"))], two, "demo/release")
    assert (joined.matched, joined.other) == ((), ("2.0esr",))
    # Another track that lists only the bare spelling takes the suffixed key by it, and the key is set
    # aside under the spelling that track lists: `3.0esr` is demo/esr's 3.0, never `3.0esr`.
    bare_other = {
        "app": "demo",
        "tracks": [
            {"track": "demo/release", "versions": [{"v": "2.0", "keys": ["2.0"]}]},
            {"track": "demo/esr", "versions": [{"v": "3.0", "keys": ["3.0"]}]},
        ],
    }
    joined = timelines.split([("3.0esr", day("2026-01-01")), ("2.0", day("2026-01-02"))], bare_other, "demo/release")
    assert (joined.matched, joined.other, joined.unmatched) == (("2.0",), ("3.0",), ())
    # Only Mozilla's whole `esr` suffix is dropped: a spelling that merely ends in one of its letters
    # stays as given, and unmatched.
    joined = timelines.split([("129.0r", day("2024-08-06")), ("129.0s", day("2024-08-06"))], doc["apps"][0], "firefox/release")
    assert (joined.matched, joined.unmatched) == ((), ("129.0r", "129.0s"))

    # End to end: Jamf's ESR title spelled with the suffix, beside the release title, still walks the
    # release track with the ESR builds set aside.
    suffixed = jamf_title(
        "0B4", "Mozilla Firefox ESR", "org.mozilla.firefox", [(v if v.count(".") < 2 else f"{v}esr", when) for v, when in ESR]
    )
    timeline = timelines.jamf(catalog(FIREFOX_0B3, suffixed), doc, "firefox", "firefox/release")
    assert {key for key, _ in timeline.observations} == {v for v, _ in RELEASES}
    assert [c.versions for c in timeline.other_channel] == [tuple(ESR_ONLY)]
    result = walk.walk(doc, app="firefox", track="firefox/release", timeline=timeline.walk_input())
    assert result["inputs"]["timeline"]["unmatched"] == []


def test_a_title_that_names_only_a_channel_that_is_not_walked_says_so_instead_of_walking_a_shared_number() -> None:
    """Jamf's ESR title alone, read for the release track, names release 140.0 and 128.0 (shared)
    and ESR builds. Walking it would keep a device on 140.0 for a year; the release track lists
    versions of its own and the title names none of them, so the view is refused, naming the channel."""
    doc = mozilla_document(esr_track=False, esr_channel=True)
    with pytest.raises(timelines.Unavailable) as empty:
        timelines.jamf(catalog(FIREFOX_ESR_0B4), doc, "firefox", "firefox/release")
    assert empty.value.state == "channel_empty"
    assert empty.value.sentence == (
        "This instance's copy of Jamf's public patch catalog lists no Mozilla Firefox release on the release channel (0B4): "
        "none of the versions it names is this track's alone. It names numbers this track shares with another list "
        "(128.0, 140.0) and builds of Mozilla Firefox ESR, a channel LoonSec's data does not walk yet, so Mozilla Firefox "
        "(release) has no Jamf timeline. Choose another track or source."
    )

    # What Jamf's ESR title really names (w3 review): the shared numbers, the listed ESR builds, and
    # older ESR builds the channel's list does not hold. Each kind is said, and none is overstated.
    older = jamf_title("0B4", "Mozilla Firefox ESR", "org.mozilla.firefox", [*ESR, ("115.18.0", day("2024-11-26"))])
    with pytest.raises(timelines.Unavailable) as mixed:
        timelines.jamf(catalog(older), doc, "firefox", "firefox/release")
    assert mixed.value.state == "channel_empty"
    assert (
        "none of the versions it names is this track's alone. It names numbers this track shares with another list "
        "(128.0, 140.0), versions LoonSec's data does not list and builds of Mozilla Firefox ESR, a channel LoonSec's "
        "data does not walk yet, so Mozilla Firefox (release) has no Jamf timeline."
    ) in mixed.value.sentence


async def test_the_apps_route_counts_each_tracks_set_aside_versions_and_leaves_the_note_to_the_source() -> None:
    doc = _with_checks(mozilla_document(esr_track=False, esr_channel=True))
    sources = await views.sources_of(doc, catalog(FIREFOX_0B3, FIREFOX_ESR_0B4), history(enabled=False))
    jamf_source = sources["firefox"]["jamf"]
    assert jamf_source["available"] is True and jamf_source["note"] is None
    (release,) = jamf_source["tracks"]
    assert (release["matched"], release["other_track"], release["other_channel"], release["unmatched"]) == (
        len(RELEASES),
        0,
        len(ESR_ONLY),
        0,
    )


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
        "LoonSec holds no public release dates for Mozilla Firefox (release) yet, so it has none of its own to walk."
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
    own states aside (§32 walks those). Two of the walk's cannot reach the route: the copy's own
    check refuses a document of another kind before it is stored, and the public timeline's absence
    is answered as `no_public_dates`. A copy of another algorithm can, though this build refuses to
    store one: a copy an older build stored before the update that moved the algorithm (#953)."""
    from pathlib import Path

    runbook = (Path(__file__).resolve().parents[2] / "docs" / "troubleshooting.md").read_text()
    section = runbook.split('\n## 33. "', 1)[1].split("\n## ", 1)[0]
    unreachable = {walk.REFUSED_DOCUMENT_KIND, walk.REFUSED_NO_PUBLIC_TIMELINE}
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
    assert states[("firefox/release", 2)] == ("matched", None, None, {})
    assert states[("firefox/release", 3)] == ("no_entry", None, None, {})

    # One check serves every source and aligned window of the track, so it names the walk it is of:
    # the label alone (labels begin with the app's name), never "this view matches".
    matched = {
        "state": "matched",
        "detail": "The walk of LoonSec's published dates for Mozilla Firefox (release) over 2 years matches the totals "
        "LoonSec published with the data.",
    }
    assert views.check_for(states, app_row, "firefox/release", 2) == matched
    unchecked = views.check_for(states, app_row, "firefox/release", 3)
    assert unchecked == {
        "state": "unchecked_window",
        "detail": "LoonSec has no check for a 3-year window of Mozilla Firefox; it is shown because the 2-year walk matched.",
    }
    # Only the walk of LoonSec's published dates is checked: a matched window says which walk that
    # was, on every view; an unchecked window on other dates, or cut to the common days, says so.
    assert views.check_for(states, app_row, "firefox/release", 2, source="jamf") == matched
    assert views.check_for(states, app_row, "firefox/release", 2, aligned=True) == matched
    assert views.check_for(states, app_row, "firefox/release", 3, source="fleet")["detail"] == (
        "LoonSec has no check for a 3-year window of Mozilla Firefox; it is shown because the 2-year walk of LoonSec's "
        "published dates matched. This view's dates come from this instance's Fleet history, and its own numbers are "
        "not checked."
    )
    assert views.check_for(states, app_row, "firefox/release", 3, aligned=True)["detail"].endswith(
        "This view is cut to the days the sources share, and its own numbers are not checked."
    )

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
    # The track's label names the app, once.
    assert invalid.value.sentence.startswith("LoonSec's patch-policy data for Mozilla Firefox (release) failed")

    # An app LoonSec holds no public dates for has nothing to check, and every view of it says so.
    undated = copy.deepcopy(bare)
    undated["doc_id"] = "doc-firefox-undated"
    for track in undated["apps"][0]["tracks"]:
        track["timeline"] = None
    with pytest.raises(views.Refused) as no_dates:
        views.check_for(await views.app_parity(undated, undated["apps"][0]), undated["apps"][0], "firefox/release", 2)
    assert no_dates.value.reason == "no_public_dates"
    assert no_dates.value.sentence == (
        "LoonSec holds no public release dates for Mozilla Firefox yet, so no walk of Mozilla Firefox can be checked "
        "against the totals LoonSec publishes, and no view of it is shown from any source, Jamf and Fleet included: a "
        "view is shown only once the walk of LoonSec's own dates for one of the app's windows matches those totals. "
        "Nothing on this instance is wrong."
    )

    # One window that disagrees refuses every source and window of the app, the ESR track's too.
    broken = copy.deepcopy(doc)
    broken["doc_id"] = "doc-firefox-broken"
    broken["apps"][0]["tracks"][0]["check"]["2y"]["60d"]["exposed"] += 1
    states = await views.app_parity(broken, broken["apps"][0])
    with pytest.raises(views.Refused) as disagrees:
        views.check_for(states, broken["apps"][0], "firefox/esr", 2)
    assert disagrees.value.reason == "parity"
    assert disagrees.value.sentence.startswith(
        "The walk of LoonSec's published dates for Mozilla Firefox (release) over 2 years does not match the totals "
        "LoonSec published with the data (60d: exposed is"
    )
    # The totals that disagreed travel with the refusal, for the page to list beside it.
    published = broken["apps"][0]["tracks"][0]["check"]["2y"]["60d"]["exposed"]
    assert disagrees.value.facts == {"stop": "60d", "key": "exposed", "walked": published - 1, "published": published}


async def test_a_track_or_app_with_no_check_refuses_only_itself_and_the_rest_of_the_document_is_served() -> None:
    """What LoonSec's publisher may now leave in a nightly document (a track with no check for a window,
    for want of a public timeline or of a dated day) costs only that track or app, here, never the
    document: the copy's check does not read `check`, and parity is judged per app.
      - Firefox's release track matched at 2 years; its ESR track has no public dates and no check.
        Its Public view is refused in its own words (`no_public_dates`, step 3); a Jamf or Fleet view of
        it is shown as an unchecked window, because the release walk matched.
      - Thunderbird has no check for any window: every view of it is refused (`unchecked`, step 7),
        and Firefox's sources are unaffected."""
    doc = _with_checks(mozilla_document(), years=(2,))
    esr = doc["apps"][0]["tracks"][1]
    esr["timeline"], esr["check"] = None, {}
    other = mozilla_document("thunderbird", "Mozilla Thunderbird")
    doc["apps"].append(other["apps"][0])
    doc["sources"]["timelines"].update(other["sources"]["timelines"])
    firefox, thunderbird = doc["apps"]

    states = await views.app_parity(doc, firefox)
    assert states[("firefox/esr", 2)].reason == "no_public_dates"
    with pytest.raises(timelines.Unavailable) as public_esr:
        timelines.public(doc, "firefox", "firefox/esr")
    assert public_esr.value.state == "no_public_dates"
    assert views.check_for(states, firefox, "firefox/esr", 2, source="jamf")["state"] == "unchecked_window"
    assert views.check_for(states, firefox, "firefox/release", 3)["state"] == "unchecked_window"

    with pytest.raises(views.Refused) as refused:
        views.check_for(await views.app_parity(doc, thunderbird), thunderbird, "thunderbird/release", 2)
    assert refused.value.reason == "unchecked"

    sources = await views.sources_of(doc, catalog(), history(enabled=False))
    assert sources["firefox"]["public"]["available"] is True
    assert {track["track"]: track["state"] for track in sources["firefox"]["public"]["tracks"]} == {
        "firefox/release": "available",
        "firefox/esr": "no_public_dates",
    }
    assert sources["thunderbird"]["public"]["state"] == "unchecked"


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
