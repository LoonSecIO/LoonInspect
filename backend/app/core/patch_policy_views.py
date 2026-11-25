"""What Posture > Patch policy's routes answer (#614): which sources can date each app, and one walk.

`app.api.patch_policy` is the HTTP half; this is the rest. Two questions:

- **`app_sources`**, for `GET /api/patch-policy/apps`: for every app the held document references,
  and every track of it, whether each of the three timelines (`app.core.patch_policy_timelines`)
  can date it and what a default two-year walk would cover. A source that cannot answers with its
  state word and sentence, the same words the walk route refuses with.
- **`walk_view`**, for `GET /api/patch-policy/walk`: one app, track, source and window, walked by
  `app.core.patch_policy_walk` over the held document, memoised by the walk's `input_id`, held to
  parity with LoonSec's published totals, and trimmed for the wire.

**Parity, per app** (plan 4.7). The walk of LoonSec's own published dates at a default window
must equal the totals LoonSec published for it (`check`). Every window of the app is walked once
per document (memoised): a window whose totals disagree refuses every source of the app; a
window that matched unlocks the app's other sources and `align=common`; a window with no
published totals is shown as an *unchecked window* when another window of the app matched, and
refused otherwise.

**Trimmed, never re-counted** (2026-11-24). A Chrome-sized walk is several megabytes,
most of it per-CVE day intervals under six stops. The response keeps every total and the whole
per-day series of every stop, keeps each CVE's outcome under every stop, keeps the day intervals
only for the stop asked for (`stop`), and pages `cves[]`. `run_id` names the walk as computed,
before it was trimmed or paged.

Nothing here reads a device, and nothing a walk returns is stored, queued or exchanged.
Every refusal's sentence is walked in docs/troubleshooting.md §33.
"""

from __future__ import annotations

import asyncio
import math
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core import patch_policy_feed as feed
from app.core import patch_policy_timelines as timelines
from app.core import patch_policy_walk as walk

PAGE_SIZE = 200
ALIGN_COMMON = "common"

# `check.state` on a served walk.
CHECK_MATCHED = "matched"
CHECK_UNCHECKED = "unchecked_window"
# The refusal when no window of the app has published totals this build matched.
REFUSED_UNCHECKED = "unchecked"

# A refusal as it is kept: its reason, sentence and detail. The exception itself is not kept, so
# raising it again never lengthens a traceback that holds the walk's frames.
_Refusal = tuple[str, str, dict[str, Any]]
# The walks kept in this process, by `input_id`. A Chrome-sized walk is several megabytes, and a
# page asks for the same few again and again as the slider and the toggle move.
_WALKS_KEPT = 8
_walks: OrderedDict[str, dict[str, Any] | _Refusal] = OrderedDict()
# Each app's parity, by (doc_id, app): per (track, years), its state, the walk's reason when it
# was refused, and the sentence; never a whole walk.
_Parity = dict[tuple[str, int], tuple[str, str | None, str | None]]
_PARITY_KEPT = 32
_parity: OrderedDict[tuple[str, str], _Parity] = OrderedDict()
# The windows `GET /api/patch-policy/apps` reports, by `input_id`.
_WINDOWS_KEPT = 128
_windows: OrderedDict[str, dict[str, Any] | _Refusal] = OrderedDict()


class Refused(Exception):
    """A walk that is not shown, and why: the route's 409. `reason` is a feed state, a timeline
    state (`patch_policy_timelines.STATES`), a walk refusal (`patch_policy_walk.REFUSED_*`) or
    `unchecked`; `sentence` is the detail; `facts` what a page may list beside it."""

    def __init__(self, reason: str, sentence: str, *, source: str | None = None, facts: Mapping[str, Any] | None = None):
        super().__init__(sentence)
        self.reason = reason
        self.sentence = sentence
        self.source = source
        self.facts = dict(facts or {})


def reset_for_tests() -> None:
    _walks.clear()
    _parity.clear()
    _windows.clear()


def _remember(cache: OrderedDict, key: Any, value: Any, kept: int) -> None:
    cache[key] = value
    cache.move_to_end(key)
    while len(cache) > kept:
        cache.popitem(last=False)


async def _memoised(cache: OrderedDict, kept: int, key: str, compute: Any, /, *args: Any, **kwargs: Any) -> dict[str, Any]:
    """`compute(*args, **kwargs)` off the event loop, once per `key`. A refusal is remembered as
    its words and raised afresh: the same inputs refuse the same way."""
    held = cache.get(key)
    if held is None:
        try:
            held = await asyncio.to_thread(compute, *args, **kwargs)
        except walk.WalkRefused as refused:
            held = (refused.reason, refused.sentence, refused.detail)
        _remember(cache, key, held, kept)
    else:
        cache.move_to_end(key)
    if isinstance(held, tuple):
        raise walk.WalkRefused(*held)
    return held


async def _walked(
    document: Mapping[str, Any],
    *,
    app: str,
    track: str,
    timeline: timelines.Timeline,
    years: int,
    common: Sequence[str] | None = None,
) -> dict[str, Any]:
    """`patch_policy_walk.walk`, memoised by its `input_id`."""
    data = timeline.walk_input()
    key = walk.input_id(document, app=app, track=track, timeline=data, years=years, common=common)
    return await _memoised(
        _walks, _WALKS_KEPT, key, walk.walk, document, app=app, track=track, timeline=data, years=years, common=common
    )


async def _window(
    document: Mapping[str, Any], *, app: str, track: str, timeline: timelines.Timeline, years: int
) -> dict[str, Any]:
    """`patch_policy_walk.window_for`, memoised: the window one timeline allows, without walking."""
    data = timeline.walk_input()
    key = walk.input_id(document, app=app, track=track, timeline=data, years=years)
    return await _memoised(
        _windows, _WINDOWS_KEPT, key, walk.window_for, document, app=app, track=track, timeline=data, years=years
    )


# --- the document, as this organization may read it -----------------------------------------------


async def held_document(db: AsyncSession) -> tuple[feed.FeedView, Mapping[str, Any]]:
    """The feed's view and the document, or the feed's own sentence when this organization has
    none to read (its tier is off, nothing has arrived, or every copy was refused)."""
    view = await feed.feed_view(db)
    if view.document is None:
        raise Refused(view.state, view.sentence)
    return view, view.document


# --- timelines -------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Catalogs:
    """The instance's Jamf and Fleet holdings for a set of bundle ids, read once per request."""

    jamf: timelines.JamfCatalog | None = None
    fleet: timelines.FleetHistory | None = None


def _bundles(app_row: Mapping[str, Any]) -> set[str]:
    return {b.strip().casefold() for b in app_row.get("bundle_ids") or [] if isinstance(b, str) and b.strip()}


def _for_app(catalogs: _Catalogs, app_row: Mapping[str, Any]) -> _Catalogs:
    """The catalogs narrowed to one app's bundle ids, for an answer about several apps."""
    mine = _bundles(app_row)
    jamf_titles = catalogs.jamf.titles if catalogs.jamf else ()
    fleet_titles = catalogs.fleet.titles if catalogs.fleet else ()
    return _Catalogs(
        jamf=(
            timelines.JamfCatalog(
                size=catalogs.jamf.size,
                refreshed_at=catalogs.jamf.refreshed_at,
                titles=tuple(title for title in jamf_titles if mine.intersection(title.bundle_ids)),
            )
            if catalogs.jamf
            else None
        ),
        fleet=(
            timelines.FleetHistory(
                enabled=catalogs.fleet.enabled,
                catalog_read=catalogs.fleet.catalog_read,
                checked_ok_at=catalogs.fleet.checked_ok_at,
                catalog_detail=catalogs.fleet.catalog_detail,
                history_failure=catalogs.fleet.history_failure,
                titles=tuple(title for title in fleet_titles if title.bundle_id.casefold() in mine),
            )
            if catalogs.fleet
            else None
        ),
    )


async def _read(db: AsyncSession, bundles: set[str], sources: Sequence[str]) -> _Catalogs:
    catalogs = _Catalogs()
    if timelines.JAMF in sources:
        catalogs.jamf = await timelines.read_jamf(db, bundles)
    if timelines.FLEET in sources:
        catalogs.fleet = await timelines.read_fleet(db, bundles)
    return catalogs


def _timeline(document: Mapping[str, Any], app: str, track: str, source: str, catalogs: _Catalogs) -> timelines.Timeline:
    if source == timelines.PUBLIC:
        return timelines.public(document, app, track)
    held = catalogs.jamf if source == timelines.JAMF else catalogs.fleet
    if held is None:  # a caller's slip: every caller reads the catalogs its sources need first
        raise RuntimeError(f"the {source} catalog was not read before its timeline was asked for")
    if isinstance(held, timelines.JamfCatalog):
        return timelines.jamf(held, document, app, track)
    return timelines.fleet(held, document, app, track)


# --- parity -----------------------------------------------------------------------------------------

_MATCHED, _NO_ENTRY, _UNJUDGED, _DISAGREES = "matched", "no_entry", "unjudged", "disagrees"


async def app_parity(document: Mapping[str, Any], app_row: Mapping[str, Any]) -> _Parity:
    """Every window of the app walked on LoonSec's published dates at its default end, as
    `(state, reason, sentence)`: `matched`; `no_entry` (no published totals for it); `unjudged`
    (no public dates, or the walk itself was refused, with its reason and sentence); or
    `disagrees` (with the parity sentence). Once per document."""
    key = (str(document.get("doc_id")), str(app_row["app"]))
    held = _parity.get(key)
    if held is not None:
        return held
    states: _Parity = {}
    for track_row in app_row.get("tracks") or []:
        track = str(track_row.get("track"))
        for years in walk.WINDOW_YEARS:
            try:
                timeline = timelines.public(document, str(app_row["app"]), track)
                result = await _walked(document, app=str(app_row["app"]), track=track, timeline=timeline, years=years)
            except timelines.Unavailable as unavailable:
                states[(track, years)] = (_UNJUDGED, unavailable.state, unavailable.sentence)
            except walk.WalkRefused as refused:
                state = _DISAGREES if refused.reason == walk.REFUSED_PARITY else _UNJUDGED
                states[(track, years)] = (state, refused.reason, refused.sentence)
            else:
                matched = result["check"]["state"] == walk.CHECK_MATCHED
                states[(track, years)] = (_MATCHED if matched else _NO_ENTRY, None, None)
    _remember(_parity, key, states, _PARITY_KEPT)
    return states


def check_for(states: _Parity, app_row: Mapping[str, Any], track: str, years: int) -> dict[str, str]:
    """The served walk's `check`, from its app's parity, or the refusal it earns: a window whose
    totals disagree refuses the app; with no window matched, LoonSec's data failing the walk's own
    check is said as that, and anything else as `unchecked`."""
    name = str(app_row.get("name") or app_row["app"])
    labels = {str(t.get("track")): str(t.get("label") or t.get("track")) for t in app_row.get("tracks") or []}
    for state, _, sentence in states.values():
        if state == _DISAGREES:
            raise Refused(walk.REFUSED_PARITY, str(sentence))
    if states.get((track, years), ("",))[0] == _MATCHED:
        return {"state": CHECK_MATCHED, "detail": f"Matches the totals LoonSec published for a {years}-year window of {name}."}
    # The same track's other window first, then the app's other tracks, in the document's order.
    order = sorted(states, key=lambda key: (key[0] != track, list(labels).index(key[0]) if key[0] in labels else 0, key[1]))
    matched = next((key for key in order if states[key][0] == _MATCHED), None)
    if matched is None:
        windows = {f"{t} {y}y": reason or state for (t, y), (state, reason, _) in states.items()}
        broken = next((sentence for _, reason, sentence in states.values() if reason == walk.REFUSED_DOCUMENT), None)
        if broken:
            raise Refused(walk.REFUSED_DOCUMENT, broken, facts={"windows": windows})
        raise Refused(
            REFUSED_UNCHECKED,
            f"LoonSec has published no totals this build could match for any window of {name}, so no view of {name} is "
            "shown: a view is shown only once the walk of LoonSec's own dates for one of its windows matches the totals "
            "LoonSec published with the data. Report the sentence with the data's date (Settings › Support).",
            facts={"windows": windows},
        )
    other_track, other_years = matched
    which = f"the {other_years}-year walk" + ("" if other_track == track else f" of {labels.get(other_track, other_track)}")
    return {
        "state": CHECK_UNCHECKED,
        "detail": f"LoonSec has no check for a {years}-year window of {name}; it is shown because {which} matched.",
    }


# --- one walk ------------------------------------------------------------------------------------------


async def walk_view(
    db: AsyncSession,
    *,
    app: str,
    track: str | None,
    source: str,
    years: int,
    align: str | None = None,
    stop: str | None = None,
    page: int = 1,
) -> dict[str, Any]:
    """One walk, as the route serves it, or `Refused` with the sentence that says why not."""
    _, document = await held_document(db)
    try:
        app_row, track_row = walk.track_of(document, app, track)
    except walk.WalkRefused as refused:
        raise Refused(refused.reason, refused.sentence, facts=refused.detail) from None
    track_id = str(track_row["track"])

    try:
        check = check_for(await app_parity(document, app_row), app_row, track_id, years)
    except Refused as refused:
        refused.source = source
        raise
    catalogs = await _read(db, _bundles(app_row), [source] if align != ALIGN_COMMON else list(timelines.SOURCES))
    try:
        timeline = _timeline(document, app, track_id, source, catalogs)
        common, aligned = None, None
        if align == ALIGN_COMMON:
            common, aligned = await _common(document, app, track_id, years, catalogs)
        result = await _walked(document, app=app, track=track_id, timeline=timeline, years=years, common=common)
    except timelines.Unavailable as unavailable:
        raise Refused(unavailable.state, unavailable.sentence, source=source) from None
    except walk.WalkRefused as refused:
        raise Refused(refused.reason, refused.sentence, source=source, facts=refused.detail) from None
    return served(result, timeline, check=check, stop=stop, page=page, aligned=aligned)


async def _common(
    document: Mapping[str, Any], app: str, track: str, years: int, catalogs: _Catalogs
) -> tuple[tuple[str, str], dict[str, Any]]:
    """The days every source that can date the track covers: the latest first day and the
    earliest last day of their windows. A source that cannot is left out and named."""
    windows: dict[str, dict[str, Any]] = {}
    left_out: list[dict[str, str]] = []
    for source in timelines.SOURCES:
        try:
            timeline = _timeline(document, app, track, source, catalogs)
            windows[source] = await _window(document, app=app, track=track, timeline=timeline, years=years)
        except timelines.Unavailable as unavailable:
            left_out.append({"source": source, "reason": unavailable.state, "sentence": unavailable.sentence})
        except walk.WalkRefused as refused:
            left_out.append({"source": source, "reason": refused.reason, "sentence": refused.sentence})
    if not windows:
        first = left_out[0]
        raise Refused(first["reason"], first["sentence"], source=first["source"])
    since = max(window["since"] for window in windows.values())
    until = min(window["until"] for window in windows.values())
    return (since, until), {"sources": list(windows), "since": since, "until": until, "left_out": left_out}


def _trimmed(row: Mapping[str, Any], stop: str | None) -> dict[str, Any]:
    outcomes = {
        name: {key: value for key, value in outcome.items() if key != "intervals" or name == stop}
        for name, outcome in row["outcomes"].items()
    }
    return {**row, "outcomes": outcomes}


def served(
    result: Mapping[str, Any],
    timeline: timelines.Timeline,
    *,
    check: Mapping[str, str],
    stop: str | None,
    page: int,
    aligned: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The walk as the route answers it: every total and series whole, `cves[]` paged, day
    intervals only for `stop`, the app's parity as `check`, and what the timeline set aside."""
    rows = result["cves"]
    pages = max(1, math.ceil(len(rows) / PAGE_SIZE))
    chosen = rows[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
    joined = result["inputs"]["timeline"]
    out = {key: value for key, value in result.items() if key != "cves"}
    out["inputs"] = {
        **result["inputs"],
        "timeline": {
            **joined,
            "ids": list(timeline.ids),
            # Set aside before the walk as another track's, so the walk's own count is added to.
            "other_track": joined["other_track"] + len(timeline.other_track),
            "other_track_versions": list(timeline.other_track),
            "note": timeline.note,
        },
    }
    if aligned is not None:
        out["window"] = {**result["window"], "aligned": dict(aligned)}
    out["check"] = dict(check)
    out["cves"] = [_trimmed(row, stop) for row in chosen]
    out["cves_page"] = {"page": page, "page_size": PAGE_SIZE, "pages": pages, "total": len(rows)}
    out["intervals_for"] = stop
    return out


# --- which sources can date each app ---------------------------------------------------------------


async def app_sources(db: AsyncSession, document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """For every app the document references: each source's state, with each track's, and the
    default two-year window a walk of it would cover. One read of each catalog for every app."""
    apps = [app for app in document.get("apps") or [] if isinstance(app, Mapping)]
    bundles: set[str] = set()
    for app_row in apps:
        bundles |= _bundles(app_row)
    jamf = await timelines.read_jamf(db, bundles)
    fleet = await timelines.read_fleet(db, bundles)
    return await sources_of(document, jamf, fleet)


async def sources_of(
    document: Mapping[str, Any], jamf: timelines.JamfCatalog, fleet: timelines.FleetHistory
) -> dict[str, dict[str, Any]]:
    """`app_sources` over catalogs already read: every app, every source, every track."""
    catalogs = _Catalogs(jamf=jamf, fleet=fleet)
    answer: dict[str, dict[str, Any]] = {}
    for app_row in (app for app in document.get("apps") or [] if isinstance(app, Mapping)):
        mine = _for_app(catalogs, app_row)
        answer[str(app_row["app"])] = {source: await _source(document, app_row, source, mine) for source in timelines.SOURCES}
    return answer


async def _source(document: Mapping[str, Any], app_row: Mapping[str, Any], source: str, catalogs: _Catalogs) -> dict[str, Any]:
    app = str(app_row["app"])
    tracks: list[dict[str, Any]] = []
    as_of, ids, note, matched_keys, days = None, [], None, set(), []
    for track_row in app_row.get("tracks") or []:
        track = str(track_row.get("track"))
        entry: dict[str, Any] = {
            "track": track,
            "available": False,
            "state": "",
            "sentence": None,
            "first": None,
            "last": None,
            "matched": 0,
            "other_track": 0,
            "unmatched": 0,
            "since": None,
            "until": None,
        }
        try:
            timeline = _timeline(document, app, track, source, catalogs)
        except timelines.Unavailable as unavailable:
            entry.update(state=unavailable.state, sentence=unavailable.sentence)
            tracks.append(entry)
            continue
        except walk.WalkRefused as refused:
            entry.update(state=refused.reason, sentence=refused.sentence)
            tracks.append(entry)
            continue
        joined = timelines.split(timeline.observations, app_row, track)
        own = set(joined.matched)
        own_days = sorted(day for key, day in timeline.observations if key in own and day is not None)
        as_of, note = timeline.as_of, timeline.note
        ids += [i for i in timeline.ids if i not in ids]
        matched_keys |= set(joined.matched)
        days += own_days
        entry.update(
            first=own_days[0].isoformat() if own_days else None,
            last=own_days[-1].isoformat() if own_days else None,
            matched=len(joined.matched),
            other_track=len(timeline.other_track),
            unmatched=len(joined.unmatched),
        )
        try:
            window = await _window(document, app=app, track=track, timeline=timeline, years=walk.DEFAULT_YEARS)
        except walk.WalkRefused as refused:
            entry.update(state=refused.reason, sentence=refused.sentence)
        else:
            entry.update(available=True, state="available", since=window["since"], until=window["until"])
        tracks.append(entry)
    default = next(
        (entry for entry, row in zip(tracks, app_row.get("tracks") or [], strict=False) if row.get("default") is True),
        tracks[0] if tracks else None,
    )
    available = any(entry["available"] for entry in tracks)
    return {
        "available": available,
        "state": "available" if available else (default["state"] if default else ""),
        "sentence": None if available or default is None else default["sentence"],
        "first": min(days).isoformat() if days else None,
        "last": max(days).isoformat() if days else None,
        "matched": len(matched_keys),
        "as_of": as_of.isoformat() if as_of else None,
        "note": note,
        "ids": ids,
        "tracks": tracks,
    }
