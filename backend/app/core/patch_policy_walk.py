"""The patch-policy day-walk (#614): what each patch-policy stop would have seen, for one app track.

`walk` is the one entry point. It takes LoonSec's `patch_policy_reference` document, one app and
track in it, one timeline of release dates (the dates LoonSec published, this instance's copy of
Jamf's public patch catalog, or this instance's Fleet history) and the window asked for, and
returns the walk as data: a per-day series of open CVEs, every CVE's outcome under each stop,
the totals, the installs, the exclusions, how the timeline joined the document, and an
`input_id` that names the inputs so a caller can memoise the answer. `GET /api/patch-policy/walk`
(`app.api.patch_policy`) serves it, over the timelines `app.core.patch_policy_timelines` reads;
the page that draws it is a later slice. Each `REFUSED_*` sentence says what failed, why and
what to check; the API answers them as 409 details, and docs/troubleshooting.md §33 walks each.

**Pure.** No database, no network, no inventory, no wall clock: the window's last day comes
from the dates the inputs carry. The same inputs give the same bytes, so `run_id` (the digest
of the output) names a run, and the same `input_id` with a different `run_id` is a defect.

**Detect vs refine.** LoonVD compiled every range judgement into the document as runs of
indexes into the track's ordered `versions[]`, and the index is the version's rank. This
module compares no version strings. It joins a timeline's version strings to `versions[].keys`
by exact lowercased key and works in ranks from then on. The one judgement made here is rule 5
(ruled 2026-10-02, run on the instance per R2b): a release at or above a CVE's fix on the
fix's line, dated by this timeline before the fix's day and not of the fix's own train (nor of
the train of the version that dated the fix), does not clear the CVE. The fix's day is the day
this timeline dates the fix, or, where it does not date it, the day of the lowest-ranked
version at or above the fix on its line that it does date and that the CVE's affected runs do
not cover (ruled 2026-11-25, "count the next dated version at or above the fix"); a line where
it dates none has no fix to install, and the CVE is walked by its affected runs there. Every
CVE row says which version dated each fix (`fix_dated_by`). It reads the `line` and `train`
strings the document gives for equality only.

**Every counting rule is in `DEFINITIONS`**, which rides in every output, so a number can be
read against the rule that made it. `compat_v1` reproduces the v1 replay's rules (CVE clock =
publication, admission = published in the window, exposure up to but not including the last
day) for the private conformance check against LoonVD's replay files; the API never sets it.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

KIND = "patch_policy_walk"
SCHEMA = 1
REFERENCE_KIND = "patch_policy_reference"
# A walk that counts differently is a new algorithm, because LoonSec publishes each track's check
# from its pinned copy of this module. `patch_walk/2` is the walk of the eight stops below, whose
# labels are the days waited (ruled 2026-11-27); `patch_walk/1`, the six stops counted the old way,
# is never published (ruled 2026-11-27, "Start at 2").
ALGORITHM = "patch_walk/2"
ALGORITHM_FAMILY = "patch_walk"
DEFINITIONS_VERSION = "3"

# The slider's stops, in order. A day stop's label is the days it waits: a stop of D days installs
# each release D days after the day it became available, so the 0-day stop installs it on that day
# itself (ruled 2026-11-27, "0 = same day"). It replaces the 2026-10-02 rule, under which a stop of
# D days waited D - 1 days.
STOPS = ("0d", "1d", "3d", "7d", "14d", "30d", "60d", "never")
NEVER = "never"
DAY_STOPS = {"0d": 0, "1d": 1, "3d": 3, "7d": 7, "14d": 14, "30d": 30, "60d": 60}
# The longest a day stop waits: the window must hold this many days of a timeline before its
# first day, or the slowest device would open the window with nothing installed.
LONGEST_WAIT = max(DAY_STOPS.values())

WINDOW_YEARS = (2, 3)
DEFAULT_YEARS = 2
SOURCES = ("public", "jamf", "fleet")
PUBLIC = "public"
# Above this share of the versions a device in the view could install matching nothing in the
# document, the timeline is refused for the app and track (plan 4.4, "above 5% unmatched steps"):
# an unmatched version is never installed, so each one in reach is an install the walk would skip.
# Measured over the versions in reach (`_reach`), not every version the timeline ever named, so
# old matched versions cannot dilute a gap in the window and old misses cannot refuse a full one.
UNMATCHED_LIMIT = 0.05

PATH_HOLD, PATH_LATEST = "hold", "latest"

CLOCK_DETECTABLE = "detectable_at"
CLOCK_PUBLISHED = "published"
CLOCKS_USED = (CLOCK_DETECTABLE, CLOCK_PUBLISHED)

# Where a CVE stands against the window, by its clock day.
IN_WINDOW = "in_window"
BEFORE_WINDOW = "before_window"
# What a CVE clocked before the window is, under one stop.
CARRIED_IN = "carried_in"
ENTERED_AFTER_START = "entered_after_start"
PRE_WINDOW_CLOSED = "pre_window_closed"
CLASSES = (IN_WINDOW, CARRIED_IN, ENTERED_AFTER_START)

EXPOSED, NEVER_SEEN, NOT_OPEN = "exposed", "never_seen", "not_open_in_window"
FIX_INSTALLED_FIRST, OUTSIDE_RANGE = "fix_installed_first", "outside_affected_range"
BECAME_DETECTABLE, ENTERED_RANGE, UPDATE_INSTALLED = "became_detectable", "entered_range", "update_installed"

BRANCH_AMBIGUITY = "branch_ambiguity"
# The document's own order (`exclusion_reasons[]`) wins when it carries one; this is the plan's
# order for a document that does not. One reason per CVE, the first that applies. The walk adds
# only `branch_ambiguity`: since 2026-11-25 a fix the timeline does not date is dated by the next
# version at or above it (`fix_dated_by`) rather than excluded, so `fixed_version_not_in_timeline`
# is no longer the walk's word. A document that still lists it keeps it as its own, counted 0.
EXCLUSION_REASONS = (
    "rejected",
    "no_configuration_for_pair",
    "excluded_platform",
    "configuration_declined",
    "only_prerelease_criteria",
    "no_fixed_version_determinable",
    "fixed_version_not_in_catalog",
    BRANCH_AMBIGUITY,
    "other_edition_only",
)

# How a fix's day was found (`fix_dated_by[].how`, `counts.fix_dating`), ruled 2026-11-25: the
# timeline dates the fix itself; it dates the lowest-ranked version at or above the fix on the
# fix's line, outside the CVE's affected runs, instead; or it dates nothing at or above it there
# (or the document names no fix version on the line), so the line has no fix to install and the
# CVE is walked by its runs.
FIX_DATED, NEXT_DATED, FIX_UNDATED = "fix", "next_dated", "undated"
FIX_DATING = (FIX_DATED, NEXT_DATED, FIX_UNDATED)

# Why the window starts after, or ends before, the day asked for. Each binding term is named.
CLOCK_COVERAGE = "clock_coverage"
TIMELINE_COVERAGE = "timeline_coverage"
LINE_START = "line_start"
CHANNEL_START = "channel_start"
COMMON_WINDOW = "common_window"
LEDGER_AS_OF = "ledger_as_of"
TIMELINE_AS_OF = "timeline_as_of"
PROMOTION_TABLE = "promotion_table"

# Why a walk is refused. Each is one sentence in `WalkRefused.sentence`.
REFUSED_DOCUMENT_KIND = "document_kind"
REFUSED_ALGORITHM = "algorithm_unknown"
REFUSED_APP = "app_unknown"
REFUSED_TRACK = "track_unknown"
REFUSED_DOCUMENT = "document_invalid"
REFUSED_NO_PUBLIC_TIMELINE = "no_public_timeline"
REFUSED_TIMELINE = "timeline_invalid"
REFUSED_NO_MATCH = "no_matched_versions"
REFUSED_UNMATCHED = "too_many_unmatched"
REFUSED_NOTHING_TO_INSTALL = "nothing_to_install"
REFUSED_CEILING_UNDATED = "ceiling_line_undated"
REFUSED_WINDOW = "window_empty"
REFUSED_REQUEST = "request_invalid"
REFUSED_INVARIANT = "invariant"
REFUSED_PARITY = "parity"

# `check.state` on a walk: the public walk at the default window matched LoonSec's totals; there is
# no entry for this window; or parity is not judged here (another timeline, an aligned or moved
# window). The API turns the last two into "unchecked window" or a refusal, per app (plan 4.7).
CHECK_MATCHED = "matched"
CHECK_NO_ENTRY = "no_entry"
CHECK_NOT_APPLICABLE = "not_applicable"

DEFINITIONS = {
    "join": "A timeline's version is matched to the track's version list by exact, lowercased "
    "spelling (`versions[].keys`); no version is compared by number on this instance. A version "
    "the track does not list but another track of the app does is the other track's "
    "(`other_track`). A version no track lists is unmatched and never installed (`unmatched`). "
    "The versions in reach are those a device in this view could install: the timeline dates "
    "them from 60 days before the window's first day to its last day. A matched version in "
    "reach is counted once, by its place in the version list, and only when the track's path "
    "installs it; every unmatched version in reach is counted, because an unmatched version "
    "cannot be placed on a line. When more than 5% of the versions in reach are unmatched, "
    "the timeline is refused for the app and track (`in_reach`); unmatched versions outside "
    "that span are listed and do not count. A version the timeline names without a date is "
    "never installed either (`undated`). A version the timeline names more than once is dated "
    "by its earliest date, and the disagreement is counted (`conflicts`).",
    "path": "`hold` installs only versions up to and including the track's ceiling line; `latest` "
    "installs every version the track lists.",
    "availability": "A release is available on the day the timeline dates it. Where the track "
    "has a promotion table, a release of a promoted major is available on that date or the "
    "major's promotion day, whichever is later, and a release above the table's newest row is "
    "never available.",
    "install": "A stop's label is the days it waits (ruled 2026-11-27: 0 is the same day): a stop "
    "of D days installs each available release D days after the day it became available, so "
    "the 0-day stop installs it on that day itself and the 1-day stop the day after. The "
    "installed version only rises: a release ranked below the installed one is never an event.",
    "steady_state": "A day stop opens the window on the newest release whose install day had "
    "already passed. `never` opens it on the newest release available by the window's first "
    "day and installs nothing after it, so for the window's first 60 days `never` can run a "
    "newer release than the 60-day stop.",
    "affected": "A version is affected by a CVE when its rank is inside one of the CVE's "
    "affected runs, as LoonVD compiled them. Rule 5 (ruled 2026-10-02): a version at or above "
    "the CVE's fix on the fix's line, that this timeline dates before the fix's day, and that "
    "is not a build of the fix's own train or of the train of the version that dated the fix, "
    "is affected too, because nothing held says an earlier build carries a later fix. The "
    "fix's day is its effective fix's (`fix_dating`); on a line with no effective fix, rule 5 "
    "does not apply.",
    "fix_dating": "Ruled 2026-11-25: count the next dated version at or above the fix. A fix "
    "this timeline does not date excludes nothing. Its effective fix is the lowest-ranked "
    "version at or above it, on the fix's own line, that this timeline dates and that none of "
    "the CVE's affected runs covers (a version the CVE still affects cannot stand in for its "
    "fix), and that version's day is the fix's day for every rule that reads it, rule 5 "
    "included. A fix the timeline dates itself is its own effective fix, even where one of the "
    "CVE's runs covers it, because LoonSec's data names it. Dating a fix is not clearing it: a "
    "device clears the CVE when it installs a version outside the CVE's affected runs that rule "
    "5 does not hold affected, so installing a fix inside another of the CVE's runs, or a "
    "stand-in rule 5 holds affected under another fix, clears nothing. On a line that holds "
    "several release trains, the stand-in can be a build of a later train shipped before the "
    "fix; rule 5 spares it as the fix's stand-in. Where the timeline dates no version at or "
    "above the fix on its line outside the CVE's runs, or LoonSec's data names no fix version on "
    "the line, the line has no fix a device could install, and the CVE is walked there by its "
    "affected runs alone. Each CVE row says which version dated each fix (`fix_dated_by`), one "
    "entry for each of the document's `fixes[]` on a line the path visits, in the document's "
    "order, so two fixes LoonSec's data points at one version, with different `named`, are two "
    "entries: `fix` is LoonSec's fix version, `named` the version NVD names where LoonSec's fix "
    "version is not that exact one, `dated_as` and `on` the version and day used, and `how`: "
    "`fix` when the timeline dates the fix itself, `next_dated` when it dates a later version "
    "instead, `undated` when it dates none, the way `clock` says which clock placed the row. "
    "`counts.fix_dating` counts those entries over the rows `cves` lists.",
    "cve_clock": "A CVE is placed by the first day it was detectable (`detectable_at`, from "
    "LoonSec's record of NVD changes) where the document holds one, and by NVD's publication "
    "date where it does not. Every CVE row says which clock placed it (`clock`), and "
    "`counts.replayed_by_clock` says how many of each.",
    "window": "The window runs from `since` to `until`, both days included. It is asked for as "
    "2 or 3 years ending on `until`, which defaults to the day before the document's date. It "
    "starts no earlier than the day after the detectable-day record begins, 60 days after the "
    "first release this timeline makes available on the track's path, 60 days after the first "
    "release on a held track's ceiling line, and 60 days after a channel's start; it ends no "
    "later than the day before the document's date, the day before the timeline was read, and "
    "the day before the timeline dates a release above the promotion table. Each binding term "
    "is in `window.shortened_by`.",
    "classes": "A CVE whose clock day is inside the window is in the headline (`in_window`). One "
    "clocked before the window is, under each stop, `carried_in` when the device runs an "
    "affected version on the first day, `entered_after_start` when it does not but does later, "
    "and `pre_window_closed` (counted only) when it never does. One clocked after the window "
    "is counted only. Carried-in and entered-after-start CVEs are reported apart from the "
    "headline.",
    "never_seen": "The device ran no affected version on any day from the CVE's clock day to "
    "the window's last day: either the fix was installed first (`fix_installed_first`), or the "
    "versions it ran were never inside an affected run (`outside_affected_range`).",
    "exposure_days": "Days on which the installed version is affected, counting both the first "
    "and the last: from the CVE's clock day (or the window's first day) to the day before the "
    "fixing install, or to the window's last day when nothing fixed it (`open_at_window_end`).",
    "series": "`open` counts, per day, the CVEs of every reported class whose installed version "
    "is affected that day. `new` counts those that opened that day, because they became "
    "detectable while affected (`became_detectable`) or because an install moved the device into "
    "an affected version (`entered_range`); CVEs open on the first day from before the window "
    "are `opening`. `resolved` counts those an install closed that day (`update_installed`). "
    "open[d] = open[d - 1] + new[d] - resolved[d].",
    "exclusions": "A CVE the document excludes keeps the document's reason. The walk adds one, "
    "judged on the lines the path visits (the line of any version a device under any of the "
    "eight stops runs on a day in the window): `branch_ambiguity` when the CVE's range is "
    "ambiguous on such a line. A fix this timeline does not date excludes nothing; it is dated "
    "as `fix_dating` says.",
    "input_id": "The digest of the document's id, the app and track, the timeline's source, name, "
    "date, clock and the digest of its dated versions, the stops and the window asked for. The "
    "same inputs walk to the same `run_id`.",
}

COMPAT_V1_DEFINITIONS = {
    "compat_v1": "Conformance mode, never served: the CVE clock is NVD publication for every CVE, "
    "a CVE is replayed only when published inside the window, the window is the requested "
    "years before `until` with no start term, a held device's line is the line of the newest "
    "release dated by the window's first day, and exposure stops the day before `until`, as "
    "LoonVD's replay files count it. A stop of D days waits D days, as `install` says: the count "
    "of LoonVD's schema-3 replay files, each of whose day rows states it (`install_delay_days`). "
    "A schema-2 file counted D - 1 and is not conformed to.",
}

_DAY = dt.timedelta(days=1)


class WalkRefused(Exception):
    """The walk cannot be run from these inputs, and a partial answer would be a wrong one.

    `reason` is one of the `REFUSED_*` names, `sentence` says what failed, why and what to check
    in the operator's words (the API's 409 detail), and `detail` carries what a page may list
    beside it (the unmatched versions, the totals that disagreed)."""

    def __init__(self, reason: str, sentence: str, detail: Mapping[str, Any] | None = None) -> None:
        super().__init__(sentence)
        self.reason = reason
        self.sentence = sentence
        self.detail = dict(detail or {})


# --- Small, shared ---------------------------------------------------------------------------


def canonical(value: Any) -> bytes:
    """The document contract's canonical JSON: sorted keys, no spaces, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def day_of(value: Any) -> dt.date | None:
    """A stamp at UTC date grain: a date, `YYYY-MM-DD`, or an ISO stamp (a zone-less one is UTC)."""
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return (value.astimezone(dt.UTC) if value.tzinfo else value).date()
    if isinstance(value, dt.date):
        return value
    text = str(value)
    if len(text) == 10:
        return dt.date.fromisoformat(text)
    moment = dt.datetime.fromisoformat(text)
    return (moment.astimezone(dt.UTC) if moment.tzinfo else moment).date()


def years_before(day: dt.date, years: int) -> dt.date:
    try:
        return day.replace(year=day.year - years)
    except ValueError:  # 29 February
        return day.replace(year=day.year - years, day=28)


def _iso(day: dt.date | None) -> str | None:
    return day.isoformat() if day else None


def algorithm_number(name: Any) -> int | None:
    """N of a `patch_walk/N` name, or None for any other name: what tells an older way of reading
    LoonSec's data from a newer one, so a refusal can say whether updating LoonInspect helps."""
    if not isinstance(name, str):
        return None
    family, slash, number = name.partition("/")
    return int(number) if family == ALGORITHM_FAMILY and slash and number.isascii() and number.isdigit() else None


def is_older_algorithm(name: Any) -> bool:
    """Whether `name` is a `patch_walk` older than this build's: data only older builds read, which
    updating this build cannot make readable (ruled 2026-11-27: `patch_walk/1` is never published)."""
    number, ours = algorithm_number(name), algorithm_number(ALGORITHM)
    return number is not None and ours is not None and number < ours


# --- The inputs, read and checked ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Version:
    index: int
    v: str
    keys: tuple[str, ...]
    line: str
    train: str


@dataclass(slots=True)
class _Row:
    """One CVE of the track, as the walk reads it."""

    cve_id: str
    raw: Mapping[str, Any]
    published: dt.date | None
    detectable: dt.date | None
    clock: str | None
    clock_day: dt.date | None
    runs: tuple[tuple[int, int], ...]
    starts: tuple[int, ...]
    fixes: tuple[tuple[str, int | None], ...]
    # NVD's fix version as the document wrote it, beside each fix, where the index does not point
    # at that exact version (`fixes[].named`); None where the index is the named fix itself.
    named: tuple[str | None, ...]
    ambiguous_lines: frozenset[str]
    exclusion: str | None
    detail: str | None
    has_v1_exclusion: bool
    v1_exclusion: str | None

    def in_runs(self, index: int) -> bool:
        at = bisect_right(self.starts, index) - 1
        return at >= 0 and self.runs[at][1] >= index


@dataclass(frozen=True, slots=True)
class _Timeline:
    source: str
    name: str
    as_of: dt.date
    clock: str | None
    observations: tuple[tuple[str, dt.date | None], ...]
    digest: str


@dataclass(slots=True)
class _Join:
    dates: dict[int, dt.date]
    named: set[int]
    unmatched: list[str]
    # Each unmatched spelling's earliest date (None when the timeline never dates it), for `_reach`.
    unmatched_dates: dict[str, dt.date | None]
    other_track: int
    conflicts: int
    observations: int


def _invalid(where: str, what: str, name: str | None = None, label: str | None = None) -> WalkRefused:
    # A track's label names its app ("Firefox (release)"), so the label alone says which.
    named = label or name
    about = f" for {named}" if named else ""
    return WalkRefused(
        REFUSED_DOCUMENT,
        f"LoonSec's patch-policy data{about} failed this build's check ({where}: {what}), so nothing "
        "was walked. The data is the same for every instance and none of yours is read: report the sentence with "
        "the data's date (Settings › Support).",
        {"where": where, "what": what},
    )


def _mapping_or_absent(
    container: Mapping[str, Any], key: str, where: str, name: str | None = None, label: str | None = None
) -> Mapping[str, Any]:
    """`container[key]` when it is an object, `{}` when it is absent or null; refused as anything else."""
    value = container.get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise _invalid(where, f"not an object ({type(value).__name__})", name, label)
    return value


def _check_document(document: Mapping[str, Any]) -> None:
    """The document-wide shapes the walk reads, refused in words rather than met with a crash."""
    doc_id = document.get("doc_id")
    if not isinstance(doc_id, str) or not doc_id:
        raise _invalid("doc_id", "absent, so no walk of it could be named")
    try:
        as_of = day_of(document.get("as_of"))
    except (TypeError, ValueError):
        as_of = None
    if as_of is None:
        raise _invalid("as_of", f"{document.get('as_of')!r} is not a date")
    if not isinstance(document.get("apps"), list):
        raise _invalid("apps", "not a list")
    for key in ("definitions", "clocks"):
        _mapping_or_absent(document, key, key)
    sources = _mapping_or_absent(document, "sources", "sources")
    for key in ("detectable", "timelines"):
        _mapping_or_absent(sources, key, f"sources.{key}")
    listed = document.get("exclusion_reasons")
    if listed is not None and (not isinstance(listed, list) or not all(isinstance(r, str) and r for r in listed)):
        raise _invalid("exclusion_reasons", "not a list of reasons")


def _find_track(document: Any, app: str, track: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if not isinstance(document, Mapping) or document.get("kind") != REFERENCE_KIND:
        found = document.get("kind") if isinstance(document, Mapping) else type(document).__name__
        raise WalkRefused(
            REFUSED_DOCUMENT_KIND,
            f"What this instance holds as LoonSec's patch-policy data is not that data (its kind is {found!r}), so "
            "nothing was walked. Settings › Support shows the last data-sharing exchange.",
        )
    if document.get("algorithm") != ALGORITHM:
        found = document.get("algorithm")
        # Only a copy an older build stored can be older: this build's own check refuses one before
        # it is stored. Updating cannot help it, and LoonSec's data for this build replaces it.
        raise WalkRefused(
            REFUSED_ALGORITHM,
            f"This build reads {ALGORITHM}; the patch-policy data on this instance is {found!r}"
            + (
                ", which older builds read, so nothing was walked. Nothing on this instance needs updating: LoonSec's "
                f"data for {ALGORITHM} replaces it when it arrives."
                if is_older_algorithm(found)
                else ". Update LoonInspect."
            ),
        )
    _check_document(document)
    apps = document["apps"]
    for at, entry in enumerate(apps):
        if not isinstance(entry, Mapping) or not isinstance(entry.get("app"), str):
            raise _invalid(f"apps[{at}]", "not an app with an id")
    row = next((a for a in apps if a["app"] == app), None)
    if row is None:
        raise WalkRefused(REFUSED_APP, f"No reference yet for {app}. That is not a count of zero.")
    tracks = row.get("tracks")
    if not isinstance(tracks, list) or not all(isinstance(t, Mapping) for t in tracks):
        raise _invalid("tracks", "not a list of tracks", str(row.get("name") or app))
    chosen = next((t for t in tracks if t.get("track") == track), None)
    if chosen is None:
        held = ", ".join(str(t.get("track")) for t in tracks if isinstance(t, Mapping)) or "none"
        raise WalkRefused(
            REFUSED_TRACK,
            f"{row.get('name') or app} has no {track} track in LoonSec's patch-policy data yet; it has {held}.",
        )
    return row, chosen


def track_of(document: Any, app: str, track: str | None = None) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """The app's row and one of its tracks, by id, or its default track when `track` is None;
    refused in the walk's own words (`app_unknown`, `track_unknown`) when there is none."""
    if track is None and isinstance(document, Mapping) and isinstance(document.get("apps"), list):
        row = next((a for a in document["apps"] if isinstance(a, Mapping) and a.get("app") == app), None)
        tracks = row.get("tracks") if isinstance(row, Mapping) else None
        if isinstance(tracks, list):
            listed = [t for t in tracks if isinstance(t, Mapping) and isinstance(t.get("track"), str)]
            chosen = next((t for t in listed if t.get("default") is True), listed[0] if listed else None)
            if chosen is not None:
                track = chosen["track"]
    return _find_track(document, app, track or "")


def _versions(track: Mapping[str, Any], name: str, label: str) -> list[_Version]:
    raw = track.get("versions")
    if not isinstance(raw, list) or not raw:
        raise _invalid("versions", "absent or empty", name, label)
    versions: list[_Version] = []
    owner: dict[str, int] = {}
    seen_lines: set[str] = set()
    for index, entry in enumerate(raw):
        where = f"versions[{index}]"
        if not isinstance(entry, Mapping) or not isinstance(entry.get("v"), str) or not entry["v"]:
            raise _invalid(where, "no version", name, label)
        keys = entry.get("keys")
        if not isinstance(keys, list) or not keys or not all(isinstance(k, str) and k for k in keys):
            raise _invalid(f"{where}.keys", "absent or not spellings", name, label)
        line, train = entry.get("line"), entry.get("train")
        if not isinstance(line, str) or not isinstance(train, str):
            raise _invalid(where, "line or train is not text", name, label)
        lowered = tuple(dict.fromkeys(k.lower() for k in keys))
        for key in lowered:
            if key in owner:
                raise _invalid(f"{where}.keys", f"{key!r} also spells versions[{owner[key]}]", name, label)
            owner[key] = index
        # A line is one unbroken run of ranks, so "up to the ceiling line" is "up to an index".
        if versions and line != versions[-1].line and line in seen_lines:
            raise _invalid(where, f"line {line!r} is not one unbroken run of the version list", name, label)
        seen_lines.add(line)
        versions.append(_Version(index=index, v=entry["v"], keys=lowered, line=line, train=train))
    return versions


def _runs(value: Any, count: int, where: str, name: str, label: str) -> tuple[tuple[int, int], ...]:
    if not isinstance(value, list):
        raise _invalid(where, "not a list of index runs", name, label)
    runs: list[tuple[int, int]] = []
    for at, run in enumerate(value):
        ok = isinstance(run, list | tuple) and len(run) == 2 and all(isinstance(i, int) and not isinstance(i, bool) for i in run)
        if not ok or not 0 <= run[0] <= run[1] < count or (runs and run[0] <= runs[-1][1]):
            raise _invalid(f"{where}[{at}]", f"{run!r} is not an ascending run inside 0..{count - 1}", name, label)
        runs.append((run[0], run[1]))
    return tuple(runs)


def _rows(
    track: Mapping[str, Any], versions: list[_Version], reasons: Sequence[str], name: str, label: str, compat_v1: bool = False
) -> tuple[list[_Row], int]:
    """The track's CVE rows, walked and excluded, and its count of CVEs not yet detectable.

    A CVE is in exactly one of `cves[]`, `exclusions.cves` and `not_detectable.cves`. One the
    document lists both as not detectable and as a row would be walked by its publication date
    while the document also counts it among the CVEs never counted (plan 4.1), so the overlap is
    refused. In conformance mode a row's `v1_exclusion` is its reason, so it must be one the
    document lists, the same as `exclusions.cves[].reason`: otherwise `by_reason` could not count
    it and the walk would blame itself (`invariant`) for the data's word."""
    count = len(versions)
    rows: list[_Row] = []
    seen: set[str] = set()

    def clocked(entry: Mapping[str, Any], where: str) -> tuple[dt.date | None, dt.date | None]:
        try:
            day_of(entry.get("detectable_not_before"))
            return day_of(entry.get("published")), day_of(entry.get("detectable_at"))
        except (TypeError, ValueError) as exc:
            raise _invalid(where, "published, detectable_at or detectable_not_before is not a date", name, label) from exc

    def add(entry: Any, where: str, exclusion: str | None) -> None:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("cve_id"), str) or not entry["cve_id"]:
            raise _invalid(where, "no cve_id", name, label)
        cve_id = entry["cve_id"]
        if cve_id in seen:
            raise _invalid(where, f"{cve_id} is listed twice", name, label)
        seen.add(cve_id)
        published, detectable = clocked(entry, where)
        runs: tuple[tuple[int, int], ...] = ()
        fixes: list[tuple[str, int | None]] = []
        named: list[str | None] = []
        ambiguous: frozenset[str] = frozenset()
        if exclusion is None:
            runs = _runs(entry.get("affected"), count, f"{where}.affected", name, label)
            for at, fix in enumerate(entry.get("fixes") or []):
                index = fix.get("index") if isinstance(fix, Mapping) else "?"
                line = fix.get("line") if isinstance(fix, Mapping) else None
                bad_index = index is not None and (
                    not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < count
                )
                if not isinstance(line, str) or bad_index:
                    raise _invalid(f"{where}.fixes[{at}]", "not a line and an index into the version list", name, label)
                spelled = fix.get("named")
                if "named" in fix and (not isinstance(spelled, str) or not spelled):
                    raise _invalid(
                        f"{where}.fixes[{at}].named", f"{spelled!r} is not NVD's fix version written as text", name, label
                    )
                fixes.append((line, index))
                named.append(spelled)
            lines = entry.get("ambiguous_lines") or []
            if not isinstance(lines, list) or not all(isinstance(line, str) for line in lines):
                raise _invalid(f"{where}.ambiguous_lines", "not a list of lines", name, label)
            ambiguous = frozenset(lines)
        clock, clock_day = (CLOCK_DETECTABLE, detectable) if detectable else (CLOCK_PUBLISHED, published)
        v1 = entry.get("v1_exclusion")
        if compat_v1 and exclusion is None and v1 is not None and v1 not in reasons:
            raise _invalid(f"{where}.v1_exclusion", f"{v1!r} is not a reason this build knows", name, label)
        rows.append(
            _Row(
                cve_id=cve_id,
                raw=entry,
                published=published,
                detectable=detectable,
                clock=clock if clock_day else None,
                clock_day=clock_day,
                runs=runs,
                starts=tuple(run[0] for run in runs),
                fixes=tuple(fixes),
                named=tuple(named),
                ambiguous_lines=ambiguous,
                exclusion=exclusion,
                detail=entry.get("detail") if exclusion else None,
                has_v1_exclusion="v1_exclusion" in entry,
                v1_exclusion=v1 if isinstance(v1, str) else None,
            )
        )

    cves = track.get("cves")
    if not isinstance(cves, list):
        raise _invalid("cves", "absent", name, label)
    for at, entry in enumerate(cves):
        add(entry, f"cves[{at}]", None)
    excluded = _mapping_or_absent(track, "exclusions", "exclusions", name, label).get("cves") or []
    if not isinstance(excluded, list):
        raise _invalid("exclusions.cves", "not a list", name, label)
    for at, entry in enumerate(excluded):
        reason = entry.get("reason") if isinstance(entry, Mapping) else None
        if reason not in reasons:
            raise _invalid(f"exclusions.cves[{at}].reason", f"{reason!r} is not a reason this build knows", name, label)
        add(entry, f"exclusions.cves[{at}]", reason)

    not_detectable = _mapping_or_absent(track, "not_detectable", "not_detectable", name, label)
    held = not_detectable.get("count", 0)
    if not isinstance(held, int) or isinstance(held, bool) or held < 0:
        raise _invalid("not_detectable.count", f"{held!r} is not a count", name, label)
    listed = not_detectable.get("cves") or []
    if not isinstance(listed, list) or not all(isinstance(cve_id, str) and cve_id for cve_id in listed):
        raise _invalid("not_detectable.cves", "not a list of CVE ids", name, label)
    if len(set(listed)) != len(listed) or len(listed) > held:
        raise _invalid("not_detectable.cves", f"{len(listed)} listed against a count of {held}", name, label)
    both = sorted(seen.intersection(listed))
    if both:
        raise _invalid(
            "not_detectable.cves",
            f"{both[0]} is also listed as a CVE to walk or as excluded, and a CVE is in exactly one of the three",
            name,
            label,
        )
    return sorted(rows, key=lambda row: row.cve_id), held


def _timeline(timeline: Any) -> _Timeline:
    def refuse(what: str) -> WalkRefused:
        return WalkRefused(
            REFUSED_TIMELINE,
            f"The release timeline given to the walk cannot be read ({what}), so nothing was walked. This is a defect in "
            "LoonInspect, not in this instance's data: report the sentence (Settings › Support).",
        )

    if not isinstance(timeline, Mapping) or timeline.get("source") not in SOURCES:
        raise refuse(f"its source is not one of {', '.join(SOURCES)}")
    if not isinstance(timeline.get("name"), str) or not timeline["name"]:
        raise refuse("it has no name")
    try:
        as_of = day_of(timeline.get("as_of"))
    except (TypeError, ValueError):
        as_of = None
    if as_of is None:
        raise refuse("it has no date it was read on")
    raw = timeline.get("observations")
    if not isinstance(raw, list):
        raise refuse("it has no list of observations")
    observations: list[tuple[str, dt.date | None]] = []
    for at, item in enumerate(raw):
        if isinstance(item, Mapping):
            version, stamp = item.get("version"), item.get("date")
        elif isinstance(item, list | tuple) and len(item) == 2:
            version, stamp = item
        else:
            raise refuse(f"observation {at} is neither a version and a date nor a pair of them")
        if not isinstance(version, str) or not version:
            raise refuse(f"observation {at} names no version")
        try:
            observations.append((version, day_of(stamp)))
        except (TypeError, ValueError):
            raise refuse(f"observation {at} ({version}) is dated {stamp!r}, which is not a date") from None
    ordered = tuple(sorted(observations, key=lambda pair: (pair[0], _iso(pair[1]) or "")))
    return _Timeline(
        source=timeline["source"],
        name=timeline["name"],
        as_of=as_of,
        clock=timeline.get("clock") if isinstance(timeline.get("clock"), str) else None,
        observations=ordered,
        digest=digest([[version, _iso(day)] for version, day in ordered]),
    )


def _join(versions: list[_Version], other_keys: set[str], timeline: _Timeline) -> _Join:
    own = {key: version.index for version in versions for key in version.keys}
    dated: dict[int, set[dt.date]] = {}
    named: set[int] = set()
    unmatched: dict[str, dt.date | None] = {}
    others: set[str] = set()
    for version, day in timeline.observations:
        key = version.lower()
        if key in own:
            index = own[key]
            named.add(index)
            if day is not None:
                dated.setdefault(index, set()).add(day)
        elif key in other_keys:
            others.add(key)
        else:
            earlier = unmatched.get(key)
            unmatched[key] = day if earlier is None or (day is not None and day < earlier) else earlier
    return _Join(
        dates={index: min(days) for index, days in dated.items()},
        named=named,
        unmatched=sorted(unmatched),
        unmatched_dates=unmatched,
        other_track=len(others),
        conflicts=sum(1 for days in dated.values() if len(days) > 1),
        observations=len(timeline.observations),
    )


# --- The track, prepared once ----------------------------------------------------------------


@dataclass(slots=True)
class _Prepared:
    document: Mapping[str, Any]
    app: Mapping[str, Any]
    track: Mapping[str, Any]
    name: str
    label: str
    versions: list[_Version]
    rows: list[_Row]
    not_detectable: int
    reasons: tuple[str, ...]
    timeline: _Timeline
    join: _Join
    path_kind: str
    path_end: int
    ceiling_line: str | None
    promoted: bool
    available: list[tuple[int, dt.date]]
    above_table: list[int]
    compat_v1: bool
    # The ranks this timeline dates, per line, ascending: where a fix it does not date finds the
    # next dated version at or above it outside the CVE's runs (`_effective_fix`), memoised per
    # (CVE, line, fix).
    dated_on_line: dict[str, list[int]]
    effective_fixes: dict[tuple[str, str, int], tuple[int | None, str]]


def _source_words(timeline: _Timeline) -> str:
    """Where a timeline's dates come from, in the words the page's source toggle uses."""
    return {
        PUBLIC: "LoonSec's published release dates",
        "jamf": "this instance's copy of Jamf's public patch catalog",
        "fleet": "this instance's Fleet history",
    }[timeline.source]


def _next_check(timeline: _Timeline, name: str) -> str:
    """What an operator can do about a timeline the walk refused: report LoonSec's own dates, or
    walk them instead of a timeline read on this instance."""
    if timeline.source == PUBLIC:
        return (
            "These dates are LoonSec's own and the same on every instance: report the sentence with the data's date "
            "(Settings › Support)."
        )
    return (
        f"These dates come from {_source_words(timeline)}. Choose Public as the source to walk LoonSec's published "
        f"dates for {name} instead."
    )


def _prepare(document: Any, app: str, track: str, timeline: Any, compat_v1: bool) -> _Prepared:
    app_row, track_row = _find_track(document, app, track)
    name = str(app_row.get("name") or app)
    label = str(track_row.get("label") or track)
    versions = _versions(track_row, name, label)
    listed = document.get("exclusion_reasons")
    reasons = tuple(listed) if listed else EXCLUSION_REASONS
    reasons = reasons + ((BRANCH_AMBIGUITY,) if BRANCH_AMBIGUITY not in reasons else ())
    rows, not_detectable = _rows(track_row, versions, reasons, name, label, compat_v1)
    path = _mapping_or_absent(track_row, "path", "path", name, label)
    _mapping_or_absent(track_row, "check", "check", name, label)
    read = _timeline(timeline)

    other_keys = {
        str(key).lower()
        for other in app_row["tracks"]
        if other.get("track") != track and isinstance(other.get("versions"), list)
        for entry in other["versions"]
        if isinstance(entry, Mapping) and isinstance(entry.get("keys"), list)
        for key in entry["keys"]
    }
    join = _join(versions, other_keys, read)
    if not join.named:
        listed_count = len({version.lower() for version, _ in read.observations})
        found = (
            ""
            if read.source == PUBLIC
            else f" If the timeline is not {name}'s, LoonInspect picked the wrong title: report the sentence "
            "(Settings › Support)."
        )
        raise WalkRefused(
            REFUSED_NO_MATCH,
            f"None of the {listed_count} versions in the timeline from {read.name} is a version LoonSec's patch-policy "
            f"data lists for {label}, so there is nothing to install and nothing was walked.{found} " + _next_check(read, name),
            {"unmatched": join.unmatched, "other_track": join.other_track},
        )

    kind = path.get("kind", PATH_LATEST)
    if kind not in (PATH_HOLD, PATH_LATEST):
        raise _invalid("path.kind", f"{kind!r} is neither hold nor latest", name, label)
    ceiling: str | None = None
    if compat_v1:
        ceiling = None  # derived from the window's first day in `_window`
    elif kind == PATH_HOLD:
        ceiling = path.get("ceiling_line")
        if not isinstance(ceiling, str) or not any(version.line == ceiling for version in versions):
            raise _invalid("path.ceiling_line", f"{ceiling!r} is not a line of the version list", name, label)
    path_end = max(v.index for v in versions if v.line == ceiling) if ceiling is not None else len(versions) - 1

    promotions = track_row.get("promotions")
    runs: list[tuple[int, int, dt.date]] = []
    if promotions is not None:
        if not isinstance(promotions, list):
            raise _invalid("promotions", "not a list", name, label)
        for at, row in enumerate(promotions):
            where_row = f"promotions[{at}]"
            span = _runs([row.get("versions")] if isinstance(row, Mapping) else None, len(versions), where_row, name, label)
            try:
                promoted_on = day_of(row.get("promoted"))
            except (TypeError, ValueError):
                promoted_on = None
            if promoted_on is None or (runs and span[0][0] <= runs[-1][1]):
                raise _invalid(where_row, "no promotion day, or not above the row before it", name, label)
            runs.append((span[0][0], span[0][1], promoted_on))
    prepared = _Prepared(
        document=document,
        app=app_row,
        track=track_row,
        name=name,
        label=label,
        versions=versions,
        rows=rows,
        not_detectable=not_detectable,
        reasons=reasons,
        timeline=read,
        join=join,
        path_kind=kind,
        path_end=path_end,
        ceiling_line=ceiling,
        promoted=bool(runs),
        available=[],
        above_table=[],
        compat_v1=compat_v1,
        dated_on_line=_dated_on_line(versions, join),
        effective_fixes={},
    )
    _availability(prepared, runs)
    return prepared


def _dated_on_line(versions: list[_Version], join: _Join) -> dict[str, list[int]]:
    dated: dict[str, list[int]] = {}
    for index in sorted(join.dates):
        dated.setdefault(versions[index].line, []).append(index)
    return dated


def _effective_fix(prepared: _Prepared, row: _Row, line: str, fix: int | None) -> tuple[int | None, str]:
    """The version whose day is this fix's day under this timeline, and how it was found (ruled
    2026-11-25, "count the next dated version at or above the fix"): the fix itself when the
    timeline dates it (`fix`), even where one of the row's runs covers it, since the document
    names it; else the lowest-ranked version at or above it, on the fix's line, that the
    timeline dates and that none of the row's affected runs covers (`next_dated`), because a
    version the CVE still affects cannot stand in for its fix; else none (`undated`), and the
    line has no fix a device could install. A fix the document names no version for (a null
    index) is `undated`. Only run-covered versions are passed over: one rule 5 holds affected
    can still stand in, as the fix itself can."""
    if fix is None:
        return None, FIX_UNDATED
    if fix in prepared.join.dates:
        return fix, FIX_DATED
    key = (row.cve_id, line, fix)
    if key not in prepared.effective_fixes:
        dated = prepared.dated_on_line.get(line, [])
        at = bisect_left(dated, fix)
        found: int | None = None
        while at < len(dated):
            run = bisect_right(row.starts, dated[at]) - 1
            if run < 0 or row.runs[run][1] < dated[at]:
                found = dated[at]
                break
            # Inside a run: the next candidate is the first dated version above that run's end.
            at = bisect_right(dated, row.runs[run][1], at)
        prepared.effective_fixes[key] = (found, NEXT_DATED) if found is not None else (None, FIX_UNDATED)
    return prepared.effective_fixes[key]


def _availability(prepared: _Prepared, runs: list[tuple[int, int, dt.date]]) -> None:
    """Fill `available` (index, first day it may be installed) and `above_table`, for the path."""
    newest = runs[-1][1] if runs else None
    starts = [run[0] for run in runs]
    available: list[tuple[int, dt.date]] = []
    above: list[int] = []
    for index in range(prepared.path_end + 1):
        released = prepared.join.dates.get(index)
        if released is None:
            continue
        if newest is not None and index > newest:
            above.append(index)
            continue
        at = bisect_right(starts, index) - 1
        if at >= 0 and runs[at][1] >= index:
            released = max(released, runs[at][2])
        available.append((index, released))
    prepared.available = available
    prepared.above_table = above


# --- The window -------------------------------------------------------------------------------


def _shortened(reason: str, day: dt.date, sentence: str) -> dict[str, str]:
    return {"reason": reason, "date": day.isoformat(), "sentence": sentence}


def _window(prepared: _Prepared, years: int, until: Any, common: Sequence[Any] | None) -> tuple[dt.date, dt.date, dict[str, Any]]:
    """The window's first and last day, and how it was arrived at. Refused when it is empty."""
    if years not in WINDOW_YEARS:
        raise WalkRefused(REFUSED_REQUEST, f"A window is {' or '.join(map(str, WINDOW_YEARS))} years; {years!r} was asked for.")
    document, timeline, name, label = prepared.document, prepared.timeline, prepared.name, prepared.label
    doc_as_of = day_of(document["as_of"])  # checked by `_check_document`
    try:
        requested_until = day_of(until) if until is not None else None
        common_since, common_until = (day_of(common[0]), day_of(common[1])) if common else (None, None)
    except (TypeError, ValueError, IndexError) as exc:
        raise WalkRefused(REFUSED_REQUEST, f"The window asked for is not a pair of dates ({exc}).") from None
    requested_until = requested_until or doc_as_of - _DAY
    requested_since = years_before(requested_until, years)

    starts: list[tuple[str | None, dt.date, str]] = [(None, requested_since, "")]
    ends: list[tuple[str | None, dt.date, str]] = [(None, requested_until, "")]
    if common_since and common_until:
        sentence = "The view is aligned to the days every compared timeline covers."
        starts.append((COMMON_WINDOW, common_since, sentence))
        ends.append((COMMON_WINDOW, common_until, sentence))
    if not prepared.available:
        unmatched = prepared.join.unmatched
        raise WalkRefused(
            REFUSED_NOTHING_TO_INSTALL,
            f"The timeline from {timeline.name} dates no {name} release the {label} device could install"
            + (
                " (every release it dates is above the newest major LoonSec's promotion table lists)"
                if prepared.above_table
                else f" (every version it names that LoonSec lists is undated or above the {prepared.ceiling_line} line)"
                if prepared.ceiling_line is not None
                else " (every version it names that LoonSec lists is undated)"
            )
            + ", so nothing was walked. "
            + (
                f"{len(unmatched)} of the versions it names match nothing LoonSec lists; they are listed beside this sentence. "
                if unmatched
                else ""
            )
            + _next_check(timeline, name),
            {"unmatched": unmatched, "above_table": [prepared.versions[i].v for i in prepared.above_table]},
        )
    if not prepared.compat_v1:
        sources = document.get("sources") or {}  # it and `detectable` are checked by `_check_document`
        coverage = (sources.get("detectable") or {}).get("coverage_since")
        try:
            coverage_day = day_of(coverage)
        except (TypeError, ValueError):
            raise _invalid("sources.detectable.coverage_since", "not a date", name, label) from None
        if coverage_day:
            starts.append(
                (
                    CLOCK_COVERAGE,
                    coverage_day + _DAY,
                    f"LoonSec's record of the day each CVE became detectable begins {coverage_day}, so the view "
                    f"starts the day after.",
                )
            )
        first_index, first_day = min(prepared.available, key=lambda pair: (pair[1], pair[0]))
        starts.append(
            (
                TIMELINE_COVERAGE,
                first_day + dt.timedelta(days=LONGEST_WAIT),
                f"The first {label} release the timeline from {timeline.name} makes available is "
                f"{prepared.versions[first_index].v} on {first_day}, and the 60-day stop needs {LONGEST_WAIT} days of it.",
            )
        )
        if prepared.ceiling_line is not None:
            on_line = [
                (day, index) for index, day in prepared.available if prepared.versions[index].line == prepared.ceiling_line
            ]
            if not on_line:
                raise WalkRefused(
                    REFUSED_CEILING_UNDATED,
                    f"The timeline from {timeline.name} dates no {name} {prepared.ceiling_line} release, so the {label} "
                    "device has no line to hold and nothing was walked. " + _next_check(timeline, name),
                )
            line_day, line_index = min(on_line)
            starts.append(
                (
                    LINE_START,
                    line_day + dt.timedelta(days=LONGEST_WAIT),
                    f"{label} begins with {prepared.versions[line_index].v} on {line_day}, and the 60-day stop needs "
                    f"{LONGEST_WAIT} days of it.",
                )
            )
        try:
            channel_start = day_of(prepared.track.get("channel_start"))
        except (TypeError, ValueError):
            raise _invalid("channel_start", "not a date", name, label) from None
        if channel_start:
            channel = prepared.track.get("channel") or label
            starts.append(
                (
                    CHANNEL_START,
                    channel_start + dt.timedelta(days=LONGEST_WAIT),
                    f"The {channel} channel begins on {channel_start}, and the 60-day stop needs {LONGEST_WAIT} days of it.",
                )
            )
        ends.append(
            (
                LEDGER_AS_OF,
                doc_as_of - _DAY,
                f"LoonSec's patch-policy data is dated {doc_as_of}, so the view ends the day before.",
            )
        )
    ends.append(
        (
            TIMELINE_AS_OF,
            timeline.as_of - _DAY,
            f"The timeline from {timeline.name} was read on {timeline.as_of}, so it knows of no release after the day before.",
        )
    )
    end = min(day for _, day, _ in ends)
    if prepared.above_table:
        dated = [(prepared.join.dates[index], index) for index in prepared.above_table if prepared.join.dates[index] <= end]
        if dated:
            first_above, index = min(dated)
            ends.append(
                (
                    PROMOTION_TABLE,
                    first_above - _DAY,
                    f"The timeline from {timeline.name} dates {prepared.versions[index].v} on {first_above}, above the promotion "
                    "table's newest row; the view ends the day before, because after it the waiting device would rest on a "
                    "promotion day nobody has read.",
                )
            )
    since = max(day for _, day, _ in starts)
    until_day = min(day for _, day, _ in ends)
    shortened = [_shortened(r, d, s) for r, d, s in starts if r and d == since and since > requested_since]
    shortened += [_shortened(r, d, s) for r, d, s in ends if r and d == until_day and until_day < requested_until]
    window = {
        "requested": {"years": years, "since": requested_since.isoformat(), "until": requested_until.isoformat()},
        "since": since.isoformat(),
        "until": until_day.isoformat(),
        "days": (until_day - since).days + 1,
        "shortened_by": shortened,
    }
    if since >= until_day:
        because = "; ".join(row["sentence"] for row in shortened) or "the window asked for is empty"
        raise WalkRefused(
            REFUSED_WINDOW,
            f"You asked for {years} years ending {requested_until}; nothing is left to walk, because the view would start "
            f"{since} and end {until_day}: {because}",
            {"window": window},
        )
    if prepared.compat_v1 and prepared.path_kind == PATH_HOLD and prepared.track.get("line_components"):
        # v1's held line: the line of the newest release the timeline dated by the window's first day.
        current = max((index for index, day in prepared.join.dates.items() if day <= since), default=None)
        if current is not None:
            prepared.ceiling_line = prepared.versions[current].line
            prepared.path_end = max(v.index for v in prepared.versions if v.line == prepared.ceiling_line)
            _availability(prepared, _promotion_runs(prepared))
    return since, until_day, window


def _promotion_runs(prepared: _Prepared) -> list[tuple[int, int, dt.date]]:
    runs = []
    for row in prepared.track.get("promotions") or []:
        first, last = row["versions"]
        runs.append((first, last, day_of(row["promoted"])))
    return runs


def _reach(prepared: _Prepared, since: dt.date, until: dt.date) -> dict[str, Any]:
    """The versions a device in this view could install, and how many of them the document lists.

    A device installs a release at most 60 days after it becomes available, so every release a
    stop installs inside [since, until] became available in [since - 60, until]. (The release a
    slow device opens the window on can be older, and counts only when it falls in that span.) A
    matched version counts once (by its place in the list), only on the track's path, on the day
    it becomes available; an unmatched one counts on the earliest day the timeline gives it, and
    always, because nothing places it on a line. Refused above `UNMATCHED_LIMIT` (plan 4.4)."""
    first = since - dt.timedelta(days=LONGEST_WAIT)
    matched = sorted({index for index, day in prepared.available if first <= day <= until})
    unmatched = sorted(key for key, day in prepared.join.unmatched_dates.items() if day is not None and first <= day <= until)
    total = len(matched) + len(unmatched)
    share = len(unmatched) / total if total else 0.0
    reach = {
        "since": first.isoformat(),
        "until": until.isoformat(),
        "matched": len(matched),
        "unmatched": unmatched,
        "share": round(share, 4),
    }
    if share > UNMATCHED_LIMIT:
        timeline, name, label = prepared.timeline, prepared.name, prepared.label
        raise WalkRefused(
            REFUSED_UNMATCHED,
            f"{len(unmatched)} of the {total} versions the timeline from {timeline.name} dates from {first} to {until}, "
            f"the days a device in this view could install them, match no version LoonSec's patch-policy data lists for "
            f"{label} ({share:.1%}). Above {UNMATCHED_LIMIT:.0%} the walk is refused, because a version that "
            "matches nothing is never installed and the walk would keep the device on the version before it. The "
            "unmatched versions are listed beside this sentence. " + _next_check(timeline, name),
            {"in_reach": reach},
        )
    return reach


def _checked_window(
    prepared: _Prepared, years: int, until: Any, common: Sequence[Any] | None
) -> tuple[dt.date, dt.date, dict[str, Any], dict[str, Any]]:
    """The window, and the versions in reach of it once they pass the unmatched limit."""
    since, until_day, window = _window(prepared, years, until, common)
    return since, until_day, window, _reach(prepared, since, until_day)


def window_for(
    document: Any,
    *,
    app: str,
    track: str,
    timeline: Any,
    years: int = DEFAULT_YEARS,
    until: Any = None,
    common: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """The window one timeline allows, without walking it: for aligning several views (`common`)."""
    prepared = _prepare(document, app, track, timeline, compat_v1=False)
    return _checked_window(prepared, years, until, common)[2]


# --- The device -------------------------------------------------------------------------------


def _steps(stop: str, available: list[tuple[int, dt.date]], since: dt.date, until: dt.date) -> list[tuple[dt.date, int | None]]:
    """The installed version as steps `(from this day, this rank)`, the first at `since`."""
    if stop == NEVER:
        return [(since, max((index for index, day in available if day <= since), default=None))]
    delay = dt.timedelta(days=DAY_STOPS[stop])
    installs = [(index, day + delay) for index, day in available]
    current = max((index for index, day in installs if day <= since), default=None)
    steps: list[tuple[dt.date, int | None]] = [(since, current)]
    due: dict[dt.date, int] = {}
    for index, day in installs:
        if since < day <= until and (day not in due or index > due[day]):
            due[day] = index
    for day in sorted(due):
        if current is None or due[day] > current:
            current = due[day]
            steps.append((day, current))
    return steps


def _on(steps: list[tuple[dt.date, int | None]], day: dt.date) -> int | None:
    at = bisect_right([start for start, _ in steps], day) - 1
    return steps[at][1] if at >= 0 else None


class _Judge:
    """Whether a rank is affected by a CVE under this timeline's dates, memoised per (CVE, rank)."""

    def __init__(self, prepared: _Prepared) -> None:
        self.prepared = prepared
        self.versions = prepared.versions
        self.dates = prepared.join.dates
        self.memo: dict[tuple[str, int], bool] = {}

    def affected(self, row: _Row, index: int) -> bool:
        key = (row.cve_id, index)
        if key not in self.memo:
            self.memo[key] = row.in_runs(index) or self._predates_its_fix(row, index)
        return self.memo[key]

    def _predates_its_fix(self, row: _Row, index: int) -> bool:
        """Rule 5, against each fix's effective fix: the fix's day is the day of the version that
        dated it (`_effective_fix`), and a build of the fix's train, or of that version's, is
        exempt. A line with no effective fix has no day to predate."""
        version = self.versions[index]
        own = self.dates.get(index)
        if own is None:
            return False
        for line, fix in row.fixes:
            if fix is None or line != version.line or index < fix:
                continue
            dated_as, _ = _effective_fix(self.prepared, row, line, fix)
            if dated_as is None or version.train in (self.versions[fix].train, self.versions[dated_as].train):
                continue
            if own < self.dates[dated_as]:
                return True
        return False


def _intervals(
    row: _Row, steps: list[tuple[dt.date, int | None]], floor: dt.date, until: dt.date, judge: _Judge
) -> list[list[dt.date]]:
    """Inclusive day intervals on which the installed version is affected, from `floor` to `until`."""
    found: list[list[dt.date]] = []
    for at, (start, index) in enumerate(steps):
        end = steps[at + 1][0] - _DAY if at + 1 < len(steps) else until
        if index is None or not judge.affected(row, index):
            continue
        first = max(start, floor)
        if first > end:
            continue
        if found and found[-1][1] + _DAY == first:
            found[-1][1] = end
        else:
            found.append([first, end])
    return found


def _exclusion(prepared: _Prepared, row: _Row, visited: set[str]) -> tuple[str | None, str | None]:
    """Why the walk leaves this CVE out, and the line or fix that decided it; `(None, None)` to walk it."""
    if row.exclusion:
        return row.exclusion, row.detail
    if prepared.compat_v1 and row.has_v1_exclusion:
        return row.v1_exclusion, None
    ambiguous = sorted(row.ambiguous_lines & visited)
    if ambiguous:
        return BRANCH_AMBIGUITY, f"the range is ambiguous on {', '.join(map(repr, ambiguous))}, which the path visits"
    return None, None


def _fix_dated_by(prepared: _Prepared, row: _Row, visited: set[str]) -> list[dict[str, Any]]:
    """Which version dated each of the row's fixes on a line the path visits, and how (ruled
    2026-11-25), the way `clock` says which clock placed the row. One entry per entry of the
    document's `fixes[]`, in its order: two fixes the document points at one version, with
    different `named` (NVD's own versions), are two entries, and `counts.fix_dating` counts both."""
    versions, dates = prepared.versions, prepared.join.dates
    entries = []
    for (line, fix), named in zip(row.fixes, row.named, strict=True):
        if line not in visited:
            continue
        dated_as, how = _effective_fix(prepared, row, line, fix)
        entries.append(
            {
                "line": line,
                "fix": versions[fix].v if fix is not None else None,
                "named": named,
                "dated_as": versions[dated_as].v if dated_as is not None else None,
                "on": _iso(dates[dated_as]) if dated_as is not None else None,
                "how": how,
            }
        )
    return entries


# --- The walk ---------------------------------------------------------------------------------


def walk(
    document: Any,
    *,
    app: str,
    track: str,
    timeline: Any,
    stops: Sequence[str] = STOPS,
    years: int = DEFAULT_YEARS,
    until: Any = None,
    common: Sequence[Any] | None = None,
    compat_v1: bool = False,
) -> dict[str, Any]:
    """Walk one app track over one timeline, for each stop in `stops`. A pure function of its arguments.

    `document` is a `patch_policy_reference`; `timeline` is `{source, name, as_of, clock?,
    observations: [{version, date|null}]}` from any source (`public_timeline` builds the public
    one from the document). `until` defaults to the day before the document's date; `common` is
    an optional `(since, until)` both views are cut to, for comparing timelines. Raises
    `WalkRefused` with a sentence rather than return a partial answer.
    """
    unknown = [stop for stop in stops if stop not in STOPS]
    if unknown or not stops or len(set(stops)) != len(stops):
        raise WalkRefused(REFUSED_REQUEST, f"The stops asked for are {list(stops)}; each is one of {', '.join(STOPS)}, once.")
    stops = tuple(stop for stop in STOPS if stop in stops)
    prepared = _prepare(document, app, track, timeline, compat_v1)
    since, until_day, window, reach = _checked_window(prepared, years, until, common)
    judge = _Judge(prepared)

    every = {stop: _steps(stop, prepared.available, since, until_day) for stop in STOPS}
    visited = {prepared.versions[index].line for steps in every.values() for _, index in steps if index is not None}

    placed: dict[str, list[_Row]] = {"before": [], "in": [], "after": [], "unclocked": []}
    exclusion_of: dict[str, str | None] = {}
    detail_of: dict[str, str | None] = {}
    for row in prepared.rows:
        clock_day = row.published if compat_v1 else row.clock_day
        if clock_day is None:
            placed["unclocked"].append(row)
            continue
        placed["before" if clock_day < since else "after" if clock_day > until_day else "in"].append(row)
        exclusion_of[row.cve_id], detail_of[row.cve_id] = _exclusion(prepared, row, visited)

    replayed = [row for row in placed["in"] if not exclusion_of[row.cve_id]]
    excluded = [row for row in placed["in"] if exclusion_of[row.cve_id]]
    # v1 replayed nothing published before its window, so conformance mode walks no pre-window CVE
    # and counts them apart (`before_window_unwalked`).
    unwalked = placed["before"] if compat_v1 else []
    before = [] if compat_v1 else [row for row in placed["before"] if not exclusion_of[row.cve_id]]
    before_excluded = [] if compat_v1 else [row for row in placed["before"] if exclusion_of[row.cve_id]]

    outcomes: dict[str, dict[str, dict[str, Any]]] = {row.cve_id: {} for row in replayed + before}
    policies: dict[str, dict[str, Any]] = {}
    for stop in stops:
        steps = every[stop]
        policies[stop] = _run_stop(prepared, stop, steps, replayed, before, outcomes, since, until_day, judge)

    listed = replayed + [row for row in before if any(outcomes[row.cve_id][s]["class"] != PRE_WINDOW_CLOSED for s in stops)]
    rows_out = [
        _cve_row(row, outcomes[row.cve_id], compat_v1, _fix_dated_by(prepared, row, visited))
        for row in sorted(listed, key=lambda r: r.cve_id)
    ]
    dating = Counter(entry["how"] for row in rows_out for entry in row["fix_dated_by"])
    by_reason = Counter(exclusion_of[row.cve_id] for row in excluded)
    clock_name = CLOCK_PUBLISHED if compat_v1 else None
    result: dict[str, Any] = {
        "kind": KIND,
        "schema": SCHEMA,
        "algorithm": ALGORITHM,
        "definitions_version": DEFINITIONS_VERSION,
        "inputs": {
            "doc_id": document.get("doc_id"),
            "doc_as_of": document.get("as_of"),
            "app": app,
            "name": prepared.name,
            "track": track,
            "label": prepared.label,
            "path": {
                "kind": prepared.path_kind,
                "ceiling_line": prepared.ceiling_line,
                "waits_for_promotion": prepared.promoted,
            },
            "timeline": _join_report(prepared, reach),
            "stops": list(stops),
            "compat_v1": compat_v1,
        },
        "window": window,
        "counts": {
            "cves_in_doc": len(prepared.rows),
            "in_window": len(placed["in"]),
            "replayed": len(replayed),
            "excluded": len(excluded),
            "before_window": len(before),
            "before_window_excluded": len(before_excluded),
            "before_window_unwalked": len(unwalked),
            "after_window": len(placed["after"]),
            "without_clock": len(placed["unclocked"]),
            "not_detectable": prepared.not_detectable,
            "uncertain_over_1d": sum(1 for row in replayed if _uncertain(row, compat_v1)),
            "replayed_by_clock": _by_clock(replayed, clock_name),
            "placed_by_clock": _by_clock([row for key in ("before", "in", "after") for row in placed[key]], clock_name),
            "fix_dating": {how: dating[how] for how in FIX_DATING},
        },
        "exclusions": {
            "by_reason": {reason: by_reason[reason] for reason in prepared.reasons},
            "cves": [
                {
                    "cve_id": row.cve_id,
                    "reason": exclusion_of[row.cve_id],
                    "clock": clock_name or row.clock,
                    "clock_date": _iso(row.published if compat_v1 else row.clock_day),
                    "published": _iso(row.published),
                    "detail": detail_of[row.cve_id],
                }
                for row in excluded
            ],
            "before_window_by_reason": dict(sorted(Counter(exclusion_of[row.cve_id] for row in before_excluded).items())),
        },
        "policies": policies,
        "cves": rows_out,
        "definitions": {**DEFINITIONS, **(COMPAT_V1_DEFINITIONS if compat_v1 else {})},
        "document_definitions": document.get("definitions") or {},
        "clocks": {
            **(document.get("clocks") or {}),
            "cve": DEFINITIONS["cve_clock"] if not compat_v1 else "NVD publication, for every CVE (conformance mode).",
            "release_date": prepared.timeline.clock or f"The date the timeline from {prepared.timeline.name} gives each release.",
        },
    }
    result["input_id"] = input_id(
        document,
        app=app,
        track=track,
        timeline=prepared.timeline,
        stops=stops,
        years=years,
        until=until,
        common=common,
        compat_v1=compat_v1,
    )
    failures = invariant_failures(result)
    if failures:
        raise WalkRefused(
            REFUSED_INVARIANT,
            f"The walk of {prepared.label} was refused because its own totals disagree ({failures[0]}). "
            "This is a defect in LoonInspect, not in this instance's data: report the sentence with the Input line "
            "(Settings › Support).",
            {"failures": failures},
        )
    result["check"] = _parity(prepared, result, years, until, common)
    result["run_id"] = digest(result)
    return result


def _uncertain(row: _Row, compat_v1: bool) -> bool:
    if compat_v1 or row.clock != CLOCK_DETECTABLE or row.detectable is None:
        return False
    try:
        not_before = day_of(row.raw.get("detectable_not_before"))
    except (TypeError, ValueError):
        return False
    return not_before is not None and (row.detectable - not_before).days > 1


def _by_clock(rows: list[_Row], forced: str | None) -> dict[str, int]:
    counted = Counter(forced or row.clock for row in rows)
    return {clock: counted[clock] for clock in CLOCKS_USED}


def _join_report(prepared: _Prepared, reach: dict[str, Any]) -> dict[str, Any]:
    join, timeline = prepared.join, prepared.timeline
    dates = sorted(join.dates.values())
    return {
        "source": timeline.source,
        "name": timeline.name,
        "digest": timeline.digest,
        "as_of": timeline.as_of.isoformat(),
        "first": _iso(dates[0]) if dates else None,
        "last": _iso(dates[-1]) if dates else None,
        "observations": join.observations,
        "matched": len(join.named),
        "unmatched": join.unmatched,
        "other_track": join.other_track,
        "undated": len(join.named - join.dates.keys()),
        "conflicts": join.conflicts,
        "in_reach": reach,
    }


def _run_stop(
    prepared: _Prepared,
    stop: str,
    steps: list[tuple[dt.date, int | None]],
    replayed: list[_Row],
    before: list[_Row],
    outcomes: dict[str, dict[str, dict[str, Any]]],
    since: dt.date,
    until: dt.date,
    judge: _Judge,
) -> dict[str, Any]:
    """One stop: every listed CVE's outcome under it (written into `outcomes`) and its totals."""
    versions, compat = prepared.versions, prepared.compat_v1
    starts = {start for start, _ in steps}
    days = (until - since).days + 1
    open_delta = [0] * (days + 1)
    new = [0] * days
    resolved = [0] * days
    reasons = {BECAME_DETECTABLE: [0] * days, ENTERED_RANGE: [0] * days}
    opening = 0
    totals = Counter()
    open_at_end = Counter()

    def name(index: int | None) -> str | None:
        return versions[index].v if index is not None else None

    for row in replayed + before:
        clock_day = row.published if compat else row.clock_day
        in_window = clock_day >= since
        found = _intervals(row, steps, max(clock_day, since), until, judge)
        inclusive = sum((last - first).days + 1 for first, last in found)
        open_at_window_end = bool(found) and found[-1][1] == until
        if in_window:
            klass = IN_WINDOW
        elif found and found[0][0] == since:
            klass = CARRIED_IN
        elif found:
            klass = ENTERED_AFTER_START
        else:
            klass = PRE_WINDOW_CLOSED
        outcome: dict[str, Any] = {"class": klass}
        if klass == PRE_WINDOW_CLOSED:
            outcome["outcome"] = NOT_OPEN
            totals[PRE_WINDOW_CLOSED] += 1
            outcomes[row.cve_id][stop] = outcome
            continue
        # v1 counted exposure up to, not including, the window's last day.
        exposure = inclusive - (1 if compat and open_at_window_end else 0)
        if found:
            last_end = found[-1][1]
            cleared_on = None if open_at_window_end else last_end + _DAY
            outcome.update(
                outcome=EXPOSED,
                exposure_days=exposure,
                open_at_window_end=open_at_window_end,
                cleared_on=_iso(cleared_on),
                cleared_by=name(_on(steps, cleared_on)) if cleared_on else None,
                intervals=[[first.isoformat(), last.isoformat()] for first, last in found],
            )
        else:
            at = _on(steps, clock_day)
            fixed_first = at is not None and any(
                fix is not None and line == versions[at].line and at >= fix for line, fix in row.fixes
            )
            outcome.update(outcome=NEVER_SEEN, why=FIX_INSTALLED_FIRST if fixed_first else OUTSIDE_RANGE)
        if in_window:
            outcome["version_at_clock"] = name(_on(steps, clock_day))
        outcomes[row.cve_id][stop] = outcome

        totals[klass] += 1
        if klass == IN_WINDOW:
            totals[EXPOSED if found else NEVER_SEEN] += 1
            totals[OUTSIDE_RANGE] += int(outcome.get("why") == OUTSIDE_RANGE)
        totals[f"days:{klass}"] += exposure if found else 0
        open_at_end[klass] += int(open_at_window_end)
        for at, (first, last) in enumerate(found):
            offset = (first - since).days
            open_delta[offset] += 1
            open_delta[(last - since).days + 1] -= 1
            if klass == CARRIED_IN and at == 0:
                opening += 1
            else:
                new[offset] += 1
                reasons[BECAME_DETECTABLE if first == clock_day else ENTERED_RANGE][offset] += 1
            if last < until:
                resolved[(last - since).days + 1] += 1

    series_open, running = [], 0
    for offset in range(days):
        running += open_delta[offset]
        series_open.append(running)
    resolution_days = sorted(since + dt.timedelta(days=offset) for offset in range(days) if resolved[offset])
    if any(day not in starts for day in resolution_days):
        raise WalkRefused(
            REFUSED_INVARIANT,
            f"The walk of {prepared.label} was refused because a CVE was closed on a day nothing was "
            "installed. This is a defect in LoonInspect: report the sentence (Settings › Support).",
        )
    installs = [{"date": day.isoformat(), "version": name(index)} for day, index in steps[1:]]
    return {
        "stop": stop,
        "install_delay_days": DAY_STOPS.get(stop),
        "never_seen": totals[NEVER_SEEN],
        "never_seen_outside_affected_range": totals[OUTSIDE_RANGE],
        "exposed": totals[EXPOSED],
        "exposure_days": totals[f"days:{IN_WINDOW}"],
        "carried_in": totals[CARRIED_IN],
        "entered_after_start": totals[ENTERED_AFTER_START],
        "pre_window_closed": totals[PRE_WINDOW_CLOSED],
        "exposure_days_carried_in": totals[f"days:{CARRIED_IN}"],
        "exposure_days_entered_after_start": totals[f"days:{ENTERED_AFTER_START}"],
        "open_at_window_end": {klass: open_at_end[klass] for klass in CLASSES},
        "update_events": len(steps) - 1,
        "initial_version": name(steps[0][1]),
        "final_version": name(steps[-1][1]),
        "installs": installs,
        "series": {
            "opening": opening,
            "open": series_open,
            "new": new,
            "resolved": resolved,
            "new_by_reason": reasons,
            "resolved_by_reason": {UPDATE_INSTALLED: list(resolved)},
        },
    }


def _cve_row(
    row: _Row, outcomes: dict[str, dict[str, Any]], compat_v1: bool, fix_dated_by: list[dict[str, Any]]
) -> dict[str, Any]:
    raw = row.raw
    clock_day = row.published if compat_v1 else row.clock_day
    return {
        "cve_id": row.cve_id,
        "class": IN_WINDOW if all(o["class"] == IN_WINDOW for o in outcomes.values()) else BEFORE_WINDOW,
        "clock": CLOCK_PUBLISHED if compat_v1 else row.clock,
        "clock_date": _iso(clock_day),
        "published": _iso(row.published),
        "detectable_at": _iso(row.detectable),
        "detectable_not_before": raw.get("detectable_not_before"),
        "detectable_censored": raw.get("detectable_censored"),
        "detectable_source": raw.get("detectable_source"),
        "severity": raw.get("severity"),
        "kev_date_added": raw.get("kev_date_added"),
        "edition_signal": raw.get("edition_signal"),
        "configurations_changed_after_detectable": raw.get("configurations_changed_after_detectable"),
        "affected_text": raw.get("affected_text"),
        "fix_dated_by": fix_dated_by,
        "outcomes": outcomes,
    }


# --- Identity, parity and the totals that must close -----------------------------------------


def input_id(
    document: Mapping[str, Any],
    *,
    app: str,
    track: str,
    timeline: Any,
    stops: Sequence[str] = STOPS,
    years: int = DEFAULT_YEARS,
    until: Any = None,
    common: Sequence[Any] | None = None,
    compat_v1: bool = False,
) -> str:
    """The memo key: the digest of what the walk reads. The observations enter as their digest,
    which is order-free, so a timeline listed in another order is the same input."""
    read = timeline if isinstance(timeline, _Timeline) else _timeline(timeline)
    return digest(
        {
            "algorithm": ALGORITHM,
            "definitions_version": DEFINITIONS_VERSION,
            "doc_id": document.get("doc_id"),
            "app": app,
            "track": track,
            "timeline": {
                "source": read.source,
                "name": read.name,
                "as_of": read.as_of.isoformat(),
                "clock": read.clock,
                "digest": read.digest,
            },
            "stops": [stop for stop in STOPS if stop in stops],
            "window": {
                "years": years,
                "until": _iso(day_of(until)),
                "common": [_iso(day_of(common[0])), _iso(day_of(common[1]))] if common else None,
            },
            "compat_v1": compat_v1,
        }
    )


CHECK_KEYS = (
    "since",
    "until",
    "in_window",
    "replayed",
    "excluded",
    "never_seen",
    "never_seen_outside_affected_range",
    "exposed",
    "exposure_days",
    "open_at_window_end",
    "carried_in",
    "entered_after_start",
    "pre_window_closed",
    "exposure_days_carried_in",
    "exposure_days_entered_after_start",
    "update_events",
    "initial_version",
    "final_version",
)


def check_totals(result: Mapping[str, Any], stop: str) -> dict[str, Any]:
    """The totals LoonVD publishes as the track's `check` for one stop: LoonVD computes them by
    running this module at a pinned commit, so the public walk is held to exactly these."""
    policy, counts, window = result["policies"][stop], result["counts"], result["window"]
    flat = {
        **{key: window[key] for key in ("since", "until")},
        **{key: counts[key] for key in ("in_window", "replayed", "excluded")},
        **{key: policy[key] for key in CHECK_KEYS if key in policy and key != "open_at_window_end"},
        "open_at_window_end": dict(policy["open_at_window_end"]),
    }
    return {key: flat[key] for key in CHECK_KEYS}


def _parity(prepared: _Prepared, result: dict[str, Any], years: int, until: Any, common: Any) -> dict[str, Any]:
    """Plan 4.7: the public walk at the unaligned default window must equal the document's check."""
    if prepared.compat_v1 or prepared.timeline.source != PUBLIC or until is not None or common:
        return {"state": CHECK_NOT_APPLICABLE, "detail": "Parity is held on LoonSec's published dates at the default window."}
    entry = (prepared.track.get("check") or {}).get(f"{years}y")
    if not isinstance(entry, Mapping):
        return {"state": CHECK_NO_ENTRY, "detail": f"The data holds no check for a {years}-year window of {prepared.name}."}
    for stop in result["policies"]:
        stated = entry.get(stop)
        computed = check_totals(result, stop)
        if stated != computed:
            first = next((k for k in CHECK_KEYS if not isinstance(stated, Mapping) or stated.get(k) != computed[k]), "the entry")
            shown = stated.get(first) if isinstance(stated, Mapping) else stated
            raise WalkRefused(
                REFUSED_PARITY,
                f"The walk of LoonSec's published dates for {prepared.label} over {years} years does not match "
                f"the totals LoonSec published with the data ({stop}: {first} is {computed.get(first)!r} here and "
                f"{shown!r} in the data), so no view of {prepared.name} is shown. Report the sentence with the data's date "
                "(Settings › Support).",
                {"stop": stop, "key": first, "walked": computed.get(first), "published": shown},
            )
    return {"state": CHECK_MATCHED, "detail": f"Matches the totals LoonSec published for a {years}-year window."}


def invariant_failures(result: Mapping[str, Any]) -> list[str]:
    """Every way the walk's own numbers disagree, in its own key names; empty when they all close.

    Checked on every walk before it is returned (plan 4.7), and by the tests on generated ones."""
    failures: list[str] = []
    counts, exclusions = result["counts"], result["exclusions"]

    def expect(ok: bool, text: str) -> None:
        if not ok:
            failures.append(text)

    placed = (
        counts["before_window"]
        + counts["before_window_excluded"]
        + counts["before_window_unwalked"]
        + counts["in_window"]
        + counts["after_window"]
    )
    expect(placed + counts["without_clock"] == counts["cves_in_doc"], f"placed {placed} + without_clock != cves_in_doc")
    expect(counts["replayed"] + counts["excluded"] == counts["in_window"], "replayed + excluded != in_window")
    expect(sum(exclusions["by_reason"].values()) == counts["excluded"], "exclusions.by_reason does not sum to excluded")
    expect(len(exclusions["cves"]) == counts["excluded"], "exclusions.cves does not list every excluded CVE")
    expect(
        sum(exclusions["before_window_by_reason"].values()) == counts["before_window_excluded"],
        "exclusions.before_window_by_reason does not sum to before_window_excluded",
    )
    expect(sum(counts["replayed_by_clock"].values()) == counts["replayed"], "replayed_by_clock does not sum to replayed")
    rows = result["cves"]
    in_window = [row for row in rows if row["class"] == IN_WINDOW]
    expect(len(in_window) == counts["replayed"], f"cves lists {len(in_window)} in-window rows, not replayed")
    dating = Counter(entry["how"] for row in rows for entry in row["fix_dated_by"])
    expect(
        {how: dating[how] for how in FIX_DATING} == counts["fix_dating"],
        "counts.fix_dating does not tally the rows' fix_dated_by",
    )
    for stop, policy in result["policies"].items():
        prefix = f"policies.{stop}"
        outcomes = [row["outcomes"][stop] for row in rows]
        mine = [o for o in outcomes if o["class"] == IN_WINDOW]
        expect(policy["never_seen"] + policy["exposed"] == counts["replayed"], f"{prefix}: never_seen + exposed != replayed")
        tallies = {
            "never_seen": sum(o["outcome"] == NEVER_SEEN for o in mine),
            "exposed": sum(o["outcome"] == EXPOSED for o in mine),
            "never_seen_outside_affected_range": sum(o.get("why") == OUTSIDE_RANGE for o in mine),
            "exposure_days": sum(o.get("exposure_days", 0) for o in mine),
            "carried_in": sum(o["class"] == CARRIED_IN for o in outcomes),
            "entered_after_start": sum(o["class"] == ENTERED_AFTER_START for o in outcomes),
            "exposure_days_carried_in": sum(o.get("exposure_days", 0) for o in outcomes if o["class"] == CARRIED_IN),
            "exposure_days_entered_after_start": sum(
                o.get("exposure_days", 0) for o in outcomes if o["class"] == ENTERED_AFTER_START
            ),
        }
        for key, listed in tallies.items():
            expect(listed == policy[key], f"{prefix}.{key} is {policy[key]}, the rows say {listed}")
        expect(
            policy["carried_in"] + policy["entered_after_start"] + policy["pre_window_closed"] == counts["before_window"],
            f"{prefix}: carried_in + entered_after_start + pre_window_closed != before_window",
        )
        series = policy["series"]
        open_, new, resolved = series["open"], series["new"], series["resolved"]
        expect(len(open_) == result["window"]["days"], f"{prefix}.series covers {len(open_)} days, not the window's")
        expect(
            bool(open_) and open_[0] == series["opening"] + new[0] - resolved[0],
            f"{prefix}.series: the window's first day does not open",
        )
        for at in range(1, len(open_)):
            if open_[at] != open_[at - 1] + new[at] - resolved[at]:
                failures.append(f"{prefix}.series: open[{at}] != open[{at - 1}] + new - resolved")
                break
        expect(
            [sum(day) for day in zip(*series["new_by_reason"].values(), strict=True)] == new,
            f"{prefix}.series: new_by_reason does not sum to new",
        )
        expect(series["resolved_by_reason"][UPDATE_INSTALLED] == resolved, f"{prefix}.series: a resolution is not an install")
        intervals = [o.get("intervals", []) for o in outcomes]
        listed_days = sum((dt.date.fromisoformat(b) - dt.date.fromisoformat(a)).days + 1 for found in intervals for a, b in found)
        expect(sum(open_) == listed_days, f"{prefix}.series: open sums to {sum(open_)}, the rows' intervals to {listed_days}")
        ends = policy["open_at_window_end"]
        expect(sum(ends.values()) == (open_[-1] if open_ else 0), f"{prefix}: open_at_window_end does not split open[until]")
        for row, outcome in zip(rows, outcomes, strict=True):
            found = outcome.get("intervals", [])
            opened = {a for at, (a, _) in enumerate(found) if not (outcome["class"] == CARRIED_IN and at == 0)}
            closed = {(dt.date.fromisoformat(b) + _DAY).isoformat() for _, b in found if b != result["window"]["until"]}
            expect(not opened & closed, f"{prefix}: {row['cve_id']} is both new and resolved on one day")
    return failures


def public_timeline(document: Any, *, app: str, track: str) -> dict[str, Any]:
    """The timeline of LoonSec's published dates for one track, read from the document itself."""
    app_row, track_row = _find_track(document, app, track)
    name = str(app_row.get("name") or app)
    source_id = track_row.get("timeline")
    label = str(track_row.get("label") or track)
    if not source_id:
        # Whether another source may then be shown is the caller's to say: an instance shows one
        # only once a walk of LoonSec's own dates for another window of the app matched (plan 4.7).
        raise WalkRefused(
            REFUSED_NO_PUBLIC_TIMELINE,
            f"LoonSec holds no public release dates for {label} yet, so it has none of its own to walk.",
        )
    source = ((document.get("sources") or {}).get("timelines") or {}).get(source_id)
    if not isinstance(source, Mapping):
        raise _invalid(f"sources.timelines.{source_id}", "absent", name, label)
    observations = []
    for at, entry in enumerate(_versions(track_row, name, label)):
        stamp = track_row["versions"][at].get("date")
        try:
            dated = day_of(stamp)
        except (TypeError, ValueError):
            raise _invalid(f"versions[{at}].date", f"{stamp!r} is not a date", name, label) from None
        if dated:
            spelled = entry.v.lower()
            observations.append({"version": spelled if spelled in entry.keys else entry.keys[0], "date": stamp})
    return {
        "source": PUBLIC,
        "name": source.get("name") or str(source_id),
        "as_of": source.get("fetched_at"),
        "clock": source.get("clock"),
        "observations": observations,
    }
