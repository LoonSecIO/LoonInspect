from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

# `app.core.patch_policy_feed.FEED_STATES`, in the order the page reads them: the organization's
# tier, whether a copy is held, and what the last attempt to receive one found.
PatchPolicyFeedState = Literal[
    "tier_off",
    "never",
    "current",
    "stale",
    "not_published",
    "algorithm_unknown",
    "download_failed",
    "invalid",
]
# What the last attempt found (`patch_policy_feed_state.outcome`): a copy stored, the copy held
# already current, or one of the four failures the states above share their names with.
PatchPolicyFeedOutcome = Literal["stored", "unchanged", "not_published", "algorithm_unknown", "download_failed", "invalid"]


class _Out(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class PatchPolicyFeedOut(_Out):
    """LoonSec's patch-policy data on this instance, as this organization reads it (#614)."""

    state: PatchPolicyFeedState
    # The state's sentence: what it means, and what to check (docs/troubleshooting.md §32).
    sentence: str
    # The algorithm this build reads; a document or a link for another is not this build's.
    algorithm: str
    # The copy that answers. All null while this organization's tier is off, or before a copy is held.
    doc_id: str | None = None
    as_of: datetime | None = None
    fetched_at: datetime | None = None
    # The first day LoonSec's record of NVD changes covers, as the document states it.
    coverage_since: date | None = None
    # The last day a walk over this copy can reach: the day before its `asOf`.
    until: date | None = None
    # The last attempt to receive a copy, whatever it found. Null before the first, and while
    # this organization's tier is off.
    attempted_at: datetime | None = None
    source: Literal["exchange", "file"] | None = None
    outcome: PatchPolicyFeedOutcome | None = None
    # The link's host (an object store, not the exchange's host), or the file's path.
    host: str | None = None
    http_status: int | None = None
    detail: str | None = None
    # True when PATCH_POLICY_FEED_FILE is set: the document is read from that file, and the
    # exchange's link is not followed.
    from_file: bool = False
    # When LoonSec's publisher last finished a build, as the exchange said; null when it did not
    # say (an older LoonSec, or the file). `stale` is judged from `asOf` alone; this names the
    # cause: within three days, the publisher runs and its NVD data has not advanced; older, the
    # publisher has stopped.
    built_at: datetime | None = None


class PatchPolicyClockCountsOut(_Out):
    # Listed CVEs counted from their first detectable day, and from NVD publication where that
    # day is not known. The two sum to the track's `listed`.
    detectable_at: int
    published: int


class PatchPolicyTrackOut(_Out):
    track: str
    label: str
    default: bool
    channel: str | None
    edition: str | None
    # The public timeline this track's dates come from, or null when its versions are undated.
    timeline: str | None
    versions: int
    versions_dated: int
    # Every CVE the document considered for the track: listed, excluded with a reason, or never
    # detectable. The three sum to `candidates`.
    candidates: int
    listed: int
    excluded: int
    not_detectable: int
    clock: PatchPolicyClockCountsOut


class PatchPolicySourceTrackOut(_Out):
    """One source against one track: whether a walk of it can be shown at the default two-year
    window, and if not, why (`state` and `sentence`, docs/troubleshooting.md §33)."""

    track: str
    available: bool
    # `available`, a reason the source cannot date the track (`app.core.patch_policy_timelines`'s
    # states: no_public_dates, never_synced, no_title, flag_off, catalog_unread, not_held,
    # history_unread, history_failed, no_versions, channel_empty, esr_missing, line_not_followed),
    # the walk's own refusal (no_matched_versions, too_many_unmatched, window_empty, ...), or the
    # app's parity refusal (parity, unchecked, document_invalid, no_public_dates), which the walk
    # route answers first and which every source and track of the app then carries.
    state: str
    sentence: str | None
    # The first and last day the source dates one of the track's own versions.
    first: date | None
    last: date | None
    # Distinct versions the source names that are the track's own, another track's (set aside),
    # a channel's LoonSec's data names in `other_channels` and does not walk (set aside, never
    # counted as unmatched), and in no list at all (never installed; above 5% in reach the walk
    # is refused).
    matched: int
    other_track: int
    other_channel: int = 0
    unmatched: int
    # The default two-year window a walk of this source would cover, when it can be walked.
    since: date | None
    until: date | None


class PatchPolicySourceOut(_Out):
    """One timeline source for an app, over all its tracks: whether any track can be walked on
    it, its first and last dated day, the sentence when it cannot (the default track's), how many
    distinct versions it matched, the day it was read, a note shown with every view of it, its
    own ids (the public timeline's id, Jamf title ids, Fleet slugs), and each track's answer."""

    available: bool
    state: str
    first: date | None
    last: date | None
    sentence: str | None
    ids: list[str]
    matched: int = 0
    as_of: date | None = None
    note: str | None = None
    tracks: list[PatchPolicySourceTrackOut] = Field(default_factory=list)


class PatchPolicySourcesOut(_Out):
    # LoonSec's published release dates, from the document.
    public: PatchPolicySourceOut
    # This instance's copy of Jamf's public patch catalog.
    jamf: PatchPolicySourceOut
    # This instance's copy of Fleet's version history, while the Fleet catalog flag is on.
    fleet: PatchPolicySourceOut


class PatchPolicyAppOut(_Out):
    app: str
    name: str
    bundle_ids: list[str]
    tracks: list[PatchPolicyTrackOut]
    sources: PatchPolicySourcesOut


class PatchPolicyAppsOut(_Out):
    feed: PatchPolicyFeedOut
    # The apps the held copy references. Null, never empty, when no copy answers for this
    # organization: `feed.state` says why.
    apps: list[PatchPolicyAppOut] | None


# --- GET /api/patch-policy/walk ----------------------------------------------------------------
#
# The walk is a document of its own (`kind: patch_policy_walk`, `schema: 1`), served in its own
# key names, snake_case like LoonSec's reference document's, rather than camelCased like a page
# model: the same bytes are what a ticket quotes and what the private conformance check reads.


class PatchPolicyWalkCheckOut(BaseModel):
    # `matched`: the walk of LoonSec's own dates for this window matched the totals LoonSec
    # published. `unchecked_window`: LoonSec published none for this window, and another window
    # of the app matched. Anything else is a 409, never a walk. Only the walk of LoonSec's own
    # dates at a default window is checked: on a Jamf or Fleet view, or one cut to the common
    # window, `detail` says this view's own numbers are not.
    state: Literal["matched", "unchecked_window"]
    detail: str


class PatchPolicyWalkPageOut(BaseModel):
    page: int
    page_size: int
    pages: int
    total: int


class PatchPolicyWalkOut(BaseModel):
    """One app track walked day by day over one timeline (#614), as `app.core.patch_policy_walk`
    returns it, trimmed for the wire: every total and every stop's per-day series whole, `cves`
    paged (`cves_page`), and each CVE's day intervals only under the stop asked for
    (`intervals_for`). `run_id` names the walk as computed, before trimming; `input_id` names its
    inputs. `definitions` and `clocks` state every counting rule in words."""

    model_config = ConfigDict(populate_by_name=True)

    kind: Literal["patch_policy_walk"]
    schema_: int = Field(alias="schema")
    algorithm: str
    definitions_version: str
    input_id: str
    run_id: str
    # The document, app, track and path walked, and the timeline as it joined the track's
    # versions: source, name, digest, as_of, first, last, matched, unmatched, other_track, undated,
    # conflicts, in_reach, and what was read (`ids`) and set aside (`other_track_versions`; and
    # `other_channel`, the count of versions of channels the document names and does not walk,
    # with `other_channels` giving each channel's id, label, source, count and versions).
    inputs: dict[str, Any]
    # since, until, days, the window asked for, and every term that shortened it (`shortened_by`),
    # with `aligned` when `align=common` cut it to the days every available source covers.
    window: dict[str, Any]
    counts: dict[str, Any]
    exclusions: dict[str, Any]
    # One entry per stop (1d, 7d, 14d, 30d, 60d, never): totals, installs, and the per-day series.
    policies: dict[str, Any]
    cves: list[dict[str, Any]]
    cves_page: PatchPolicyWalkPageOut
    intervals_for: str | None
    check: PatchPolicyWalkCheckOut
    definitions: dict[str, str]
    document_definitions: dict[str, Any]
    clocks: dict[str, Any]


class PatchPolicyRefusalOut(BaseModel):
    """A walk that is not shown: `detail` is the sentence (what failed, why, what to check;
    docs/troubleshooting.md §33), `reason` its word, `source` the timeline it concerns when it
    concerns one, and `facts` what a page may list beside it (the unmatched versions, the totals
    that disagreed, the window)."""

    detail: str
    reason: str
    source: str | None = None
    facts: dict[str, Any] = Field(default_factory=dict)
