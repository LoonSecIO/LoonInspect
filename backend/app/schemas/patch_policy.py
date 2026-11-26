from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict
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


class PatchPolicySourceOut(_Out):
    """One timeline source for an app: whether it can date the app's versions, its first and
    last dated day, the sentence when it cannot, and its own ids (timeline ids for `public`)."""

    available: bool
    first: date | None
    last: date | None
    sentence: str | None
    ids: list[str]


class PatchPolicySourcesOut(_Out):
    public: PatchPolicySourceOut
    # Not built yet: both answer `available: false` with a sentence saying so.
    jamf: PatchPolicySourceOut
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
