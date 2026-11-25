"""Patch policy's three timelines (#614): the release dates a day-walk installs on, read on this instance.

The day-walk (`app.core.patch_policy_walk`) takes one timeline: `(version, day)` observations, a
name, the day it was read and how its days were stamped. This module builds the three the
page's source toggle offers, each from what this instance already holds and from nothing else:

- **public**: the release dates LoonSec's patch-policy document carries for the track
  (`versions[].date`), from the public release records the document names in `sources.timelines`
  (a vendor's own feed, such as Google's VersionHistory, Mozilla's product-details or Wireshark's
  tags, or Homebrew's cask history where no vendor feed is read).
- **jamf**: this instance's copy of Jamf's public patch catalog (`jamf_patch_titles.patches`,
  each patch's `version` and `releaseDate`), for every title whose bundle ids include one of the
  app's. The hourly sync reads Jamf's public server and needs no Jamf Pro connection
  (docs/troubleshooting.md §6).
- **fleet**: this instance's copy of Fleet's version history (`fleet_app_versions.seen_at`, the day
  Fleet's catalog first carried each version), for every Fleet title whose bundle id is one of the
  app's, and only while this organization's Fleet catalog flag is on (docs/fleet-catalog.md).

Jamf and Fleet dates are read here, walked here and sent nowhere: a walk's result is never stored,
queued or exchanged.

**Joined by membership, never by comparison** (plan 4.4). A version is a track's when its
lowercased spelling is one of the track's `versions[].keys`; it is another track's when it is one
of another track of the same app (Jamf's "Firefox ESR" title shares Firefox's bundle id, and
Thunderbird's title lists both channels interleaved); and it is unmatched when no track lists it.
An instance timeline keeps the track's versions and the unmatched ones, and sets the other
tracks' aside (`other_track`), so a release channel is never walked over ESR builds and an ESR
build is never counted against the release channel's 5% unmatched limit. Nothing here compares
two versions.

**A held line is judged by the document's own lines.** A track that holds a device on one line
(`path.kind: hold`, Wireshark 4.4) needs a dated release on that line; whether a version is on it
is the `line` LoonSec's document gives the version, never a comparison here. Fleet's catalog
carries only an app's newest line, so its history dates no 4.4 release however the document
lists the held track's versions.

**A source that cannot date a track says why** (docs/diagnosability.md rule 1): `Unavailable`
carries a state word and its sentence, and every one is a step in docs/troubleshooting.md §33.
What the walk itself refuses (no matched version, too many unmatched, an empty window) it
words itself.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import fleet_catalog
from app.core import patch_policy_walk as walk
from app.mdm.patch.matching import parse_release_date
from app.mdm.patch.requirements import bundle_ids_named
from app.models.schema import FleetAppVersion, FleetCatalogState, FleetMaintainedApp, JamfPatchTitle

PUBLIC, JAMF, FLEET = "public", "jamf", "fleet"
SOURCES = (PUBLIC, JAMF, FLEET)

# Why a source cannot date a track: `Unavailable.state`. Each is one sentence below and one step
# in docs/troubleshooting.md §33.
NO_PUBLIC_DATES = "no_public_dates"
JAMF_NEVER_SYNCED = "never_synced"
JAMF_NO_TITLE = "no_title"
FLEET_FLAG_OFF = "flag_off"
FLEET_CATALOG_UNREAD = "catalog_unread"
FLEET_NOT_HELD = "not_held"
FLEET_HISTORY_UNREAD = "history_unread"
FLEET_HISTORY_FAILED = "history_failed"
NO_VERSIONS = "no_versions"
CHANNEL_EMPTY = "channel_empty"
ESR_MISSING = "esr_missing"
LINE_NOT_FOLLOWED = "line_not_followed"
STATES = (
    NO_PUBLIC_DATES,
    JAMF_NEVER_SYNCED,
    JAMF_NO_TITLE,
    FLEET_FLAG_OFF,
    FLEET_CATALOG_UNREAD,
    FLEET_NOT_HELD,
    FLEET_HISTORY_UNREAD,
    FLEET_HISTORY_FAILED,
    NO_VERSIONS,
    CHANNEL_EMPTY,
    ESR_MISSING,
    LINE_NOT_FOLLOWED,
)

JAMF_CLOCK = (
    "The release date this instance's copy of Jamf's public patch catalog gives each version (its releaseDate), "
    "at UTC day grain, as the hourly sync last read it."
)
# Shown with every Fleet view, whatever it walks (plan 3.5, "always shown"); measured in
# docs/fleet-catalog.md.
FLEET_CLOCK = (
    "The day Fleet's catalog first carried each version, read from Fleet's public repository on this instance. "
    "These are Fleet's dates, not the vendor's: Fleet builds its catalog from Homebrew and commits it some hours "
    "later (5 to 13 hours for Firefox in October and November 2026)."
)

JAMF_NEVER_SYNCED_SENTENCE = (
    "This instance has not finished a sync of Jamf's public patch catalog yet, so it has no Jamf dates to walk. "
    "The sync runs at the top of every hour and needs no Jamf Pro connection; Sync now on Devices › Applications › "
    "Jamf Patch runs it at once (docs/troubleshooting.md §6)."
)
FLEET_FLAG_OFF_SENTENCE = fleet_catalog.FLAG_OFF
# What to do when the titles read list no version at all (`no_versions`), per source.
_READ_AGAIN = {
    JAMF: "Sync now on Devices › Applications › Jamf Patch reads the catalog again (docs/troubleshooting.md §6); if "
    "it reads the same, choose another source.",
    FLEET: "The title's history on the Fleet catalog tab says why a version is left out (docs/troubleshooting.md §27 "
    "step 10); if it reads the same after Read again, choose another source.",
}


class Unavailable(Exception):
    """A source that cannot date this app or track, and why: `state` is one of `STATES` and
    `sentence` says it in the operator's words (the walk route's 409 detail)."""

    def __init__(self, source: str, state: str, sentence: str) -> None:
        super().__init__(sentence)
        self.source = source
        self.state = state
        self.sentence = sentence


@dataclass(frozen=True, slots=True)
class Timeline:
    """One source's dates for one track, ready to walk.

    `observations` are `(version key, day or None)`, the key lowercased as the walk joins it,
    ordered by day and then key (undated last). `digest` is the walk's own digest of them, so it
    is the same figure the walk's `inputs.timeline.digest` reports. `other_track` lists the
    versions set aside as another track's; `ids` names what was read (a public timeline's id,
    Jamf title ids, Fleet slugs)."""

    source: str
    name: str
    as_of: dt.date
    clock: str | None
    observations: tuple[tuple[str, dt.date | None], ...]
    digest: str
    ids: tuple[str, ...]
    other_track: tuple[str, ...] = ()
    note: str | None = None

    def walk_input(self) -> dict[str, Any]:
        """The mapping `patch_policy_walk.walk` reads."""
        return {
            "source": self.source,
            "name": self.name,
            "as_of": self.as_of.isoformat(),
            "clock": self.clock,
            "observations": [{"version": key, "date": day.isoformat() if day else None} for key, day in self.observations],
        }


def _ordered(observations: Iterable[tuple[str, dt.date | None]]) -> tuple[tuple[str, dt.date | None], ...]:
    unique = set(observations)
    return tuple(sorted(unique, key=lambda pair: (pair[1] is None, pair[1] or dt.date.min, pair[0])))


def _digest(observations: Sequence[tuple[str, dt.date | None]]) -> str:
    """`patch_policy_walk`'s digest of a timeline's observations, which is order-free."""
    ordered = sorted(observations, key=lambda pair: (pair[0], pair[1].isoformat() if pair[1] else ""))
    return walk.digest([[key, day.isoformat() if day else None] for key, day in ordered])


def track_keys(app_row: Mapping[str, Any]) -> dict[str, set[str]]:
    """Each track's version keys, lowercased: the membership every instance timeline is split by."""
    keys: dict[str, set[str]] = {}
    for track in app_row.get("tracks") or []:
        if not isinstance(track, Mapping) or not isinstance(track.get("track"), str):
            continue
        found = keys.setdefault(track["track"], set())
        for entry in track.get("versions") or []:
            if isinstance(entry, Mapping):
                found.update(str(key).strip().lower() for key in entry.get("keys") or [] if isinstance(key, str))
    return keys


@dataclass(frozen=True, slots=True)
class Split:
    """An instance timeline against one track: what is the track's, another track's, or nobody's.

    `kept` is what the walk is given: the track's own observations and the unmatched ones, which
    the walk never installs but measures against its 5% limit and lists. `matched` are the
    track's own keys among them, and `exclusive` those no other track lists; `other` the keys set
    aside as another track's. `lists_exclusive` says whether the track lists any version no other
    track does: a held line inside a newest-line track (Wireshark 4.4 inside Wireshark's newest)
    lists none, a channel beside another channel (Firefox ESR beside Firefox) does."""

    kept: tuple[tuple[str, dt.date | None], ...]
    matched: tuple[str, ...]
    exclusive: tuple[str, ...]
    other: tuple[str, ...]
    unmatched: tuple[str, ...]
    lists_exclusive: bool

    @property
    def channel_missing(self) -> bool:
        """The timeline names another track's versions and none that would show it carries this
        one: nothing of the track's at all, or, for a track that lists versions of its own, only
        versions both tracks list (Fleet's Firefox title read for the ESR track names 140.0, which
        is on both lists, and no ESR build)."""
        if not self.other:
            return False
        return not self.matched or (self.lists_exclusive and not self.exclusive)


def split(observations: Iterable[tuple[str, dt.date | None]], app_row: Mapping[str, Any], track: str) -> Split:
    """Membership, never comparison: the track's own keys first, then any other track's, else unmatched."""
    keys = track_keys(app_row)
    own_keys = keys.get(track, set())
    other_keys: set[str] = set()
    for name, found in keys.items():
        if name != track:
            other_keys |= found
    kept: list[tuple[str, dt.date | None]] = []
    matched: set[str] = set()
    other: set[str] = set()
    unmatched: set[str] = set()
    for key, day in observations:
        if key in own_keys:
            matched.add(key)
            kept.append((key, day))
        elif key in other_keys:
            other.add(key)
        else:
            unmatched.add(key)
            kept.append((key, day))
    return Split(
        kept=_ordered(kept),
        matched=tuple(sorted(matched)),
        exclusive=tuple(sorted(matched - other_keys)),
        other=tuple(sorted(other)),
        unmatched=tuple(sorted(unmatched)),
        lists_exclusive=bool(own_keys - other_keys),
    )


def _words(names: Iterable[str]) -> str:
    return ", ".join(names)


def _track_words(track_row: Mapping[str, Any]) -> tuple[str, str, str]:
    label = str(track_row.get("label") or track_row.get("track"))
    channel = str(track_row.get("channel") or "release")
    path = track_row.get("path") if isinstance(track_row.get("path"), Mapping) else {}
    return label, channel, str(path.get("ceiling_line") or "") if path.get("kind") == walk.PATH_HOLD else ""


def _no_line(source: str, owner: str, name: str, track_row: Mapping[str, Any], ids: str) -> Unavailable:
    """The source dates no release on the line a held track holds to (`_dates_line`)."""
    label, _, ceiling = _track_words(track_row)
    newest = " Fleet's catalog carries only an app's newest line." if source == FLEET else ""
    return Unavailable(
        source,
        LINE_NOT_FOLLOWED,
        f"{owner} ({ids}) dates no {name} {ceiling} release, so the {label} device has no line to hold and there is no "
        f"{source.capitalize()} timeline for it.{newest} Choose a track that follows the newest line, or another source.",
    )


def _dates_line(joined: Split, track_row: Mapping[str, Any], ceiling: str) -> bool:
    """Whether the timeline dates a release of the track that the document puts on `ceiling`."""
    line_of = {
        str(key).strip().lower(): entry.get("line")
        for entry in track_row.get("versions") or []
        if isinstance(entry, Mapping)
        for key in entry.get("keys") or []
        if isinstance(key, str)
    }
    return any(day is not None and line_of.get(key) == ceiling for key, day in joined.kept)


def _no_channel(source: str, owner: str, name: str, track_row: Mapping[str, Any], ids: str) -> Unavailable:
    """The source names another track's versions and nothing that shows it carries this track
    (`Split.channel_missing`): the track's channel is not in what was read. Jamf's catalog may
    hold only one channel's title of the two that share a bundle id; a Fleet title read for the
    ESR track may carry the release channel only."""
    label, channel, _ = _track_words(track_row)
    who = source.capitalize()
    if source == FLEET and channel == "esr":
        return Unavailable(
            source,
            ESR_MISSING,
            f"{owner} ({ids}) names no {name} ESR release: every version it names is on another track's list, so "
            f"{label} has no Fleet timeline. Choose another source.",
        )
    return Unavailable(
        source,
        CHANNEL_EMPTY,
        f"{owner} lists no {name} release on the {channel} channel ({ids}): every version it names is on another "
        f"track's list, so {label} has no {who} timeline. Choose another track or source.",
    )


def _from_split(
    *,
    source: str,
    owner: str,
    name: str,
    app_row: Mapping[str, Any],
    track_row: Mapping[str, Any],
    observations: Sequence[tuple[str, dt.date | None]],
    as_of: dt.date,
    clock: str,
    ids: Sequence[str],
    timeline_name: str,
    note: str | None = None,
    unread: Unavailable | None = None,
) -> Timeline:
    """`unread` is what to say instead when the titles read cannot date the track and others
    under the app's bundle id are held but not yet read: those may be the track's."""
    shown = _words(ids)
    if not observations:
        if unread is not None:
            raise unread
        raise Unavailable(
            source,
            NO_VERSIONS,
            f"{owner} names no {name} version ({shown}), so there is nothing to walk. {_READ_AGAIN[source]}",
        )
    joined = split(observations, app_row, str(track_row["track"]))
    _, _, ceiling = _track_words(track_row)
    if ceiling and not _dates_line(joined, track_row, ceiling):
        if unread is not None:
            raise unread
        raise _no_line(source, owner, name, track_row, shown)
    if joined.channel_missing:
        if unread is not None:
            raise unread
        raise _no_channel(source, owner, name, track_row, shown)
    return Timeline(
        source=source,
        name=timeline_name,
        as_of=as_of,
        clock=clock,
        observations=joined.kept,
        digest=_digest(joined.kept),
        ids=tuple(ids),
        other_track=joined.other,
        note=note,
    )


# --- public: the dates in LoonSec's document ------------------------------------------------------


def public(document: Mapping[str, Any], app: str, track: str) -> Timeline:
    """The track's dates as LoonSec's document carries them. A document fault is the walk's
    refusal (`document_invalid`); a track with no public timeline is `no_public_dates`."""
    try:
        read = walk.public_timeline(document, app=app, track=track)
    except walk.WalkRefused as refused:
        if refused.reason == walk.REFUSED_NO_PUBLIC_TIMELINE:
            raise Unavailable(PUBLIC, NO_PUBLIC_DATES, refused.sentence) from None
        raise
    observations = [(str(row["version"]).lower(), walk.day_of(row["date"])) for row in read["observations"]]
    try:
        as_of = walk.day_of(read.get("as_of"))
    except (TypeError, ValueError):
        as_of = None
    if as_of is None:
        # The document names when its timeline was fetched; without it the walk could not end the window.
        raise walk.WalkRefused(
            walk.REFUSED_DOCUMENT,
            f"LoonSec's patch-policy data for {app} failed this build's check (sources.timelines: no fetched_at day), so "
            "nothing was walked. The data is the same for every instance and none of yours is read: report the sentence "
            "with the data's date (Settings › Support).",
            {"where": "sources.timelines", "what": "no fetched_at"},
        )
    track_row = walk.track_of(document, app, track)[1]
    ordered = _ordered(observations)
    return Timeline(
        source=PUBLIC,
        name=str(read["name"]),
        as_of=as_of,
        clock=read.get("clock"),
        observations=ordered,
        digest=_digest(ordered),
        ids=(str(track_row.get("timeline")),),
    )


# --- jamf: this instance's copy of Jamf's public patch catalog -----------------------------------


@dataclass(frozen=True, slots=True)
class JamfTitle:
    """One catalog title as the timeline reads it: shaped like a `jamf_patch_titles` row."""

    id: str
    name: str
    bundle_ids: tuple[str, ...]
    # `(version, day)` for each patch the title lists, as Jamf lists them.
    patches: tuple[tuple[str, dt.date | None], ...]


@dataclass(frozen=True, slots=True)
class JamfCatalog:
    """What this instance holds of Jamf's catalog for some bundle ids.

    `size` is every title held (0 before the first sync finishes), and `refreshed_at` the newest
    moment any of them was written: the catalog's own last refresh, since every hourly sync that
    finds a change writes the titles it changed."""

    size: int
    refreshed_at: dt.datetime | None
    titles: tuple[JamfTitle, ...]


def jamf_patches(patches: Iterable[Any]) -> tuple[tuple[str, dt.date | None], ...]:
    """A title's `patches` column as `(version, day)`: the version Jamf names and its
    `releaseDate` at UTC day grain (None when Jamf gives none, or none that reads as a date)."""
    found = []
    for patch in patches or ():
        if not isinstance(patch, Mapping):
            continue
        version = str(patch.get("version") or "").strip()
        if not version:
            continue
        released = parse_release_date(patch.get("releaseDate"))
        found.append((version, released.astimezone(dt.UTC).date() if released else None))
    return tuple(found)


def jamf(catalog: JamfCatalog, document: Mapping[str, Any], app: str, track: str) -> Timeline:
    """The track's dates from this instance's copy of Jamf's public patch catalog."""
    app_row, track_row = walk.track_of(document, app, track)
    name = str(app_row.get("name") or app)
    owner = "This instance's copy of Jamf's public patch catalog"
    if catalog.size == 0 or catalog.refreshed_at is None:
        raise Unavailable(JAMF, JAMF_NEVER_SYNCED, JAMF_NEVER_SYNCED_SENTENCE)
    if not catalog.titles:
        bundles = _words(app_row.get("bundle_ids") or []) or "none named"
        raise Unavailable(
            JAMF,
            JAMF_NO_TITLE,
            f"{owner} has no title for {name} (bundle id {bundles}), so there are no Jamf dates to walk. Devices › "
            "Applications › Jamf Patch lists the titles it holds; choose another source.",
        )
    titles = sorted(catalog.titles, key=lambda title: title.id)
    observations = [(version.lower(), day) for title in titles for version, day in title.patches]
    return _from_split(
        source=JAMF,
        owner=owner,
        name=name,
        app_row=app_row,
        track_row=track_row,
        observations=observations,
        as_of=catalog.refreshed_at.astimezone(dt.UTC).date(),
        clock=JAMF_CLOCK,
        ids=[title.id for title in titles],
        timeline_name=f"this instance's copy of Jamf's public patch catalog ({_words(t.name for t in titles)})",
    )


# Every title's id, name and bundle ids, parsed once per state of the catalog: its size and its
# newest write move whenever a sync writes anything, so the pair names the content.
_jamf_index: tuple[tuple[int, dt.datetime | None], tuple[tuple[str, str, tuple[str, ...]], ...]] | None = None


async def read_jamf(db: AsyncSession, bundle_ids: Iterable[str]) -> JamfCatalog:
    """The titles of this instance's Jamf catalog that name any of `bundle_ids` (compared
    case-insensitively, through the same walk of a title's requirements the catalog index uses),
    each with its patches. Reads `jamf_patch_titles` only: no device, no connection."""
    global _jamf_index
    wanted = {bundle.strip().casefold() for bundle in bundle_ids if bundle and bundle.strip()}
    size, refreshed_at = (await db.execute(select(func.count(), func.max(JamfPatchTitle.synced_at)))).one()
    key = (int(size), refreshed_at)
    if _jamf_index is None or _jamf_index[0] != key:
        rows = (
            await db.execute(
                select(JamfPatchTitle.id, JamfPatchTitle.name, JamfPatchTitle.bundle_id, JamfPatchTitle.requirements)
            )
        ).all()
        index = tuple(
            (title_id, name or title_id, tuple(bundle.casefold() for bundle in bundle_ids_named(bundle_id, requirements or [])))
            for title_id, name, bundle_id, requirements in rows
        )
        _jamf_index = (key, index)
    chosen = {title_id: (name, bundles) for title_id, name, bundles in _jamf_index[1] if wanted.intersection(bundles)}
    titles: list[JamfTitle] = []
    if chosen:
        patches = dict(
            (await db.execute(select(JamfPatchTitle.id, JamfPatchTitle.patches).where(JamfPatchTitle.id.in_(list(chosen))))).all()
        )
        for title_id, (name, bundles) in sorted(chosen.items()):
            titles.append(JamfTitle(id=title_id, name=name, bundle_ids=bundles, patches=jamf_patches(patches.get(title_id))))
    return JamfCatalog(size=int(size), refreshed_at=refreshed_at, titles=tuple(titles))


# --- fleet: this instance's copy of Fleet's version history ---------------------------------------


@dataclass(frozen=True, slots=True)
class FleetTitle:
    """One Fleet title as the timeline reads it: shaped like a `fleet_maintained_apps` row with
    its `fleet_app_versions`."""

    slug: str
    name: str
    bundle_id: str
    history_read_at: dt.datetime | None
    # When the daily check last saw the title's version move (None: never seen to move).
    version_changed_at: dt.datetime | None
    versions: tuple[tuple[str, dt.datetime], ...]


@dataclass(frozen=True, slots=True)
class FleetHistory:
    """What this instance holds of Fleet's catalog for some bundle ids, for this organization.

    `enabled` is the organization's Fleet catalog flag. `catalog_read` is whether any daily check
    has stored titles; `checked_ok_at` is the last check that got an answer and holds every title
    (a complete snapshot), which confirms a title whose version has not moved since its history
    was read; `catalog_detail` is the last check's sentence when it failed; `history_failure` the
    last history read's, when it failed."""

    enabled: bool
    catalog_read: bool
    checked_ok_at: dt.datetime | None
    catalog_detail: str | None
    history_failure: str | None
    titles: tuple[FleetTitle, ...]


def _fleet_as_of(read_at: dt.datetime, title: FleetTitle, checked_ok_at: dt.datetime | None) -> dt.datetime:
    """Up to when a title's history is known: the moment it was read, or the last answered daily
    check after that when the title's version has not moved since the read."""
    moved_since = title.version_changed_at is not None and title.version_changed_at > read_at
    if checked_ok_at is not None and checked_ok_at > read_at and not moved_since:
        return checked_ok_at
    return read_at


def fleet(history: FleetHistory, document: Mapping[str, Any], app: str, track: str) -> Timeline:
    """The track's dates from this instance's copy of Fleet's history (Fleet's dates, not the
    vendor's), while this organization's Fleet catalog flag is on."""
    app_row, track_row = walk.track_of(document, app, track)
    name = str(app_row.get("name") or app)
    if not history.enabled:
        raise Unavailable(FLEET, FLEET_FLAG_OFF, FLEET_FLAG_OFF_SENTENCE)
    bundles = _words(app_row.get("bundle_ids") or []) or "none named"
    if not history.titles:
        if not history.catalog_read:
            failed = f" The last check did not get an answer: {history.catalog_detail}" if history.catalog_detail else ""
            raise Unavailable(
                FLEET,
                FLEET_CATALOG_UNREAD,
                "Fleet's catalog has not been read on this instance yet, so there is no Fleet history to walk." + failed + " "
                "The daily check runs at twenty past the hour while the Fleet catalog flag is on; Check now on the Fleet "
                "catalog tab reads it at once (docs/troubleshooting.md §27).",
            )
        raise Unavailable(
            FLEET,
            FLEET_NOT_HELD,
            f"Fleet's catalog, as this instance last read it, holds no Mac title for {name} (bundle id {bundles}), so "
            "there is no Fleet history to walk. Check now on the Fleet catalog tab reads it again; choose another source.",
        )
    titles = sorted(history.titles, key=lambda title: title.slug)
    read = [title for title in titles if title.history_read_at is not None]
    unread = [title.slug for title in titles if title.history_read_at is None]
    if not read:
        raise _fleet_not_read(history, unread)
    observations = [(version.strip().lower(), seen_at.astimezone(dt.UTC).date()) for t in read for version, seen_at in t.versions]
    # Known only up to the earliest of them: a later day may hold a version a title read earlier lacks.
    as_of = min(_fleet_as_of(title.history_read_at, title, history.checked_ok_at) for title in read if title.history_read_at)
    slugs = [title.slug for title in read]
    note = FLEET_CLOCK
    if unread:
        # Held under the app's bundle id and not read yet (firefox@esr beside firefox, say): said
        # with the view, and said instead of the view when what was read cannot date the track.
        note += (
            f" Fleet's version history for {_words(unread)} has not been read on this instance, so its versions are not "
            "in this view; Read history on the Fleet catalog tab reads it (docs/troubleshooting.md §27)."
        )
    return _from_split(
        source=FLEET,
        owner="This instance's Fleet history",
        name=name,
        app_row=app_row,
        track_row=track_row,
        observations=observations,
        as_of=as_of.astimezone(dt.UTC).date(),
        clock=FLEET_CLOCK,
        ids=slugs,
        timeline_name=f"this instance's Fleet history ({_words(slugs)})",
        note=note,
        unread=_fleet_not_read(history, unread, read=slugs) if unread else None,
    )


def _fleet_not_read(history: FleetHistory, unread: Sequence[str], *, read: Sequence[str] = ()) -> Unavailable:
    """The Fleet titles under the app's bundle id whose history is not read yet, when nothing
    read can date the track: whether the last history read failed, and how to read them."""
    slugs = _words(unread)
    besides = f", and the history read so far ({_words(read)}) dates nothing this track can walk" if read else ""
    if history.history_failure:
        return Unavailable(
            FLEET,
            FLEET_HISTORY_FAILED,
            f"Fleet's version history for {slugs} has not been read on this instance{besides}, and the last history read "
            f"did not get an answer: {history.history_failure} The background tries again within the hour; an "
            "administrator with patch:catalog-sync can try at once with Read history on the Fleet catalog tab "
            "(docs/troubleshooting.md §27).",
        )
    return Unavailable(
        FLEET,
        FLEET_HISTORY_UNREAD,
        f"Fleet's version history for {slugs} has not been read on this instance yet{besides}. The background reads the "
        "titles installed on this organization's Macs, a few minutes apart; an administrator with patch:catalog-sync "
        "can read it now with Read history on the Fleet catalog tab (docs/troubleshooting.md §27).",
    )


async def read_fleet(db: AsyncSession, bundle_ids: Iterable[str]) -> FleetHistory:
    """The Fleet titles whose bundle id is one of `bundle_ids`, with their dated versions, for
    the acting organization. With its flag off nothing else is read."""
    if not await fleet_catalog.enabled(db):
        return FleetHistory(
            enabled=False, catalog_read=False, checked_ok_at=None, catalog_detail=None, history_failure=None, titles=()
        )
    state = await db.get(FleetCatalogState, 1)
    wanted = {bundle.strip().casefold() for bundle in bundle_ids if bundle and bundle.strip()}
    rows = (
        (await db.execute(select(FleetMaintainedApp).where(func.lower(FleetMaintainedApp.bundle_id).in_(sorted(wanted)))))
        .scalars()
        .all()
        if wanted
        else []
    )
    versions: dict[str, list[tuple[str, dt.datetime]]] = {}
    if rows:
        found = await db.execute(
            select(FleetAppVersion.slug, FleetAppVersion.version, FleetAppVersion.seen_at).where(
                FleetAppVersion.slug.in_([row.slug for row in rows])
            )
        )
        for slug, version, seen_at in found.all():
            versions.setdefault(slug, []).append((version, seen_at))
    # A check that answered but skipped manifests leaves those titles as held (snapshot `partial`),
    # so only a complete one confirms that a title's version has not moved since its history was read.
    answered = state is not None and state.outcome not in fleet_catalog.FAILED and state.snapshot_status == "complete"
    held = await db.scalar(select(func.count()).select_from(FleetMaintainedApp))
    return FleetHistory(
        enabled=True,
        catalog_read=bool(held),
        checked_ok_at=state.checked_at if answered else None,
        catalog_detail=state.detail if state is not None and state.outcome in fleet_catalog.FAILED else None,
        history_failure=(state.history_detail if state is not None and state.history_outcome in fleet_catalog.FAILED else None),
        titles=tuple(
            FleetTitle(
                slug=row.slug,
                name=row.name,
                bundle_id=row.bundle_id,
                history_read_at=row.history_read_at,
                version_changed_at=row.version_changed_at,
                versions=tuple(sorted(versions.get(row.slug, []))),
            )
            for row in rows
        ),
    )
