"""LoonSec's patch-policy reference document on this container: received, checked and held (#614).

The document (`kind: patch_policy_reference`) is one object for every app LoonSec references:
NVD-derived affected ranges compiled against each track's ordered version list, a first-
detectable day per CVE, and the public release records each track's dates come from (a vendor's
own feed, or Homebrew's cask history where no vendor feed is read). It
arrives the way the corpus does (`app.core.vuln_library`): a signed link riding the daily
data-sharing exchange's response, under `patch_policy`, keyed by the algorithm that reads it —
`{"patch_walk/2": {"signature", "asof", "url"}}` — and downloaded only when the signature, which
is the document's own `doc_id`, has moved. An air-gapped instance reads it from
`PATCH_POLICY_FEED_FILE` instead, and then the exchange downloads none.

**Checked whole before anything is written.** `read_document` recomputes `doc_id` (the sha256 of
the canonical body without it), and holds the kind, the schema, the algorithm and the counts each
track states to the rows it lists, and each app's `other_channels` (the channels it names beside
its tracks and does not walk) to their shape. A document that fails any of them is refused in a
sentence naming what failed, and the copy already held keeps answering. The last two copies are
kept.

**Held, never computed with, here.** Nothing in this module walks a timeline or compares a
version; it receives, verifies and stores, and answers `GET /api/patch-policy/apps` with the feed's
state and what the document says about each app. The day-walk over a timeline is
`app.core.patch_policy_walk`, served by `app.core.patch_policy_views`.

**Stale is judged from the copy's own date, always; LoonSec's last build only names the cause**
(2026-11-25). A copy whose `as_of` (the NVD state LoonSec built it from) is more than three days
old reads `stale`. The exchange's entry may carry `built_at`: when LoonSec's publisher last
finished a build, which it rewrites every night whether or not the document changed. It never
makes an old copy current, because a publisher that runs every night while LoonSec's NVD data
stands still makes no new document, so `built_at` stays fresh over old data: that is the case the
rule exists to catch, and why LoonSec's exchange contract has an instance judge age from `as_of`.
`built_at` picks the stale sentence: within three days, the publisher is running and its NVD data
has not advanced; older, the publisher has stopped finishing builds; absent (an older LoonSec, or
the file on an instance with no network), the copy's own date is all the sentence says.

**The tier gate is the organization.** The document is a global artifact, like the corpus, and
it is consent-gated the way the corpus is (ruled R21, 2026-11-24): an organization whose
data-sharing tier is `off` reads the tier sentence even while the container holds a copy, whichever
way the copy arrived.

Every state an operator can meet has its sentence below and its step in
`docs/troubleshooting.md` §32.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import logging
import os
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from app.core.config import settings
from app.core.egress import BlockedCorpusUrl, validate_corpus_url
from app.core.patch_policy_walk import is_older_algorithm
from app.core.tenancy import get_tenant_id
from app.core.vuln import TIER_OFF
from app.core.vuln_library import CorpusRefused, download_signed
from app.models.schema import DataSharingSettings, PatchPolicyDoc, PatchPolicyFeedState

logger = logging.getLogger(__name__)

# What this build reads. A document is refused unless all three match; a link under another
# algorithm's key is not this build's to download (LoonSec keeps publishing N-1 for at least
# 90 days after a bump, ruled R11). The walk's own (`patch_policy_walk.ALGORITHM`): publication
# starts at `patch_walk/2`, and `patch_walk/1` is never published (ruled 2026-11-27).
ALGORITHM = "patch_walk/2"
DOC_KIND = "patch_policy_reference"
DOC_SCHEMA = 1

# The copies kept: the one that answers and the one before it.
KEPT = 2

# Ceilings, not budgets, as for the corpus: a small gzip can decompress into a large one. About
# 300 KB compressed for four apps; these leave room for every app LoonSec will reference.
_MAX_DOC_BYTES = 32 * 1024 * 1024
_MAX_JSON_BYTES = 256 * 1024 * 1024

# A copy whose `as_of` is older than this reads `stale` on the page, with the day the walk must end.
STALE_AFTER = timedelta(days=3)

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Where an attempt looked.
SOURCE_EXCHANGE = "exchange"
SOURCE_FILE = "file"

# What an attempt found: `patch_policy_feed_state.outcome`.
STORED = "stored"
UNCHANGED = "unchanged"
NOT_PUBLISHED = "not_published"
ALGORITHM_UNKNOWN = "algorithm_unknown"
DOWNLOAD_FAILED = "download_failed"
INVALID = "invalid"
_FAILED = (NOT_PUBLISHED, ALGORITHM_UNKNOWN, DOWNLOAD_FAILED, INVALID)

# The feed's state as an organization reads it: the gate, then whether a copy is held, then the
# last attempt's outcome. `current` and `stale` are a held copy whose last attempt was fine.
STATE_TIER_OFF = "tier_off"
STATE_NEVER = "never"
STATE_CURRENT = "current"
STATE_STALE = "stale"
FEED_STATES = (
    STATE_TIER_OFF,
    STATE_NEVER,
    STATE_CURRENT,
    STATE_STALE,
    NOT_PUBLISHED,
    ALGORITHM_UNKNOWN,
    DOWNLOAD_FAILED,
    INVALID,
)

# The sentences, one per state (docs/diagnosability.md rule 3; docs/troubleshooting.md §32 walks
# each). The page's own copies in `frontend/src/i18n/en.ts` say the same words and
# `tests/test_patch_policy_feed.py` holds the two together.
TIER_OFF_SENTENCE = (
    "This organization does not share data with LoonSec, so it does not receive LoonSec's patch-policy data. "
    "Settings › Data Sharing."
)
NEVER_SENTENCE = (
    "LoonSec's patch-policy data has not arrived on this instance yet. It rides the daily data-sharing exchange; "
    "Settings › Data Sharing shows the last exchange."
)
NEVER_FILE_SENTENCE = (
    "LoonSec's patch-policy data has not been read from PATCH_POLICY_FEED_FILE yet. The file is read at startup "
    "and again whenever it changes; the container log says what was found."
)
NOT_PUBLISHED_SENTENCE = (
    "LoonSec's last exchange carried no patch-policy data. Nothing on this instance is wrong; report it if it lasts a day."
)
NO_COPY = " This instance holds no copy yet."


class DocumentRefused(Exception):
    """A document this container will not store, and why, in the operator's words: the
    `invalid` outcome. The previous copy keeps answering."""


@dataclass(frozen=True, slots=True)
class PatchPolicyPointer:
    """`response["patch_policy"]["patch_walk/2"]`: where the current document is.

    `signature` is the document's `doc_id`, and equality is its only operation, as for the corpus
    signature. `asof` is a copy of the document's own `as_of`, optional, and read by nothing here:
    the document is the authority.
    """

    signature: str
    asof: datetime | None
    # The query string is the credential (`app.core.egress.corpus_url_for_log`): never in a repr.
    url: str = field(repr=False)
    # When LoonSec's publisher last finished a build, changed or not (additive; None: not said).
    built_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class Offer:
    """What the exchange's response said about the document, before anything is downloaded.

    `kind` is `pointer` (a usable link for this build's algorithm), `not_published` (no
    `patch_policy` key, or an empty one), `algorithm_unknown` (links for other algorithms only:
    `algorithms` names them) or `unusable` (a link for this algorithm that cannot be dialled:
    `detail` says why, `host` names its host when it has one).
    """

    kind: str
    pointer: PatchPolicyPointer | None = None
    algorithms: tuple[str, ...] = ()
    detail: str | None = None
    host: str | None = None


def read_offer(value: object) -> Offer:
    """`response.get("patch_policy")`, read tolerantly: nothing here raises.

    Every entry carries all three keys or none (the corpus rule), so an entry missing one is not
    a link, and is said to be unusable rather than read as nothing published.
    """
    if value is None:
        return Offer(NOT_PUBLISHED)
    if not isinstance(value, Mapping):
        return Offer("unusable", detail=f"the exchange's patch_policy field is a {type(value).__name__}, not an object")
    if ALGORITHM not in value:
        others = tuple(sorted(str(key) for key in value))
        return Offer(ALGORITHM_UNKNOWN, algorithms=others) if others else Offer(NOT_PUBLISHED)
    entry = value[ALGORITHM]
    if not isinstance(entry, Mapping):
        return Offer("unusable", detail=f"the exchange's {ALGORITHM} entry is not an object")
    signature, url = entry.get("signature"), entry.get("url")
    if not isinstance(signature, str) or len(signature) != 64 or not all(c in "0123456789abcdef" for c in signature):
        return Offer("unusable", detail=f"the exchange's {ALGORITHM} entry carries no sha256 signature")
    if not isinstance(url, str):
        return Offer("unusable", detail=f"the exchange's {ALGORITHM} entry carries no link")
    host = _host(url)
    try:
        url = validate_corpus_url(url, name="the patch-policy link")
    except BlockedCorpusUrl as exc:
        return Offer("unusable", detail=f"the exchange named a link this container refuses ({exc})", host=host)
    pointer = PatchPolicyPointer(
        signature=signature, asof=_timestamp(entry.get("asof")), url=url, built_at=_instant(entry.get("built_at"))
    )
    return Offer("pointer", pointer=pointer)


def _host(url: str) -> str | None:
    try:
        return urlsplit(url.strip()).hostname
    except ValueError:
        return None


def only_older(named: str | None) -> bool:
    """Whether every algorithm the exchange named (`algorithm_unknown`'s detail, the names joined
    by commas) is an older `patch_walk` than this build's. The exchange then named the document
    only for older builds, which updating this one cannot reach: nothing here needs updating, and
    the sentence says so. Any name newer, or not a `patch_walk/N` at all, keeps the sentence that
    says to update LoonInspect if it lasts."""
    names = [name.strip() for name in (named or "").split(",") if name.strip()]
    return bool(names) and all(is_older_algorithm(name) for name in names)


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, _TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def _instant(value: object) -> datetime | None:
    """An ISO-8601 instant with its zone (`…Z` or an offset), in UTC; None for anything else, so an
    additive key that is absent or malformed reads as not said rather than as a refusal."""
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment.astimezone(UTC) if moment.tzinfo else None


# --- the check: what stands between the bytes and the table ----------------------------------


@dataclass(frozen=True, slots=True)
class Document:
    """A verified document, in memory, before anything is written."""

    doc_id: str
    schema: int
    algorithm: str
    as_of: datetime
    body: Mapping[str, object]
    body_gz: bytes
    sha256: str


def canonical_doc_id(body: Mapping[str, object]) -> str:
    """sha256 of the canonical body without `doc_id`: sorted keys, no spaces, UTF-8 unescaped.

    The body carries no build time, so a document rebuilt from the same inputs has the same id
    and an unchanged night writes nothing anywhere.
    """
    rest = {key: value for key, value in body.items() if key != "doc_id"}
    canonical = json.dumps(rest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def read_document(data: bytes, *, expected_doc_id: str | None = None) -> Document:
    """Verify one document whole, or raise `DocumentRefused` naming the first thing wrong.

    In order: the bytes are gzip JSON (or plain JSON, as a file may be) within the ceilings; the
    kind, schema and algorithm are this build's; `doc_id` is what the body hashes to, and is the
    one the exchange named; and every count a track states closes against the rows it lists. Only
    then may the caller write it.

    **Total.** Whatever the bytes are, the answer is a `Document` or a `DocumentRefused`: the
    check runs at container startup (`PATCH_POLICY_FEED_FILE`) as well as after an exchange, so a
    malformed document must never surface as a bare exception. Every shape the check knows how to
    word is worded; anything else it trips over is refused naming the exception, which is the
    line to report (docs/troubleshooting.md §32, state AB).
    """
    try:
        return _read_document(data, expected_doc_id)
    except DocumentRefused:
        raise
    except RecursionError:
        raise DocumentRefused(_TOO_DEEP) from None
    except Exception as exc:  # the check is total; the refusal names what it tripped on
        raise DocumentRefused(f"its structure could not be checked ({type(exc).__name__})") from None


_TOO_DEEP = "it is not JSON this container reads (it nests more deeply than any document does)"


def _read_document(data: bytes, expected_doc_id: str | None) -> Document:
    sha256 = hashlib.sha256(data).hexdigest()
    if data[:2] == b"\x1f\x8b":
        raw = _gunzip(data)
        body_gz = data
    else:
        raw = data
        body_gz = gzip.compress(data, mtime=0)
    try:
        body = json.loads(raw.decode("utf-8"))
    except RecursionError:
        raise DocumentRefused(_TOO_DEEP) from None
    except (UnicodeDecodeError, ValueError) as exc:
        raise DocumentRefused(f"it is not JSON ({type(exc).__name__})") from None
    if not isinstance(body, dict):
        raise DocumentRefused(f"it is a JSON {type(body).__name__}, not an object")
    if body.get("kind") != DOC_KIND:
        raise DocumentRefused(f"its kind is {_shown(body.get('kind'))}, not {DOC_KIND}")
    if body.get("schema") != DOC_SCHEMA:
        raise DocumentRefused(f"its schema is {_shown(body.get('schema'))}; this build reads schema {DOC_SCHEMA}")
    if body.get("algorithm") != ALGORITHM:
        raise DocumentRefused(f"its algorithm is {_shown(body.get('algorithm'))}; this build reads {ALGORITHM}")
    stated = body.get("doc_id")
    if not isinstance(stated, str):
        raise DocumentRefused("it lacks doc_id")
    actual = canonical_doc_id(body)
    if stated != actual:
        raise DocumentRefused(f"its doc_id {stated[:12]}… is not what its contents hash to, {actual[:12]}…")
    if expected_doc_id is not None and actual != expected_doc_id:
        raise DocumentRefused(
            f"it is not the document the exchange named: its doc_id is {actual[:12]}… and the exchange named "
            f"{expected_doc_id[:12]}…"
        )
    as_of = _timestamp(body.get("as_of"))
    if as_of is None:
        raise DocumentRefused("it lacks as_of, a UTC timestamp")
    problem = _first_problem(body)
    if problem is not None:
        raise DocumentRefused(problem)
    return Document(doc_id=actual, schema=DOC_SCHEMA, algorithm=ALGORITHM, as_of=as_of, body=body, body_gz=body_gz, sha256=sha256)


def _gunzip(data: bytes) -> bytes:
    """The decompressed bytes, or a refusal at the ceiling rather than after it."""
    inflater = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        raw = inflater.decompress(data, _MAX_JSON_BYTES + 1)
    except zlib.error:
        raise DocumentRefused("it is not a gzip file this container can read") from None
    if len(raw) > _MAX_JSON_BYTES or inflater.unconsumed_tail:
        raise DocumentRefused(f"it decompresses past the {_MAX_JSON_BYTES}-byte ceiling this container accepts")
    if not inflater.eof:
        raise DocumentRefused("its gzip stream is cut short")
    return raw


def _shown(value: object) -> str:
    return "absent" if value is None else json.dumps(value)


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_day(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return len(value) == 10


def _first_problem(body: Mapping[str, object]) -> str | None:
    """The first key the document lacks, or the first of its own counts that does not close, as
    a clause in the document's own key names; `None` when there is none.

    What is held here is structure and arithmetic only — never a version comparison, which is
    LoonSec's to compile (the ranges arrive as runs of indexes into each track's version list).
    """
    for key in ("definitions", "clocks", "sources"):
        if not isinstance(body.get(key), Mapping):
            return f"it lacks {key}"
    sources = body["sources"]
    timelines = sources.get("timelines") if isinstance(sources, Mapping) else None
    if not isinstance(timelines, Mapping):
        return "it lacks sources.timelines"
    detectable = sources.get("detectable")
    if not isinstance(detectable, Mapping) or not _is_day(detectable.get("coverage_since")):
        return "it lacks sources.detectable.coverage_since"
    reasons = body.get("exclusion_reasons")
    if not isinstance(reasons, list) or not all(isinstance(reason, str) for reason in reasons):
        return "it lacks exclusion_reasons"
    apps = body.get("apps")
    if not isinstance(apps, list):
        return "it lacks apps"
    seen_apps: set[str] = set()
    for index, app in enumerate(apps):
        if not isinstance(app, Mapping) or not isinstance(app.get("app"), str) or not isinstance(app.get("name"), str):
            return f"it lacks apps[{index}].app or .name"
        name = app["app"]
        if name in seen_apps:
            return f"its own counts disagree (apps lists {name} twice)"
        seen_apps.add(name)
        bundle_ids = app.get("bundle_ids")
        if bundle_ids is not None and not (isinstance(bundle_ids, list) and all(isinstance(b, str) for b in bundle_ids)):
            return f"it lacks {name}.bundle_ids as a list of bundle ids"
        problem = _channels_problem(name, app.get("other_channels"), app.get("tracks"))
        if problem is not None:
            return problem
        tracks = app.get("tracks")
        if not isinstance(tracks, list) or not tracks:
            return f"it lacks {name}.tracks"
        defaults = sum(1 for track in tracks if isinstance(track, Mapping) and track.get("default") is True)
        if defaults != 1:
            return f"its own counts disagree ({name} has {defaults} default tracks, not 1)"
        seen_tracks: set[str] = set()
        for track in tracks:
            problem = _track_problem(name, track, reasons, timelines, seen_tracks)
            if problem is not None:
                return problem
    return None


def _channels_problem(app: str, channels: object, tracks: object) -> str | None:
    """An app's `other_channels`, when it has any: the channels LoonSec names beside its tracks and
    does not walk, each `{channel, label, source, versions[]}`. A day-walk sets those versions
    aside when it splits a Jamf or Fleet timeline (`app.core.patch_policy_timelines.split`). Absent,
    null or empty is none; anything else must be that shape, or the document is refused naming
    where.

    Held to the contract's spelling too (LoonVD's sharedAssets/contract/patch-policy-reference.md),
    because a version spelled otherwise would match nothing an instance reads and be counted as
    unmatched without a word: each version as an instance reads it (lowercase, no space around it,
    Mozilla's `esr` suffix stripped), none twice; each channel once, ignoring case, and never one
    the app's tracks walk; `source` the https URL the versions were read from. Order is not held:
    the contract lists versions in its own version order, and a reader matches by membership."""
    if channels is None:
        return None
    shape = "a list of channels, each with channel, label and source as text and versions as a list of versions"
    if not isinstance(channels, list):
        return f"it lacks {app}.other_channels as {shape}"
    walked = {
        track["channel"].strip().lower()
        for track in (tracks if isinstance(tracks, list) else [])
        if isinstance(track, Mapping) and isinstance(track.get("channel"), str)
    }
    seen: set[str] = set()
    for index, entry in enumerate(channels):
        where = f"{app}.other_channels[{index}]"
        if not isinstance(entry, Mapping):
            return f"it lacks {app}.other_channels as {shape}"
        for key in ("channel", "label", "source"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                return f"it lacks {where}.{key} as text"
        versions = entry.get("versions")
        if not isinstance(versions, list) or not all(isinstance(v, str) and v.strip() for v in versions):
            return f"it lacks {where}.versions as a list of versions"
        channel = entry["channel"].strip().lower()
        if channel in seen:
            return f"its own counts disagree ({app}.other_channels lists {entry['channel']} twice)"
        seen.add(channel)
        if channel in walked:
            return f"its own counts disagree ({where} names {entry['channel']}, a channel a track of {app} walks)"
        source = entry["source"].strip()
        if not source.lower().startswith("https://") or _host(source) is None:
            return f"it lacks {where}.source as the https URL its versions were read from"
        for version in versions:
            if version != version.strip().lower() or version.endswith("esr"):
                return (
                    f"it lacks {where}.versions spelled as an instance reads them (lowercase, no space around, "
                    f"Mozilla's esr suffix stripped): {_shown(version)} is not"
                )
        if len(versions) != len(set(versions)):
            return f"its own counts disagree ({where}: a version is listed twice)"
    return None


def _track_problem(app: str, track: object, reasons: list[str], timelines: Mapping[str, object], seen: set[str]) -> str | None:
    """One track's structure, then every count it states against the rows it lists."""
    if not isinstance(track, Mapping) or not isinstance(track.get("track"), str):
        return f"it lacks a track id under {app}"
    where = f"{app} {track['track']}"
    if track["track"] in seen:
        return f"its own counts disagree ({app} lists {track['track']} twice)"
    seen.add(track["track"])
    # What `GET /api/patch-policy/apps` answers with must be text or nothing: a document the
    # route could not serve is refused here, not on every page load after it was stored.
    for key in ("label", "channel", "edition", "timeline"):
        if track.get(key) is not None and not isinstance(track.get(key), str):
            return f"it lacks {where} {key} as text"
    timeline = track.get("timeline")
    if timeline is not None and timeline not in timelines:
        return f"it lacks sources.timelines.{timeline}, which {where} names"
    versions, cves = track.get("versions"), track.get("cves")
    exclusions, undetectable, counts = track.get("exclusions"), track.get("not_detectable"), track.get("counts")
    if not isinstance(versions, list) or not all(isinstance(v, Mapping) and isinstance(v.get("v"), str) for v in versions):
        return f"it lacks {where} versions"
    if not all(isinstance(v.get("keys"), list) and all(isinstance(k, str) for k in v["keys"]) for v in versions):
        return f"it lacks the keys of a version of {where}"
    if not all(v.get("date") is None or _is_day(v.get("date")) for v in versions):
        return f"it lacks a day for a dated version of {where}"
    problem = _promotions_problem(track.get("promotions"), len(versions))
    if problem is not None:
        return f"it lacks {where} promotions as {problem}"
    if not isinstance(cves, list) or not all(isinstance(row, Mapping) and isinstance(row.get("cve_id"), str) for row in cves):
        return f"it lacks {where} cves"
    if not isinstance(exclusions, Mapping) or not isinstance(exclusions.get("by_reason"), Mapping):
        return f"it lacks {where} exclusions.by_reason"
    excluded_rows = exclusions.get("cves")
    if not isinstance(excluded_rows, list) or not all(
        isinstance(row, Mapping) and isinstance(row.get("cve_id"), str) for row in excluded_rows
    ):
        return f"it lacks {where} exclusions.cves, each with a cve_id"
    if not isinstance(undetectable, Mapping) or not isinstance(undetectable.get("cves"), list):
        return f"it lacks {where} not_detectable"
    # CVE ids, as the contract (LoonVD's sharedAssets/contract/patch-policy-reference.md) has them
    # and the walk reads them.
    if not all(isinstance(row, str) and row for row in undetectable["cves"]):
        return f"it lacks {where} not_detectable.cves, each a CVE id"
    if not isinstance(counts, Mapping) or not isinstance(counts.get("clock"), Mapping):
        return f"it lacks {where} counts"
    for key in ("versions", "versions_dated", "candidates", "listed", "excluded", "not_detectable"):
        if not _is_count(counts.get(key)):
            return f"it lacks {where} counts.{key}"
    for key in ("detectable_at", "published"):
        if not _is_count(counts["clock"].get(key)):
            return f"it lacks {where} counts.clock.{key}"

    def disagree(detail: str) -> str:
        return f"its own counts disagree ({where}: {detail})"

    # The versions and the index runs into them.
    size = len(versions)
    if counts["versions"] != size:
        return disagree(f"versions lists {size} ≠ counts.versions {counts['versions']}")
    dated = sum(1 for v in versions if v.get("date") is not None)
    if counts["versions_dated"] != dated:
        return disagree(f"{dated} dated versions ≠ counts.versions_dated {counts['versions_dated']}")
    keys = [key for v in versions for key in v["keys"]]
    if len(keys) != len(set(keys)):
        return disagree("a version key is listed twice")
    for row in cves:
        problem = _row_problem(row, size)
        if problem is not None:
            return disagree(problem)

    # The partition: every candidate CVE is listed, excluded, or not detectable, once.
    by_reason = exclusions["by_reason"]
    if set(by_reason) != set(reasons) or not all(_is_count(n) for n in by_reason.values()):
        return disagree("exclusions.by_reason does not name exactly the document's exclusion_reasons")
    excluded = sum(by_reason.values())
    if counts["excluded"] != excluded or len(excluded_rows) != excluded:
        return disagree(
            f"exclusions.by_reason sums to {excluded}, exclusions.cves lists {len(excluded_rows)}, "
            f"counts.excluded is {counts['excluded']}"
        )
    for reason in reasons:
        listed = sum(1 for row in excluded_rows if row.get("reason") == reason)
        if listed != by_reason[reason]:
            return disagree(f"exclusions.cves lists {listed} {reason} ≠ exclusions.by_reason.{reason} {by_reason[reason]}")
    undetected_rows = undetectable["cves"]
    if undetectable.get("count") != len(undetected_rows) or counts["not_detectable"] != len(undetected_rows):
        return disagree(
            f"not_detectable lists {len(undetected_rows)}, says {undetectable.get('count')}, "
            f"counts.not_detectable is {counts['not_detectable']}"
        )
    if counts["listed"] != len(cves):
        return disagree(f"cves lists {len(cves)} ≠ counts.listed {counts['listed']}")
    if counts["candidates"] != len(cves) + excluded + len(undetected_rows):
        return disagree(
            f"counts.candidates {counts['candidates']} ≠ listed {len(cves)} + excluded {excluded} "
            f"+ not_detectable {len(undetected_rows)}"
        )
    ids = [row["cve_id"] for row in cves] + [row.get("cve_id") for row in excluded_rows]
    ids += undetected_rows
    if len(ids) != len(set(ids)):
        return disagree("a CVE is listed twice across cves, exclusions and not_detectable")

    # The clock each listed row used: detectable_at where it is known, NVD publication otherwise.
    clocks = {"detectable_at": 0, "published": 0}
    for row in cves:
        clocks[row["clock"]] += 1
    for key, tallied in clocks.items():
        if counts["clock"][key] != tallied:
            return disagree(f"{tallied} rows use the {key} clock ≠ counts.clock.{key} {counts['clock'][key]}")
    return None


def _promotions_problem(promotions: object, size: int) -> str | None:
    """A Chrome-style promotion table, or `None` for a track without one: rows of
    `{versions: [i, j], promoted: day}` whose index runs climb the version list without
    overlapping. The shape the day-walk, a separate module, reads; a version range stays a run
    of indexes LoonSec compiled, never a version this container compares. Returns what the
    table should be, or `None` when it is fine."""
    if promotions is None:
        return None
    shape = "rows of {versions: [i, j], promoted: day} climbing the version list"
    if not isinstance(promotions, list):
        return shape
    above = -1
    for row in promotions:
        if not isinstance(row, Mapping) or not _is_day(row.get("promoted")):
            return shape
        run = row.get("versions")
        if not isinstance(run, list) or len(run) != 2 or not all(_is_count(i) for i in run):
            return shape
        if not above < run[0] <= run[1] < size:
            return shape
        above = run[1]
    return None


def _row_problem(row: Mapping[str, object], size: int) -> str | None:
    """One listed CVE: the clock it states, which must be the one the rule gives it, and index
    runs that point into the version list.

    The rule (ruled 2026-11-24): a row is placed by its first detectable day where LoonSec knows
    it, and by NVD publication otherwise, and says which. The day-walk derives the same answer
    from whether `detectable_at` is present, so a row whose stated clock disagrees would be
    counted one way here and walked the other; it is refused instead.
    """
    cve = row["cve_id"]
    clock = row.get("clock")
    if clock not in ("detectable_at", "published"):
        return f"{cve} names no clock (detectable_at or published)"
    if not _is_day(row.get(clock)):
        return f"{cve} uses the {clock} clock and has no {clock} day"
    if clock == "published" and row.get("detectable_at") is not None:
        return f"{cve} has a detectable_at day and says it uses the published clock"
    affected = row.get("affected")
    if not isinstance(affected, list):
        return f"{cve} lacks affected"
    for run in affected:
        if not isinstance(run, list) or len(run) != 2 or not all(_is_count(i) for i in run) or not run[0] <= run[1] < size:
            return f"{cve} has an affected run {json.dumps(run)} outside its {size} versions"
    fixes = row.get("fixes")
    if not isinstance(fixes, list):
        return f"{cve} lacks fixes"
    for fix in fixes:
        index = fix.get("index") if isinstance(fix, Mapping) else "?"
        if index is not None and (not _is_count(index) or index >= size):
            return f"{cve} has a fix index {json.dumps(index)} outside its {size} versions"
        # NVD's fix version as written, present only where the index does not point at it (ruled
        # 2026-11-25); the walk shows it beside the version that dated the fix, so it must be text.
        named = fix.get("named") if isinstance(fix, Mapping) else None
        if isinstance(fix, Mapping) and "named" in fix and (not isinstance(named, str) or not named):
            return f"{cve} has a fix whose named version {json.dumps(named)} is not text"
    return None


# --- storage: the last two copies, and the one row that says what the last attempt found -----


async def current_doc(db: AsyncSession) -> PatchPolicyDoc | None:
    """The copy that answers, or `None` before the first. Without its body, which is read only
    when it is not already parsed in this process (`_document`)."""
    statement = select(PatchPolicyDoc).options(defer(PatchPolicyDoc.body_gz, raiseload=True))
    return (await db.execute(statement.where(PatchPolicyDoc.current.is_(True)))).scalar_one_or_none()


async def store_document(db: AsyncSession, doc: Document) -> None:
    """Make `doc` the current copy and keep one before it, in the caller's transaction.

    Serialized with a transaction-scoped advisory lock: two organizations' exchanges, or an
    exchange and Send now, may bring the same document at once, and the partial unique index on
    `current` would refuse the second writer rather than let two copies answer.
    """
    await db.execute(text("SELECT pg_advisory_xact_lock(614, 1)"))
    now = datetime.now(UTC)
    await db.execute(update(PatchPolicyDoc).where(PatchPolicyDoc.current.is_(True)).values(current=False))
    held = (await db.execute(select(PatchPolicyDoc.doc_id).where(PatchPolicyDoc.doc_id == doc.doc_id))).scalar_one_or_none()
    if held is not None:
        await db.execute(update(PatchPolicyDoc).where(PatchPolicyDoc.doc_id == doc.doc_id).values(current=True, fetched_at=now))
    else:
        await db.execute(
            insert(PatchPolicyDoc).values(
                doc_id=doc.doc_id,
                schema=doc.schema,
                algorithm=doc.algorithm,
                as_of=doc.as_of,
                fetched_at=now,
                sha256=doc.sha256,
                body_gz=doc.body_gz,
                current=True,
            )
        )
    keep = (
        select(PatchPolicyDoc.doc_id)
        .order_by(PatchPolicyDoc.current.desc(), PatchPolicyDoc.fetched_at.desc())
        .limit(KEPT)
        .scalar_subquery()
    )
    await db.execute(delete(PatchPolicyDoc).where(PatchPolicyDoc.doc_id.not_in(keep)))


async def record_attempt(
    db: AsyncSession,
    *,
    source: str,
    outcome: str,
    host: str | None = None,
    http_status: int | None = None,
    detail: str | None = None,
    built_at: datetime | None = None,
) -> None:
    """Write the feed's one state row, in the caller's transaction. `built_at` is when LoonSec's
    publisher last finished a build, as the exchange said it with the copy this attempt found."""
    values = {
        "attempted_at": datetime.now(UTC),
        "source": source,
        "outcome": outcome,
        "host": host,
        "http_status": http_status,
        "detail": detail[:2000] if detail else None,
        "built_at": built_at,
    }
    await db.execute(
        pg_insert(PatchPolicyFeedState).values(id=1, **values).on_conflict_do_update(index_elements=["id"], set_=values)
    )


# --- the two ways a document arrives -------------------------------------------------------


async def deliver_from_exchange(
    db: AsyncSession, offer: Offer, *, transport: httpx.AsyncBaseTransport | None = None
) -> str | None:
    """The exchange's patch-policy half, end to end, after the corpus. Answers the outcome word,
    or `None` when the attempt could not be recorded at all.

    Never raises into the exchange: a refused document is a logged sentence and a state row, the
    copy already held keeps answering, and tomorrow's exchange tries again. An unmoved signature
    downloads nothing.
    """
    if settings.patch_policy_feed_file.strip():
        # The air-gapped path is the source; the exchange's link is not dialled.
        logger.debug("patch-policy data: the exchange's link not followed, because PATCH_POLICY_FEED_FILE is set")
        return None
    host = offer.host
    try:
        if offer.kind == NOT_PUBLISHED:
            await record_attempt(db, source=SOURCE_EXCHANGE, outcome=NOT_PUBLISHED)
            outcome = NOT_PUBLISHED
        elif offer.kind == ALGORITHM_UNKNOWN:
            listed = ", ".join(offer.algorithms)
            await record_attempt(db, source=SOURCE_EXCHANGE, outcome=ALGORITHM_UNKNOWN, detail=listed)
            logger.warning(
                "patch-policy data not updated: this build reads %s and LoonSec's exchange named only %s%s "
                "(docs/troubleshooting.md §32)",
                ALGORITHM,
                listed,
                (
                    ", which older builds read. Nothing on this instance needs updating: once is a passing gap at "
                    "LoonSec, and if the next exchange names the same, report it"
                    if only_older(listed)
                    else ". Once is a passing gap at LoonSec; if the next exchange names the same, update LoonInspect"
                ),
                extra={"state": ALGORITHM_UNKNOWN},
            )
            outcome = ALGORITHM_UNKNOWN
        elif offer.kind != "pointer" or offer.pointer is None:
            await record_attempt(db, source=SOURCE_EXCHANGE, outcome=DOWNLOAD_FAILED, host=host, detail=offer.detail)
            _log_refusal(DOWNLOAD_FAILED, offer.detail or "the exchange's link was unusable", host)
            outcome = DOWNLOAD_FAILED
        else:
            outcome = await _follow(db, offer.pointer, transport=transport)
        await db.commit()
        return outcome
    except SQLAlchemyError:
        await db.rollback()
        logger.warning(
            "patch-policy data could not be stored; the copy already held keeps answering. Check database "
            "availability and free storage, then retry Send now (docs/troubleshooting.md §32)",
            extra={"state": "store_failed"},
        )
        return None


async def _follow(db: AsyncSession, pointer: PatchPolicyPointer, *, transport: httpx.AsyncBaseTransport | None) -> str:
    """Download, check and store when the signature moved; record what happened either way."""
    host = _host(pointer.url)
    held = await current_doc(db)
    if held is not None and held.doc_id == pointer.signature:
        await record_attempt(db, source=SOURCE_EXCHANGE, outcome=UNCHANGED, host=host, built_at=pointer.built_at)
        logger.debug("patch-policy data unchanged (doc_id %s…)", pointer.signature[:12])
        return UNCHANGED
    try:
        data = await download_signed(pointer.url, what="patch-policy", max_bytes=_MAX_DOC_BYTES, transport=transport)
        doc = read_document(data, expected_doc_id=pointer.signature)
    except CorpusRefused as exc:
        await record_attempt(
            db, source=SOURCE_EXCHANGE, outcome=DOWNLOAD_FAILED, host=host, http_status=exc.http_status, detail=str(exc)
        )
        _log_refusal(DOWNLOAD_FAILED, str(exc), host, held)
        return DOWNLOAD_FAILED
    except DocumentRefused as exc:
        await record_attempt(db, source=SOURCE_EXCHANGE, outcome=INVALID, host=host, detail=str(exc))
        _log_refusal(INVALID, str(exc), host, held)
        return INVALID
    await store_document(db, doc)
    await record_attempt(db, source=SOURCE_EXCHANGE, outcome=STORED, host=host, built_at=pointer.built_at)
    _log_stored(doc, SOURCE_EXCHANGE)
    return STORED


# The file as this process last read it: (path, mtime_ns, size), or (path, the error) for a file
# it could not open. A tick that finds the same key reads nothing; a restart reads once more.
_file_seen: tuple | None = None


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(_MAX_DOC_BYTES + 1)


async def load_feed_file(db: AsyncSession) -> str | None:
    """Read `PATCH_POLICY_FEED_FILE` when it is set and has changed since this process last read
    it. Called at startup and on every exchange tick; answers the outcome word, or `None` when
    nothing was read.

    The same checks as a download, and the same state row with `source: file` and the path where
    a download records the link's host. Never raises, because it runs in the container's startup:
    a file that cannot be read, checked or stored is a logged sentence and a state row, never a
    container that will not start. The container log names what was found.
    """
    global _file_seen
    path = settings.patch_policy_feed_file.strip()
    if not path:
        return None
    data: bytes | None = None
    try:
        stat = os.stat(path)
        key: tuple = (path, stat.st_mtime_ns, stat.st_size)
        if key != _file_seen and stat.st_size <= _MAX_DOC_BYTES:
            data = await asyncio.to_thread(_read_bytes, path)
    except OSError as exc:
        key = (path, f"the file could not be read ({exc.strerror or type(exc).__name__})")
    if key == _file_seen:
        return None
    try:
        held = await current_doc(db)
        outcome = await _take_file(db, path, key, data, held)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        logger.warning(
            "patch-policy data from PATCH_POLICY_FEED_FILE could not be stored; the copy already held keeps "
            "answering, and the file is read again at the next tick. Check database availability and free storage "
            "(docs/troubleshooting.md §32)",
            extra={"state": "store_failed"},
        )
        return None
    except Exception as exc:  # startup must survive the file; the line logged is the report
        await db.rollback()
        outcome = await _record_unexpected(db, path, exc)
    # Marked seen whatever was found, so an unchanged file is not re-read, and a failure is not
    # re-logged, every five minutes; a change to the file reads it again.
    _file_seen = key
    return outcome


async def _record_unexpected(db: AsyncSession, path: str, exc: Exception) -> str | None:
    """A failure that is not a refusal, while taking the file: a defect to report, recorded as
    `invalid` so the page says the file was not taken, and the copy already held keeps answering."""
    logger.error(
        "patch-policy data not read from PATCH_POLICY_FEED_FILE: an unexpected failure (%s), not a refusal; the "
        "copy already held keeps answering and the file is read again when it changes. Report this line and the "
        "stack locations logged with it (docs/troubleshooting.md §32)",
        type(exc).__name__,
        exc_info=exc,
        extra={"state": INVALID, "patch_policy_source": SOURCE_FILE},
    )
    try:
        await record_attempt(
            db,
            source=SOURCE_FILE,
            outcome=INVALID,
            host=path,
            detail=f"an unexpected failure ({type(exc).__name__}) that the container log reports",
        )
        await db.commit()
    except Exception:  # the database failed too: the line above is already the report, and this never raises
        await db.rollback()
        return None
    return INVALID


async def _take_file(db: AsyncSession, path: str, key: tuple, data: bytes | None, held: PatchPolicyDoc | None) -> str:
    """One read of the file, checked and stored, with its state row written either way."""
    reason = None
    if len(key) == 2:
        reason = key[1]
    elif data is None or len(data) > _MAX_DOC_BYTES:
        reason = f"the file is larger than the {_MAX_DOC_BYTES}-byte ceiling this container accepts"
    if reason is not None:
        await record_attempt(db, source=SOURCE_FILE, outcome=DOWNLOAD_FAILED, host=path, detail=reason)
        _log_refusal(DOWNLOAD_FAILED, reason, path, held, source=SOURCE_FILE)
        return DOWNLOAD_FAILED
    try:
        doc = read_document(data)
    except DocumentRefused as exc:
        await record_attempt(db, source=SOURCE_FILE, outcome=INVALID, host=path, detail=str(exc))
        _log_refusal(INVALID, str(exc), path, held, source=SOURCE_FILE)
        return INVALID
    if held is not None and held.doc_id == doc.doc_id:
        await record_attempt(db, source=SOURCE_FILE, outcome=UNCHANGED, host=path)
        return UNCHANGED
    await store_document(db, doc)
    await record_attempt(db, source=SOURCE_FILE, outcome=STORED, host=path)
    _log_stored(doc, SOURCE_FILE)
    return STORED


def _log_refusal(
    outcome: str, reason: str, where: str | None, held: PatchPolicyDoc | None = None, *, source: str = SOURCE_EXCHANGE
) -> None:
    """One line at warning, naming what failed, the copy that still answers, and where to look."""
    origin = "PATCH_POLICY_FEED_FILE" if source == SOURCE_FILE else (where or "the exchange's link")
    kept = f"the copy dated {held.as_of.date().isoformat()} still answers" if held else "no copy is held yet"
    logger.warning(
        "patch-policy data not updated (%s, from %s): %s. %s; the next %s tries again (docs/troubleshooting.md §32)",
        outcome,
        origin,
        reason,
        kept,
        "change to the file" if source == SOURCE_FILE else "exchange",
        extra={"state": outcome, "patch_policy_source": source},
    )


def _log_stored(doc: Document, source: str) -> None:
    apps = doc.body.get("apps") or []
    logger.info(
        "patch-policy data updated: doc_id %s…, dated %s, %d apps, from %s",
        doc.doc_id[:12],
        doc.as_of.date().isoformat(),
        len(apps),
        "PATCH_POLICY_FEED_FILE" if source == SOURCE_FILE else "the exchange",
        extra={"patch_policy_doc_id": doc.doc_id, "patch_policy_as_of": doc.as_of.isoformat()},
    )


# --- what an organization reads -----------------------------------------------------------


async def tenant_tier(db: AsyncSession) -> str:
    """The acting organization's data-sharing tier, read once per request, `off` when there is
    no organization in context or no consent row — the corpus gate's rule
    (`app.core.vuln_library.read_tenant_tier`), without its side effects. The `where` names the
    tenant from context, so the row and the answer agree about whose consent this is."""
    tenant_id = get_tenant_id()
    if tenant_id is None:
        return TIER_OFF
    tier = (
        await db.execute(select(DataSharingSettings.tier).where(DataSharingSettings.tenant_id == tenant_id))
    ).scalar_one_or_none()
    return tier or TIER_OFF


@dataclass(frozen=True)
class FeedView:
    """The feed's state for one organization, with its sentence, and the document when that
    organization may read it."""

    state: str
    sentence: str
    doc_id: str | None = None
    as_of: datetime | None = None
    fetched_at: datetime | None = None
    coverage_since: date | None = None
    until: date | None = None
    attempted_at: datetime | None = None
    source: str | None = None
    outcome: str | None = None
    host: str | None = None
    http_status: int | None = None
    detail: str | None = None
    # True when PATCH_POLICY_FEED_FILE is set: the document is read from that file, and the
    # exchange's link is not followed.
    from_file: bool = False
    # When LoonSec's publisher last finished a build (the exchange's `built_at`), or None when that
    # is not known. `stale` is judged from `as_of` alone; this only picks the stale sentence's cause.
    built_at: datetime | None = None
    # Whether that build is within `STALE_AFTER` of now by this instance's clock (`held_freshness`):
    # the cause `sentence` names for a stale copy, sent so the page names the same one rather than
    # judging it again by the browser's clock. None when `built_at` is.
    publisher_running: bool | None = None
    document: Mapping[str, object] | None = field(default=None, repr=False)


def app_summaries(body: Mapping[str, object]) -> list[dict]:
    """Each app the document references and its tracks, with the counts the document states. Read
    from a checked document, so every key is there; nothing is computed. Which sources can date
    each track is `app.core.patch_policy_views.app_sources`, which reads this instance's catalogs."""
    summaries = []
    for app in body["apps"]:
        tracks = []
        for track in app["tracks"]:
            counts = track["counts"]
            tracks.append(
                {
                    "track": track["track"],
                    "label": track.get("label") or track["track"],
                    "default": track.get("default") is True,
                    "channel": track.get("channel"),
                    "edition": track.get("edition"),
                    "timeline": track.get("timeline"),
                    "versions": counts["versions"],
                    "versions_dated": counts["versions_dated"],
                    "candidates": counts["candidates"],
                    "listed": counts["listed"],
                    "excluded": counts["excluded"],
                    "not_detectable": counts["not_detectable"],
                    "clock": {"detectable_at": counts["clock"]["detectable_at"], "published": counts["clock"]["published"]},
                }
            )
        summaries.append(
            {
                "app": app["app"],
                "name": app["name"],
                "bundle_ids": [b for b in app.get("bundle_ids") or [] if isinstance(b, str)],
                "tracks": tracks,
            }
        )
    return summaries


# Parsed documents by doc_id: a page asks once per load, the document changes once a day at most,
# and decompressing it per request is a calculation the cache spares (KEPT bounds it).
_parsed: dict[str, Mapping[str, object]] = {}


async def _document(db: AsyncSession, row: PatchPolicyDoc) -> Mapping[str, object]:
    """The held copy's body, parsed once per process per `doc_id`. It was checked whole when it
    was stored, so it is read back without the check."""
    body = _parsed.get(row.doc_id)
    if body is None:
        stored = (await db.execute(select(PatchPolicyDoc.body_gz).where(PatchPolicyDoc.doc_id == row.doc_id))).scalar_one()
        body = json.loads(_gunzip(stored).decode("utf-8"))
        if len(_parsed) >= KEPT:
            _parsed.clear()
        _parsed[row.doc_id] = body
    return body


def copy_clause(as_of: date | None, *, still_used: bool = False) -> str:
    """The tail a failure sentence carries: the copy that answers, or that there is none."""
    if as_of is None:
        return NO_COPY
    return (
        f" The copy dated {as_of.isoformat()} is still used." if still_used else f" Showing the copy dated {as_of.isoformat()}."
    )


def sentence_for(
    state: str,
    *,
    as_of: date | None = None,
    source: str | None = None,
    host: str | None = None,
    detail: str | None = None,
    built_at: date | None = None,
    publisher_running: bool = False,
) -> str:
    """The one sentence for a state, filled from what the state row and the held copy say.

    For `stale`, `built_at` and `publisher_running` (`built_at` within `STALE_AFTER` of now) name
    the cause: the publisher running over NVD data that has not advanced, the publisher stopped,
    or, with no `built_at`, only the copy's own date."""
    if state == STATE_TIER_OFF:
        return TIER_OFF_SENTENCE
    if state == STATE_NEVER:
        return NEVER_FILE_SENTENCE if settings.patch_policy_feed_file.strip() else NEVER_SENTENCE
    if state == STATE_CURRENT:
        return f"Showing LoonSec's patch-policy data dated {as_of.isoformat() if as_of else '—'}."
    if state == STATE_STALE:
        dated = as_of.isoformat() if as_of else "—"
        until = (as_of - timedelta(days=1)).isoformat() if as_of else "—"
        if built_at is None:
            return f"Showing patch-policy data dated {dated}, more than three days old; the walk ends {until}."
        cause = f"but its NVD data has not advanced since {dated}" if publisher_running else "more than three days ago"
        return (
            f"Showing patch-policy data dated {dated}, more than three days old: LoonSec's publisher last ran on "
            f"{built_at.isoformat()}, {cause}, and the walk ends {until}."
        )
    if state == NOT_PUBLISHED:
        return NOT_PUBLISHED_SENTENCE + copy_clause(as_of)
    if state == ALGORITHM_UNKNOWN:
        published = detail or "other algorithms"
        if only_older(detail):
            # The exchange named the document only for older builds (`patch_walk/1` is never
            # published, ruled 2026-11-27): an update would change nothing, so the sentence says not to.
            return (
                f"This build reads {ALGORITHM}; LoonSec's last exchange named only {published}, which older builds read. "
                "Nothing on this instance needs updating; report it if it lasts a day."
            ) + copy_clause(as_of)
        return (
            f"This build reads {ALGORITHM}; LoonSec's last exchange named only {published}. If the next exchange "
            "names the same, update LoonInspect."
        ) + copy_clause(as_of)
    if state == DOWNLOAD_FAILED:
        if source == SOURCE_FILE:
            head = f"The patch-policy file could not be read from {host or 'PATCH_POLICY_FEED_FILE'}: {detail}."
        else:
            where = host or "the exchange's link"
            head = f"The patch-policy file could not be downloaded from {where}: {detail}."
        return head + copy_clause(as_of)
    if state == INVALID:
        return f"LoonSec's patch-policy data failed its check ({detail}), so it was not stored." + copy_clause(
            as_of, still_used=True
        )
    raise ValueError(f"no sentence for feed state {state!r}")


def held_freshness(as_of: datetime, built_at: datetime | None, now: datetime) -> tuple[str, bool]:
    """A held copy whose last attempt was fine: `current` or `stale`, and whether LoonSec's
    publisher is still running (`built_at` within `STALE_AFTER` of `now`), which picks the stale
    sentence's cause.

    Stale is judged from the copy's `as_of` alone, whatever `built_at` says: a publisher that
    finishes a build every night over NVD data that has not advanced writes no new document, so its
    `built_at` stays fresh over an old copy, and that is the case `stale` exists to catch."""
    running = built_at is not None and now - built_at <= STALE_AFTER
    return (STATE_STALE if now - as_of > STALE_AFTER else STATE_CURRENT), running


async def feed_view(db: AsyncSession, *, now: datetime | None = None) -> FeedView:
    """The feed's state as the acting organization reads it: the tier gate first, then whether a
    copy is held, then the last attempt. The document itself only when the gate is open."""
    from_file = bool(settings.patch_policy_feed_file.strip())
    if await tenant_tier(db) == TIER_OFF:
        return FeedView(state=STATE_TIER_OFF, sentence=TIER_OFF_SENTENCE, from_file=from_file)
    held = await current_doc(db)
    attempt = await db.get(PatchPolicyFeedState, 1)
    seen = {
        "from_file": from_file,
        "attempted_at": attempt.attempted_at if attempt else None,
        "source": attempt.source if attempt else None,
        "outcome": attempt.outcome if attempt else None,
        "host": attempt.host if attempt else None,
        "http_status": attempt.http_status if attempt else None,
        "detail": attempt.detail if attempt else None,
    }
    failed = attempt is not None and attempt.outcome in _FAILED
    if held is None:
        state = attempt.outcome if failed else STATE_NEVER
        words = sentence_for(state, source=seen["source"], host=seen["host"], detail=seen["detail"])
        return FeedView(state=state, sentence=words, **seen)
    body = await _document(db, held)
    as_of = held.as_of.date()
    sources = body.get("sources")
    detectable = sources.get("detectable") if isinstance(sources, Mapping) else None
    coverage = detectable.get("coverage_since") if isinstance(detectable, Mapping) else None
    now = now or datetime.now(UTC)
    # LoonSec's last build, when the attempt that found the copy current carried one.
    built_at = attempt.built_at if attempt is not None and attempt.outcome in (STORED, UNCHANGED) else None
    fresh, running = held_freshness(held.as_of, built_at, now)
    state = attempt.outcome if failed else fresh
    words = sentence_for(
        state,
        as_of=as_of,
        source=seen["source"],
        host=seen["host"],
        detail=seen["detail"],
        built_at=built_at.date() if built_at else None,
        publisher_running=running,
    )
    return FeedView(
        state=state,
        sentence=words,
        built_at=built_at,
        publisher_running=running if built_at is not None else None,
        doc_id=held.doc_id,
        as_of=held.as_of,
        fetched_at=held.fetched_at,
        coverage_since=date.fromisoformat(coverage) if isinstance(coverage, str) else None,
        until=as_of - timedelta(days=1),
        document=body,
        **seen,
    )
