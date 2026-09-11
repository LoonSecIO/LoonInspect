"""`vuln{}` on the app sub-event — the corpus seam, the summary block, and the sentinel
(#249; the contract is `docs/vulnerabilities.md` §3 and §4).

Three things live here and nothing else:

* **the seam** — `VulnCorpus`, the protocol `app.core.vuln_library` implements over the
  epoch it loaded (#248), and `NO_CORPUS`, the answer until one has been. Nothing in this
  module loads data, reads a file, or touches a session: `install_corpus` is a setter the
  library calls, and `loaded_corpus()` reads what it set;
* **the block** — `vuln_block()`, which turns a corpus answer about one installed build
  into the ruled summary, in canonical form (`None`, never `-1`);
* **the sentinel** — `mint_hec_sentinels()`, the HEC-shaping seam's `None` → `-1`
  (§4c), called by `app.core.hec_fanout` and by nothing else.

**The summary is an inline enrichment on `loon:jamf:mac:app`, not a sourcetype of its
own** (§3). `loon:jamf:mac:app:vuln` stays minted with no writer and is reserved for the
post-v0 lifecycle records: one event per finding transition, not one per app. Taking the
compound here would force `loon:jamf:mac:app:patch:vuln` on an app carrying both blocks,
and a sourcetype is a permanent hand-written `props.conf` stanza in a customer's Splunk.

**Every number is scoped to this app on this device.** Never the fleet, never the app
across the fleet. The seam is keyed on the two content keys the container already
computes for every installed app (`app.core.content_keys`, stamped once in
`app.mdm.service.apply_hashes`): `key_title` identifies the application and answers *does
the corpus know this app at all*, `key_full` identifies the build and answers *which
findings are active against it*. That is #113's local hash-join, and it is why no network
call appears anywhere in this file.

**Absence is the ruling, not an omission** (§4a). Under `unknown_app` and `off` the
counts, the days and the id list are absent — not zero — because
`counts.total: 0` beside `assessment: unknown_app` hands a careless
`stats sum(vuln.counts.total)` a clean bill for a fleet nobody assessed. The
reconciliation with additive-only clause 4 is mechanical: `assessment` is always present
and always says why. `app.schemas.payload.VulnEnrichment` refuses any other combination
at enqueue, in both directions, rather than trusting this module to be careful.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Protocol, runtime_checkable

from app.schemas.payload import (
    VULN_ASSESSMENT_COVERED,
    VULN_ASSESSMENT_UNKNOWN_APP,
    VULN_SEVERITY_BANDS,
    VulnCounts,
    VulnDaysOldestPublished,
    VulnEnrichment,
    VulnSeverityCounts,
    VulnSeverityDays,
)

# The corpus's severity bands, worst first — which is also the priority order the id cap
# uses. Read off the wire model rather than restated here, so a band exists in exactly one
# place. Bands do NOT have to sum to `counts.total`: a finding the corpus carries with no
# severity score is counted in `total` and in no band (§4), which is why an unscored
# finding is a `severity: None` here rather than a fifth band.
SEVERITY_BANDS: tuple[str, ...] = VULN_SEVERITY_BANDS

# `~50 ids, priority KEV -> severity -> recency` (§4e). A server-side knob, deliberately
# NOT a wire key — which stays safe only because `vulnIDsTruncated` ships beside the list
# to say when it bit. Moving this number is free; the flag is what makes it free.
VULN_IDS_CAP = 50

# The id namespaces (§5). `CVE-` is MITRE's and `LoonVD-` is ours; `LOCAL-` is the
# customer's, reserved 2026-09-02 with nothing built behind it. Nothing LoonInspect ships
# mints a `LOCAL-` id, so one reaching this module is a corpus defect and is refused where
# the finding is constructed — see `VulnFinding`.
LOCAL_PREFIX = "LOCAL-"

# §5, "one shape … one validator": the two namespaces a finding may actually be
# constructed with. `CVE-YYYY-NNNN…` is the real CVE shape (four digits minimum, no
# maximum — MITRE's sequence numbers grow past four digits). `LoonVD-YYYY-NNNNNN` is
# ours, fixed at six. `LOCAL-` is a third, reserved namespace refused above with its own
# message, and nothing else is licensed — a `GHSA-`/`OSV-` id from a public source must
# not mint a fourth namespace on the wire, so it is refused here rather than passed
# through verbatim.
_ALLOWED_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|LoonVD-\d{4}-\d{6})$")

# `-1` means never (§4c). Minted at the HEC-shaping seam and nowhere upstream: the
# canonical payload keeps `None`, so a warehouse destination can still render SQL `NULL`.
NEVER = -1


def validate_finding_id(value: str) -> str:
    """The one validator §5 asks for, in the one place it lives.

    Called where a finding is constructed (`VulnFinding`) **and** where the library
    imports a stored row's id list (`app.core.vuln_library`), so an epoch carrying a
    `LOCAL-` id or a fourth namespace fails the epoch import loudly rather than failing
    every device sync on a per-lookup raise (docs/vulnerabilities.md §5).
    """
    if not value:
        raise ValueError("a finding needs an id")
    if value.upper().startswith(LOCAL_PREFIX):
        raise ValueError(
            f"{value!r} uses the reserved LOCAL- namespace, which nothing LoonInspect ships mints (docs/vulnerabilities.md §5)"
        )
    if not _ALLOWED_ID.match(value):
        raise ValueError(
            f"{value!r} is not one of the namespaces §5 licenses for a constructed finding — "
            "CVE-YYYY-NNNN… or LoonVD-YYYY-NNNNNN (docs/vulnerabilities.md §5)"
        )
    return value


@dataclass(frozen=True, slots=True)
class VulnFinding:
    """One active finding against one installed build, as the corpus reports it.

    Four fields, and `published` is the load-bearing one: `daysOldestPublished` is ruled
    on days since publication (§4d), so a corpus record without a publication date cannot
    answer the key at all. #248 owns the corpus format; this is the shape it must be able
    to produce.

    `severity` is one of `SEVERITY_BANDS` or `None` for a finding the corpus carries with
    no score. `kev` is CISA's Known Exploited Vulnerabilities list — a flag, not a band
    (§4), so a KEV finding is also counted in whatever band it has.

    An id outside the two constructible namespaces is refused here, at construction —
    `LOCAL-` by its own reserved-namespace message, anything else (a `GHSA-`/`OSV-` id
    from a public source, say) by not matching the shape §5 licenses. The prefix alone
    routes, so a fourth namespace minted by accident would live forever once it shipped;
    refusing it at construction means #248's corpus load fails loudly on the bad record
    instead of every device sync failing on a per-lookup raise. **#248 must therefore
    construct its findings when the corpus is loaded, not per lookup.**
    """

    id: str
    published: date
    severity: str | None = None
    kev: bool = False

    def __post_init__(self) -> None:
        validate_finding_id(self.id)
        if self.severity is not None and self.severity not in SEVERITY_BANDS:
            raise ValueError(f"{self.severity!r} is not one of {SEVERITY_BANDS} — use None for an unscored finding")


@dataclass(frozen=True, slots=True)
class AssessedBuild:
    """One assessed build as a **stored** corpus row already holds it: the aggregates,
    not the findings they were computed from (#248, and the epoch format's `rows.jsonl`).

    The second thing `findings()` may answer with, and the reason it exists: the corpus
    that arrives by the exchange carries a **capped** id list beside precomputed counts
    and publication dates, so the uncapped truth — `counts.total`, and the oldest date in
    a band whose id the cap dropped — is not recoverable from the list. Recounting a
    capped list under-reports, which is §4a's failure with a plausible-looking number in
    front of it. So the row is passed through rather than reduced to `VulnFinding`s, and
    `vuln_block` reports what the corpus counted.

    Every id is validated here, at load, for the reason §5 gives: a bad record must fail
    the epoch import rather than every device sync that touches that app. The two
    invariants the wire model would otherwise refuse at enqueue are checked here too, so
    a malformed epoch is refused whole instead of poisoning one device's snapshot:

        oldest_published.<band> is not None  <=>  severity[<band>] > 0
        truncated                            <=>  total > len(ids)

    Dates, not day counts: `daysOldestPublished` is derived at the event's own clock
    (§4c and §4d), which is why a stored row can never carry an age.
    """

    total: int
    kev: int
    severity: Mapping[str, int]
    oldest_published: date | None
    oldest_published_severity: Mapping[str, date | None]
    ids: tuple[str, ...] = ()
    truncated: bool = False

    def __post_init__(self) -> None:
        for name, mapping in (("severity", self.severity), ("oldest_published_severity", self.oldest_published_severity)):
            if tuple(mapping) != SEVERITY_BANDS:
                raise ValueError(f"{name} must carry exactly {SEVERITY_BANDS}, worst first, and carries {tuple(mapping)!r}")
        for value in (self.total, self.kev, *self.severity.values()):
            if value < 0:
                raise ValueError("a count cannot be negative")
        for finding_id in self.ids:
            validate_finding_id(finding_id)
        pairs = [(self.total, self.oldest_published, "total")]
        pairs += [(self.severity[band], self.oldest_published_severity[band], band) for band in SEVERITY_BANDS]
        for count, oldest, band in pairs:
            if (oldest is not None) != (count > 0):
                raise ValueError(f"oldest_published.{band} and the count for {band} disagree about whether a finding exists")
        if self.truncated != (self.total > len(self.ids)):
            raise ValueError(
                f"truncated is {self.truncated} with {len(self.ids)} ids and a total of {self.total}; it is true if and "
                "only if the cap dropped one"
            )


@runtime_checkable
class VulnCorpus(Protocol):
    """The lookup #249 consumes and #248 implements. Two members, deliberately.

    `as_of` is the corpus generation — the `corpusAsOf` stamp that makes a hand-refreshed
    corpus decay visibly instead of silently (§4, and Kyle's 2026-09-01 ruling 4). `None`
    means **no corpus is loaded**, and every app on every device reads `off`. That is the
    contract's own equivalence rather than two facts pressed into one: `corpusAsOf` is
    present exactly when `assessment` is not `off`.

    `findings` answers for one installed build, and its three-valued return is the whole
    `assessment` vocabulary — **`()` means this exact build was positively assessed as
    clean; anything less certain, an unknown title or a known title whose build was never
    itself assessed, means `None`** (docs/vulnerabilities.md §4f):

    * `None` — the corpus does not know this application, OR it has not itself assessed
      *this exact build*. `unknown_app`, dated, never zero vulnerabilities (§4a);
    * `()` — the corpus knows the application AND has positively assessed this exact
      build, with no active findings against it. `covered`, which is a clean bill
      precisely because `covered` says we looked at this build specifically;
    * a non-empty sequence — `covered`, with the counts, days and ids this module derives.

    **The hash-join trap this distinction exists to name:** for a corpus keyed on
    `(title, build)` hashes, a known title with no stored hash for *this exact build* is
    the common case — most builds of a well-known app were never individually scanned —
    and answering `()` there is a `covered` clean bill for a build nobody assessed, §4a's
    failure one layer down. This module cannot tell an unassessed build from a positively
    clean one; both arrive as `()`. So the corpus must not default to `()` (a
    `dict.get(key_full, ())` reads exactly like a positive clean bill to this module) —
    it must return `None` unless it can name the assessment that produced the empty
    result.

    Order is not the corpus's problem: `vuln_block` sorts by the ruled priority before it
    caps. Nor is the day arithmetic, which depends on the event's own occurrence time and
    so cannot be stored per app.

    **The fourth answer, added by #248 and additive to the three above:** an
    `AssessedBuild` — one stored row's precomputed aggregates. It says exactly what a
    non-empty sequence says (`covered`, with counts, days and ids) for a corpus that
    counted the findings when the epoch was compiled and ships a capped id list. The
    protocol's member set does **not** widen: still `as_of` and `findings`, so every
    corpus written against the two-member interface — `NO_CORPUS`, a test's stub — is
    unchanged and stays a `VulnCorpus`. Only the return type does.
    """

    @property
    def as_of(self) -> date | None: ...

    def findings(self, *, key_title: str, key_full: str) -> AssessedBuild | Sequence[VulnFinding] | None: ...


class _NoCorpus:
    """The corpus every container ships with until #248 lands: none.

    `as_of` is `None`, so `vuln_block` short-circuits to `{"assessment": "off"}` without
    ever calling `findings` — the byte-identical constant #241 and #242 were told to emit,
    now produced by the seam rather than hard-coded at the app item.
    """

    as_of: date | None = None

    def findings(self, *, key_title: str, key_full: str) -> Sequence[VulnFinding] | None:
        return None


NO_CORPUS: VulnCorpus = _NoCorpus()

# The corpus this process has loaded, or None for "none". Written by exactly one module —
# `app.core.vuln_library`, when it imports an epoch and when it reads the epoch row at
# startup — and read by `loaded_corpus()` below. A module-level variable rather than an
# import of the library here, because the library imports this module for `AssessedBuild`;
# the setter keeps the dependency one-way and keeps this file free of anything that reads
# a file, a session or a socket.
_INSTALLED: VulnCorpus | None = None


def install_corpus(corpus: VulnCorpus | None) -> None:
    """Put the loaded library behind `loaded_corpus()`, or take it away (`None`).

    **The refresh rule, stated once:** the process-level answer changes when the epoch row
    changes and at no other time — `app.core.vuln_library.refresh_from_db` at startup, and
    the importer itself after it has replaced the epoch. Nothing polls, and nothing reads
    the database on the page path (that is the whole of "cache, don't calculate"). A second
    process that did not run the import picks the new epoch up at its next start; the row
    in the database is the truth, and #381's set-based join reads it there rather than
    here.
    """
    global _INSTALLED
    _INSTALLED = corpus


def loaded_corpus() -> VulnCorpus:
    """The corpus this container has loaded — the single place that decides.

    `NO_CORPUS` until an epoch has been imported, which is the whole of #281's Option A
    and the reason it needs no argument: the library arrives on the data-sharing exchange,
    a pod that has not consented never exchanges, so it is never handed a link and never
    loads anything (docs/data-sharing.md, docs/vulnerabilities.md §8). Nothing else in the
    codebase changes when an epoch lands — the snapshot builder takes a `VulnCorpus` and
    `app.mdm.service.process_sync` passes whatever this returns.

    A function rather than a module constant so the swap is one assignment and so a test
    can pass its own corpus without reaching for a global.
    """
    return _INSTALLED if _INSTALLED is not None else NO_CORPUS


def _band_index(finding: VulnFinding) -> int:
    """Worst band first; an unscored finding sorts after `low`.

    **Assumption**: §4e rules the priority `KEV -> severity -> recency` and does not say
    where a finding with no severity score goes. Last, because the cap exists to keep the
    findings most worth naming, and a band the corpus could not score is the one it knows
    least about. It is not dropped — it is still in `counts.total`.
    """
    return SEVERITY_BANDS.index(finding.severity) if finding.severity in SEVERITY_BANDS else len(SEVERITY_BANDS)


def _priority(finding: VulnFinding) -> tuple[int, int, int, str]:
    """The ruled cap order (§4e): KEV first, then severity band, then recency.

    **Assumption**: "recency" is read as *most recently published first*; the contract
    names the term and not the direction. The id breaks the remaining tie so two findings
    published on one day in one band always cap the same way — the fan-out has to expand
    one stored row to the same bytes on every retry.
    """
    return (0 if finding.kev else 1, _band_index(finding), -finding.published.toordinal(), finding.id)


def _days_since(published: date, as_of: date) -> int:
    """Days since publication, floored at zero.

    **Assumption**: a publication date later than the event's own occurrence time — a
    snapshot replayed out of the retention window against a corpus refreshed since — reads
    `0` rather than a negative number. `-1` already means *never* (§4c) and a negative day
    count would collide with it; zero says "published no earlier than this event", which
    is what happened.
    """
    return max((as_of - published).days, 0)


def _from_assessed(row: AssessedBuild, *, corpus_as_of: date, as_of: date) -> VulnEnrichment:
    """The same block, from a row that was counted when the epoch was compiled.

    Two things are still this module's and are still done here, because both depend on
    something the corpus cannot know. **The day arithmetic** — the row carries absolute
    publication dates and the event carries its own clock (§4d), and an age stored in a
    row would be stale the moment it was written. And **the cap** — `VULN_IDS_CAP` is this
    container's server-side knob (§4e); an epoch that shipped a longer list than this
    build's cap is trimmed here and says so, so moving the number stays free in both
    directions. `counts.total` is untouched by either: it is the uncapped truth the row
    states, which is exactly why a stored row is passed through rather than recounted.
    """

    def days(published: date | None) -> int | None:
        return None if published is None else _days_since(published, as_of)

    return VulnEnrichment(
        assessment=VULN_ASSESSMENT_COVERED,
        corpus_as_of=corpus_as_of,
        counts=VulnCounts(
            total=row.total,
            kev=row.kev,
            severity=VulnSeverityCounts(**{band: row.severity[band] for band in SEVERITY_BANDS}),
        ),
        days_oldest_published=VulnDaysOldestPublished(
            total=days(row.oldest_published),
            severity=VulnSeverityDays(**{band: days(row.oldest_published_severity[band]) for band in SEVERITY_BANDS}),
        ),
        vuln_ids=list(row.ids[:VULN_IDS_CAP]),
        vuln_ids_truncated=row.truncated or len(row.ids) > VULN_IDS_CAP,
    )


def vuln_block(corpus: VulnCorpus, *, key_title: str, key_full: str, as_of: date) -> VulnEnrichment:
    """The `vuln{}` summary for one installed app on one device.

    `as_of` is the snapshot's own `occurredAt` date, not the wall clock: the builder is
    pure and clock-free, and delivery is retried against the stored row up to ten times,
    so a day boundary crossed between attempts must not change the bytes.

    Everything the block reports is derived from the findings the corpus returned for this
    build. `daysOldestPublished` is the OLDEST — the largest day count, per band and
    overall — which is why the total is not the maximum of the four bands: an unscored
    finding is in the total and in no band.
    """
    if corpus.as_of is None:
        return VulnEnrichment()
    findings = corpus.findings(key_title=key_title, key_full=key_full)
    if findings is None:
        return VulnEnrichment(assessment=VULN_ASSESSMENT_UNKNOWN_APP, corpus_as_of=corpus.as_of)
    if isinstance(findings, AssessedBuild):
        return _from_assessed(findings, corpus_as_of=corpus.as_of, as_of=as_of)

    ordered = sorted(findings, key=_priority)
    by_band = {band: [f for f in ordered if f.severity == band] for band in SEVERITY_BANDS}
    oldest = {band: max((_days_since(f.published, as_of) for f in found), default=None) for band, found in by_band.items()}
    return VulnEnrichment(
        assessment=VULN_ASSESSMENT_COVERED,
        corpus_as_of=corpus.as_of,
        counts=VulnCounts(
            total=len(ordered),
            kev=sum(1 for f in ordered if f.kev),
            severity=VulnSeverityCounts(**{band: len(found) for band, found in by_band.items()}),
        ),
        days_oldest_published=VulnDaysOldestPublished(
            total=max((_days_since(f.published, as_of) for f in ordered), default=None),
            severity=VulnSeverityDays(**oldest),
        ),
        vuln_ids=[finding.id for finding in ordered[:VULN_IDS_CAP]],
        vuln_ids_truncated=len(ordered) > VULN_IDS_CAP,
    )


def mint_hec_sentinels(item: Mapping[str, object]) -> Mapping[str, object]:
    """`None` -> `-1` in every `daysOldestPublished`, on one fan-out sub-event body item.

    §4c, in the seam it names: *"The sentinel is minted in the HEC-shaping seam. The
    canonical layer keeps `None`, and other destination dialects may render it natively —
    SQL `NULL`."* So the stored snapshot, a generic webhook and an Elastic document all
    carry `null`, and only the Splunk fan-out sees `-1`. The reason the wire needs a
    sentinel at all is additive-only clause 4: absence is already reserved to mean *the
    event predates this key*, so it cannot also mean *never*.

    Returns the item unchanged — the same object, not a copy — when there is nothing to
    mint, which is every app item under `off` and `unknown_app` and every one of the
    thirteen other sections. The input is never mutated: delivery is retried against the
    same stored row, and the second attempt must expand exactly what the first did.
    """
    block = item.get("vuln")
    if not isinstance(block, Mapping):
        return item
    days = block.get("daysOldestPublished")
    if not isinstance(days, Mapping):
        return item
    minted = {
        key: {inner: NEVER if value is None else value for inner, value in value.items()}
        if isinstance(value, Mapping)
        else (NEVER if value is None else value)
        for key, value in days.items()
    }
    return {**item, "vuln": {**block, "daysOldestPublished": minted}}
