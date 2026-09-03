"""`vuln{}` on the app sub-event — the corpus seam, the summary block, and the sentinel
(#249; the contract is `docs/vulnerabilities.md` §3 and §4).

Three things live here and nothing else:

* **the seam** — `VulnCorpus`, the protocol #248 implements, and `NO_CORPUS`, the one
  implementation that ships today. Nothing in this module loads data, reads a file, or
  touches a session;
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

# `-1` means never (§4c). Minted at the HEC-shaping seam and nowhere upstream: the
# canonical payload keeps `None`, so a warehouse destination can still render SQL `NULL`.
NEVER = -1


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

    A `LOCAL-` id is refused here, at construction. The prefix is reserved and nothing is
    built behind it, so an id wearing it is a corpus defect rather than a customer
    finding — and refusing it at construction means #248's corpus load fails loudly on the
    bad record instead of every device sync failing on a per-lookup raise. **#248 must
    therefore construct its findings when the corpus is loaded, not per lookup.**
    """

    id: str
    published: date
    severity: str | None = None
    kev: bool = False

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("a finding needs an id")
        if self.id.upper().startswith(LOCAL_PREFIX):
            raise ValueError(
                f"{self.id!r} uses the reserved LOCAL- namespace, which nothing LoonInspect ships mints "
                "(docs/vulnerabilities.md §5)"
            )
        if self.severity is not None and self.severity not in SEVERITY_BANDS:
            raise ValueError(f"{self.severity!r} is not one of {SEVERITY_BANDS} — use None for an unscored finding")


@runtime_checkable
class VulnCorpus(Protocol):
    """The lookup #249 consumes and #248 implements. Two members, deliberately.

    `as_of` is the corpus generation — the `corpusAsOf` stamp that makes a hand-refreshed
    corpus decay visibly instead of silently (§4, and Kyle's 2026-09-01 ruling 4). `None`
    means **no corpus is loaded**, and every app on every device reads `off`. That is the
    contract's own equivalence rather than two facts pressed into one: `corpusAsOf` is
    present exactly when `assessment` is not `off`.

    `findings` answers for one installed build, and its three-valued return is the whole
    `assessment` vocabulary:

    * `None` — the corpus does not know this application. `unknown_app`, dated, never
      zero vulnerabilities (§4a);
    * `()` — it knows the application and this build has no active findings. `covered`,
      which is a clean bill precisely because `covered` says we looked;
    * a non-empty sequence — `covered`, with the counts, days and ids this module derives.

    Order is not the corpus's problem: `vuln_block` sorts by the ruled priority before it
    caps. Nor is the day arithmetic, which depends on the event's own occurrence time and
    so cannot be stored per app.
    """

    @property
    def as_of(self) -> date | None: ...

    def findings(self, *, key_title: str, key_full: str) -> Sequence[VulnFinding] | None: ...


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


def loaded_corpus() -> VulnCorpus:
    """The corpus this container has loaded — the single place that decides.

    `NO_CORPUS` today. #248 replaces this function's body with the static, hand-refreshed,
    public-sources corpus it ships (§2), and nothing else in the codebase changes: the
    snapshot builder takes a `VulnCorpus` and `app.mdm.service.process_sync` passes
    whatever this returns. A function rather than a module constant so the swap is one
    edit and so a test can pass its own corpus without reaching for a global.
    """
    return NO_CORPUS


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
