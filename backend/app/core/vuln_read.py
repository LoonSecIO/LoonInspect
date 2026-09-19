"""The corpus's edge on the read path — the same seam the wire uses, over rows the API
already has in hand (#251; the contract is `docs/vulnerabilities.md` §4 and §4a).

`app.core.vuln` answers *one app on one device at the moment of an event*. This module
answers the same question for *a person looking at a page now*, and it exists so there is
exactly one lookup rather than two: `assess()` is `vuln_block()` with the read path's
clock, and the block it returns is the wire's own `VulnEnrichment`. A REST client and a
Splunk event therefore use the same three words for the same three states — `covered`,
`unknown_app`, `off` — which is the whole point of putting `assessment` in front of a
person at all.

**Why the block, not a second DTO.** The contract's closed set is already typed
(`VulnEnrichment`: a `Literal` assessment, presence refused in both directions, the
absent keys dropped rather than nulled). A REST-shaped copy of it would be a second place
for the vocabulary to drift, and the first drift would be silent — a UI that renders
`counts.total: 0` for an app nobody assessed is exactly the failure §4a exists to
prevent, one layer further from where it was prevented. So the wire's model IS the REST
field, serialization aliases included: `corpusAsOf`, `daysOldestPublished`, `vulnIDs`,
`vulnIDsTruncated` land in camelCase on their own, which is what the REST layer spells
anyway.

**The sentinel is not minted here.** `-1` belongs to the HEC-shaping seam (§4c); a REST
consumer gets the canonical `null` for *never*, the same as a warehouse destination. A
page reads `null` as "no finding in this band" with no cast, and a JSON reader never has
to know that `-1` is a number Splunk needs and JavaScript does not.

**Which clock — there are two, and §4d now says so.** The wire pins `as_of` to the
snapshot's own `occurredAt`, because a Splunk event is a *historical record*: it says what
was true when that snapshot was taken, and ten delivery retries of one stored row must
expand to identical bytes. A page is not a record. It answers *how old is this finding
now*, for a person looking now, so this module counts from today's UTC date.

The two numbers therefore differ, and the gap is **not** the sync gap: it is the age of
that device's newest snapshot — bounded by the check-in cadence for a healthy device and
**unbounded once a device stops checking in**, since the event's clock stops with it while
the page's does not. Both are true; they answer different questions. Reusing the
snapshot's clock here was the alternative and it loses on §4d's own argument — it would
date the page to the last sync, so a fleet would appear to age more slowly the worse its
check-ins are, and the number would measure our collection rather than their exposure.

**What this costs, and where the answer now comes from.** One dictionary-shaped question
per row, over the rows one response already carries: one device's ~100 apps, or the
tenant's distinct app versions on the catalog page (a few thousand at most — distinct
builds, never installs, so the number does not grow with the fleet). Under `NO_CORPUS` it
is one `is None` per response and no per-row work at all. That is inside "cache, don't
calculate": no database and no walk of devices, bar the two ledger readers at the foot.

#381 (built 2026-09-11) is what fills it. The join is stored **per distinct build** on
`app_catalog` — never per device, which is the grain ruling R-D forbids and the reason a
40k-device fleet costs a pass over its few thousand builds — and copied onto every
`installed_apps` row carrying that build. So the corpus this module is handed is
`app.core.vuln_answer.stored_corpus`: a `VulnCorpus` over the answers already on the rows
the caller loaded, read rather than derived. The seam did not move and the REST shape did
not move; only where the answer comes from did. Do not reach for a per-device lookup here
— there is no per-device answer to look up.

**The exception, and its rule** (#591). The finding ledger (`device_findings`, #590) is a store,
not a derivation: *when did this pod first see CVE-X, and does it still* is not computable from
the rows a response carries at any price. So the two readers at the foot do read the database, and
that is the whole of it: **one statement per id looked up, one grouped statement per page of
builds**, never one per row — the paragraph above, applied to a table.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Protocol

from sqlalchemy import case, distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.vuln import VulnCorpus, vuln_block
from app.core.vuln_answer import HasStoredAnswer, update_effect
from app.models.schema import Device, DeviceFinding
from app.schemas.catalog import VulnUpdateOut
from app.schemas.payload import VULN_ASSESSMENT_UNKNOWN_APP, VulnEnrichment

# The refusal a vulnerability filter meets when nothing answers (#529), in
# `app.api.evidence.NO_LEDGER`'s shape. An empty list under `vuln=findings` reads as
# *nothing found* — §4a's failure written in a query string — so it is refused, and both
# causes are named because the response cannot tell them apart and neither can we. Here
# rather than on one endpoint (#535): the catalog list and the device list refuse the same
# filter for the same reason, and a second copy of these words is how one of them ends up
# naming the wrong list to drop the filter from — so the last sentence names neither.
NO_ANSWER = (
    "Nothing is answering for this organization, so a vulnerability filter has no rows to be right about. Either no "
    "corpus epoch is loaded in this container, or data sharing is off for this organization — a corpus answers only for "
    "an organization that shares (docs/vulnerabilities.md §8). Drop the filter and this list answers unfiltered."
)


class HasContentKeys(Protocol):
    """Anything carrying the v1 content-key pair — which is every row this product stores
    about an installed app: `InstalledApp` and `AppCatalogEntry` both materialize them
    (`app.core.content_keys`, stamped at device process). Typed as a protocol rather than
    a union of the two models: the ledger readers below are this module's only models import."""

    key_title: str
    key_full: str


def today() -> date:
    """The read path's `as_of` — the second of §4d's two clocks. UTC, and a function so a
    test can pin it without freezing the process clock: the wire's determinism argument
    does not apply to a page, but a test asserting a day count still needs a fixed today."""
    return datetime.now(UTC).date()


def corpus_as_of(corpus: VulnCorpus) -> date | None:
    """The stamp a page puts in its header. `None` means **no corpus is loaded** — every
    app reads `off`, and a surface must say that in words rather than showing an empty
    column, a zero, or a fabricated date (§4a; #251's "the trap").

    A one-line function on purpose: the page's stamp and the block's `corpusAsOf` come
    from the same property of the same object, so a header can never disagree with the
    rows under it.
    """
    return corpus.as_of


def assess(corpus: VulnCorpus, row: HasContentKeys, *, as_of: date) -> VulnEnrichment:
    """One row's `vuln{}`, for a reader rather than for an event."""
    return vuln_block(corpus, key_title=row.key_title, key_full=row.key_full, as_of=as_of)


def assess_all(corpus: VulnCorpus, rows: Iterable[HasContentKeys], *, as_of: date) -> Sequence[VulnEnrichment]:
    """The rows of one response, in the order they were given.

    Positional rather than keyed by hash: two rows of one catalog page can share a
    `key_title` (two versions of one app) and a device can carry two builds of one app, so
    a dict keyed on either content key would silently collapse rows that must answer
    separately. The corpus answers per build.
    """
    return [assess(corpus, row, as_of=as_of) for row in rows]


def update_line(row: HasStoredAnswer, *, corpus: VulnCorpus) -> VulnUpdateOut | None:
    """One row's *what updating would fix*, for a reader (#482), or `None` for nothing to
    say — which becomes an absent field rather than a zero, because `closes: 0` on a row
    nobody answered is §4a's failure a release along.

    The shape of `assess` above, for its reason: the arithmetic is one pure function over
    columns the caller already loaded and this is the REST dress for it. No lookup, no
    database, and no fleet-wide count — §4g's "none per request" is what half 2 must face.
    """
    effect = update_effect(row, corpus=corpus)
    if effect is None:
        return None
    return VulnUpdateOut(
        version=effect.version,
        assessment=effect.assessment or VULN_ASSESSMENT_UNKNOWN_APP,
        closes=effect.closes,
        opens=effect.opens,
        net=effect.net,
    )


@dataclass(frozen=True)
class FindingDetection:
    """One id's interval over the tenant's whole ledger (#591). `last_detected_at` is the maximum of
    two clocks, because an open row and a closed one know different things: an open row is *still
    detected as of that Mac's last observation* (nothing is written while it stays open, §6), so
    `last_seen_at` answers for it; a closed row carries its own close."""

    first_detected_at: datetime
    last_detected_at: datetime | None
    devices_open: int
    devices_ever: int


async def detection(db: AsyncSession, finding_id: str) -> FindingDetection | None:
    """The ledger's answer for one id, in ONE statement, or `None` where it holds no row for it.

    `None` is the case a surface must word rather than fill: the ledger starts the day it lands, so
    an id nothing has recorded is *not tracked by id here* and never *0 Macs* — a Mac unswept since
    #590 has no row, nor has an id beyond a build's cap (§4e). §4a one grain further in, hence an
    option rather than four zeros nothing could tell from a clear fleet."""
    open_row = DeviceFinding.resolved_at.is_(None)
    seen = case((open_row, Device.last_seen_at), else_=DeviceFinding.last_observed_at)
    macs = func.count(distinct(DeviceFinding.device_id))
    query = (
        select(func.min(DeviceFinding.first_observed_at), func.max(seen), macs.filter(open_row), macs)
        .select_from(DeviceFinding)
        .join(Device, Device.id == DeviceFinding.device_id)
        .where(DeviceFinding.finding_id == finding_id)
    )
    first, last, still_open, ever = (await db.execute(query)).one()
    return None if first is None else FindingDetection(first, last, int(still_open), int(ever))


async def seen_here_days(db: AsyncSession, builds: Sequence[str], *, as_of: date) -> dict[str, int]:
    """*Seen here* for a page of builds: days since the oldest OPEN row on each, keyed by `key_full`.
    **One grouped statement for the page**, never one per row (cache, don't calculate) — the whole
    reason this takes the page's builds rather than a build. A build with no open row is absent from
    the mapping and the surface prints a dash, not a zero: *published* is the world's clock and
    always has a date, while this is **this pod's first observation, bounded by the tenant's own
    history** (§4d). Floored at zero as the wire's is."""
    if not builds:
        return {}
    query = (
        select(DeviceFinding.build_key_full, func.min(DeviceFinding.first_observed_at))
        .where(DeviceFinding.resolved_at.is_(None), DeviceFinding.build_key_full.in_(set(builds)))
        .group_by(DeviceFinding.build_key_full)
    )
    return {build: max((as_of - at.astimezone(UTC).date()).days, 0) for build, at in (await db.execute(query)).all()}
