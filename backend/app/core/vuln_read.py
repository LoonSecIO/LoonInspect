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

**What this costs, and what #248 changes.** One dictionary-shaped question per row, over
the rows one response already carries: one device's ~100 apps, or the tenant's distinct
app versions on the catalog page (a few thousand at most — distinct builds, never
installs, so the number does not grow with the fleet). Under `NO_CORPUS` it is one
`is None` per response and no per-row work at all. That is inside "cache, don't
calculate" — nothing here reads the database, and nothing here walks devices. When #248
stores the join per (device, app), this module is where the stored answer is read instead
of derived, and the REST shape does not move.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import date, datetime, timezone
from typing import Protocol

from app.core.vuln import VulnCorpus, vuln_block
from app.schemas.payload import VulnEnrichment


class HasContentKeys(Protocol):
    """Anything carrying the v1 content-key pair — which is every row this product stores
    about an installed app: `InstalledApp` and `AppCatalogEntry` both materialize them
    (`app.core.content_keys`, stamped at device process). Typed as a protocol rather than
    a union of the two models so this module imports no ORM."""

    key_title: str
    key_full: str


def today() -> date:
    """The read path's `as_of` — the second of §4d's two clocks. UTC, and a function so a
    test can pin it without freezing the process clock: the wire's determinism argument
    does not apply to a page, but a test asserting a day count still needs a fixed today."""
    return datetime.now(timezone.utc).date()


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
