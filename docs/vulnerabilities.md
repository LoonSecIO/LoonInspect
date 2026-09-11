# The vulnerability contract

Status: **ruled; the wire block is built and the corpus now arrives by the exchange** ·
Ruled on [#113](https://github.com/LoonSecIO/LoonInspect/issues/113): the corpus cut and
`assessment` on 2026-09-01, the four naming and lifecycle items on 2026-09-02; the
delivery of the corpus re-ruled 2026-09-10 (§2) · Wire keys obey the frozen vocabulary in
[`docs/splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md)

This document exists because the vulnerability design lived in a session record and two
issue comments, and a contract that lives only in a session record is one that gets
re-argued by whoever builds it. Everything below is a decision with an argument.

**What is built, as of 2026-09-10** ([#249](https://github.com/LoonSecIO/LoonInspect/issues/249),
[#251](https://github.com/LoonSecIO/LoonInspect/issues/251),
[#248](https://github.com/LoonSecIO/LoonInspect/issues/248)): the summary block of §4 in
full — every key, the presence rules, the cap, the clock and the sentinel — plus the
lookup seam it reads (`VulnCorpus` in `app/core/vuln.py`), **the UI half** (the same block
on the REST responses that carry installed apps, and the three states rendered distinctly
with `corpusAsOf` beside them, §4g), and **the library behind the seam**: #248 loads a
published corpus epoch from the data-sharing exchange into a global table pair and answers
from stored rows (`app/core/vuln_library.py`).

A container with no epoch imported is still exactly what it was: `loaded_corpus()` answers
`NO_CORPUS`, every app on every device reads `assessment: off`, and the snapshot is
byte-identical to the one #241 and #242 shipped — asserted, not claimed
(`backend/tests/test_vuln_block.py`). So does a **tenant** whose data-sharing tier is
`off`, even where the pod holds an epoch: that is #281's Option A, read at the grain a
multi-tenant pod actually has (§8, ruled 2026-09-11).

What is **not** built is the per-build join at judge time — the stored answer on
`app_catalog` and `installed_apps`
([#381](https://github.com/LoonSecIO/LoonInspect/issues/381)) — and the four posture keys
([#250](https://github.com/LoonSecIO/LoonInspect/issues/250)). §10 tracks the rest.

The block it rules is `vuln{}` — LoonInspect's own answer about an app Jamf reported,
riding that app's sub-event beside `patch{}`. It is the highest fan-out object the
product emits: one block per app, per device, per sync. Every name here is paid for at
that multiple, and under additive-only every name here is permanent.

---

## 1. The legal condition, stated rather than assumed

#113 was raised with a condition attached: an in-flight repository holds an API gateway
and a dataset exposing the start of this data, and an open question about data sourcing
makes using it conditional. The ruling states the condition instead of designing around
a dataset that may not be available.

> **The condition.** The NVD-derived dataset and its gateway may be read by a shipped
> LoonInspect artifact only once the data-sourcing question is resolved in writing.
> Until then no shipped artifact reads it, and nothing in this contract assumes it
> exists, when it arrives, or in what form.

**Nothing in this document depends on that answer**, because v0 does not use the
dataset. The v0 corpus is static, hand-refreshed, and built from public sources only
(§2). If the sourcing question later resolves in favour of the dataset, it enters as a
*bigger corpus and a `corpusAsOf` that starts moving on its own* — an additive change to
the data, never a change to the wire. If it resolves against, nothing written here has
to be unsaid, because nothing written here claims a detection.

What the condition does gate is scale, not shape. That is the whole reason these
namings were worth taking inside the freeze window: **the vocabulary is the part that
freezes, and it freezes independently of the data.**

## 2. What v0 is

Ruled 2026-09-01, against AI-over-inventory for the last v0 feature slot. CVE won on one
argument: **CVE has a clock and AI does not.** The four reserved `vuln.*` posture keys
(§7) start a tape that cannot be backfilled; an AI summary is worth the same whenever it
ships, and is *better* after CVE, since the version-diff narration's payload is the CVE
delta.

| | v0 | Not v0 |
| --- | --- | --- |
| Corpus | **Arrives by the exchange** — a Jamf-derived epoch, compiled elsewhere, published complete once a day (ruled 2026-09-10; #248 loads it) | The nightly NVD→corpus scan itself |
| Join | Local hash-join, in the container | Any call to a vulnerability gateway |
| Refresh | Daily, when the published signature moves; stamped in `corpusAsOf` | — |
| Half | Container↔cloud: the exchange response's `corpus` pointer, and the `verdicts` slot beside it — still reserved, still unparsed, and a **separate channel** from the corpus (`backend/app/core/sharing.py`) | The compiler, which lives outside this repo, touches no container and breaks no contract |

**Amended 2026-09-10.** The v0 cut named a static set of ~100 titles, hand-refreshed in
the image. The corpus went back to v1 on 2026-09-03 with the container half already built
and inert, and it returns in the shape ruled on 2026-09-10: **complete, once a day, as its
own consent-gated channel on the data-sharing exchange, downloaded only when its signature
moves, joined locally.** Two things that ruling changes and nothing else: the corpus is no
longer hand-refreshed, so `corpusAsOf` moves on its own; and the container reads a
published format rather than one this repository defines
(LoonVD-Internal's `sharedAssets/contract/epoch.md`, `epoch/1`). Wireshark is still in it —
it is the standing fixture, and it is the one row of the committed test epoch that is real.

The split is contract versus internal. The container half ships in v0 because it cannot
be added to containers already in the field; the scan half lands after the flip because
it can.

**Wireshark must be in it.** It is the standing vulnerability fixture and also a Jamf
Patch title, which makes it the one app that exercises `patch{}` and `vuln{}` in the same
event. Which titles the compiler covers beyond it is the compiler's business — install
prevalence in the Jamf catalog, not name recognition — and the container's job is to say
honestly where the coverage ends, which is what `unknown_app` and `corpusAsOf` are for.

## 3. Which sourcetype an enriched app carries

`loon:jamf:mac:app`. The summary is an **inline enrichment** — it rides the app's own
sub-event, the way `patch{}` and `alert{}` do
([`wire_vocabulary.py`](../backend/app/core/wire_vocabulary.py) `ENRICHMENTS`), so an app
does not become a different kind of event by being assessed.

`loon:jamf:mac:app:vuln` is minted and reserved for the **lifecycle records** of §6 —
one event per finding transition, not one per app. This is what §1 of the vocabulary doc
means by *"the trailing compound survives"*: `*:vuln` finds every lifecycle record
across every subject and every vendor, and it does not accidentally collect the whole
app inventory along with them. #249 built the summary and stamped nothing: the string
stays minted with no writer
([`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md) §7), the fan-out's registry
drift test is untouched, and a populated `vuln{}` rides `loon:jamf:mac:app` exactly as an
empty one did.

Stated because the alternative reading is available and wrong: if the summary took the
compound sourcetype, then an app carrying both `patch{}` and `vuln{}` would need
`loon:jamf:mac:app:patch:vuln`, and a customer's `props.conf` would grow a stanza per
combination of enrichments. Sourcetypes are permanent; combinatorial sourcetypes are
permanently wrong.

## 4. The summary block

**Every number in the block is scoped to this app on this device.** Never the fleet,
never the app across the fleet. An analyst reading `vuln.counts.total` is reading one
install.

| Key | Type | Meaning |
| --- | --- | --- |
| `assessment` | `covered` \| `unknown_app` \| `off` | Whether this app was assessed at all. Always present. |
| `corpusAsOf` | date | The corpus generation this answer came from. Present when `assessment` is `covered` or `unknown_app`. |
| `counts.total` | int | Active findings against this installed version. |
| `counts.kev` | int | Of those, findings on CISA's KEV list. Not a severity band. |
| `counts.severity.critical` \| `.high` \| `.medium` \| `.low` | int | Findings by the corpus's severity band. |
| `daysOldestPublished.total` | int | Days since the publication date of the oldest active finding. `-1` = none. |
| `daysOldestPublished.severity.critical` \| `.high` \| `.medium` \| `.low` | int | The same, per band. `-1` = none. |
| `vulnIDs` | list of strings | The finding ids, capped, priority KEV → severity → recency. |
| `vulnIDsTruncated` | bool | Whether the cap bit. |

**Bands do not have to sum to `total`.** A finding the corpus carries with no severity
score is counted in `counts.total` and in no band. Said out loud because the obvious
`stats sum()` over the four bands is a number that silently under-reports otherwise.

**A clean bill is `assessment: covered` with `counts.total: 0`**, an empty `vulnIDs`,
and `-1` in every `daysOldestPublished`. That is honest precisely because `covered` says
we looked.

**What each answer costs.** Measured 2026-09-03 on the real fixture (one Mac mini, 83
apps), as compact JSON, per app: **20 bytes** to say `off`, **54** to say `unknown_app`
with a date, **1,067** to say `covered` at the full fifty-id cap. As a Splunk request of
107 sub-events that is 84,135 bytes today, 86,957 if every app were `unknown_app`, and
171,036 — 2.03× — if every app were `covered` at the cap. All three are far inside the
900,000-byte request setting, and the third is the number #248 turns on; the arithmetic
lives in `backend/tests/test_vuln_block.py` so nobody discovers it in the field. The 20
bytes are also the answer to *why say `off` at all*: `vuln.assessment=off` extracts to a
Splunk field and `{}` does not.

### 4a. `assessment`, and why absence is legible here

Ruled 2026-09-01: a small corpus is only honest if its edge is countable. An app LoonVD
does not know reads `unknown_app`, dated — **never zero vulnerabilities**. An unlicensed
or unconsented pod reads `off` and leaks nothing.

The encoding follows from that ruling rather than restating it: **under `unknown_app`
and `off`, the counts, the days and the id list are absent, not zero.** Shipping
`counts.total: 0` beside `assessment: unknown_app` hands a careless
`stats sum(vuln.counts.total)` a clean bill for a fleet nobody assessed — the exact
failure the `assessment` vocabulary exists to prevent, one layer down from where it was
prevented.

This is the one place the block's absences do not mean what additive-only clause 4 says
absences mean (*"the event predates the key"*), and the reconciliation is mechanical:
**`assessment` is always present and always says why.** An absence next to a
discriminator that explains it is not the ambiguous absence clause 4 protects against.
The product already runs this doctrine one layer down — the posture tape's *"absent
means 'did not apply', never zero"* ([`posture-snapshot.md`](posture-snapshot.md)) — and
`patch.supported` is the same instinct in bool form: always present, so a search can
`NOT` it.

Under `off` the whole block is `{"assessment": "off"}` — what
[#241](https://github.com/LoonSecIO/LoonInspect/issues/241) stamped on every `app` item of
the `device.inventory` snapshot at enqueue and
[#242](https://github.com/LoonSecIO/LoonInspect/issues/242) copies through to the app
sub-event. Since [#249](https://github.com/LoonSecIO/LoonInspect/issues/249) it is no
longer a constant but the answer the seam gives when no corpus is loaded
(`app/core/vuln.py`, `NO_CORPUS`), which is still every app on every device until #248
lands. **The three states' presence rules are refused rather than documented**:
`VulnEnrichment` (`app/schemas/payload.py`) is typed to the closed set of assessments and
validates, in both directions, that `corpusAsOf` rides `covered` and `unknown_app` and
that the counts, the days and the id list ride `covered` alone — so a producer cannot
ship `counts.total: 0` beside `unknown_app` even by accident.

### 4b. Values are not camelCase, and `unknown_app` is not a typo

The casing law is scoped to **keys** ([`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md) §4).
Wire *values* were never camelCase — `event` carries `device.inventory`, `level` carries
`high`. `unknown_app` is the founder's word, on the record on #113 and again in #241's
ruling table, and it stays exactly as spelled. Pinned here so a later conformance sweep
does not "fix" a ruled value into `unknownApp` and break every saved search that names
it.

### 4c. `-1` means never

Ruled 2026-08-25 and unchanged: `daysOldestPublished` keys are **always present and
always int** when the block is populated, with `-1` for "no finding in this band". Fixed
schema, so a non-Splunk consumer — the macOS client, a warehouse — never casts `None`;
the Splunk idiom is `>= 0 AND`, and it goes into every shipped example and dashboard.
The decisive argument is additive-only clause 4: absence is already reserved to mean
*the event predates this key*, so it cannot also mean *never*. A vocabulary that needs
to say "never" says so with a sentinel.

The invariant, in both directions:

```
daysOldestPublished.severity.X >= 0   ⟺   counts.severity.X > 0
daysOldestPublished.total       >= 0   ⟺   counts.total       > 0
```

The sentinel is minted in the HEC-shaping seam. The canonical layer keeps `None`, and
other destination dialects may render it natively — SQL `NULL`, for instance.

Built that way (#249): the stored outbox payload and every non-Splunk destination carry
`null`, and `app.core.vuln.mint_hec_sentinels` — called from `app/core/hec_fanout.py` and
from nowhere else, so no second dialect of `-1` can grow — rewrites them on the way into
the sub-event. The invariant above is asserted at enqueue by the model, not left to the
producer.

### 4d. `daysOldestPublished`: the clock, and why the key says which clock

**Basis: days since the finding's publication date.** Ruled 2026-09-01, and it is #68's
ruling in a second domain, deliberately: the world's clock measures exposure, our clock
measures how long the customer has owned LoonInspect. Under a hand-refreshed corpus a
knew-about-it basis is actively perverse — first-detected collapses onto the
corpus-refresh date for the whole backlog, so every fleet would look *better* the slower
we refresh. The number would measure our cadence, not their exposure.

The other reason it wins is recoverability. Because the wire is a snapshot stream, a
finding's first appearance in the customer's own index **is** first-detected-in-tenant,
computable in SPL from data they already hold, with zero server state. Publication
cannot be reconstructed from anything the customer has; it has to be shipped. Ship the
one that cannot be recovered.

**The basis is in the key name**, ruled 2026-09-02. A bare `daysOldest` would repeat,
permanently and in a frozen contract, exactly the `days_since` ambiguity that
[`splunk-event-shaping.md`](splunk-event-shaping.md) records as asked and never
answered. "Oldest" names the aggregation; "published" names the clock; a frozen key
needs both. It also leaves `daysOldestDetected` free as an additive sibling if
remediation-SLA scoring is ever wanted — additive-only working as designed rather than
as an excuse.

**This places one requirement on the corpus format:** a detection record must carry a
publication date. The format is still provisional, so this ruling is asking for the
field before the format sets, which is cheap now and a migration later. #249 turned the
requirement into a type: `app.core.vuln.VulnFinding` has no constructor without
`published`.

**Which "today" the days are counted from** — assumed 2026-09-03, pending ratification,
per [PR #279's verify pass](https://github.com/LoonSecIO/LoonInspect/pull/279#pullrequestreview-5107281104):
**on the wire**, the snapshot's own `occurredAt`, never the wall clock. The builder is
pure and clock-free, and a delivery is retried against the stored row up to ten times —
so a day boundary crossed between attempts must not change the bytes. **The zero floor is
the same pending assumption:** a publication date later than the event (a snapshot
replayed out of the retention window against a corpus refreshed since) reads `0`, never a
negative, because a negative would collide with the sentinel.

**There are two clocks, and that is the design** — assumed 2026-09-03 by #251, pending
ratification, per [PR #283's verify pass](https://github.com/LoonSecIO/LoonInspect/pull/283#pullrequestreview-5107525423).
The clause above is scoped to the wire because a Splunk event is a **historical record**:
it says what was true when that snapshot was taken, and it must say the same thing on
every one of its ten retries. A page is not a record. It answers *how old is this finding
now*, for a person looking now, so the read path (`app/core/vuln_read.py`) counts from
today's UTC date.

The consequence, said out loud rather than discovered: **the same app on the same day can
read a different `daysOldestPublished` in Splunk than on the page.** The difference is
*not* the sync gap. It is the age of the newest snapshot for that device — bounded by the
check-in cadence for a healthy device, and **unbounded once a device stops checking in**,
because the event's clock stops with it while the page's does not. A device dark for a
year shows a year's difference, and that is the honest pair: the event is still a true
record of a year ago, and the page is still the true age today.

Making the page reuse the snapshot's clock was the alternative and it loses on the same
argument §4d already makes about corpus refresh: it would date the page to the last sync,
so a fleet would appear to age more slowly the worse its check-ins are — the number would
measure our collection, not their exposure. Making the event use the wall clock loses on
retry-stability, which is what the clause above exists for.

**No sentinel arithmetic changes.** Both clocks floor at zero and both leave `None` for
*never*; only the basis differs.

### 4e. `vulnIDs`, and the name that was rejected

Ruled 2026-09-02. `cve_l` was named when the list held CVEs; under the ruled namespaces
(§5) it holds mixed prefixes from day one, so the name would ship as a lie at v1. The
`_l` multivalue-hint suffix is add-on-era convention that appears nowhere else in this
product's vocabulary, and snake_case lost to #188 regardless.

`vuln.vulnIDs` stutters, and that is the cost of the ruling rather than an oversight.
The bare leaf `vuln.IDs` reads better in nested SPL and survives nothing else: Splunk
admins flatten, alias, and paste fields into lookups, and an `IDs` that has left its
block identifies nothing. Five characters buy immunity to every one of those. `cveIDs`
was rejected on accuracy — the v0 corpus is public-sources and yields mostly real CVE
ids, which makes the name comfortable exactly until the first `LoonVD-` id ships inside
it, at which point it is permanent and wrong.

**The cap is not a wire key.** ~50 ids, priority KEV → severity → recency, and the
number stays a server-side knob that can move any time — which is only true because
`vulnIDsTruncated` exists to say when it bit. The list is load-bearing for
summary-tier customers: with no fan-out, *"is CVE-X on my fleet"* is answered from this
list alone.

Built as `VULN_IDS_CAP = 50` in `app/core/vuln.py`, with the ordering done there rather
than asked of the corpus — the cap and the priority that protects it are one decision.
**The cap never touches the counts**: `counts.total` is every active finding, so a
truncated list under-names findings and never under-reports them. Two orderings the
contract leaves open are labelled as assumptions in the code: *recency* is read as
most-recently-published first, and a finding the corpus carries with no severity score
sorts after `low` — counted in `total`, never dropped.

### 4f. The corpus interface: what `findings()` answers

`VulnCorpus.findings(key_title=…, key_full=…)` (`app/core/vuln.py`) is three-valued, and
the value **is** the `assessment` vocabulary of §4a — #248 must read it exactly this way:

* **`None`** — the corpus does not know `key_title` at all, OR it has not itself
  positively assessed *this exact `key_full`*. `unknown_app`.
* **`()`** — the corpus knows `key_title` **and has positively assessed this exact
  `key_full`**, with no active findings against it. `covered`, a clean bill, because
  `covered` says we looked at this build specifically.
* **a non-empty sequence** — `covered`, with the findings this module derives into
  counts, days and `vulnIDs`.

**`()` means positively assessed; every other case means `None`.** This is the hash-join
trap named on [PR #279's verify pass](https://github.com/LoonSecIO/LoonInspect/pull/279#pullrequestreview-5107281104):
for a corpus keyed on `(title, build)` hashes, a known title with no stored hash for
*this exact build* is the common case — most builds of a well-known app were never
individually scanned — and answering `()` there is a `covered` clean bill for a build
nobody assessed, §4a's failure one layer down. `vuln_block` cannot tell an unassessed
build from a positively clean one; both arrive as `()`. So `findings()` must not default
to `()` (a `dict.get(key_full, ())` reads exactly like a positive clean bill) — it must
answer `None` unless it can name the assessment that produced the empty result.

**The published corpus expresses that with a row, not with an absence** (#248): an
assessed-and-clean build ships as a *row* carrying an empty id list and zero counts, and a
build nobody assessed has no row at all. So the loaded library answers `None` for a
missing row, always — and `()` never arises from a lookup that missed.

**And nothing beside a row may upgrade a missing one** — ruling R-D, 2026-09-11, which
withdrew a branch this document previously expected #381 to build. The published format
carried an assessed-titles object whose stamp, compared against the pod's own Jamf catalog,
would have turned a rowless build of a compiled title into a positive clean bill. Two
measurements from the Jamf enumeration killed it, and either is sufficient: Jamf publishes
one patch title per *version line*, so one `key_title` is shared by **sixteen** of the
catalog's seventeen Wireshark titles and there is no single stamp to compare against; and
the container's own `app_catalog_versions` (72,879 rows) and the compiler's enumeration of
the same catalog (78,109) are not the same set, so a pod can hold a build the compiler
never saw — and under the withdrawn rule that build would have read **clean**, silently.
The titles object is now coverage metadata, keyed on Jamf's `title_id` with `key_title` as
a non-unique index (`vuln_library_titles`), and the read path does not consult it at all.

**A fourth answer, added 2026-09-10 and additive to the three above: an `AssessedBuild`**
— one stored row's precomputed aggregates. The `VulnCorpus` protocol's member set does not
widen (still `as_of` and `findings`, so every corpus written against the two-member
interface is unchanged); only the return type does. It exists because the corpus ships a
**capped** id list beside **uncapped** counts: `counts.total` and the oldest publication
date in a band whose id the cap dropped are not recoverable from the list, so recounting
the list would under-report — §4a's failure wearing a plausible number. `vuln_block`
reports what the corpus counted, and keeps exactly two things for itself, because both
depend on something a stored row cannot know: the day arithmetic (the event's own clock,
§4d — a row carries absolute dates and never an age) and the cap (`VULN_IDS_CAP`, this
container's knob, §4e — a longer published list is trimmed here and says so).

**The join key, on both sides.** The corpus key is `app.full(name, bundleId,
shortVersion, None)` — the fourth slot is `None`, and the short version goes in the
*version* slot, because Jamf's patch catalog and NVD both speak the short version and
neither speaks a bundle version. The container pins that: `normalize_computer` sets
`short_version=None` on every app it builds from Jamf's inventory
([`backend/app/mdm/jamf/client.py:813`](../backend/app/mdm/jamf/client.py#L813)), the
catalog index hashes the same tuple
([`backend/app/catalog/index.py:75`](../backend/app/catalog/index.py#L75)), and
[`backend/app/mdm/snapshot.py:233`](../backend/app/mdm/snapshot.py#L233) already warns
that the two sides diverge silently if that pin ever moves. **A source that carries a
bundle version hashes it into the prevalence key only** — never into the key the corpus is
joined on — because a corpus keyed on a field its own sources cannot see would answer
`unknown_app` for every app on every device and nothing would say why. That is the whole
failure mode of a drifting key: it is not a counting bug, it is a silent false negative in
vulnerability matching (`docs/data-sharing.md`, "The key scheme"), and it is why
`backend/tests/test_vuln_library.py` asserts the fixture epoch's keys against this
repository's own `content_keys` rather than trusting them.

### 4g. The same three words in front of a person

Built 2026-09-03 (#251). `assessment` was ruled visible **on the wire and in the UI**, and
the UI half is where the rule is easiest to break silently: a page that renders
`0 vulnerabilities` for an app nobody assessed breaks §4a in the surface a buyer looks at,
where no saved search exists to catch it.

So the block a person's browser receives **is** the block above — `VulnEnrichment` itself
on the REST response, not a REST-shaped copy of it. One model, one vocabulary: a person
reading a Splunk event and a person reading the page use the same three words for the same
three facts, and there is no second place for the vocabulary to drift.

**Two dialect differences, both ruled above, and no others.** First, no `-1` on the read
path (§4c): the sentinel belongs to the HEC-shaping seam, so a REST client gets the
canonical `null`. Second, **the clock** (§4d): the wire counts days from the snapshot's
`occurredAt` because an event is a historical record, and the page counts from today
because a page is not. The same app can therefore read a different `daysOldestPublished`
in each, by the age of that device's newest snapshot — unbounded once a device stops
checking in. Every other key is the same value in both.

| Surface | What it gained |
| --- | --- |
| `GET /api/devices/{id}` | `apps[].vuln` — the block per installed app; `corpusAsOf` on the device |
| `GET /api/catalog` | `items[].vuln` — the block per distinct build; `corpusAsOf` on the list response |
| `GET\|POST /api/catalog/lookup` | **Nothing.** See below |
| Devices › Applications › **Catalog** | A **Vulnerabilities** column, and the corpus banner above it |
| Devices › *hostname* (the device page, #300) | A **LoonInspect** column per installed app, and the same banner above it |
| Devices › Applications › *appHash* (the application record, #299) | A **Vulnerabilities** column per carried build — legal there because each row is one build at `key_full` grain — and the banner |
| Devices › Applications › Jamf Patch › *title* | **Nothing** (#298). A title's version row carries no `key_full`, so there is no grain to answer at; the stub column that stood there (`C — H — M — L — Σ` beside coloured dots, under a tooltip naming an integration nobody can enable) was deleted rather than rewritten, per the #95 precedent |

**Where `off` goes (#298).** A terminal sentence is a dead end, and the obvious link — *turn on
data sharing* — was a lie when it was ruled: `loaded_corpus()` took no argument and answered
`NO_CORPUS` in every v0 build, the daily exchange received nothing, and no code read a licence
key for vulnerability data. So the banner carries the one link, and it explains rather than
promises: an in-product *why this container says nothing*, in the present tense, dated with
nothing, with §8 below linked by section. The per-row cell stays a terminal sentence; two
thousand identical links in cells would be noise.

**That premise moved on 2026-09-10, and the strings moved with it on 2026-09-11.** With
#248, consent *is* what earns a corpus — the epoch rides the exchange, and a tenant at
tier `off` is exactly the one that reads `off` (§8). #298's *ruling* is untouched: still no
fourth state, still nothing rendered on `off` beyond the banner, still one link and not two
thousand. What changed is that three of its sentences had become false, and the pull
request that falsified them is the one that fixed them. The five strings, in both locales:

| String | Was | Is |
| --- | --- | --- |
| `en.ts` `system.sharing.pageDescription` / `de.ts` `pageDescription` | *"None ships yet, and nothing flows back to this instance in this build."* | The corpus is named as the one thing that does flow back, and only to an instance that shares |
| `en.ts:whyNoSwitch` / `de.ts:whyNoSwitch` (`vulnerabilities.*`) | *"Turning on data sharing does not change that in this build: the daily exchange contributes inventory and receives no verdicts and no feeds back."* | Data sharing is what earns the corpus; an instance with sharing off reads *not assessed*. The licence-key clause is unchanged and still true |
| `en.ts:whyNoCorpus` / `de.ts:whyNoCorpus` | *"No vulnerability corpus ships with LoonInspect in this build …"* | Argues from **none loaded** rather than from *in this build* — the premise that moved. Still rendered only under `corpusAsOf === null` |

The banner still explains rather than promises, and it still carries no date: `off` has
none to carry.

**Why the lookup answers no assessment.** It is keyed by hash and accepts `appHash` as
well as `versionHash` / `keyFull`; under `appHash` the row it returns is deliberately a
**stand-in** — the newest version the tenant has seen — not the caller's build. `vuln` is
scoped to `key_full`, so a stand-in's answer is another build's answer, and a newer
build's clean bill returned under a title's key is §4a's failure one grain out. Rather
than shipping it and asking the caller to notice the row's `keyFull`, the grain is refused
in the type: `CatalogLookupOut.tenant` is the plain `CatalogEntryOut`, which has **no
`vuln` field at all**, while the list's rows use `CatalogEntryAssessedOut`, which does.
There is no `corpusAsOf` on the lookup either — it returns a bare list, and a stamp with
nothing to stamp is noise.

**Why the catalog tab and not a Vulnerabilities page.** The corpus is keyed on `key_full`
— one answer per distinct build — which is exactly one row of the app catalog, so the
column is an attribute of a row a person is already reading rather than a second place to
go. A standalone page would have been a heading, one date and a link to that table: the
"nav destination that does nothing" ruled against on
[#95](https://github.com/LoonSecIO/LoonInspect/issues/95). It returns when it can show
something the catalog cannot — the per-finding lifecycle records of §6, which are post-v0.

**The three renderings, and why they cannot collapse.** `covered` with nothing found is
green, says *no findings*, and carries the date it was checked against. `unknown_app` is
amber, says *outside the corpus*, and carries the date the corpus was generated —
deliberately not green, because "we did not look at this" is a gap in the answer and a gap
coloured green is the picture this issue exists to prevent. `off` is grey, says *not
assessed · no corpus loaded*, and carries **no date at all** rather than borrowing today's.

That is held by the compiler rather than by care: the REST block's three shapes differ by
key set (§4a's absences), the frontend types them as a union discriminated on `assessment`,
and `counts` exists on the `covered` member alone — so `vuln.counts.total` does not compile
until a value has been narrowed to `covered`. There is no expression in which an
unassessed app yields a zero.
`frontend/src/features/vulnerabilities/noCollapse.ts` asserts exactly that, in `tsc`
rather than in the frontend's vitest lane (#285) — a guarantee about the shape of a type
belongs to the type checker: type-level assertions on the shape of the `off` member that
fail the build the day `counts` becomes readable from it (the file itself explains why
`@ts-expect-error` was rejected).

**The stamp rides the rows.** `corpusAsOf` is returned on the response that carries the
apps it describes, never from a separate call, so a header can never date a column the
server answered from a different corpus. `null` means no corpus is loaded; the page says
that in a sentence and dates it with nothing.

**What is deliberately not counted.** No fleet-wide "*n* covered / *m* unknown" tile. The
per-request lookup is bounded by the rows in one response — one device's apps, or one page
of distinct builds — and counting the three states across the whole tenant is a scan per
request. Those counts are #250's, off the join #248 stores.

## 5. Three id namespaces, one shape

| Prefix | Minted by | Status |
| --- | --- | --- |
| `CVE-YYYY-NNNN…` | MITRE | Used as-is |
| `LoonVD-YYYY-NNNNNN` | LoonInspect | Ruled 2026-08-25 |
| `LOCAL-YYYY-NNNNNN` | The customer | **Reserved 2026-09-02; nothing is built behind it** |

`LoonVD-` is deliberately CVE-shaped and prefix-distinguishable — the pattern AWS and
Wiz use for findings reported ahead of a MITRE assignment. One shape across all three
means one field extraction and one validator; the prefix alone routes.

**`LOCAL-` is a reservation, not a feature.** Customers will eventually want to record
findings of their own, and the prefix must not be `LoonVD-` — that is the authorship
boundary. `LOCAL-` names the *scope* rather than the author, which is what makes it
self-describing in a shared index: one Splunk index can hold events from several pods,
and `LOCAL-2026-000042` read anywhere still says *this id resolves to nothing outside
the fleet that minted it*. A tenant-name prefix would say who minted it and not that it
is unresolvable elsewhere, while baking a customer-identifying string into an id — the
same hazard that made #81 rule a fleet must never be asked to name a bundle key.

The reservation is the cheap thing. Without it, the first customer who wants local
findings invents a convention, or mints `LoonVD-` ids in a lookup, and it is a fait
accompli before anyone notices. **Rule the namespace; build nothing behind it.**

**Rider:** `LOCAL-` ids never leave the pod. Not in the data-sharing payload, not in
community keys. They are tenant-local by definition and customer-identifying by content.

Enforced by #249 where a finding is constructed: `app.core.vuln.VulnFinding` refuses a
`LOCAL-` id outright. For a static corpus that is load time, so a bad record fails the
corpus loudly rather than failing every device sync on a per-lookup raise — **which is a
requirement on #248: build the findings when the corpus is loaded, not per lookup.**

## 6. Supersede: the id swaps, nothing resolves

A `LoonVD-` finding gets a real CVE assigned. Ruled 2026-09-02, in three parts:

1. **The `LoonVD-` id is never retired and never resolved.** `resolved` means *this
   build is no longer affected*. A CVE assignment means *the same finding acquired a
   second name*. Emitting `resolved` for a rename writes a false negative into the
   customer's own history — the exact failure the tombstone rule exists to prevent.
2. **The summary carries one id per finding: the canonical one.** Canonical is the CVE
   once assigned, the `LoonVD-` id until then. The count does not move, no finding
   opens, no finding closes; the id swaps.
3. **The transition is an event in the fan-out, never in the summary.** One lifecycle
   record, `status: active`, `reason: superseded`, carrying `supersedes:
   LoonVD-2026-000123` on the record that now bears the CVE id. Aliasing is one-way and
   permanent: a superseded `LoonVD-` id is never reused and never re-minted.

**The consequence, said out loud rather than discovered:** a saved search pinned to
`vulnIDs="LoonVD-2026-000123"` stops matching the day the CVE lands. That is real, and
the mitigation is the `supersedes` record plus a published alias mapping — a
Splunk-native lookup, shippable in a TA without touching the wire.

Carrying both ids forever was the serious alternative, and it is the only option under
which no saved search ever silently stops matching. It loses on the double count: the
summary's job is answering *"is CVE-X on my fleet"* **and** *"how many findings do I
have"*, and one finding wearing two ids makes the second question permanently wrong for
every consumer who runs the obvious `stats dc()`. Search stability for a transitional id
is worth less than count correctness for every id, and the instability is bounded and
one-directional — `LoonVD-` ids become CVEs, never the reverse.

### The lifecycle records — named, not built

Post-v0, licensed tier, sourcetype `loon:jamf:mac:app:vuln`. One event per finding
transition, scanner-shaped: `status: new | active | resolved` with a `reason`, per-finding
scalars (`cveID`, `kevListed`, `epssScore`, the severity band, the publication date),
and `supersedes` where §6 applies. **Resolution must be an emitted tombstone** — absence
is not searchable. Rare against a static corpus, which is why v0 ships the summary
alone; named here because the summary's ruling above depends on where the transition
lives.

`fixed_in` stays **off the wire** (ruled 2026-08-25). Fix-version data lives in the Jamf
Patch and `app_catalog` tables, in-app only: correctable there, and it avoids a
`patch{}`-versus-corpus contradiction landing in a customer's SIEM. `patch{}`'s latest
version stays the wire's coarse "a fix path exists" proxy. Promotable later, additively,
if it is ever demanded.

## 7. The posture tape

Four keys, reserved with frozen definitions and no writer
([`posture-snapshot.md`](posture-snapshot.md), `app.core.posture.RESERVED_KEYS`):
`vuln.apps_affected`, `vuln.apps_kev_affected`, `vuln.apps_unknown`,
`vuln.devices_affected`.

**The activation rule, ruled here because it is a correctness bug waiting to happen:**
while a tenant has never run the corpus join — every app reading `assessment: off` —
those four keys write **no rows, not zeros**. The guardrail already says why: a key that
records before its feature's table exists writes a run of zeros that lies about when
measurement began. A naive recorder would manufacture a clean bill of health for a fleet
that was never assessed, which is §4a's failure one more layer down. The keys activate
the night the join first runs for that tenant, and their tape starts *then*.

That is what the reservation buys and the only thing it buys: the definitions are fixed
now, at leisure, rather than under time pressure with a customer's SPL already written.

## 8. Tiers

Ruled 2026-08-25, against Fleet Device Management's precedent of giving the summary away
free. **LoonInspect does not copy that** — too much value is packed into the summary
block, and this product's "free" is the data-sharing tier.

| Tier | `assessment` | What it gets |
| --- | --- | --- |
| Nothing | `off` | The shipper. No enrichment, no leak. |
| Data sharing | `covered` / `unknown_app` | The summary block. Paid for in hashes. |
| Licence | `covered` / `unknown_app` | The summary plus the lifecycle fan-out and the premium scalars. |

There is no zero-cost enrichment tier. Which scalar keys — EPSS, CVSS, KEV — sit at
which tier stays a server-side knob, additive-safe and tunable at any time. The
fleet-coverage statistic (*"% of observed apps identified"*) is gated on licence **and**
data-sharing consent, structurally as well as commercially: identification requires
sending hashes.

**How the gate is built (#281, Option A; #248).** Inside `loaded_corpus()`, which is where
Option A put it. Two conditions, and both must hold: an epoch is loaded, **and** the acting
tenant's data-sharing tier is not `off`. The first is the shape — the corpus link rides the
daily exchange, a pod at tier `off` never exchanges, so it is never handed a link and never
imports an epoch. The second is the correction of 2026-09-11 below.

**Ruled 2026-09-11: the tenant is the unit that earns the summary, and the rows are
kept.** The library is one *global* artifact — three non-tenant tables and one process
cache, for the same reason `jamf_patch_titles` is global — and the tier is a *per tenant*
column. On a pod with one tenant those two facts coincide and the shape alone gates
everything; on a pod with two they do not, and the shape alone would let one consenting
tenant's import answer `covered` for a tenant that never exchanged, never consented and
was never handed a link. Option A's own words are *"a pod that has not earned the
summary"*. So:

* `loaded_corpus()` answers `NO_CORPUS` while the acting tenant's tier is `off`, or while
  that tenant has no settings row at all, or outside any tenant context — an install
  nobody has answered for has not consented, and outside a tenant there is nobody to have
  consented. Every app then reads `assessment: off`, byte-identical to a container with no
  epoch.
* **The rows are kept.** Tier-off does not purge: one tenant's switch must not delete a
  global artifact every other tenant on the pod is entitled to. Turning sharing back on
  answers again immediately, with no download — and a tenant that stays off sees an epoch
  age in the database and nothing else.
* The tier is read **once per unit of work** — one sweep run, one webhook, one re-emit, one
  API response, one exchange — and cached per tenant
  (`app.core.vuln_library.read_tenant_tier`, `earned_corpus`). Never per device and never
  per app: that is the same "cache, don't calculate" rule the rest of the read path is
  built on, and a 40,000-device run must not pay 40,000 queries for one row that cannot
  change mid-run. The cache is fail-closed — a tenant nothing has read the tier for reads
  `off` — so a path that forgets costs a tenant its summary and never the reverse.

*The alternative, stated so the ruling is legible as a choice:* **the held epoch keeps
answering.** Read "pod" in Option A literally — the container earned the epoch when it was
consenting, the epoch is already on disk, `corpusAsOf` makes it decay visibly, and turning
sharing off stops the contribution rather than the answer. That is what the code did
before this ruling, by accident rather than by argument. It was rejected because the
answer is a *tier benefit* and not a possession: the summary is what data sharing buys
(the table above), and a tenant that has stopped paying in hashes should stop being paid
in verdicts. It is a one-word ruling to reverse.

## 9. What this ruling amends

The additive-only clause 4 in [`wire_vocabulary.py`](../backend/app/core/wire_vocabulary.py)
cited `days_oldest` as its sentinel example — a snake_case name minted before #188 froze
camelCase and #113 named the clock. The clause is unchanged in substance; the key it
cites is now `daysOldestPublished`. Amended under the vocabulary's own procedure: the
ruling issue edits the module, regenerates the doc, and leaves a pointer on #188.

## 10. Ruled here, built elsewhere

Four sessions, in this order. The first blocks the other three; the other three do not
block each other.

| Consequence | Issue | State |
| --- | --- | --- |
| The corpus behind the seam: the library loader — the exchange's `corpus` pointer, the verified epoch, the global row/title tables, `corpusAsOf`, and `loaded_corpus()` answering from stored rows | [#248](https://github.com/LoonSecIO/LoonInspect/issues/248) | **Built 2026-09-10.** `app/core/vuln_library.py`, the three `vuln_library_*` tables (migration `d1f8b6a34e07`), the `AssessedBuild` widening in `app/core/vuln.py`; pinned in `backend/tests/test_vuln_library.py` and `…_db.py` against the committed fixture epoch |
| The per-build join at judge time, stored on `app_catalog` and copied onto `installed_apps` | [#381](https://github.com/LoonSecIO/LoonInspect/issues/381) | Open. The assessed-titles stamp branch it was also going to carry is **withdrawn** (ruling R-D, 2026-09-11): a verdict comes from a row and from nothing else, so a rowless build reads `unknown_app` permanently rather than provisionally (§4f) |
| `vuln{}` populated on the app sub-event; `assessment` stops being a constant `off`. Also needs the fan-out ([#242](https://github.com/LoonSecIO/LoonInspect/issues/242)) | [#249](https://github.com/LoonSecIO/LoonInspect/issues/249) | **Built 2026-09-03.** `app/core/vuln.py`, `VulnEnrichment` in `app/schemas/payload.py`, the sentinel in `app/core/hec_fanout.py`, pinned in `backend/tests/test_vuln_block.py` |
| The four `vuln.*` posture keys go ACTIVE, under §7's no-zero rule | [#250](https://github.com/LoonSecIO/LoonInspect/issues/250) | Open. Still RESERVED, deliberately: the join has stored nothing to count |
| The corpus's edge made visible in the UI — `assessment`, `corpusAsOf`, three empty states | [#251](https://github.com/LoonSecIO/LoonInspect/issues/251) | **Built 2026-09-03.** §4g. `app/core/vuln_read.py` over the same seam, `vuln` + `corpusAsOf` on the device and catalog responses, the Catalog tab's column and banner; pinned in `backend/tests/test_vuln_read.py` and `frontend/src/features/vulnerabilities/noCollapse.ts` |
| The lifecycle fan-out under `loon:jamf:mac:app:vuln`, and `LOCAL-` ids behind their reservation | post-v0 (§5, §6) | Named, not built. The string stays minted with no writer |
