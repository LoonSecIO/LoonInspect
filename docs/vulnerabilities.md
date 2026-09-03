# The vulnerability contract

Status: **ruled; the wire block is built, the corpus is not** · Ruled on
[#113](https://github.com/LoonSecIO/LoonInspect/issues/113): the corpus cut and
`assessment` on 2026-09-01, the four naming and lifecycle items on 2026-09-02 · Wire
keys obey the frozen vocabulary in
[`docs/splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md)

This document exists because the vulnerability design lived in a session record and two
issue comments, and a contract that lives only in a session record is one that gets
re-argued by whoever builds it. Everything below is a decision with an argument.

**What is built, as of 2026-09-03** ([#249](https://github.com/LoonSecIO/LoonInspect/issues/249)):
the summary block of §4 in full — every key, the presence rules, the cap, the clock and
the sentinel — plus the lookup seam it reads (`VulnCorpus` in `app/core/vuln.py`). What
is not built is the corpus behind that seam ([#248](https://github.com/LoonSecIO/LoonInspect/issues/248)),
so the container ships `NO_CORPUS` and every app on every device still reads
`assessment: off`. The day #248 loads a corpus, the block starts answering with no wire
change at all — which is the whole reason the vocabulary was frozen before the data
existed. §10 tracks the rest.

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
| Corpus | A static set of ~100 titles, public sources only, Jamf-catalog apps | The nightly NVD→corpus scan |
| Join | Local hash-join, in the container | Any call to a vulnerability gateway |
| Refresh | By hand, stamped in `corpusAsOf` | Automatic, `corpusAsOf` moving on its own |
| Half | Container↔cloud: the exchange response's `verdicts` slot, reserved in the v1 contract and deliberately left unparsed so this work does not freeze its shape (`backend/app/core/sharing.py:206`) | The scan itself, which lives outside this repo, touches no container and breaks no contract |

The split is contract versus internal. The container half ships in v0 because it cannot
be added to containers already in the field; the scan half lands after the flip because
it can.

**Wireshark must be in the hundred.** It is the standing vulnerability fixture and also
a Jamf Patch title, which makes it the one app that exercises `patch{}` and `vuln{}` in
the same event. Select the rest by install prevalence in the Jamf catalog, not by name
recognition.

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

**Which "today" the days are counted from:** the snapshot's own `occurredAt`, never the
wall clock. The builder is pure and clock-free, and a delivery is retried against the
stored row up to ten times — so a day boundary crossed between attempts must not change
the bytes. A publication date later than the event (a snapshot replayed out of the
retention window against a corpus refreshed since) reads `0`, never a negative, because
a negative would collide with the sentinel.

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
| The v0 corpus and the local hash-join — ~100 titles, public sources, `corpusAsOf`, Wireshark included, and the publication date §4d requires of the format | [#248](https://github.com/LoonSecIO/LoonInspect/issues/248) | Open. It plugs into `app.core.vuln.VulnCorpus` and swaps `loaded_corpus()`; the rest of the wire is built and waiting |
| `vuln{}` populated on the app sub-event; `assessment` stops being a constant `off`. Also needs the fan-out ([#242](https://github.com/LoonSecIO/LoonInspect/issues/242)) | [#249](https://github.com/LoonSecIO/LoonInspect/issues/249) | **Built 2026-09-03.** `app/core/vuln.py`, `VulnEnrichment` in `app/schemas/payload.py`, the sentinel in `app/core/hec_fanout.py`, pinned in `backend/tests/test_vuln_block.py` |
| The four `vuln.*` posture keys go ACTIVE, under §7's no-zero rule | [#250](https://github.com/LoonSecIO/LoonInspect/issues/250) | Open. Still RESERVED, deliberately: the join has stored nothing to count |
| The corpus's edge made visible in the UI — `assessment`, `corpusAsOf`, three empty states | [#251](https://github.com/LoonSecIO/LoonInspect/issues/251) | Open |
| The lifecycle fan-out under `loon:jamf:mac:app:vuln`, and `LOCAL-` ids behind their reservation | post-v0 (§5, §6) | Named, not built. The string stays minted with no writer |
