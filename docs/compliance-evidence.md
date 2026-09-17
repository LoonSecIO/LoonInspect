# The evidence artefact

Status: **built** · Ruled on [#219](https://github.com/LoonSecIO/LoonInspect/issues/219) (R5, 2026-09-16)
5.1–5.6 · Built by [#472](https://github.com/LoonSecIO/LoonInspect/issues/472) (the object) and
[#473](https://github.com/LoonSecIO/LoonInspect/issues/473) (the page)

The contract for the object `GET /api/evidence/report` returns, here for the reason
[`vulnerabilities.md`](vulnerabilities.md) is: the artefact is **archived the day it is first printed**, and next
year's auditor compares against that copy — a key renamed later is a document nobody can compare. Keys are camelCase
with the token `ID` uppercased ([`runs.md`](runs.md); `udid` stays `udid`), additive-only thereafter, on the terms
[`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md) sets. It is a record of technical state read from one MDM
over one window: not an attestation, and it names no framework (§2).

[`baseline-rules.yml`](baseline-rules.yml) says what a rule reads (#463); `app.baseline.evaluator` turns a stored
section document into a verdict (#464); `app.baseline.intervals` lays those verdicts over the observation ledger as
closed labelled intervals (#465); `app.baseline.report` composes the three and computes nothing an auditor could not
re-derive from the ledger.

## 1. The object: `header` · `rules` · `devices` · `rows` · `totals`

**`rules`** is the catalogue as evaluated: `ruleID`, `title`, `section`, `field`, `predicate` (`operator`, `operand`
— so an archive carries LI-0010's OS floor, the one operand that drifts), and `mscp` (`ruleID`, `branch`, `match`)
on the three rules that cite one.

**`devices`** is `deviceID` — the Jamf computer id, `devices.external_id` on the same connection — with `name` and
the lineage triple `udid`, `serialNumber`, `managementID`. All three: a logic-board repair keeps the serial and
changes the UDID, so neither alone is a Mac over its life. It is named **once here** and cited by `deviceID` from
every row: a Mac with ten rules over eight intervals is eighty rows, and the triple repeated on each of them is the
same four strings printed eighty times in a document that gets archived.

**`rows`** is one row per (device, rule, interval): `ruleID`, `deviceID`, `state`, `from`, `to`, `seconds`, `days`,
`duration`, `longestGap`, and on an observed stretch `observations`, `collectedFrom`, `collectedTo`, `witnessed`,
plus `sectionDigest` and `contractVersion` where the span carried a digest for the section. A departed stretch adds
`departedAt`. **`witnessed`** is the artefact's whole value over a spreadsheet — `field`, `value`, and the
`statement` the catalogue's sentence renders, not "FileVault: met" but "met — `…partitionFileVault2State` =
`ENCRYPTED`". It is on **every** observed row, digest or none: a span whose aperture never read the section is
`notReported`, and that row says *Jamf's record for this stretch carried no `…`* rather than leaving the cell blank.
**`sectionDigest`** lets a row say *this content hashes to this value under contract v0*, stronger than a printed
number and free, the hash being on disk.

## 2. The header, and the four words that must not appear on it

Five things, in this order (R5 5.3): **`method`** (`statement`, `connection`, `source`, `catalogue` at its version,
`window` with `start` and `asOf`); **`notVisible`** — what cannot be seen from here, named: policy controls, process
controls, personnel controls; **`refusal`**, the one line; **`contractVersions`**, read off the digests the rows
rest on; **`clock`**, device time as the interval clock with collection time beside it (R5 5.4).

**No framework is named anywhere on the artefact** — not as an example, not as a "shaped like", not in a footnote.
`backend/tests/test_evidence_report_db.py` greps the whole serialized object for CMMC, 800-171, SOC 2 and Cyber
Essentials. `notVisible` is the item a later session trims for space: it does not get trimmed, because a page of
technical evidence with no framework claim on it is read as a framework claim unless it says otherwise in its own
header. The catalogue's `mscp` citations stay on the rows as provenance for three rules and never rise to here; its
`difference` and `origin` prose stays in the catalogue, out of reach of a document someone keeps.

## 3. Five states, two of them absences

`met` · `unmet` · `notReported` · `noObservation` · `departed`. `notReported` is a field the aperture did not
collect in a document we **do** hold; `noObservation` is a day we hold no document for; `departed` is such a day
with a `subject_departures` row behind it — the same days, a better word. The two absences never merge, and neither
is ever folded into `met` or `unmet`: a Mac nobody asked about, printed as a Mac that failed, is a fabricated
finding on a document someone keeps.

## 4. The three-way sum

> **met + unmet + not observed = the window**

`totals` prints it as `fleet`, `byRule` and `byDevice`, and it closes exactly. `notObserved` is therefore every day
the report cannot answer for, and `notObservedParts` names its pieces (`notReported`, `noObservation`, `departed`)
so §3 survives the sum. Above the (device, rule) grain, `window` is the report window times the rows folded into
that bucket. Quiet devices are **never excluded**: a Mac silent for three weeks appears by name with three weeks of
`noObservation`. The headline gets uglier deliberately — an auditor who finds the third number themselves stops
trusting the first two.

**Absent, never zero.** A rule nothing could be counted for has no `byRule` entry at all, not an entry of zeros —
[`posture-snapshot.md`](posture-snapshot.md)'s no-zero-priming rule, so a careless sum cannot hand a fleet nobody
assessed a clean bill. The three columns themselves always print: an identity a reader cannot check is not one.

**The clock is one second wide, and the boundaries take the floor.** Device time arrives whole — Jamf's
`reportDate`, parsed with the fraction dropped — but the two instants the report supplies itself, the window's edges
and a `departed_at`, are `datetime.now(UTC)` and carry microseconds. The artefact floors every instant it prints and
measures between the floored ones, so `window` is `floor(asOf) - floor(start)` and the buckets telescope to it
exactly: adjacent intervals share a boundary, and a shared boundary floored moves both sides together. Flooring each
*duration* instead is the version that does not add up — the default window puts a fraction in `met` or `unmet` and
its complement in the tail, and two truncations lose the second between them. Every composite figure in `totals` is
therefore the sum of the printed figures under it, `notObserved` of its `notObservedParts` included: the identity
holds on the page, not only on the floats behind it.

**Duration is exact in `seconds`**, which the identity is asserted on; `days` is the reading figure derived from it,
**absent** where it would round to zero, and `duration` then reads **"under one reporting interval"** rather than
`0 days` (R5 5.4). A zero meaning "we saw it once" wearing the costume of a zero meaning "it never happened" is the
defect [`diagnosability.md`](diagnosability.md) §1 forbids, and here it would be archived.

## 5. The endpoint, and what is not here

`GET /api/evidence/report?connectionID=&start=&asOf=` under **`AUDIT_READ`**, the permission and the argument
[`/api/system/share-log`](../backend/app/api/system.py) already made. `asOf` defaults to the ledger's heartbeat —
`max(observation_spans.last_collected_at)`, never `runs`, which purge at 30 days while the ledger has no retention
at all (R5 5.5) — and `start` to a quarter before it. Neither is clamped to the data: a window reaching past what
was observed answers with not-observed days. A connection with no observations is refused (409) rather than answered
with an empty document; [`troubleshooting.md`](troubleshooting.md) §2 step 5 has the words.

## 6. The page

`GET /api/evidence/report.html`, same permission and parameters, is the object as one **self-contained** HTML
document: no CDN, no font, no stylesheet, because it will be opened a year from now on a machine that cannot reach
us. The object travels **inside** it — `<script type="application/json" id="evidence-bundle">`, one selector then
`JSON.parse` — rather than beside it, where the two could be separated; `<` is written `\u003c` there, so a Mac
named `</script>` cannot end the block ([`ai-threat-model.md`](ai-threat-model.md): the fleet is untrusted input).
The response is an attachment named `evidence-<connectionID>-<start>-to-<asOf>.html`, following
[`/api/system/share-log`](../backend/app/api/system.py) in shape as well as in permission.

Print CSS is A4 portrait, table headings repeating, rows unbroken, and the **refusal on every sheet**. **No
server-side PDF and no stub for one**: a rendering service is a font problem and a permanent maintenance surface
bought on a guess, and whether a printed page is an acceptable artefact is a question the first assessor settles.
The page also says what it cannot answer rather than printing a thin table and letting a reader infer — five
sentences in `app.baseline.page`, stepped through in [`troubleshooting.md`](troubleshooting.md) §17. A connection
with no ledger at all has no sixth: the endpoint refuses it at 409 with its own words, so a page for it is never
rendered. **`notObserved` is where several facts wear one label**, and the sentence about it names all three the
page cannot tell apart — the head before a Mac's first observation, the tail after its last, and dates nobody swept
— because naming the alarming one alone sends every reader to a run history with no missing run in it
([`diagnosability.md`](diagnosability.md) §2 rule 1). §4's grain is on the page too: the sum's heading reads
**= the window × rows** and the prose above it gives the window's own length and both multiples, so the reader who
finds the third number can also check it.

No posture keys: the report's own wait for #183's follow-up, as #219 ruled.
