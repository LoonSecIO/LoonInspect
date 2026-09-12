# Community data sharing

**Status: settled.** This document freezes the parts of data sharing that ship inside
customers' containers — the key scheme, the consent model, the wire contract, and the
share log. Everything cloud-side is deliberately out of scope except where the contract
constrains it: the server can be rebuilt at leisure; a shipped container cannot.

The feature in one paragraph: participating instances contribute anonymous application,
OS, and hardware prevalence — keyed by salted-nothing content hashes, summed per tenant,
never attributable — and the patching and vulnerability feeds are built from that corpus.
Sharing and the feeds are two halves of the same exchange: the daily upload *is* the
feed query, one conversation per tenant per day.

## Why sharing is coupled to the feeds

If contribution were anonymous *and* the feeds were server-gated to contributors, the
server would have to know who contributed — the two properties are mutually exclusive.
We keep anonymity and enforce reciprocity client-side instead: sharing off means the
container stops asking for verdicts. A motivated fork can bypass that; the audience that
would bother overlaps almost entirely with the audience that would contribute anyway,
and the honest framing — the feed is literally derived from the shared corpus — is what
makes a pre-checked default defensible in front of security people.

## The key scheme

Every shared fact is identified by a content hash. The same keys serve three consumers:
the container's local rollup (computed once, stored as a column, reused for upload and
feed join), the cloud's dedup/threshold logic, and the feed lookup. A drifting key is
therefore not a counting bug — it is a **false negative in vulnerability matching**.
The canonicalization below is a frozen contract with test vectors asserted in the
backend test harness; it changes only behind a new version prefix.

### Canonicalization (frozen, v1)

```
key = "v1:" + lowercase_hex(sha256(utf8(domain ⟂ field₁ ⟂ field₂ ⟂ …)))
```

- `⟂` is U+001F (unit separator). It cannot appear in any field; strip it if seen.
- Each field is Unicode-normalized to **NFC**, then stripped of leading/trailing
  whitespace. macOS delivers NFD from some paths and NFC from others; without this
  rule the same app forks into two keys depending on which MDM read it.
- A missing/null field participates as the **empty string**. Null and empty are
  deliberately indistinguishable.
- No case folding. Case is significant in bundle identifiers and names.
- `domain` namespaces the hash so an OS tuple can never collide with an app tuple.

| domain | fields, in order |
| --- | --- |
| `app.title` | app_name, bundle_id |
| `app.full` | app_name, bundle_id, version, short_version |
| `os` | platform, os_version, os_build |
| `hw` | model_identifier, cpu_arch |

The app and hardware domains hash **no platform**, and gain none: the corpus tables are
partitioned by platform, so the platform travels *beside* the key as a snapshot-row field
(see the request body below) rather than inside it. Putting it in the hash would mean a `v2:`
prefix, which invalidates every vector below and every count already summed against them.

`app.title` is the disclosure-control and feed-join key (the app's *identity*);
`app.full` is the prevalence key (the exact tuple). The split exists because
vulnerability rules are ranges while keys are points, and because reveal thresholds
on full tuples would starve on fast-moving versions (a five-customer app with five
versions never crosses any per-tuple threshold).

MD5 from the prior art is replaced by SHA-256: same role (a stored, derivable surrogate
key — computed once at snapshot build, never per lookup), without shipping MD5 in a
security product's public wire format.

### Test vectors (asserted in both codebases)

| input | key |
| --- | --- |
| `app.title` ("Google Chrome", "com.google.Chrome") | `v1:be346ceb600488c11f502c5b8cccd213941d12e783c798ce9ef901a0b88a0830` |
| `app.full` ("Google Chrome", "com.google.Chrome", "6478.127", "126.0.6478.127") | `v1:7ffc73c1311760fa2de0b52b84865940380264906a8f63d4c5fb2075fbde7378` |
| `app.full` ("Contoso Deploy", "com.contoso.deploy", "1.4", null) | `v1:333332009338fd345dfdc481009910bc729ef2cf965ad33a90df297e2f4d9592` |
| `app.title` ("Café Tool" — NFC *or* NFD input, "io.example.cafetool") | `v1:1db5e02b18524033fd33aa36d27b3f26e70953a13f57de3cb45729e91e7e36bb` |
| `os` ("macos", "14.6.1", "23G93") | `v1:f74565fbdda8b8036799e1e3a67b22ee909acac8840f2a6ae040b3d5a4e18867` |
| `hw` ("Mac15,7", "arm64") | `v1:efaeacc74866d7664560069b9b8f5b63f3cbd30f2d410cad4358ded71d3a2840` |

## What is shared, and what never is

Snapshots are **aggregated before they leave the box**: distinct tuples with counts,
summed per tenant. Never per-device rows.

Shared, per tenant, daily: the key pairs above with raw install counts; OS and hardware
tuples with counts; the platform each of those rows was counted on; the tenant's random
submission UUID; the container build version; the contract version. The platform is the
one addition that is not a hash — it is a fixed vocabulary word (`macos` today), it says
nothing a fleet is not already telling the collector by the OS keys it sends, and the
corpus cannot be partitioned without it. Counts are raw (not bucketed) because the
cloud's whole job is summation across customers, and buckets don't sum — the cost, that a
tenant's top-app count approximates its fleet size, is disclosed rather than obfuscated.

Never shared, by construction: device identifiers, serials, hostnames, user names,
file paths (macOS paths embed user names), extension attributes, connection names,
tenant names, e-mail addresses, or anything from the accounts, audit, or credential
tables. The ingest endpoint's side of the bargain: source IPs are not persisted.

**Reveals.** Plaintext (app_name, bundle_id, and that title's version tuples) is sent
only when the server explicitly asks for a specific `app.title` key, only if the
tenant's tier permits it, and the server's published rule is to ask only for titles
seen at **k ≥ 5 independent submission UUIDs** and not on its known-catalog or
exclusion lists. Two structural properties do most of the protective work:

1. *The server cannot ask a question it doesn't already know the answer to.* Computing
   a key requires possessing the plaintext; a targeted request can only name apps that
   are already public knowledge. Genuinely private titles are unaddressable.
2. *The threshold is a structural definition of "not company-specific."* An app present
   at five unrelated organizations is not one org's secret; an internal tool sits at
   count 1 forever and its name never crosses the wire.

Honesty note for the disclosure page: k is a promise, not a proof — clients cannot
verify it. And keys of publicly known apps are dictionary-reversible by anyone, which
is the intended product, not a leak; the protection is specifically for unknown titles.

## Anonymity model

Each **tenant** carries its own random submission UUID, generated when sharing is
enabled, resettable by an admin at any time. Per-tenant (not per-instance) UUIDs mean
the server cannot tell which tenants co-reside on one box — an MSP's customer
relationships never cross the wire. The UUID's only job is dedup: snapshots replace
prior snapshots from the same UUID, and global sums are taken over latest snapshots
only, so a daily feed can never double-count (**replace-then-sum**). The UUID is
pseudonymous, not anonymous — submissions from one tenant are linkable to each other —
and the disclosure page says exactly that.

## Consent

Three tiers, one enum, tenant-scoped in the schema from day one (V0's single
operational tenant renders it as one switch):

| tier | uploads | answers reveals | receives verdicts/feeds |
| --- | --- | --- | --- |
| `off` *(an install nobody has answered for)* | — | — | — |
| `keys` | keys + counts | never | yes — the [vulnerability corpus](#the-corpus-channel) link, and `verdicts` when they exist |
| `reveal` *(the wizard's pre-checked answer)* | keys + counts | common titles only, per the k-rule | the same |

The "receives" column stopped being a promise on 2026-09-10: the response now carries a
`corpus` pointer at the Jamf-derived vulnerability library, which the container downloads
and joins locally ([`vulnerabilities.md`](vulnerabilities.md), and the section below).
`verdicts` — the per-key community half — stays reserved and unparsed; the two are
**separate channels** on one exchange, and adding the second is additive to the first.

- **An install that was never asked does not share.** Consent is a row somebody's
  answer wrote, not the absence of one: the stored default is `off`, and the tier only
  becomes `reveal` because a wizard submission said so. This is the rule the two
  bullets below are consequences of, and it is deliberately stated first — the earlier
  arrangement inverted it, defaulting an unwritten row to `reveal`, which made the
  wizard bullet's promise false on every non-interactive install.
- **First-run wizard**: the choice is presented pre-checked at `reveal` during setup,
  and submitting the form records the answer either way — the checked box is written
  down, not inferred. Every operator who goes through the wizard affirmatively sees it
  before the first byte leaves; nobody discovers it in a traffic capture. This moment
  does not repeat per customer, which is why the feature ships in V0 at all.
- **Non-interactive bootstrap** (`INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD`, the
  path a pod, a script, or an MSP's fortieth container takes) skips the wizard
  entirely, so nobody is asked and nothing is shared. Sharing starts only when an
  administrator turns it on under Settings → Data Sharing. The startup log says so on
  that path, because an operator who never saw the wizard should not have to read this
  document to find out which way the switch is set.
- **Settings → Data Sharing**: the tier control, the disclosure content (this
  document's "what is shared" section, rendered), last-exchange status with the failed
  row's reason, the submission UUID with a reset button, and a **"Show exactly what
  would be sent now"** button that renders the literal next payload from live data. That
  button is the trust feature; everything else is furniture around it. Beside it,
  **Send now** runs the exchange immediately and shows the row it wrote in the preview's
  place ([below](#send-now)).
- **`COMMUNITY_SHARING=false`** (env) hard-disables regardless of UI state, for fleet
  and air-gapped deployments; the UI shows the override as the reason, names the file
  it lives in, and writes one `skipped_env` row to the share log per day so the page
  can say the override is biting. An administrator can still record a tier while it is
  set — the choice takes effect once the override is removed — and a role without
  `SYSTEM_WRITE` is told why the controls are read-only rather than shown them greyed
  out with no explanation (INSPECT-0302).
- Tier changes are audit-logged. An operator exclude list (glob on bundle_id, e.g.
  `com.acme.*`) filters matching apps out of **both** paths — the snapshot's hashed
  tuples and the reveal path's plaintext names — belt and suspenders ahead of the
  server's own rules. Both, deliberately: until INSPECT-0174 the filter covered only
  snapshots, so an excluded app still had its name revealed once the server asked
  about the title. Anything added here that sends app data must apply `_excluded`.

### AI inference (INSPECT-0112)

The same settings row carries a second, independent consent: `ai_inference`
(default **off**), governing whether any byte may leave the pod for AI inference.
It is deliberately not a fourth tier — the tiers describe the community exchange —
and deliberately not a feature flag: the `ai_features` flag turns the AI feature
area on, the consent decides whether anything may leave. Both default off; the gate
every AI feature must call, and the standing doctrine (no model-sourced numbers,
fleet-identifying payloads BYO-key or on-device only, no silent egress), live in
`backend/app/core/ai.py`.

## The exchange (outbound contract, v1)

One scheduled conversation per tenant per day, plus any an administrator sends with
[Send now](#send-now). The upload is simultaneously the feed query; the
response carries whatever the server currently implements — a V0 collector answering
with empty arrays is a valid peer, and the container treats absent capabilities as
"nothing today," never as an error.

```
POST {sharing_endpoint}/v1/exchange          default https://api.loonsec.io/v1/exchange
Content-Type: application/json
User-Agent: LoonSecIO/<build-version> exchange
```

The product token is `LoonSecIO`, not `LoonInspect`: every outbound call this
container makes — the exchange, the update check, Jamf, the patch catalogue — is
built by `app.core.user_agent.build_user_agent` from one setting
(`user_agent_product_name`), and the trailing word is the per-caller comment. A
server matching on the token should match that one, and treat the comment as the
thing that distinguishes an exchange from an update check.

```jsonc
// request
{
  "contract": "v1",
  "submission": "3f8a…-uuid",            // tenant-scoped, resettable
  "tier": "keys" | "reveal",
  "build": "2026.08.20+d4488cd",         // container build (public builds; coarse)
  "snapshot": {                           // full replacement, idempotent
    "apps":     [ { "title": "v1:…", "full": "v1:…", "count": 412, "platform": "macos" }, … ],
    "os":       [ { "key": "v1:…", "count": 380, "platform": "macos" }, … ],
    "hardware": [ { "key": "v1:…", "count": 380, "platform": "macos" }, … ]
  },
  "reveals": [                            // answers to a PRIOR response's requests;
    {                                     // [] always, when tier is "keys"
      "title": "v1:…",
      "app_name": "Some Common Tool",
      "bundle_id": "com.vendor.tool",
      "versions": [ { "version": "88", "short_version": "2.4.1", "count": 31 }, … ]
    }
  ]
}
```

```jsonc
// response — every field optional; container no-ops on anything absent or unknown
{
  "contract": "v1",
  "reveal_requests": [ "v1:…", … ],       // title keys; answered in TOMORROW's request
  "corpus": {                              // the vulnerability library: where it is,
    "signature": "6054bbb4…",              //   and whether it moved (sha256 of the
    "asof": "2026-09-10T20:00:00Z",        //   epoch's manifest — EQUALITY only)
    "url": "https://…/epoch-0001.tar.gz?…" // a signed link; never stored, never logged
  },
  "verdicts": [ … ],                       // post-V0; schema settles with the feed work
  "revoke": false                          // true = server-side kill switch: stop
}                                          //   sharing until an admin re-consents
```

### The corpus channel

Added 2026-09-10 ([#248](https://github.com/LoonSecIO/LoonInspect/issues/248)), additively:
a server that omits `corpus` is a valid peer and a container that does not understand it
ignores it, which is the same clause every other field of this response lives under.

- **The signature decides, and equality is its only operation.** The container stores the
  signature of the epoch it holds and downloads nothing while the two match — one exchange
  a day costs one string comparison on an unchanged corpus. It is never ordered and never
  compared for distance: a rollback moves the published epoch *backwards* and must still
  be imported.
- **The link is a capability.** It is fetched over the exchange's own transport, and it is
  never written to the share log, never stored in a column, and never logged — only its
  origin reaches a log line. The URL is refused outright unless it is `https` and names a
  host this container is willing to dial (`app.core.egress`, the same loopback and
  link-local rules a destination URL lives under).
- **Verified whole, or refused whole.** The bundle's manifest must be the one the
  signature names; every object must match its digest, its byte count and its row count;
  every row must be one the wire model would accept. A refusal imports nothing, leaves the
  previous epoch answering, and says so in a line an operator can read
  ([`troubleshooting.md`](troubleshooting.md) §5).
- **Nothing about a fleet leaves in this half.** The corpus is published complete and the
  join is local, so no app, hash, or count is sent in order to receive it — the request
  body above is the whole of what goes up, unchanged.
- **What it earns, it earns per tenant.** The imported epoch is a global artifact on this
  container, and the consent that pays for it is a per-tenant row, so the answer is gated
  per tenant too: a tenant whose tier is `off` reads `assessment: off` for every app even
  where the container holds an epoch, and the rows stay for the tenants entitled to them
  (ruled 2026-09-11, [`vulnerabilities.md`](vulnerabilities.md) §8). A revoke — the
  server's kill switch — stops both halves in one act: it writes the tier `off`, imports
  nothing that day, and stops that tenant being answered from the epoch it already had.

Semantics the server may rely on:

- **Every snapshot row names its platform.** `platform` is present on every `apps`, `os` and
  `hardware` row, and it is the routing token: the cloud corpus tables are partitioned by
  platform (Kyle, R4), and a content key cannot route a row to a table — not even the `os`
  key, which hashes the platform but is not reversible into a partition name. The vocabulary
  is one value per Apple OS — `macos`, `ios`, `ipados`, `tvos`, `visionos` — and it is the
  **content-key** spelling, not the Splunk sourcetype's `mac`; the two are different frozen
  namespaces (`docs/mobile-devices.md` §2). A value is never reused for a different
  population, and there is deliberately no submission-level platform: one container reads
  more than one platform from a single connection, so a per-submission field would have had
  to be deprecated rather than extended.
  Added in the container release that closed [#231](https://github.com/LoonSecIO/LoonInspect/issues/231),
  additively — a server reading a `v1` submission from an older container sees rows without
  the key and must treat those as **unknown platform**, never as `macos` by default. Rows
  already summed cloud-side cannot be given a platform after the fact, which is the entire
  reason the key ships before the first exchange rather than after.
  `hardware` is `[]` from every container shipped so far: the `devices` columns the `hw` key
  needs do not exist yet, so the row above is the shape it will take, not one being sent.
- **Idempotent replacement.** A request fully supersedes the previous snapshot for its
  `submission`. Aggregation is sum-over-latest; UUIDs unseen for N days age out (the
  ingest store's TTL is the natural mechanism).
- **Reveals lag by one exchange.** Requested in one exchange, answered in the next —
  ordinarily tomorrow's, sooner if an administrator sends one in between. No extra round
  trip, no server-side session state.
- **Scheduling is jittered.** Each container derives a stable minute-of-day offset from
  its submission UUID; operators choose coarse windows only. Peak converges to average
  by construction. A Send now is the one unjittered request, and it is a person's click,
  not a fleet's schedule.
- **Failure is silent and logged locally.** Timeout/5xx → exponential backoff within
  the run (3 attempts), then wait for tomorrow. No user-visible error, no repeating log
  noise — an air-gapped instance with sharing left on is a supported configuration.
- `413` → the container **sheds the reveals** and retries; the snapshot itself is never
  shrunk. The retry is the next attempt in the same backoff schedule, not an extra one,
  and it carries `"reveals": []` with the snapshot byte-for-byte unchanged. Reveals are
  shed at most once per run: a `413` against a reveal-less body is an ordinary failure
  from there on, retried until the delays are exhausted and then logged as failed. The
  load-bearing consequence for the server: **it must never `413` a reveal-less
  snapshot** — the container has nothing further to give up, so that is a day lost, not
  a day degraded.
- Unknown request fields must be ignored by the server; unknown response fields are
  ignored by the container. Contract changes bump the version string.

### Send now

Added 2026-09-12 ([#408](https://github.com/LoonSecIO/LoonInspect/issues/408)) for the
operator who needs to know *now* whether an exchange works — a new pod, a changed
endpoint, a corpus that should have arrived — rather than at the tenant's slot, which can
be a day away. The request body and the contract are unchanged; what the button adds is
around them.

- **The same code path.** Send now runs the exchange the scheduler runs: the same
  builder, the same 413 handling, the same share-log row, and the corpus import after it.
  A second builder would break the preview's promise that it cannot drift from the wire.
- **An administrator's act.** `SYSTEM_WRITE`, like the tier and the UUID reset, and
  audit-logged as `sharing.exchange.sent`; seeing what would be sent stays `SYSTEM_READ`.
- **It refuses in words and writes nothing** when nothing can be attempted:
  `COMMUNITY_SHARING=false` (the day's `skipped_env` row stays the only record of the
  override), an `off` tier, or an exchange already running for the tenant.
- **One at a time.** The scheduler and the button share a lock per tenant and neither
  waits on it: the scheduler skips a tenant whose send is in flight, and the button
  answers busy. Both would otherwise post, and both could reach the corpus import, which
  replaces the library wholesale.
- **The schedule does not move.** A sent row counts as an attempt like any other, so one
  sent after the tenant's slot is that day's exchange and one sent before it leaves the
  slot owed. For the server, a second exchange in a day is the idempotent replacement
  above: the same submission overwritten, nothing double-counted.
- **The box shows the past.** After a send, the preview gives way to the row the send
  wrote — outcome, the failed row's reason, `revealsShed`, and the payload that left —
  never the corpus link, which is a capability and is shown nowhere.

## The share log

Every exchange writes one tenant-scoped row recording **exactly what left the box**:
timestamp, tier, what started it (`scheduled`, or `manual` for a [Send now](#send-now)),
endpoint, outcome (sent / failed / skipped-by-env), the request payload
the run assembled (verbatim JSON — this is the point; reveals especially), the
`revealsShed` marker below, the response's request list, and on a failure the reason,
as a sentence naming the host and what it answered. Rows older than 90 days are
pruned on write.

- Read + download: `AUDIT_READ` (the auditor role exists precisely for "prove to me
  what this thing does").
- Download: NDJSON of the selected range from Settings → Data Sharing.
- **`revealsShed`.** True when the `413` path above ran and the submission the server
  accepted was the reveal-less retry — so the row's `payload` is a *superset* of what
  earned the `200`: everything in it left the box except the `reveals` array, which did
  not. False on every ordinary day, which is what makes a `413` day legible after the
  fact instead of looking like a normal reveal day. The payload is deliberately still
  the assembled body rather than the shed one: an auditor asking "what did this instance
  offer, and what did it actually send?" needs both halves, and one boolean beside the
  full payload carries them where a rewritten payload would silently lose the first.
- The payload column is plain JSONB, not `EncryptedString` — the data has already left;
  the log's value is that it is inspectable, and pretending it is secret would be
  theater.

Permitted off-pod AI inference calls write to the **same log** (one log is the
point): tier `ai`, the destination as the endpoint, and a payload naming the feature
and the field-level disclosure of what left — field names only, never contents.
These rows are not exchange attempts; the exchange's scheduling and the
"last exchange" status ignore them, and their `trigger` is empty.

The share log and the "show what would be sent" button are the same honesty told two
ways: the button shows the future, the log proves the past.

## V0 / post-V0

**V0 (container):** canonicalization module + key columns + vectors · consent surfaces
(wizard, Settings page, env override, README disclosure row) · the exchange job with
the full v1 parser (verdict/reveal handling shipped but dormant) · share log + download.
**V0 (cloud):** a dumb collector — receive, validate, store snapshots. Nothing else.

**Post-V0, with triggers:** reveal activation (trigger: enough UUIDs that k ≥ 5 has
teeth; plant canary titles *before* this, not before launch) · verdict/feed responses
and the hot-partition file (trigger: first CVE/patch rules keyed to the corpus — the
**corpus channel** above landed ahead of them, 2026-09-10, because a complete published
epoch needs no per-key protocol at all) ·
rate budgets and mirror detection (trigger: feeds carrying licensed value) · the
api.loonsec.io consolidation of the update check (#43's seam) · EU-region ingest
(trigger: a customer asks; per-tenant UUIDs make it clean).

Priority note: this ships in V0 **only alongside** the cross-tenant sweep (#37) — a
security product must not launch default-on telemetry and an IDOR hole in the same
release.

## Cloud notes (informative, fluid)

Nothing here binds the container. Current shape: DynamoDB keyed by the hashes
(PK `app.title` key, SK for rules / full-tuple verdicts / `PREV#<uuid>` snapshots with
TTL), Streams → Lambda for the ~50 fast-moving titles' hot file, nightly scan → static
versioned feed artifacts, no managed export, single region, CloudFront in front.
Exact-key lookups mean the corpus is unenumerable (2²⁵⁶ address space) and a scraped
row set is nameless for the long tail; the durable moats are freshness, canaries, and
license terms, not request throttling.
