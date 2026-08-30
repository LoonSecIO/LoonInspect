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
tuples with counts; the tenant's random submission UUID; the container build version;
the contract version. Counts are raw (not bucketed) because the cloud's whole job is
summation across customers, and buckets don't sum — the cost, that a tenant's top-app
count approximates its fleet size, is disclosed rather than obfuscated.

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
| `off` | — | — | — |
| `keys` | keys + counts | never | yes |
| `reveal` *(default)* | keys + counts | common titles only, per the k-rule | yes |

- **First-run wizard**: the choice is presented pre-checked at `reveal` during setup.
  Every operator affirmatively sees it before the first byte leaves; nobody discovers
  it in a traffic capture. This moment does not repeat per customer, which is why the
  feature ships in V0 at all.
- **Settings → Data Sharing**: the tier control, the disclosure content (this
  document's "what is shared" section, rendered), last-exchange status, the submission
  UUID with a reset button, and a **"Show exactly what would be sent now"** button that
  renders the literal next payload from live data. That button is the trust feature;
  everything else is furniture around it.
- **`COMMUNITY_SHARING=false`** (env) hard-disables regardless of UI state, for fleet
  and air-gapped deployments; the UI shows the override as the reason.
- Tier changes are audit-logged. An operator exclude list (glob on bundle_id, e.g.
  `com.acme.*`) filters tuples out of snapshots entirely — belt and suspenders ahead
  of the server's own rules.

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

One conversation per tenant per day. The upload is simultaneously the feed query; the
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
    "apps":     [ { "title": "v1:…", "full": "v1:…", "count": 412 }, … ],
    "os":       [ { "key": "v1:…", "count": 380 }, … ],
    "hardware": [ { "key": "v1:…", "count": 380 }, … ]
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
  "verdicts": [ … ],                       // post-V0; schema settles with the feed work
  "revoke": false                          // true = server-side kill switch: stop
}                                          //   sharing until an admin re-consents
```

Semantics the server may rely on:

- **Idempotent replacement.** A request fully supersedes the previous snapshot for its
  `submission`. Aggregation is sum-over-latest; UUIDs unseen for N days age out (the
  ingest store's TTL is the natural mechanism).
- **Reveals lag by one exchange.** Requested today, answered tomorrow. No extra round
  trip, no server-side session state.
- **Scheduling is jittered.** Each container derives a stable minute-of-day offset from
  its submission UUID; operators choose coarse windows only. Peak converges to average
  by construction.
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

## The share log

Every exchange writes one tenant-scoped row recording **exactly what left the box**:
timestamp, tier, endpoint, outcome (sent / failed / skipped-by-env), the request payload
the run assembled (verbatim JSON — this is the point; reveals especially), the
`revealsShed` marker below, and the response's request list. Rows older than 90 days are
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
"last exchange" status ignore them.

The share log and the "show what would be sent" button are the same honesty told two
ways: the button shows the future, the log proves the past.

## V0 / post-V0

**V0 (container):** canonicalization module + key columns + vectors · consent surfaces
(wizard, Settings page, env override, README disclosure row) · the exchange job with
the full v1 parser (verdict/reveal handling shipped but dormant) · share log + download.
**V0 (cloud):** a dumb collector — receive, validate, store snapshots. Nothing else.

**Post-V0, with triggers:** reveal activation (trigger: enough UUIDs that k ≥ 5 has
teeth; plant canary titles *before* this, not before launch) · verdict/feed responses
and the hot-partition file (trigger: first CVE/patch rules keyed to the corpus) ·
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
