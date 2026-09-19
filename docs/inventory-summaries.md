# Inventory summaries (#594)

## Contract

Opt-in inventory briefings use the explicitly selected saved Apple FM or OpenAI-compatible
provider. The AI master flag and inference consent must be enabled. Settings → AI → Inventory
summaries names the provider and its customer tone/emphasis instructions (500 characters).
No automatic fallback to another endpoint occurs. Changing a provider/model/preprompt invalidates
pending work and cached answers for that configuration.

The worker reads **committed** `device.inventory` snapshots independently of destination delivery.
It does not call the model from MDM ingestion and does not depend on `device.change` existing.
An unchanged app version with changed CVE IDs or severity counts is a meaningful comparison.
Corpus changes become eligible on the **next inventory snapshot**, not immediately at corpus import.
Webhooks and scheduled sweeps already produce those snapshots; this feature changes neither schedule.

This first iteration compares applications, OS version/build and selected security fields
(FileVault, SIP, Gatekeeper, firewall). Missing sections are unknown, not removed. A baseline
receives `Baseline recorded`; a fully comparable unchanged observation receives exactly `No updates`;
neither invokes a model. These are scoped change statements, never clean-bill-of-health claims.
Other inventory fields and finding-ledger integration are follow-ups.

## Evidence and prose

Code builds detailed before/after facts, including available CVE lists, capped-list indicators and
aggregate severity counts. A version transition is paired only when one prior and one current
version share an app identity. Ambiguous multiple installed versions remain separate changes.
IDs leaving a truncated current list are not reported as absent. An unavailable assessment is not
zero findings. A missing corpus entry is not a claim that a vulnerability was fixed.

The provider receives compact fact lines, not old/new JSON, device identity or full CVE lists.
The prompt has a 2400-byte fact budget plus at most 800 UTF-8 bytes of customer preference;
omitted fact lines are counted explicitly. Output is capped at 180 tokens and validated as bounded
plain text with no novel numeric tokens. The system instruction constrains the customer preference
to tone/emphasis. Model prose remains **advisory**, not evidence or permission to execute anything.
Semantic hallucinations remain possible; downstream agents must use the deterministic evidence.

The current corpus wire has severity counts, not a severity per CVE. Severity can change while IDs
stay constant: that case is tested and triggers work. Until #590/#591 provide a settled per-finding
contract, this feature does not invent which CVE changed severity, first-detection intervals, or
resolved counts per severity. The handoff carries current corpus dates separately.

## Queue and metering

Settings, per-device comparison state and jobs have FORCE RLS tenant policies. Jobs retain a source
outbox ID, source time, fixed expiry, attempts and outcome. Intake considers snapshots since enablement
with a seven-day lookback in pages of 500. A maximum of 1000 pending/leased jobs per tenant bounds the
inference backlog; excess jobs are dropped and logged, while the source evidence remains untouched.
Terminal job receipts/cache are retained eight days to cover the intake lookback; comparison state
is retained as the next observation's baseline. These are initial policy bounds, not measured scale limits.

The scheduler ticks every five seconds. Two work slots serve the tenant; Apple FM shares a serial
lane with interactive calls in the same application process, plus a configurable 1–60 second pause
(default 2) for summary calls. OpenAI-compatible calls use the existing bounded concurrent adapter.
**One application process per shared FM endpoint is the supported configuration for this iteration.**
The local lane cannot meter unrelated programs or another container calling the same FM host.
Cross-process endpoint arbitration and interactive priority are follow-ups, not shipped guarantees.

The TTL is one hour from the source snapshot's enqueue time, never extended by retry. Each call
has at most 60 seconds and no more than the remaining TTL. A job claim has a two-minute lease for
crash recovery. Rate-limit, timeout and unreachable errors retry up to three attempts with backoff;
expired, disabled, changed-configuration and invalid-result jobs have explicit outcomes.
Completed identical evidence is reused only inside the same tenant/configuration/prompt version.
There is no exactly-once inference guarantee across a process crash after the provider answered.

Native OpenAI Batch is not used: its documented 24-hour completion window cannot promise this
one-hour deadline. OpenAI-compatible does not itself imply Batch support.
Source: https://developers.openai.com/api/reference/resources/batches/methods/create

## SIEM handoff and time

A separate `device.inventory.summary` event (`loon:inventory:summary` in Splunk) carries
`summaryID`, `sourceEventID`, copied `deviceMeta`, `summaryProvider`, `promptVersion`, `summaryStatus`,
`shortSummary`, deterministic `evidence`, `evidenceScope`, `corpusAsOf`, and `advisory: true`.
Statuses include completed, cached, no_updates, baseline, incomplete, dropped and failed.
`reason` explains absence of prose. A failed summary never becomes `No updates`.

`occurredAt` and HEC `time` use the source inventory event time, preserving its established sweep/
webhook clock. `queuedAt`, `generatedAt` and `expiresAt` show the actual delay. Splunk `_indextime`
remains actual index arrival time. Late summaries do not rewrite the original event: searches must
allow late arrival or correlate by `deviceMeta.eventID` / `sourceEventID`, rather than assuming order.
Destinations with default subscriptions receive the new family; explicit subscription lists must
add `device.inventory.summary`. Source event delivery and summary delivery are independent.

## Overview metrics and troubleshooting

System-read users see a panel when summaries are enabled. The selected provider's 24-hour window
reports successful jobs / inference attempts, dropped-or-failed jobs / received jobs, rate-limit
responses, mean latest-attempt latency (includes metering), cache hits, no-update jobs and oldest
queued timestamp. No samples shows an em dash, not a successful benchmark. Poll errors visibly
mark the reading unavailable. Operational metrics are not nightly fleet posture keys.

If summaries are missing: check the selected saved provider, master flag and consent; ensure the
source inventory includes the compared sections and postdates enablement; inspect queue age and
drop rate; check the destination's explicit subscription list. Structured drop logs name the summary
ID, source event ID, age and reason without copying payloads or credentials. `capacity` means reduce
work or improve measured throughput; `expired` means the deadline elapsed; `overload` means the
provider returned 429; `configuration_changed` requires a new observation under the new configuration.
Normal inventory delivery remains the evidence fallback. No automatic redrive of expired AI work.

posture_snapshot: none

## First-release validation boundary

The regression suite covers corpus-only and severity-only transitions, no-change skipping,
missing/capped observations, source-time delivery, expiry, capacity drops, overload retries,
crash-lease recovery, configuration invalidation, tenant isolation, permissions and consent.
Apple FM and OpenAI-compatible wire paths are exercised with synthetic HTTP fixtures.

A local Apple FM smoke check with three synthetic change prompts returned bounded replies in
1.47–2.65 seconds including the configured meter wait, using 13–35 completion tokens. This is
not a fleet throughput benchmark. The corpus-change reply omitted the newly-listed count;
that count remains in deterministic evidence. Human review of model quality is still required.
No real Jamf fleet, Splunk instance or paid cloud endpoint was exercised for this change.
The 30,000-device workload needs a separate load test before sizing queue or concurrency limits.
The initial settings/metrics copy is English; localized copy is a follow-up.
