# Inventory summaries (#594)

## Contract

An administrator selects the saved Apple FM or OpenAI-compatible provider under Settings → AI,
**below** the master flag and consent controls. Both gates are required before inference. The
500-character customer preference requests tone/emphasis; it grants no tools or action authority.
The endpoint configuration is reused, encrypted secrets stay server-side, and no fallback provider
is selected automatically. Settings and metrics have English and German presentation.

Code compares committed inventory, never calling a model from ingestion or waiting for SIEM
source delivery. It compares app versions and available vulnerability assessments, OS version/build,
`diskEncryption.fileVault2Enabled`, and security SIP/Gatekeeper/firewall. Corpus-only CVE changes
and severity-count changes with unchanged CVE IDs trigger work on the next inventory observation.
Missing sections are unknown, never removals. A first partial snapshot establishes a partial baseline;
a later newly observed section extends that baseline without AI unless an already observed value
also changed. A name-only app change is `metadata_changed`, not `assessment_changed`.

**Kyle's review ruling: emit meaningful changes only.** Comparable unchanged observations retain
exactly `No updates` in per-device summary state, with zero AI calls, zero summary job rows and zero
extra SIEM events. Baseline and incomplete observations also remain local. Drops/failures are counted
and logged with reasons and next checks, not emitted as empty briefings. The original inventory
remains the evidence fallback. Only completed/cached meaningful-change briefings emit a summary.

## Evidence and prompt

Code owns all counts and comparisons. The model receives at most 2400 UTF-8 bytes of compact fact
lines plus 800 bytes of preference, not raw inventory, device identity or CVE lists. Omitted lines
are counted. It returns at most 180 tokens of advisory prose. Bounded/plain-text/numeric checks
reject unsupported output; they do **not** prove semantic accuracy. A shortened version such as
`128` when only `128.0.1` occurs in the facts is conservatively refused as `unsupported_number`.
The detailed deterministic evidence remains authoritative for SOAR decisions.

The first iteration consumes the snapshot's aggregate severity counts, not the newly merged
finding ledger's history. It detects changing severities but does not invent which CVE changed
severity or resolved counts per severity. Full per-finding enrichment can follow the ledger work.
An ID absent from a truncated current list is not reported as resolved; unavailable assessment is
not zero. Unique old/new versions of one app identity are paired; ambiguous multiversion installs
remain separate installed/removed records.

## Storage, queue and scheduling

Four tables have FORCE RLS: settings, per-device state, changed-observation jobs, and minute metric
counters. State keeps the latest compact app list (including already-capped CVE lists), source ID,
source time and local summary status/text. It is one row per device, retained for the next comparison.
State size still grows with each device's app count and corpus coverage; it is not a full historical
inventory copy. Measure actual state storage before sizing a large deployment.

The existing outbox receives one nullable `summary_collected_at` receipt marker, independent of
`fanned_out`. That marker and comparison state/outcome commit together; no extra receipt job is
needed for unchanged observations. Unlike a numeric high-water cursor, this cannot miss a lower
source ID whose transaction commits later. A partial index covers eligible inventory intake by tenant,
creation time and ID. Intake reads at most 500 snapshots since enablement, with a seven-day lookback.
Malformed identity/time is counted and marked, so one bad event cannot starve the queue forever.

A tenant may have 1000 pending/leased changed jobs. Capacity drops record a counter and reason,
not another full evidence row. Completed cache entries can be used at intake even when that queue
is full. Terminal changed jobs/cache expire after eight days; minute counters after 25 hours,
including while inference is disabled. At 30,000 devices, six *unchanged* sweeps a day no longer
produce roughly 1.44 million eight-day job receipts. A fleet with genuinely changing evidence at
that frequency can still produce many jobs; this is not a proven 30,000-device capacity claim.

Two workers drain available jobs for up to 30 seconds of scheduling time each (an active request
can finish within its own timeout), with a 1000-job fairness bound. Cache hits are drained in the
same pass; a pending twin of a live lease is skipped so unrelated work proceeds. The loop sleeps
five seconds **after** a tick finishes, and is cancelled/awaited at shutdown. Slow model calls do
not create overlapping APScheduler invocations or maximum-instance warnings.

Apple FM has one in-process lane. Interactive requests take priority over queued background work,
but never interrupt an already active call. Background pauses (1–60 seconds; default 2) do not
occupy the lane. One application process per shared FM endpoint remains the supported configuration;
unrelated programs/containers are outside this meter. OpenAI-compatible uses bounded concurrency.
Native OpenAI Batch is not used because its documented 24-hour completion window cannot promise
the one-hour TTL: https://developers.openai.com/api/reference/resources/batches/methods/create.

TTL remains one hour from **source enqueue**, never extended by retry. `queuedAt` records actual
job creation independently. Calls have at most 60 seconds and no more than remaining TTL. Claims
have a two-minute recovery lease. Rate-limit/timeouts/unreachable failures retry up to three attempts.
Cache keys include tenant isolation, selected configuration, prompt version and complete evidence.
A process crash after inference can repeat the call; exactly-once inference is not promised.

## Wire contract

One `device.inventory.summary` event, stamped with registered `loon:inventory:summary`, is sent
only for a meaningful change with a usable summary. Optional keys are absent rather than null,
including recursively within before/after objects. This unmerged feature's vocabulary is proposed
for independent review; once shipped it follows the frozen additive-only contract.

| Key | Type and meaning |
| --- | --- |
| `event` | String, always `device.inventory.summary`. |
| `summaryID` | UUID string identifying this briefing; use for deduplication. |
| `sourceEventID` | Integer source outbox ID. |
| `deviceMeta` | Source metadata under the existing frozen contract. Its `eventID` correlates the source observation, not a unique summary. |
| `occurredAt` | ISO timestamp of source observation; also used for HEC `time`. |
| `sourceEnqueuedAt` | ISO timestamp when the source entered the outbox. |
| `queuedAt` | ISO timestamp when the changed-observation job was created. |
| `generatedAt` | ISO timestamp when this job completed, including cache completion. |
| `expiresAt` | ISO deadline, source enqueue plus one hour. |
| `summaryStatus` | `completed` or `cached`; other outcomes are local. |
| `summaryProvider` | `apple_fm` or `openai_compatible`. |
| `promptVersion` | String identifying the prompt contract (`inventory-1`). |
| `shortSummary` | Validated advisory string, always present on emitted briefings. |
| `advisory` | Boolean, always true. |
| `corpusAsOf` | Array of available corpus timestamp strings; empty if unavailable. |
| `evidenceScope` | Array of strings: `applications`, `os_version_build`, `disk_encryption`, `selected_security_fields`. |
| `evidence` | Object defined below. |

Every `evidence` key:

| Key | Type and meaning |
| --- | --- |
| `kind` | `changed` on emitted events. Internal comparisons can also be `baseline`, `incomplete`, `unchanged`. |
| `changes` | Array of deterministic change objects, including newly observed sections if accompanied by a real change. |
| `facts` | Compact, bounded string sent to the provider. |
| `omitted` | Integer count of fact lines omitted from that string; full changes remain in `changes`. |
| `missingSections` | Array of section names absent from this observation. |

Each change has `section` (`apps`, `operatingSystem`, `diskEncryption`, or `security`). A newly
observed section has `reason: newly_observed` and no fabricated prior values. An app change has
`key` (internal app identity/version correlation string), `reason` (`installed`, `removed`,
`version_changed`, `assessment_changed`, `metadata_changed`), and available `before`/`after` objects.
Installed apps omit `before`; removed apps omit `after`. Each app object has `name` and `version`
strings, `assessment` string using the existing vulnerability assessment vocabulary, optional
`counts` using the existing `{total, severity, kev}` vocabulary, `vulnIDs` string array and
`vulnIDsTruncated` boolean. For two covered assessments, `newlyListedIDs` and `noLongerListedIDs`
are arrays of CVE IDs newly present/absent in the supplied lists; these are not lifecycle assertions.
A truncated current list forces `noLongerListedIDs` empty.

Other section changes have `field`, and available `before`/`after` native scalar values. The fields
are OS `version`/`build`, encryption `fileVault2Enabled`, and security `sipStatus`, `gatekeeperStatus`,
`firewallEnabled`. Absent keys mean unavailable; zero and false remain explicit values.

The private outbox envelope is stripped at delivery. HEC `time` backdates the summary to its source;
Splunk `_indextime` remains arrival time. Searches must allow late arrival. Default subscriptions
receive the new family; explicit subscriptions must add it. Summary and source delivery are independent.

## Metrics and diagnostics

The selected provider's 24-hour Overview window uses minute counters (up to one minute of boundary
rounding). Unchanged/baseline/incomplete/immediate-drop outcomes use counters rather than jobs.
Pending counts and attempt/latency measurements read jobs through the `(tenant_id, provider,
created_at)` index. Success is completed jobs / attempts; drops are dropped-or-failed / received
observations. Cache hits, no-update count, rate-limit responses, oldest queued time and diagnostic
reason counts are separate. No samples is an em dash; a polling error hides stale readings.

The diagnostics disclosure and container logs name the next check. Unexpected failures include
exception type and stack *locations*, never exception messages, payloads, API keys or local variables.
To troubleshoot, start with Settings → AI's provider test, flag and consent; then Overview's oldest
queued time and reason. Original inventory still delivers if a summary fails. Reasons are listed below.

| Reason | What to check |
| --- | --- |
| `expired` | The one-hour deadline elapsed. Check queue age and provider latency on Overview. |
| `capacity` | The summary backlog is full. Check queue age, rate limits and provider capacity. |
| `disabled` | Inventory summaries or the AI master flag were disabled. Check Settings > AI and Feature Flags. |
| `configuration_changed` | Provider settings or customer instructions changed. New observations use the current settings. |
| `consent_missing` | Inference consent was revoked. Check Settings > AI before requesting another summary. |
| `stale_observation` | This observation predates the last compared snapshot. Check the source inventory timestamps. |
| `invalid_observation` | Inventory identity or occurrence time is missing or invalid. Check the source outbox event and MDM collection. |
| `overload` | The provider returned a rate limit. Check its capacity and the Apple FM pause setting. |
| `timeout` | The provider did not finish within the call deadline. Check endpoint responsiveness and queue age. |
| `unreachable` | The provider could not be reached. Test the saved endpoint in Settings > AI. |
| `http_status` | The provider refused the request. Test its model, key and endpoint in Settings > AI. |
| `malformed` | The provider returned an unsupported response shape. Check OpenAI-compatible API support. |
| `too_large` | The provider response exceeded the size limit. Check the model's response behavior. |
| `unsupported_number` | The reply introduced a numeric token absent from the facts, including a shortened version. Check model choice or customer emphasis; full evidence remains authoritative. |
| `unsupported_no_change` | The reply claimed no changes despite changed evidence. Check model choice and customer emphasis. |
| `invalid_summary` | The reply was empty, too long, multiline or contained markup. Check model choice and output behavior. |
| `endpoint_refused` | Endpoint safety or key validation refused the saved configuration. Re-save and test it in Settings > AI. |
| `internal_error` | The summary worker encountered an unexpected error. Check the exception type and stack locations in container logs and report the summary ID. |

posture_snapshot: none

## Device history integration (#605)

The device-history card retains a summary outcome on its exact source-correlated historical point.
This does not extend queue/cache TTL, generate a model call, or add a wire event. Unchanged sweeps
still produce no extra summary jobs; they also do not create a history point when inventory and
assessment evidence match the last recorded point. See [Device history](device-history.md) for
historical count semantics, retention and the optional upgrade import.
