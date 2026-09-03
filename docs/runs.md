# The run

Status: **implemented (#31, 2026-08-23)** · Target: V0

Every pull LoonInspect performs happens inside a *run*. Before this there was no such
object: a run was a function call with a status string beside it on `mdm_sync_state`, and
four separate contract clauses each needed something that string could not carry.

| Contract clause | What it needs from the run | Where it is now |
| --- | --- | --- |
| "Postgres-backed mutex — the run row **is** the lock" | The row, and a partial unique index | `uq_run_active_lock` |
| "`device_meta` carries jobID, tenant, runtype, run_type, shortdate" | Identity and classification | `app.core.runs.run_meta` |
| "scheduled runs back-date all events to the run window" | The window | `app.core.runs.event_time` |
| "Run log queryable in Postgres, scoped by tenant and jobID" | A foreign key | `run_log` |

They are one piece of work wearing four hats, which is why they landed together.

---

## 1. The mutex

```
partial unique index on (tenant_id, mdm_connection_id, lock_class)
  where status = 'running' and lock_class <> 'webhook'
```

**Acquisition is the INSERT.** Two callers racing for the same connection both insert;
one commits, the other takes an integrity error and is handed the winner's run. This
replaces a check-then-set race: `connections.py` read `mdm_sync_state.status`, and if it
was not `syncing`, wrote `syncing` — two statements across an `await`, so two run-now
requests arriving together both read `idle`, both passed, and both started a full pull
against the same Jamf server.

**The key is the connection, not the tenant.** #31 originally sketched the index on
`(tenant_id)` alone. That is wrong in one direction: it permits one run per *tenant*, so
a customer holding two Jamf Pro instances could sweep only one at a time, for no reason —
they are separate hosts with separate capacity.

**`lock_class` separates the expensive from the cheap.** A fifteen-minute catalog refresh
has no reason to queue behind a forty-minute device sweep of the same connection, and
making it wait starves the catalog exactly when the sweep is generating references into
it (`ingest-scheduling.md` §6.2).

**Webhooks are exempt, in the predicate rather than in code.** They must ACK fast, a busy
tenant fires many, and serializing them behind a sweep makes the real-time path useless.
A webhook still gets a run — it needs the jobID and the log — but never the lock. Their
ordering against a sweep is handled by the ledger's monotonic guard instead, which is
independently correct: an observation older than what the ledger already holds is
refused, so sweep/webhook interleaving is irrelevant rather than coordinated.

## 2. The heartbeat, which is not optional

A mutex without a heartbeat is a deadlock. A process that dies holding a run leaves the
row `running` forever and **nothing on that connection can sync again** — worse than the
race it replaces, because duplicate load is noisy and self-limiting while permanent
silence pages nobody.

`heartbeat_at` is written every 15 seconds from the device loop (throttled, so it is one
small `UPDATE` per interval and not one per device). A run whose heartbeat is older than
`RUN_STALE_AFTER_SECONDS` (default 300 — twenty missed beats, not a slow one) is failed
by the next acquirer.

Reclaim happens **on acquisition, not at startup**. Startup was the wrong moment twice
over: it never fires in a process that stays up for a month, and the blanket sweep it
replaces (`main.py`, now deleted) failed runs that a *different, healthy* instance was
still performing during a rolling restart — while that instance carried on writing under
a status saying it had died.

## 3. The window, and the `_time` rule

`occurred_at` used to be `datetime.now()` at emit time on all three paths, so a scheduled
event and a webhook event were stamped identically — by when the container processed
them, not by when anything happened.

| Trigger | `_time` | Why |
| --- | --- | --- |
| `sweep` | `window_start` | Every event of one nightly sweep shares one timestamp. A forty-minute pull must not smear across forty minutes of the index, and a sweep the tick reached late must still report the configured hour. |
| `webhook` | device time (Jamf's `reportDate`) | It is a real-time signal about a device; the device's clock is the truth. |
| `manual` | now | Someone is watching it happen. There is no window to belong to, and back-dating an interactive action is a lie about when it occurred. |

`window_start` for a scheduled run is the occurrence being served — the `next_due_at`
value the tick claimed, captured *before* the claim advances it, not the moment the tick
got around to it.

This is what makes the contract's *"verify webhooks always land after the run stamp"* a
checkable statement rather than a hope: the sweep's events sit at the window, the
webhook's sit later at device time, and the ordering falls out. `test_runs.py` asserts it.

## 4. `runtype` and `run_type` became `trigger` and `comparison`

The contract specified two `device_meta` fields differing by one underscore and meaning
entirely unrelated things: `runtype` (what triggered this) and `run_type` (what kind of
comparison this is). That sits badly against the contract's own rule two lines below —
*"Field names readable English, no abbreviations"* — because an analyst reading
`runtype=manual run_type=delta` has no way to tell which is which, and will eventually
type the wrong one and get zero results with no error.

Emitted as **`trigger`** (`sweep` | `manual` | `webhook`) and **`comparison`**
(`baseline` | `delta`). Renamed while renaming was still free; customer SPL written
against these names makes them permanent.

`trigger` reuses the vocabulary the observation ledger already stamps on every span as
`last_trigger`, rather than the contract's `scheduled`: one word per concept across the
ledger, the run, and the wire. `comparison` is `baseline` until a connection and lock
class have completed one successful run, and `delta` after.

The `deviceMeta` block on `device.inventory.changed`, ruled in #189:

```json
{"jobID": "…", "trigger": "sweep", "comparison": "delta",
 "connectionID": 1, "collectionID": 4, "shortDate": "2026-08-31",
 "eventID": "…", "serialNumber": "C02…", "jamfProID": "1743",
 "hostName": "kyle-mbp", "lastReportDate": "2026-08-31T21:44:03+00:00",
 "managed": true, "schemaVersion": "v0"}
```

Capped at **thirteen keys**, because a Splunk destination expands one device's event
into one sub-event per app, per extension attribute, per certificate and per profile,
and every field here is written onto all of them — measured against a real tenant record
the block is over half the raw feed. Keys can be added later and never taken away, so
anything proposed for it goes through #189 first.

Two rules a consumer can rely on:

- **Null values are dropped, not sent.** `collectionID` is absent on the webhook path,
  where a run carries no collection. `NOT deviceMeta.collectionID=*` finds those events.
- **`eventID` is one id per device per pull** — `uuid5(jobID, jamfProID)`, so a retry
  recomputes the same value. It is the only key that selects a single device's complete
  inventory pass: two sweeps in a day share a `shortDate`, and one sweep's `jobID` is
  shared by every device in the fleet.

Casing is camelCase throughout with the token `ID` uppercased on LoonInspect's own keys
(#188). A vendor's native key keeps the vendor's spelling — Jamf writes `bundleId`, so
the wire does too.

The law covers **all four families** — `device.inventory.changed`, `device.change`,
`run.completed`, `run.failed` — and for a year it was applied to one. The consequence,
seen on real indexed data, was one index, one sourcetype, and one run UUID arriving under
three names (`deviceMeta.jobID`, `job_id`, `run_id`) with no single predicate able to
select LoonInspect events by type. Three decisions closed that:

- **The discriminator is `event`, on every family.** The run families said `event_type`;
  they now say `event` too, so `event=device.*` and `event=run.*` are one search. This is
  the change most visible to a customer: a saved search or alert written against
  `event_type=run.failed` returns zero rows — silently, because SPL has no such thing as
  an unknown-field error. `event` won over `eventType` because it was already the
  spelling on the two device families, which carry essentially all of the volume, and
  renaming those to chase the smaller pair would have been the expensive direction.
- **The run UUID is `jobID` everywhere.** `deviceMeta` said `jobID`, `device.change` said
  `job_id`, and the run events said `run_id`; all three are now `jobID`, carrying the
  same value. `runID` was rejected for the same reason: one value, one name.
- **`jamfProID` is the object's id in Jamf Pro on both device families**, computer or
  group — `subjectKind` says which kind of object it belongs to.

`jobID` is **top-level on all four families**, and on `device.inventory.changed` it is
carried a second time inside `deviceMeta`, where Splunk's JSON extraction names it
`deviceMeta.jobID`. The cross-family join is therefore a bare `jobID=$id$` — not
`jobID=$id$ OR deviceMeta.jobID=$id$`, and not a `coalesce` — which is what lets the
payload tables below call the run id joinable with no qualification attached.

The duplicate is deliberate, ruled on
[#220](https://github.com/LoonSecIO/LoonInspect/issues/220), 2026-09-02, against three
alternatives. The root copy is what lets one predicate select every family. The nested
copy stays because a customer's SPL may already name it and an unknown field returns zero
rows with no error, and because `deviceMeta` is meant to be the self-contained identity of
the pull — a sub-event read alone should still know which run produced it. It costs ~47
bytes on the event whose cost multiplies by every app, EA, certificate and profile once
the fan-out lands, which is what made this a #189 decision rather than a casing one; a
join every consumer writes twice, or writes once and silently under-reports on the
highest-volume family, was ruled the more expensive of the two. `host` already rides in
both the envelope and the body on the same reasoning.

Two spellings were genuinely ambiguous and are ruled here so nobody has to guess twice:

- **`jamfUrl`, not `jamfURL`.** The law uppercases exactly one token, `ID`. Extending it
  to `URL` in passing would be a second ruling; Jamf's own API spells url keys `...Url`.
- **`udid` stays `udid`.** It is one acronym rather than a name ending in an `Id` token,
  camelCase puts the leading word in lower case, and Jamf spells it `udid` as well.

Alongside the body, a Splunk HEC delivery sets three envelope fields: `time` from the
event's own `occurredAt`, `host` from the hostname, and `source` from the Jamf instance
(scheme dropped, non-default port kept — `jamf.corp.local:8443`). They are indexed
metadata, so they cost no licence volume. `sourcetype` is deliberately not set yet: the
ruled tree names fan-out sub-events that do not exist, and a sourcetype is a permanent
`props.conf` stanza.

**The run id is UUIDv7, not `uuid4`, since
[#225](https://github.com/LoonSecIO/LoonInspect/issues/225).** `jobID` being a
correlation key (the ruling above) means `eventstats max(jobID) by serialNumber` — the
natural latest-state idiom on a fan-out sourcetype — is a search an analyst will reach
for. Over `uuid4`'s random hex that search was not wrong, exactly; it was meaningless,
silently, which is the failure mode this whole document exists to close off elsewhere.
UUIDv7 keeps the exact 36-character shape `uuid4()` already had — nothing downstream
that stores or displays a run id changes format — and sorts by creation time instead of
by nothing. Minted locally (`app/core/uuid7.py`) rather than the standard library's own
`uuid.uuid7()`, which is Python 3.14; this repo runs 3.12. ULID was considered and
rejected on the same #188 ruling that named UUIDv7: a second, differently-shaped id
format on the wire beside `eventID` for no gain UUIDv7 doesn't already give. Free before
the flip and a breaking change after it: `eventID` is `uuid5(jobID, jamfProID)`, so
changing `jobID`'s generator changes every derived event id too.

## 5. The log, and run-now

`run_log` is one row per engine line, scoped by tenant and run. Deliberately **not** per
device — a 40,000-device sweep writes milestones plus a progress line every 500 devices,
about 80 rows. The ledger is already the per-device record.

- `GET /api/runs?connectionId=&status=&limit=` — recent runs
- `GET /api/runs/{jobId}` — one run
- `GET /api/runs/{jobId}/log?after=<id>` — lines after a cursor, plus the run and a
  `complete` flag

`POST /api/mdm/connections/{id}/sync` now **always returns 202 with a jobID**, plus
`started` saying whether it began a run or joined one. Contention is not a 409: someone
clicking "Run now" during a cron sweep is asking "is my fleet syncing?", and showing them
the running sweep's log answers that better than an error does
(`ingest-scheduling.md` §4.2).

The UI (`RunLogPanel.tsx`) polls every two seconds and stops on two conditions, both
required: the run reaching a terminal status (**not** an empty page — a sweep mid-fleet
can be quiet for a minute and still be alive), and the tab becoming hidden
(`visibilitychange`, resumed on return; the cursor means resuming costs one request for
everything missed).

## 6. Retention

`RUN_RETENTION_DAYS`, default **30**, purged daily at 02:50 alongside the other cleanups.

Two existing precedents disagreed: `event_outbox_retention_days = 7` and
`audit_retention_days = 30`. The run log follows audit. It is what someone opens to
answer "did this run last month", so a week cannot serve its own purpose, and it is far
smaller than the outbox, which carries a row per event per destination. Log lines are
removed by cascade from the run rather than by a second delete that could drift.

## 7. Failure accounting (#92)

One device must not kill the sweep. Before this, the device loop had no per-device
isolation: any single failure — a corrupt record, or the race a webhook's mutex
exemption makes possible when both paths insert the same device's span within
milliseconds — failed the entire run, and because the tick claims an occurrence before
running it, that occurrence was already spent. On a 40,000-device fleet the odds of one
bad device are roughly certainty, so the failure mode lived exactly where a first
impression is made.

**Isolation.** A device that raises mid-sweep is rolled back (its partial writes must
not poison the session for the next device — per-device commits are the checkpoints
that make this cheap), recorded in the run log with its identity and error
(`device failed; sweep continues`, with `jamfId`, `serialNumber`, and the error class),
and the sweep continues. Two exceptions deliberately pass through: `RunReclaimed`
(the #94 fence — a reclaimed run must unwind, not absorb the signal into a failure
count) and cancellation.

**The threshold.** The run fails only when failures exceed
`max(SWEEP_FAILURE_MAX_ABSOLUTE, SWEEP_FAILURE_MAX_PERCENT% of devices attempted so
far)` — defaults **25** and **1.0**. Both are settings rather than constants on
least-regret grounds: a wrong default is corrected by an operator with one env var, not
by waiting for a release. The absolute floor keeps a small fleet from failing over a
handful of bad devices (1% of 200 is 2); the percentage keeps 25 from reading as an
outage on 40,000. Evaluated against devices *attempted so far* because that is the only
denominator that exists mid-stream — Jamf's totalCount is a floor, not gospel. The
consequence is deliberate: scattered failures across a big fleet stay inside a growing
allowance, while a run where everything fails from the first device is stopped just
past the floor rather than grinding through the whole fleet. At or under the threshold
the run finishes `succeeded` with its failures recorded; over it, the run is `failed`
with the count in its error and processing stops where the threshold was crossed.

**On the row.** `devices_processed` and `devices_failed`, with
`processed + failed = device_count` (attempted). A run can be `succeeded` with
`devices_failed > 0` — that is the point: "39,998 processed, 2 failed" is a healthy
night on a big fleet, and hiding the 2 inside a bare `succeeded` is how evidence rots.
The API returns both; the run panel shows a failed count only when it is non-zero.

**On the wire.** Every device-sweep run that closes — `succeeded` or `failed` — emits
`run.completed` through the outbox, in the same transaction as the status flip, so the
row and the wire cannot drift apart. Always-emitting is the least-regret choice: it
makes absence detection one SPL search (`no run.completed today` = the sweep did not
run to completion) and puts partial failure in the evidence trail, where the silent gap
— this product's worst class of bug — cannot hide. Deliberately *not* emitted for
webhook runs (one device each; a busy tenant would double its event volume for no
signal) or catalog refreshes (an hourly catalog `run.completed` would satisfy the
absence search the nightly sweep was supposed to answer). A *reclaimed* run emits no
`run.completed` either — the reclaim is not a finish, and the absence downstream is the
signal that the sweep died (it does emit `run.failed`; see below). Payload, camelCase
under the casing law above — every key on every family, not just the inventory one:

| Field | Meaning |
| --- | --- |
| `event` | `run.completed` |
| `jobID` | The run — the same name and value `deviceMeta.jobID` carries |
| `connectionID` | Which connection swept |
| `trigger` | `sweep` \| `manual` (webhook runs never emit this event) |
| `comparison` | `baseline` \| `delta` |
| `occurredAt` | The run's window end — the instant the row's `window_end` was stamped |
| `devicesTotal` | Devices attempted (`processed + failed`) |
| `devicesProcessed` | Devices ingested |
| `devicesFailed` | Devices that raised and were isolated |
| `status` | `succeeded` \| `failed` |

**The alarm beside the heartbeat (#103).** The moment any run reaches `failed` — by
finish or by the reclaim — it also emits `run.failed`, in the same transaction as the
status flip. Where `run.completed` is scoped to device sweeps so its *absence* stays
meaningful, `run.failed` fires for every trigger and every lock class: a failed
webhook or catalog run is exactly as silent as a failed sweep, and a failed device
sweep emits both — one answers "did the sweep close", the other pages on why. A
reclaimed run's `run.failed` comes from the reclaim itself; the zombie's late,
refused finish adds nothing, so each failure is one event. Delivery is default-on for
every destination: null/empty subscriptions already mean "all", and the
`a9d4c7e1f3b8` migration appended the type to every pre-existing explicit list — a
destination unsubscribes through its `subscribed_events` the ordinary way. Payload,
camelCase like `run.completed`'s — exactly the ruled fields, no credentials, no log
lines (the run id is the pointer to the full story):

| Field | Meaning |
| --- | --- |
| `event` | `run.failed` |
| `jobID` | The run — joinable against the run log and everything the run produced |
| `connectionID` | Which connection failed |
| `connectionName` | The same connection, readable in an alert without a join |
| `trigger` | `sweep` \| `manual` \| `webhook` |
| `windowStart` | The occurrence the run was serving |
| `windowEnd` | When it died — the instant the row's `window_end` was stamped |
| `error` | The stored run error, truncated to 500 characters |

## 8. What this does not do

- **The concurrency cap** (`ingest-scheduling.md` §4.3) — thirty connections due at 02:00
  are still admitted one at a time only because the tick runs sequentially, not because
  anything bounds it. Belongs to #27's queue.
- **`MdmSyncState` is now a projection**, not a lock. The Connections list still reads its
  `status`, and the sweep still writes it; nothing decides anything from it any more. The
  tick's busy check reads the run table instead. Collapsing it into `runs` is a follow-up.
- **The generic (non-Jamf) provider path** does not open a run. It has no collections and
  no ledger; when a second provider gets either, it gets a run with them.
