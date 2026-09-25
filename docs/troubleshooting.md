# Troubleshooting: the step-throughs

Status: **ruled**, 2026-09-10 ([#290](https://github.com/LoonSecIO/LoonInspect/issues/290)) ·
The language these paths are written in is [`diagnosability.md`](diagnosability.md) ·
Every step below uses only what a fresh operator has: the app, its API,
`docker compose logs`, and the run log. A step that needed source code was not written;
it was filed.

Each path is ordered — *check this; if X, then that* — and ends in a fix or in a **named,
reportable state**. When you reach a reportable state, §8 says what to include.

**What is in here.** The paths run §1–§7 and §10–§19, in the order they were written
rather than in order of likelihood. §0 is what you can read before you start; §8 and §9 are
about the paths rather than about a symptom, and they sit mid-file because that is where
they were written — §9 ends by saying the paths continue at §10.

- **§0** [The four things you can read](#0-the-four-things-you-can-read)
  - [What the page says, and which path answers it](#what-the-page-says-and-which-path-answers-it)
- **§1** ["Test connection is green, and the first run swept zero
  devices"](#1-test-connection-is-green-and-the-first-run-swept-zero-devices)
- **§2** ["A run reports 0 devices"](#2-a-run-reports-0-devices)
- **§3** ["Events are not arriving in Splunk" (or any
  destination)](#3-events-are-not-arriving-in-splunk-or-any-destination)
- **§4** ["It will not start" (or it starts, and every connection is
  unreadable)](#4-it-will-not-start-or-it-starts-and-every-connection-is-unreadable)
- **§5** ["Applications say *not assessed*, or the vulnerability date is
  old"](#5-applications-say-not-assessed-or-the-vulnerability-date-is-old)
- **§6** ["The Jamf Patch table is empty, or it stopped
  refreshing"](#6-the-jamf-patch-table-is-empty-or-it-stopped-refreshing)
- **§7** ["Jamf Pro webhooks are not arriving"](#7-jamf-pro-webhooks-are-not-arriving)
- **§8** [When a path ends in "report"](#8-when-a-path-ends-in-report)
- **§9** [What this document deliberately does not
  contain](#9-what-this-document-deliberately-does-not-contain)
- **§10** ["The update notice never appears, or names a release I do not
  have"](#10-the-update-notice-never-appears-or-names-a-release-i-do-not-have)
- **§11** ["The Prompt bar is missing, or it answers *AI search
  unavailable*"](#11-the-prompt-bar-is-missing-or-it-answers-ai-search-unavailable)
- **§12** ["Every sweep for one connection fails at once, and the run says the stored
  credential has no clientId"](#12-every-sweep-for-one-connection-fails-at-once-and-the-run-says-the-stored-credential-has-no-clientid)
- **§13** ["Settings › AI is missing, or says AI features are
  off"](#13-settings--ai-is-missing-or-says-ai-features-are-off)
- **§14** ["Settings › AI has no Apple Foundation Models
  card"](#14-settings--ai-has-no-apple-foundation-models-card)
- **§15** ["I deleted a smart group and the Changes page says
  nothing"](#15-i-deleted-a-smart-group-and-the-changes-page-says-nothing)
- **§16** ["A Mac I deleted in Jamf is still listed, or a Mac vanished from the
  list"](#16-a-mac-i-deleted-in-jamf-is-still-listed-or-a-mac-vanished-from-the-list)
- **§17** ["The evidence report is empty, or every row says it was not
  reported"](#17-the-evidence-report-is-empty-or-every-row-says-it-was-not-reported)
- **§18** ["Posture is not in my sidebar, or Vulnerabilities lists
  nothing"](#18-posture-is-not-in-my-sidebar-or-vulnerabilities-lists-nothing)

- **§19** [Device-page update from Jamf](#19-device-page-update-from-jamf)

**The reportable states**, lettered in the order they were written, so they do not run in
section order and never will — code, tests and the README cite them where they are. When a
ticket names one, this says which path it came off.

| State | Path | What it names |
| --- | --- | --- |
| **A** | §1 | A device sweep failed with an error that is not 401 or 403 |
| **B** | §1 | A sweep succeeded with zero devices while Jamf lists computers |
| **C** | §2 | Webhook runs for inventory events process zero devices |
| **D** | §3 | Deliveries stay pending across several ticks with no failures |
| **E** | §3 | Everything reports healthy and the destination shows nothing |
| **F** | §4 | Startup migration failed |
| **G** | §4 | Something is still unreadable after the key and its key id are ruled out |
| **H** | §5 | A corpus arrived, the tier is not `off`, and the pages do not answer from it |
| **I** | §5 | The published corpus is refused, unreachable, or unchanging |
| **J** | §6 | A refresh reporting no error leaves the Jamf Patch table empty |
| **K** | §0 | Occasional `502`s from the proxy in front while the app is healthy |
| **L** | §7 | Jamf Pro's callbacks never produce a request line |
| **M** | §5 | The exchange reads `failed` for a reason on the collector's side |
| **N** | §10 | The update notice names a release this build does contain |
| **O** | §11 | The Prompt bar reads *shown* and stays missing after a reload |
| **P** | §12 | A connection's row says nothing while every one of its runs fails |
| **Q** | §13 | **AI features** reads **On** and Settings › AI still refuses |
| **R** | §14 | *Where this container runs* names a runtime the machine is not |
| **S** | §15 | A collapse line for an object that still exists in Jamf |
| **T** | §16 | A finished device sweep whose log has no *device census* line |
| **U** | §17 | The baseline rule catalogue will not load, or a sum does not close |
| **V** | §18 | *being judged against it* more than an hour after the corpus date moved |
| **W** | §18 | *Longest exposed* is empty while *Most exposed* lists builds |

## 0. The four things you can read

**The app.** Settings › Connections shows every connection with its last sync; **Sync
now** opens a panel under the row with the run's log. Settings › Destinations shows every
destination with what is queued, what gave up, and the last error. Settings › Data
Sharing shows the last community exchange, why it failed if it did, and **Send now**,
which runs one immediately. The Overview's status strip is the first line to read: it
says which of those is unwell.

**The API**, when the page is not enough or you want to paste an answer into a ticket.
Sign in once and keep the cookies; every mutation needs the CSRF header:

```bash
BASE=http://localhost:8001            # your instance
curl -s -c jar -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"…"}' $BASE/api/auth/login
CSRF=$(awk '$6=="loon_csrf"{print $7}' jar)
curl -s -b jar $BASE/api/runs?pageSize=5                       # recent runs, newest first
curl -s -b jar $BASE/api/runs/<jobId>                           # one run: status, error, counts
curl -s -b jar $BASE/api/runs/<jobId>/log                       # its log lines
curl -s -b jar $BASE/api/mdm/connections                        # connections
curl -s -b jar $BASE/api/mdm/connections/<id>/collections       # what each connection collects
curl -s -b jar $BASE/api/destinations                           # destinations with delivery counts
curl -s -b jar $BASE/api/posture                                # last night's posture tape
```

**The container log.** `docker compose logs app --since 30m` (add `db` for the
database). This is where the app speaks before there is a run to write to. A scheduled
pass that could not finish says so here and nowhere else: `outbox tick failed`,
`outbox cleanup failed` and `run cleanup failed` each name what was not done, when it is
tried again, and what to check.

**The run log.** One line per milestone: `run started`, `devices processed`,
`group definitions observed`, `run finished`, and warnings such as `throttled by Jamf;
backed off and continued` or `extension attribute definitions not readable; census
skipped`. It is the panel under the connection's row, or `GET /api/runs/{jobId}/log`.

### What the page says, and which path answers it

Most of the time the screen has already named the path. Every sentence below is the page's
own, as `frontend/src/i18n/en.ts` has it, and `backend/tests/test_troubleshooting_index.py`
holds this table to that file — so a reworded page cannot leave the runbook routing by
words nobody sees.

| What the page says | Which path |
| --- | --- |
| *Vulnerability corpus as of …* above the Catalog, with a date | §5 step 5 |
| *Vulnerabilities: not assessed* above the Catalog, with no date | §5 steps 1–2 |
| A row reading *No findings*, *Outside the corpus* or *Not assessed* | §5 |
| *A corpus is loaded and … apps are being judged against it* | §18 step 4 |
| An application record's *Judged* column reading *Not judged yet* | §5 step 3 |
| An evidence row reading *not reported* | §17 |
| Needs Attention saying *Deliveries are failing* | §3 |
| A connection reading *Last sync failed* — 401, 403, or another error | §1 step 2 |
| *AI search unavailable — the filters below still work.* | §11 step 2 |
| *No Jamf Patch titles synced yet.* | §6 |
| *… is available, and this build does not contain it.* — the update notice | §10 |

### The front page is not the same for every role

`/` tells one of two stories ([#115](https://github.com/LoonSecIO/LoonInspect/issues/115)).
An account holding `destination:read` — analyst, auditor, admin — gets the pipeline:
stepper, running sweep, status strip, Needs Attention. A Viewer holds inventory read only
and gets the inventory board instead: fleet size, the hygiene counts, the catalog, the
most-installed apps. Two people on one pod seeing different tiles is the design.

Every tile on that board carries `as of <UTC> (<age>)` and the age climbs while the page
stays open: an age in hours means the browser stopped getting answers — reload, then §4.
That stamp dates the browser's read, not the pod's inventory: it says *just now* even on a
pod whose Jamf sync died last week. Freshness per connection is an administrator's page.
One tile reading **Could not load** means that source refused while the others answered;
`GET /api/devices?pageSize=1`, `/api/catalog?pageSize=1` and `/api/applications?pageSize=5`
say which, and with what status. A board saying your role cannot read devices or
applications is not an empty fleet: an administrator grants `device:read` and `app:read`.

### A proxy in front answers for itself

With a reverse proxy or load balancer in front, not every error the browser shows is the
app's. The app writes a `request` line in the container log for each request it answers
(a healthy `/api/health` aside); a blank `502` that left no such line never reached it.

1. **Is the app well?** `curl -s $BASE/api/health` is `{"status":"ok"}` and the request
   that failed works when you try it again → step 2. Health failing too is not this
   occasional case; start at §4.
2. **Compare two timeouts.** The app's keep-alive is on the line it writes as it starts:
   `docker compose logs app | grep binding` → `keep_alive_timeout_seconds` (5 unless
   `KEEP_ALIVE_TIMEOUT_SECONDS` is set). The proxy's idle timeout is in its own
   settings: an AWS ALB's is 60 seconds unless changed. The app's must be the larger:
   the proxy reuses a connection to the app for up to its idle timeout, and a request it
   sends down one the app already closed comes back as a `502`. Set
   `KEEP_ALIVE_TIMEOUT_SECONDS` above the proxy's (a 130-second ALB takes 135),
   `docker compose up -d`, and the `binding` line shows the new value.
3. The keep-alive is above the proxy's idle timeout and the `502`s go on → reportable **K**.

**K.** Occasional `502`s from the proxy in front while the app is healthy and its
keep-alive is above the proxy's idle timeout. Report the `binding` line, the proxy's
idle timeout, the times and requests that failed, and the proxy's own count of the `502`s
it generated in that window (an ALB's `HTTPCode_ELB_502_Count`).

## 1. "Test connection is green, and the first run swept zero devices"

The top failure, and by design: **Test connection performs only the OAuth sign-in**, which
needs no privilege, so an API Role with every box unticked passes the test and then
sweeps nothing ([README §3](../README.md)).

1. **Find the run you mean.** `GET /api/runs?connectionId=<id>&pageSize=5`, or the panel
   after Sync now. Look at `lockClass` on the run:
   - `catalog` → this run never reads devices; `0 devices` is expected. Go to §2, step 1.
   - `webhook` → one device per Jamf event; go to §2, step 1.
   - `device_sweep` → continue.
2. **Read `status` and `error` on the run.**
   - `failed`, and the error mentions **401** → the Client ID or Client Secret is wrong or
     was rotated in Jamf. Settings › Connections › Edit, re-enter the secret, Sync now.
   - `failed`, and the error mentions **403** → the API Role lacks **Read Computers**.
     Step 3.
   - `failed` with another error → reportable state **A**.
   - `succeeded` with `deviceCount: 0` → step 3.
3. **The API Role.** In Jamf Pro: Settings → System → API roles and clients → the role
   your client is assigned to. It must hold `Read Computers`; hold the rest of the table
   in [README §3](../README.md) too, each of which the run log names when it is missing.
   Save, then Sync now. Still zero → step 4.
4. **The collection's selector.** `GET /api/mdm/connections/<id>/collections`: the
   `device_sweep` collection's `selector`. A selector is a Jamf filter, and one that matches
   nothing sweeps nothing. Clear it (Settings › Connections › the collection › Edit) and
   Run now. Still zero → step 5.
5. **Jamf itself.** In Jamf Pro, Computers → Search Inventory: are there computers?
   LoonInspect collects computers only ([`mobile-devices.md`](mobile-devices.md)); a tenant
   of iPads sweeps zero Macs, correctly. If Jamf lists computers and the sweep still
   reports none → reportable state **B**.
6. **Whenever a step above says Run now, and the answer is *already running*.** The
   collection list says it in words with a job id, and the answer carries `started: false`
   with that `jobId`. It is not a refusal and not a queue: a run of that kind was already
   in flight on this connection, so the click joined it rather than starting a second pull
   against the same Jamf server, and nothing is waiting behind it. Read the job it names —
   `GET /api/runs/<jobId>`, its lines at `/log`, and **Recent runs** on the front page is
   showing the same one. The zero you are chasing may be that run's, and it began before
   the change you just made; wait for it to finish and Run now again.
   If a manually triggered connection sync or re-emit fails, its run closes as `failed`
   with the original error and releases the lock immediately. Read that error, correct
   the cause, and retry; there is no heartbeat-staleness wait for a handled failure.

**A.** A device sweep failed with an error that is not 401 or 403. Report the run's
`jobID`, its `error`, and the panel's lines.
**B.** A device sweep succeeded with zero devices although the role holds `Read
Computers`, the selector is empty, and Jamf lists computers. Report the `jobID` and the
run log.

## 2. "A run reports 0 devices"

One symptom, three unrelated causes, and only one of them is a problem.

1. **Which kind of run?** `GET /api/runs/<jobId>` → `lockClass`; or the collection's
   `kind` in `GET /api/mdm/connections/<id>/collections`.
   - **`catalog`** — a catalog refresh reads smart-group definitions and
     extension-attribute definitions. It never reads devices. **This is not a bug.** The
     number that matters is on the log line `group definitions observed` (`groupCount`);
     zero *there* means Jamf has no smart groups or the role lacks `Read Smart Computer
     Groups`, which the same line says. Done.
   - **`webhook`** — one run per Jamf event, and a run for an event LoonInspect does not
     act on processes nothing. `ComputerCheckIn` is deliberately not acted on
     ([`ingest-scheduling.md`](ingest-scheduling.md)): a check-in is not an inventory. If
     the events you send are `ComputerAdded` / `ComputerInventoryCompleted` and runs still
     report zero → reportable state **C**.
   - **`device_sweep`** → step 2.
2. **The selector** → §1 step 4.
3. **The privileges** → §1 step 3.
4. Still zero → §1 reportable state **B**.
5. **The evidence report refuses with *this connection has no observations*.** Same root, asked
   a different way: `GET /api/evidence/report` reads the observation ledger, which only a
   `device_sweep` writes — a connection that has only ever run `catalog` or unacted webhook runs
   has no ledger to report on. Run a device sweep (Connections → **Run now**), then ask again;
   if the sweep itself reports zero, you are at step 1 above, not here. A window with no
   observations *in it* is answered rather than refused, as not-observed days by device —
   see [`compliance-evidence.md`](compliance-evidence.md) §5.

**C.** Webhook runs for inventory events process zero devices. Report the `jobID`, the
event type Jamf sent (the webhook's own configuration), and the run log.

## 3. "Events are not arriving in Splunk" (or any destination)

Work from the app outward: was anything produced, was it queued, was it delivered, and
did Splunk keep it.

`GET /api/outbox` (`destination:read`) answers the middle of that in one read, in the
three states an event can be in — **held** (produced, considered against no enabled
destination, holding no delivery row at all), **pending** (a delivery still inside the
retry envelope) and **dead-lettered** (a delivery that spent its ten attempts and waits
for a redrive) — plus the two retention windows and the next purge, so each state's
deadline is readable without the source. Ages are `null` when a set is empty, never `0`.
Settings › Destinations reads it for the two sentences above the list and says plainly when
that read fails, so a missing sentence there is never a silent zero.

**The three ways this goes quiet, and the one read that separates them.** None of them
fails and none of them writes a log line. The first two leave no delivery row at all, so no
destination row counts them; the third leaves rows that are counted and never attempted, so
its destination's row reads `N queued` and climbing while nothing moves.

- **No enabled destination.** The event is produced and held, considered against nothing:
  `held.events` with `held.reason: no_enabled_destination` (step 2).
- **The type is not subscribed.** A destination is enabled and its `subscribedEvents` omits
  the type, so fan-out considers the event, writes no delivery and marks it done. It is in
  **none** of the three states — a run that produced events with an empty queue behind it
  is this, not a drain (step 5).
- **The destination was disabled after its events fanned out.** The deliveries exist and
  stay pending with nothing attempting them, so `pending.oldestAgeSeconds` climbs and the
  disabled destination's own row goes on counting them — the delivery counts are not
  filtered by `enabled` — with no line in either log (step 4).

`GET /api/outbox` is the read that tells them apart, and Settings › Destinations says the
same in sentences — including when the read itself fails: *Could not read the queue depth —
the held and dead-letter counts are missing, not zero. Reload, or call GET /api/outbox
directly.*

1. **Was anything produced?** `GET /api/runs?pageSize=5`: a `device_sweep` run with
   `status: succeeded` and `deviceCount` above zero. None → this is §1 or §2, not a
   delivery problem.
2. **Is there an enabled destination?** Settings › Destinations, or
   `GET /api/destinations` → `enabled: true`. A stack with no enabled destination holds
   its events and delivers nothing — the setup stepper calls the destination step
   optional, and holding is the ruled behaviour ([`splunk-setup.md`](splunk-setup.md)).
   `GET /api/outbox` says how many and for how long: `held.events` with
   `held.reason: no_enabled_destination`, and `held.oldestAgeSeconds` against
   `retention.eventRetentionDays` is what is left before the oldest is purged and that
   part of the baseline is gone for good — Settings › Destinations prints it as a
   sentence. Add or enable a destination; fan-out considers at most a thousand events a
   tick, so a large backlog drains over several minutes — `held.events` falling while
   `held.reason` is `null` is that drain, not a second fault.
3. **Test it.** The Test button, or `POST /api/destinations/<id>/test`.

   **The words it answers in, whichever bullet below you land on.** Every sentence here is
   the product's own. A delivery that succeeded is worded two ways, and which one you are
   holding says where it came from: the page says
   *Delivered — the destination accepted a test event.*, the API's `detail` says
   *Delivered. The destination accepted a test event.* A refusal reads
   *Test delivery refused: `<detail>`*, where a destination that gave no detail leaves
   *Delivery failed with no detail from the destination.*; a request that came back with no
   status reads *No HTTP status — the request failed before the destination answered.*; and
   one that never left reads *Could not run the test. The app could not reach the
   destination at all.*

   Then read `statusCode` and the error:
   - connection refused, timeout, name not resolved → the URL, the port, a firewall, or a
     TLS certificate the container does not trust. `https://` with a private CA needs the
     CA in the container ([`splunk-setup.md`](splunk-setup.md) §5). Fix, test again.
   - **plain `http://`, with no status code** → Edit the destination and choose HTTPS,
     or **Allow HTTP (lab only)** under Transport security for a trusted lab SIEM. The
     orange URL field's info button explains that credentials and events are unencrypted.
     **Use deployment default (legacy)** still reads `ALLOW_INSECURE_DESTINATION_URL`
     on each delivering container; an explicit choice avoids differences between workers.
     Test again after saving. Refused attempts can dead-letter; **Redrive** (step 4)
     returns them after the fix.
   - **host is not in `DESTINATION_ALLOWED_HOSTS`** → the deployment administrator must
     add the exact hostname or IP to that JSON array and recreate every delivering
     container. No scheme, port, path, or wildcard belongs in an entry. `*.internal`,
     `localhost`, `127.0.0.1`, and `::1` are built-in exceptions. A list entry permits
     loopback resolution but never link-local metadata addresses. See
     [`splunk-setup.md`](splunk-setup.md) §3 for the configuration example.
   - **`host.docker.internal` fails** → read the reason before changing its name. An HTTP
     refusal needs Allow HTTP; a connection refusal needs the receiver's listening port
     and Docker host reachability checked. A blocked resolved address needs DNS checked.
     `localhost` inside Docker is the app container, not the host SIEM. Link-local
     addresses remain blocked even for internal names.
   - **401 / 403** → the token or auth header is wrong. Edit the destination, re-enter the
     secret, test again.
   - **400 from HEC** → usually the token's index (step 5) or the URL's path
     (`/services/collector/event`, [`splunk-setup.md`](splunk-setup.md) §3).
   - **200** → step 4.
4. **Delivery health.** The destination row: `pendingCount`, `failedCount`, `failed24h`,
   `deadLetterOldestExpiresAt`, `lastError`.
   - `failedCount` above zero → those deliveries gave up after ten attempts; `lastError`
     is why. Fix the cause (step 3), then **Redrive** returns them to the queue. Events
     that arrived after the fix flow on their own.
   - **The ladder, stated once.** A failed delivery waits 30 s × 2ⁿ before the next
     attempt, capped at an hour, and gives up after ten: **≈ 4 h 03 m** from the first
     failure to the dead letter. A destination refusing everything therefore shows *queued*
     climbing for four hours before *gave up* moves at all, and a queue older than that with
     nothing dead-lettered is not backing off — nothing is attempting it, which is the
     bullet below.
   - **How long is left, and whether it is failing now.** `deadLetterOldestExpiresAt` is
     the instant the oldest of those dead letters is purged with its event — after it, a
     redrive cannot reach that one and the gap it left in the trail is permanent. Settings ›
     Destinations prints it beside the count, the Redrive confirmation says it again before
     you confirm, and `retention.nextPurgeAt` from `GET /api/outbox` is when the purge that
     enforces it runs; `null` is "nothing is dead-lettered here", never a deadline that has
     passed. `failedCount` is the lifetime count and a redrive zeroes it, so read `failed24h`
     beside it — the same rows inside the trailing 24 hours, the window `outbox.failed_24h`
     counts fleet-wide. A high `failedCount` with `failed24h: 0` is an outage already over,
     and its dead letters are still worth redriving before the deadline.
   - `pendingCount` climbing and nothing delivered → **ask first whether the queue is
     moving at all**, without a shell: read `pending.oldestAgeSeconds` from
     `GET /api/outbox` twice, a minute apart. **Falling** means the queue is draining and
     only its head is old; `pendingCount` can climb at the same time, because new events
     keep arriving, which is why the age is the sharper measure. **Rising by about the
     seconds between the reads** means nothing left it — nothing was attempted. Only then
     is a log worth reading, and two lines say which of the two reasons it is. The first is
     a fault: `docker compose logs app --since 10m | grep "outbox tick failed"` — the tick
     gave up before it dialled, and the line names what to check, usually a destination
     whose URL it refuses or whose stored secret this container cannot read (§4). Fix that,
     and the next tick drains the queue. **Before reporting anything, rule the scheduler
     out**: a container started with `SCHEDULER_ENABLED=false` is web-only — it serves the
     pages and the API and runs no ticks at all, so nothing is ever attempted and neither
     line is ever written. `docker compose logs app | grep "scheduler started"` prints one
     line per process that runs them, and no line at all is the answer, a setting rather
     than a fault ([`operations.md` §7](operations.md#7-more-than-one-app-process)). The
     second reason is the next bullet. Still rising with neither line → reportable **D**,
     once step 2's rows are *all* enabled: the age is tenant-wide, and a destination
     disabled after its events fanned out holds them pending until it is enabled again,
     pinning the age with no line in either log.
     `deadLettered.oldestExpiresAt` is the instant the oldest dead letter stops being
     redrivable, and `retention.nextPurgeAt` is when the purge that takes it runs.
   - **More than one app process, and the queue is not draining.** The second reason a
     tick attempts nothing, and usually not a fault at all.
     `docker compose logs app --since 10m | grep "outbox tick skipped"`. That line means
     the process printing it found another one already delivering for that organization
     and did nothing, which is correct: one process delivers at a time and the rest say
     so every tick ([`operations.md` §7](operations.md#7-more-than-one-app-process)). It is
     only a problem when *every* process prints it and the queue is still not moving —
     `pendingCount` climbing and `pending.oldestAgeSeconds` rising with it. Then the process
     holding the lock is wedged rather than working. Restart the stack: the lock goes with
     its connection, and the next tick takes it.
   - **How long has it been held?** The nightly tape is the only history of the held set:
     `GET /api/posture?keys=outbox.pending,outbox.failed_24h,outbox.oldest_pending_age_s&days=7`
     is one row per key per night it was captured. `outbox.oldest_pending_age_s` **missing
     from a night that carries the other two** is that night's empty queue — absence is
     never zero here — and `total: 0` means no full sweep closed in the window, so the tape
     has nothing to say about those nights (§1, §2) rather than saying the queue was empty.
     `GET /api/posture/registry` is what each key counts.
   - Both zero and the runs in step 1 succeeded → step 5.
5. **Subscriptions.** `subscribedEvents` on the destination: `null` means every event
   type; a list means only those. A list without `device.inventory` gets no snapshots,
   without `device.change` no change events, and a list of none gets nothing at all,
   silently. Set it to what you expect, or clear it.
   - **No departure events, and a smart group really was deleted.** These are their own
     types, `subject.departure` and `subject.returned`, under the sourcetype
     `loon:departure`, and nothing else carries them: a search for `loon:jamf:mac:*` will
     never show one. Migration `bd51c7a9e402` added **both** to every explicit list, so a
     list holding one and not the other was edited by hand — put the other back, because
     departures without returns describe a fleet that only ever shrinks. Then confirm the
     census actually departed something: the catalog run's log line is *departures
     reconciled* with `departed`, `returned` and `eventsEnqueued`. `departed 0` is path 15,
     not a delivery problem; `departed 1, eventsEnqueued 0` is reportable **E**.
6. **The index.** LoonInspect never sends an `index` field. The HEC token must have exactly
   one allowed index and it must be the default ([`splunk-setup.md`](splunk-setup.md)
   §2); a token with no default index does not put the events where you are looking.
   Then search the cheapest event first: `index=<yours> sourcetype=loon:run` finds every
   `run.completed`; `sourcetype=loon:jamf:mac:app` finds the app sub-events.
7. Runs succeed, the test is 200, nothing failed or pending, the subscription includes
   the type, the index is right, and the search is empty → reportable **E**.

**D.** Deliveries stay pending across several ticks with no failures. Report the
destination `id` and **both** `GET /api/outbox` bodies from step 4's two reads — the three
numbers that describe the queue are `held.events`, `pending.deliveries` and
`pending.oldestAgeSeconds`, and the pair is what says nothing is being attempted at all.
**E.** Everything reports healthy and Splunk shows nothing. Report the destination `id`,
the run `jobID`, the token's index settings, and the search you ran.

## 4. "It will not start" (or it starts, and every connection is unreadable)

1. **Which container?** `docker compose ps`.
   - `docker compose up` refused with `set POSTGRES_PASSWORD in .env` (or
     `POSTGRES_APP_PASSWORD`, or `ENCRYPTION_KEY`) → the `.env` beside
     `docker-compose.yml` lacks one of the three required values. Set it
     (`backend/.env.example` names all three), `docker compose up -d`.
   - `db` not healthy → `docker compose logs db`; a full volume says so only there
     ([`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) §3).
   - `app` restarting or unhealthy with `db` healthy → step 2.
2. **The app's log.** `docker compose logs app --tail 100`:
   - `password authentication failed for user "looninspect_app"` → `POSTGRES_APP_PASSWORD`
     in `.env` is not the one the database was created with; the database keeps the
     first. Put the original back ([`operations.md`](operations.md) §3 shows the role the
     database created, and its password is the one that value held then).
   - waiting for the database, repeatedly → `db` is not answering; step 1.
   - `1 validation error for Settings` (or `2 validation errors`, and so on) → a variable
     in the environment was refused. The next line names it in lower case
     (`keep_alive_timeout_seconds` is `KEEP_ALIVE_TIMEOUT_SECONDS`) and the one after says
     what it accepts and why. Correct it where it is set — for the shipped stack, the
     `.env` beside `docker-compose.yml` — then `docker compose up -d`.
   - upgrading through `e621c4a8b903` and startup takes longer → this migration builds
     the installed-app tenant/device index before removing the older tenant-only index.
     It blocks writes during the transactional build, even with the vulnerability
     preview off. Schedule a maintenance window and allow space for both indexes during
     replacement. Check `docker compose logs db` for storage errors or lock waits; let
     the build finish rather than repeatedly restarting it. If it fails, keep the logs
     and follow the migration-failure step below; do not remove indexes by hand.
   - an Alembic error → the migration on startup failed. Do not downgrade by hand
     ([`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) §6); reportable **F**.
3. **Healthy, signed in, and Settings › Connections says it could not load.**
   `curl $BASE/api/health` is `{"status":"ok"}`, sign-in works, and
   `GET /api/mdm/connections` answers **503** with the sentence *Stored credentials cannot
   be read: the ENCRYPTION_KEY in the environment is not the one this database was written
   under…*, the Connections and Destinations pages show that sentence, and
   `docker compose logs app` carries it once, with no traceback (#374; a build before it
   showed a `500` and a traceback ending in `ENCRYPTION_KEY may have changed`). The key in
   `.env` is not the one this database's credentials were written under — the shape of every restore that brought
   the dump and not the key ([`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) §5). **This is the
   fix:** put the original key back from your secret store ([`operations.md`](operations.md)
   §1 has the one-liner that verifies a dump-and-key pair), then `docker compose up -d`.
   **Did you just put an *older* image back?** Then read
   [`operations.md`](operations.md) §5 before you touch a secret: credentials written by
   the newer build carry a key id (`k1:`) that an image older than #480 cannot read, and
   it reports that as this same wrong-key sentence on an instance whose key is fine. The
   fix there is to go forward, not to re-enter anything.
   If the original key really is gone, the stored credentials are gone with it: delete each
   connection and destination and create it again with its secret. Account passwords
   survive; they are hashed, not encrypted. Only if the original key is back and the 500
   persists → reportable **G**.
4. **The same 503, but the sentence names a *key id*.** `GET /api/mdm/connections` answers
   **503** with *Stored credentials cannot be read: this value carries key id `k2`, which
   this build does not know…* — not the `ENCRYPTION_KEY` sentence in step 3. **The key is
   not the problem, so do not go looking for it.** Every stored secret says which key
   wrote it (`k1` is the only one this build knows), and this row was written by a newer
   build: the running image is older than the database, the shape of a rollback that
   swapped the image back ([`operations.md`](operations.md) §5). **This is the fix:** roll
   forward to the newer image, or restore the dump taken before the upgrade. Rolled
   forward and the sentence persists → reportable **G**.
5. Healthy and signed in, and something else is unreadable → reportable **G**.

**F.** Startup migration failed. Report `docker compose logs app --tail 200` and the
build (Settings › Support shows it).
**G.** Report the request that fails, its status, and the matching lines from
`docker compose logs app`.

## 5. "Applications say *not assessed*, or the vulnerability date is old"

The Vulnerabilities column on Devices › Applications › **Catalog**, and the banner above
it, answer this before any command does. There are three states and they mean different
things ([`vulnerabilities.md`](vulnerabilities.md) §4g): **no findings** (green — this
exact build was checked), **outside the corpus** (amber — this build was not checked), and
**not assessed** (grey — nothing is answering for your organization). The banner carries
the date the library was generated; grey has no date, because there is nothing to date.

**Grey has two causes, and the page cannot tell you which.** Either this container holds
no vulnerability library at all, or it holds one and your organization's data sharing is
**off** — the library is one artifact for the whole container and consent is per
organization, so a container can hold a library that does not answer for you
([`vulnerabilities.md`](vulnerabilities.md) §8). That is not a multi-tenant curiosity: it
is what a single-organization instance reads the moment sharing is turned off after a
library has arrived. The two checks are *what is this organization's tier* (step 1, a
page) and *is a library installed* (step 2, a banner and then a log line), in that order —
the tier is the cheaper question and the more common answer. A library that has never
arrived at all is the ordinary reading before the production cutover rather than a fault,
and step 2 ends with how to tell that apart from a broken exchange.

1. **Grey, on every app — check the tier first.** Data sharing is what earns the library,
   in both directions: it arrives on the daily exchange, and it answers only for an
   organization whose own sharing is on ([`vulnerabilities.md`](vulnerabilities.md) §8).
   Settings › Data Sharing: if the tier is **off**, that is the answer. Turn it on. If a
   library is already installed, the answers come back immediately with no new download;
   if none is, one arrives with the next exchange — the daily one is jittered per tenant,
   so it is not immediate, and an administrator can press **Send now** under *Exactly what
   would be sent* to run it at once. If this instance has more than one tenant, check the
   tier for **the tenant you are looking at** — one tenant with sharing off reads grey
   while another on the same container reads dates and answers. If
   `COMMUNITY_SHARING=false` is set, the page says so and names the file; the override
   wins until it is removed.
2. **The tier is on and it is still grey — is a library installed?** The page answers
   that before any log does: with the tier on, the banner above the Vulnerabilities
   column carries the corpus date when a library is installed and says it has none when
   there is none, and `GET /api/catalog` carries the same fact as `corpusAsOf` beside the
   rows it describes. The log says *why*. Read the lines the loader and startup write:
   `docker compose logs app --since 48h | grep -i "vulnerability library"`. Two of them
   are written at startup and nowhere else, so drop `--since 48h` if the container has
   been up longer than that.
   - `vulnerability library updated: epoch 0002, generated …` → a library *is* loaded, so
     with the tier on in step 1 this page should be answering; grey is then stale browser
     state, so reload. If the page still says nothing is answering, that is reportable
     state **H**.
   - `vulnerability library not updated: the corpus download did not complete …` → this
     container could not reach the published corpus. The line names the host it dialled.
     Check outbound access to that host from the container itself
     (`docker compose exec app curl -sSI https://<host>/`); a proxy, an egress firewall or
     a TLS interception middlebox is the usual cause. Nothing is broken in the meantime —
     the previous library keeps answering and the next exchange tries again.
   - `vulnerability library not updated: … does not match the digest its manifest states`
     or `… is not the one the exchange pointed at` → the download did not survive the trip
     or the published epoch is corrupt. **This is refused on purpose:** nothing was
     imported, the library still answers from the epoch it had, and a wrong answer is
     never preferred to a stale one. If the same line repeats for more than a day, that is
     reportable state **I** — the corrupt epoch is ours to fix, not yours.
   - `vulnerability library not updated: the exchange named a corpus link this container
     refuses …` → the link was not `https`, or named a host this container will not dial
     (loopback, link-local). Reportable state **I**.
   - `vulnerability library not updated: the exchange named a corpus with no signature`
     (or `… no link to download it from`, `… whose signature is not a sha256 digest`, or
     `… is a str and the format states an object`) → the exchange answered with a corpus
     pointer this container could not use, so nothing was downloaded. Nothing is broken
     here either; it is reportable state **I**, and the line names which half was missing.
   - `… matches the digest its manifest states but is not UTF-8 text` → the published
     object arrived intact and is not the text the format states. Refused for the same
     reason a digest mismatch is: reportable state **I**.
   - `vulnerability library updated: … ; 1 object(s) this container does not read were
     passed over (verdicts.jsonl.gz) …` → **not a fault.** The published corpus grew an
     object this build is too old to read, and the rest of the epoch imported normally.
     The format grows additively by design; upgrading the image is what starts reading it,
     and nothing is wrong until you want what that object carries.
   - `the corpus is published as format 'epoch/2' and this container reads 'epoch/1';
     update the container` → exactly what it says: the published format moved ahead of
     this build. Settings › Support shows the build; upgrade the image.
   - `vulnerability library could not be stored; this process keeps its previously loaded answer`
     → the database rejected the import transaction. Check `docker compose logs db`,
     database availability and available volume space, then use Settings → Data Sharing →
     **Send now** to retry. The exchange log may say sent: that proves the upload succeeded,
     not that corpus storage did. If testing `VULN_RELEASE_RETENTION=true` (#621), retained
     releases also consume space and do not yet prune. Leave that development setting off
     in production; turning it off stops accumulation but does not reclaim retained rows.
     Do not delete the active library or evidence to make an update appear successful.
   - `the stored vulnerability library could not be read (epoch 0002): …` → this
     container holds an epoch it can no longer read. **It is written once, at startup, and
     never again** — `--since 48h` will not find it on a container that has been up
     longer, so search the whole log
     (`docker compose logs app | grep -i "stored vulnerability library"`) before
     concluding there is no line. It means the stored rows moved after they were imported
     and verified: a database restored from a different build, or a row edited by hand.
     Every app reads *not assessed* until an epoch with a different signature is published
     and imported, which is the next day the published corpus moves; restoring a matching
     backup is the fix if you have one. If a restart writes it again after a day of
     succeeding exchanges, that is reportable state **H**, and include it — it names the
     epoch.
   - `vulnerability library loaded {"epoch_id": "0002", "corpus_as_of": "2026-09-11", …}`
     → the line startup writes when this container read back the epoch it already held.
     Not an exchange and not an import: it names which epoch is answering and how old it
     is, and on a container that downloads nothing it is the only library line there is.
     With the tier on in step 1, this page should be answering.
   - **no line at all** → three different silences, and the banner in this step's first
     sentence tells them apart. A library *is* installed and this is the ordinary day: an
     exchange whose signature has not moved downloads nothing and says nothing at the
     default log level; a restart is the exception, and writes the `loaded` line above.
     Or no library is installed, and then either no exchange has completed since the
     container started — Settings › Data Sharing shows the last exchange and its outcome,
     and `failed` there is an exchange problem rather than a corpus one, with its reason
     printed beneath it (step 6) — or the exchanges are succeeding and naming no corpus
     at all, which is the paragraph below.

   **Succeeding exchanges, no library, and nothing wrong.** An exchange that answers
   without naming a corpus is silent by design, so this state is grey with no log line to
   explain it. There is nothing to fix in the container. One state looks exactly like this
   and is not it — an epoch this container holds and cannot read — so search the whole log
   for `the stored vulnerability library could not be read` before you read this paragraph
   as your answer. The published corpus reaches staging first, and **a customer's first
   epoch arrives with the production cutover**; until then an instance pointed at
   production reads *not assessed* for every app with the tier on, and that is the expected
   reading rather than reportable state **H** — its exchanges read `failed` with a `403`
   until the cutover, which is step 6's first row. Settings › Data Sharing is what
   separates this from a broken exchange: rows reading `sent`, day after day, with no
   library line beside them.
3. **A date is on the banner, and every app under it says *outside the corpus*.** Not the
   same fault as grey, and usually not a fault at all. The container stores each build's
   answer beside the build and re-judges when a new corpus arrives: the exchange that
   imports a corpus runs that pass for every organization on the box before it returns
   (#554), so on the ordinary day the pass is seconds behind the corpus line in step 2.
   `docker compose logs app | grep "re-judged after import"` shows it — one
   `vulnerability answers re-judged after import` line per organization, carrying `builds`
   and `apps`. In those seconds, and for as long as that line is missing, apps read
   **outside the corpus** rather than keeping yesterday's numbers under today's date. That
   is deliberate: a count from one corpus shown under another's date is a wrong answer that
   looks right, and this one corrects itself. A line reading
   `vulnerability answers NOT re-judged after import` names an organization whose pass
   failed, with the reason after it; that organization clears within the hour (the
   patch-catalog job re-judges every organization hourly), and sooner for a Mac that checks
   in — that Mac. A build one
   Mac's check-in judged does not answer on the others until the hourly pass copies it
   across, which that pass does every run. Two ways to stop waiting:
   - `docker compose logs app --since 2h | grep "vulnerability answers refreshed"` — the
     line the pass writes, carrying `builds` (how many it re-judged) and `apps` (how many
     app rows it copied onto). A line since the corpus line in step 2 means both halves have
     run, and amber on a build is then that build's real answer: the corpus did not assess
     it. `builds=0` with a non-zero `apps` is the normal repair line — a check-in judged the
     builds first and this pass carried the answer to the rest of the fleet. **No line at
     all** is not proof the pass did not run — it writes nothing when nothing moved, which
     is the ordinary hour. Do not wait on it: use *Refresh* below, which runs the same pass
     now, and judge by what the page says afterwards;
   - Devices › Applications › **Catalog** › *Refresh* re-judges this organization now.
   If an hour has passed, the log shows the pass running, and the same builds still read
   amber, that is reportable state **H**.
4. **One app, and only that one, says *outside the corpus* after every refresh.** Look for
   `the stored vulnerability answer for v1:… could not be read` in the app's log. That line
   means this container declined to trust a stored answer it could not parse — the row was
   written by a copy out of a corpus the container had already verified, so seeing it means
   the stored row changed underneath the container (a restored backup from a different
   build, a hand-edited row). The app reads **outside the corpus** until the next judge pass
   rewrites it, which the *Refresh* button above does immediately. If it comes back after a
   refresh, that is reportable state **H**, and include the line — it names the build key.
5. **The date on the banner is old.** The container **reports** the corpus generation
   date; it does not judge it. There is no staleness threshold to fail — the published
   format does not set a cadence, so any number this container invented would be a
   guess — and the date is shown precisely so the decision is the operator's. What it
   means: everything green was checked *as of that date*, and a finding published since is
   not in the answer yet. If the date has not moved for several days while the exchange is
   succeeding, step 2's log lines say why; if they say `updated` with an unmoved date, the
   published corpus itself has not moved, which is reportable state **I**.
6. **Settings › Data Sharing says the last exchange *failed*.** The reason is printed
   beneath *Last exchange*. It names the host the container dialled — `api.loonsec.io`
   unless a hosted pod's template set `SHARING_ENDPOINT` — and ends with how many times
   the run tried. **Send now**, in the same page's *Exactly what would be sent* box, runs
   an exchange on demand and shows the row it wrote, so each check below can be proved
   fixed in a click instead of a day. To see who answers at that address from inside the
   container — it sends `{}`, nothing of the fleet:

   ```bash
   docker compose exec app python -c 'import sys, urllib.request as u, urllib.error as e
   try: print(u.urlopen(u.Request(sys.argv[1], b"{}", {"Content-Type": "application/json"}), timeout=10).status)
   except e.HTTPError as x: print(x.code, x.read().decode()[:200])' https://api.loonsec.io/v1/exchange
   ```

   The collector answers that with `400 {"error": "unsupported contract"}`; any other
   answer is not the collector. The address at the end of the command is the default: a
   pod whose template set `SHARING_ENDPOINT` probes that value instead, whole — the
   container posts to it exactly as set and adds no path.
   - `The collector at api.loonsec.io answered 403 Forbidden: {"message":"Missing
     Authentication Token"}` → nothing at that address takes exchanges yet. Until
     LoonSec's production cutover this is what every instance on the default endpoint
     reads, and it is expected: nothing is lost, because each day's snapshot replaces the
     last in full, and the first exchange after the cutover reads `sent`. After the
     cutover the same line is reportable state **M**. From any other host, a `403` or
     `404` means there is no collector at that path: check the pod's `SHARING_ENDPOINT`.
   - `Could not connect to <host>: …` → the container could not reach the host at all,
     and the text after the colon says how. `Name or service not known` is DNS — `docker
     compose exec app getent hosts <host>` prints nothing when the container cannot
     resolve it. `Connection refused` is nothing listening at that address.
     `CERTIFICATE_VERIFY_FAILED` is something between this container and the collector
     presenting its own certificate, usually a TLS-inspecting proxy: exempt the host from
     inspection.
   - `No answer from <host> within 10 seconds.` → an egress firewall dropping the
     connection, or the collector down; the probe above tells them apart. An air-gapped
     instance with sharing on reads this every day, and that is a supported configuration.
   - `<host> answered 200 with a body that is not JSON …`, or `answered 302 Found,
     redirecting to <another host>` → something other than the collector answered: a
     proxy or a captive portal. The probe above shows who.
   - `answered 400 Bad Request: …` or `answered 413 …` → the collector refused this
     container's body, and the text after the colon is its reason. Reportable state **M**:
     the container built something the collector will not take, which is ours to fix.
   - `answered 429 …` or `answered 5…` → the collector is throttling or unwell. Nothing
     to fix on this side; the next exchange tries again. The same line for more than a
     day is reportable state **M**.

7. **A build says how many findings it has, and the line beside it says *updating to
   …: not in the corpus of …*.** That line is the answer for the release **Jamf calls
   latest for the named title**, not for the build you are looking at, and it means the corpus holds no row
   for that release — nobody assessed it. It is deliberately not rendered as *closes all
   of them*: an update whose target nobody looked at buys an unknown, not a clean bill,
   and a missing row is never upgraded into one. Nothing is broken and there is nothing
   to fix in the container. Two things tell the ordinary reading from a fault:
   - each line names its own title and latest release; the reference title comes first.
     An in-branch title can name a different release. The release is often newer than
     anything the corpus has had time to assess — the corpus is dated on the banner, and
     a release published after that date cannot be in it. Wait for the corpus to move;
   - if the release is *older* than the banner's date and the same line survives a
     *Refresh* (step 3), the corpus skipped that build. That is ours, not yours:
     reportable state **I**, and include the app name, the installed version and the
     release the line names.

   A build with no line at all is not this: the line is printed only beside a **covered**
   build whose target was actually looked up, so a grey or amber build (steps 1–4), a build
   already on the latest release, and a build Jamf lists no title for all show nothing. So
   does **every** build for a while after the upgrade that added this line: the lookup is
   set up when the row is re-matched against the Jamf catalog, which happens on its own the
   next normal catalog refresh or device sweep. A release nobody looked up is never dressed as one the
   corpus has no row for, so the absence is the honest state and not a silent failure. To
   stop waiting, use Devices › Applications › **Catalog** › *Refresh* (step 3) — it
   re-matches every row, and the lines appear on the next page load.

8. **The Devices list's *Apps with findings* column disagrees with the Mac's own page.**
   The two numbers are read off the same rows — the copy of the answer that sits on that
   Mac's own app rows ([`vulnerabilities.md`](vulnerabilities.md) §4f) — and both count
   **apps**, never findings added up across them, so *1 (0 KEV) · 2 outside* in the column
   and *1 app with findings · 0 on KEV · 2 outside the corpus* on the page are the same
   sentence twice. A disagreement is therefore two reads taken at different moments rather
   than two answers, and something moved between them: the hourly pass copied a build's
   answer onto this Mac, or the Mac itself checked in. **Reload whichever page you opened
   first.** If they still disagree, it is step 3's lag seen one surface over — the copies on
   this Mac have not been rewritten yet — and it closes the same two ways: the hourly
   refresh, which Devices › Applications › **Catalog** › *Refresh* runs now, or that Mac's
   next check-in. A disagreement that survives both, on a reloaded page, is reportable
   state **H**; include both numbers and the Mac's serial.

9. **A finding stopped being counted for a Mac that still has the app.** If no finding was ever
   recorded, check **Findings first checked** on the device page first (§ 18 step 12). Each finding is kept as
   a row with the date it was first detected, and every one that stops names its reason and the
   next check: `3 finding(s) on mac-014 now read resolved (corpus_withdrawn): the corpus epoch
   this container has loaded no longer lists them for a build the Mac still carries, which is not
   the same as fixed — check the epoch loaded and that the tier is still on (Devices ›
   Applications › Catalog)`. The others are `build_changed` (check the build on the Mac) and
   `app_removed`. `device_departed` means the Mac’s seven-day departure period ended,
   not that the vulnerability was fixed. In Connections, expand the sweep’s run log:
   its census line reports how many findings closed on Macs that left the fleet and
   explains that last detected remains the Mac’s last observation. A scoped or incomplete
   sweep can finish an already established departure period; it cannot establish a new
   departure. If unexpected, check the Mac’s presence in Jamf and run an unscoped device
   sweep; a returning observation can reopen its findings. A withdrawal is not a fix, and a
   later epoch reopens the row on its first date
   — Jamf's inventory clock, never the CVE's publication. One Mac's rows, by serial:
   ```bash
   docker compose exec -T db psql -U looninspect -d looninspect -c \
     "SELECT carrier_key, finding_id, first_observed_at, resolved_at, resolved_reason FROM device_findings
        WHERE device_id = (SELECT id FROM devices WHERE serial_number = 'C02XXXXXXXXX');"
   ```

**H.** A corpus has arrived on this container, this organization's tier is not `off`, and
the pages still do not answer from it — either they say nothing is answering (grey,
including an epoch the container holds and cannot read), or a *Refresh* leaves builds the
corpus should know reading **outside the corpus** (amber). Report the library
log line, any `vulnerability answers refreshed` or `stored vulnerability answer … could
not be read` lines, the tier shown on Settings › Data Sharing, the build (Settings ›
Support), and `GET /api/catalog` — the response carries `corpusAsOf` beside the rows it
describes, and a `null` there with the tier on is the defect. A `null` with the tier
**off** is step 1, not a defect.
**I.** The published corpus is refused, unreachable, or unchanging. Report the exact log
line (it names the epoch and the state), the build, and roughly when it started.
**M.** The exchange reads `failed` for a reason on the collector's side: a `400` or `413`,
a `429` or `5xx` for more than a day, or a `403`/`404` from `api.loonsec.io` after the
production cutover. Report the reason printed under *Last exchange* (the same sentence is
the `error` field of that row in the share-log download), when it started, the probe's
answer from step 6, and the build (Settings › Support).

### Development preview: tenant-selected intelligence (#621)

This applies only when `VULN_TENANT_SELECTION=true`; leave it off in production until
release validation is complete. All workers must use the same setting.

- **“Intelligence update could not be assessed; this organization's previous answers
  remain selected.”** In `docker compose logs app`, inspect the accompanying database
  error. Check database connectivity and free storage, then use **Settings › Data Sharing
  › Send now** to retry. The accepted contribution receipt is already saved. The prior
  selected corpus and its date keep answering; a newer download alone does not select it.
- **Inventory, re-emission or posture capture waits during an update:** the preview
  serializes these writers with corpus assessment for the organization. Let the current
  update finish and check database activity, free storage and the container logs if it
  stalls. Local tests have observed a 144-second first assessment at 1,000 synthetic
  devices, mostly in the installed-app copy statement; see the
  [validation record](vulnerability-scale-validation.md#concurrent-correctness-and-latency-follow-up).
  This is not an expected production duration or a timeout recommendation. Avoid repeated
  manual refreshes while diagnosing a slow pass. Read-only vulnerability pages keep one
  committed answer/date snapshot per request; reloading after a successful update shows
  the new release. A re-emit can cross releases between batches, but each event's date
  must agree with its answers. Report mixed pairs with the build and operation time.
- **No assessment after enabling the preview:** use **Devices › Applications › Catalog
  › Refresh** to assess a migration-granted release. If this organization had no grant,
  use its permitted contribution exchange first. Another organization's download does
  not grant access. Do not enable sharing on behalf of an opted-out organization.
- **A date stays old after sharing is turned off:** expected in this preview. The held
  release still assesses local inventory and displays its original date; no new delivery
  is implied. An older feed, missing coverage or incomplete IDs do not prove remediation.
- **Missing selected intelligence or repeated organization-context refusal:** stop the
  affected operation, preserve the logs, and contact support. Restore a known complete
  database backup if reference data was removed; do not delete pointers or substitute
  another organization's grant. No automatic pruning is enabled in this preview.

Assessment-only entries in **Devices › Device history** keep the last inventory observation
time and show a separate assessment time. They do not mean the device checked in again
or a finding was remediated. Expand **Recorded assessment evidence** for the release and
per-build counts/clocks; incomplete ID lists are explicitly marked.

If an intelligence update fails while saving assessment history, check the container log
and database connectivity/free storage, then retry **Send now**. History and answers roll
back together with selection; the previous release keeps answering. An unchanged sweep
should not add another identical assessment. Older observations without provenance remain
unrecorded rather than being reconstructed using today's feed.

A downgrade message saying **“Assessment history exists … downgrade would lose evidence”**
is deliberate. Keep the schema or restore a complete pre-upgrade backup. Do not delete
history to make the downgrade succeed.

### Manual cleanup of unacquired intelligence

Cleanup is optional and never scheduled. It preserves the active library, all acquired
releases (including rollback options), selections and historical evidence. Commercial
expiry or disabling sharing does not make a tenant's releases eligible for cleanup.

1. Choose a past cutoff with an explicit timezone. It means **first loaded locally before
   this time**, not the intelligence source date. Preview from the deployed app image:

   ```bash
   docker compose exec app uv run --frozen --no-sync --no-dev python -m app.core.vuln_pruning --before 2026-09-01T00:00:00Z
   ```

2. Read the examined, protected and eligible counts. **Preview only; nothing deleted**
   means no cleanup was applied. Zero eligible releases can mean every old release is
   active or acquired; it does not indicate a broken command. The preview takes the
   corpus import lock but changes no data. Acquisitions can change eligibility afterward.
3. To remove eligible releases, rerun the command with `--apply`. The command checks
   protection again and commits all deletions together. No database-owner or RLS bypass
   privilege is needed beyond the application's normal database role. Run during a quiet
   period: cleanup waits up to five seconds for database locks and holds the import lock
   until it finishes; total cleanup duration has not been benchmarked.
4. **Corpus cleanup failed:** check database connectivity and the configured role's
   permissions, wait for imports or assessments to finish, and retry the preview. A
   database error rolls back the cleanup transaction. If the connection was lost during
   commit, rerun the preview to establish what remains before retrying `--apply`.
5. For the agreed **30-day acquisition policy**, add `--retire-acquisitions` to the preview,
   inspect its additional acquisition counts, then add `--apply` to perform it. Without
   this extra flag the command continues to remove only orphans. All workers must be on
   the new version before retirement. Example preview:

   ```bash
   docker compose exec app uv run --frozen --no-sync --no-dev python -m app.core.vuln_pruning --before 2026-09-01T00:00:00Z --retire-acquisitions
   ```

   Only acquisitions older than **both 30 days and the supplied cutoff** can be retired.
   Current and immediately previous selected releases remain protected, even after expiry
   or consent withdrawal. The active global library also stays. Acquisitions and orphaned
   bytes are cleaned in one transaction; historical assessments are not deleted.
6. **An old acquisition stays protected:** its tenant may still need the current or previous
   selection. An upgraded selection with no recorded previous digest conservatively keeps
   all acquisitions until a successful transition records the pair; nothing is guessed from
   download order. A first-ever selection uses that same conservative rule. Another tenant
   may also still need the shared bytes after your tenant's acquisition is retired.
7. **A retired release cannot be selected:** complete a new authorized delivery before
   using it again. Shared local storage is not a grant. Historical assessment evidence still
   shows what that release reported, but it cannot reassess new inventory without the corpus.
   If a failed cleanup or lost connection makes the result uncertain, preview again before
   retrying. Logical deletion does not promise an immediate reduction in database file size.

## 6. "The Jamf Patch table is empty, or it stopped refreshing"

The patch catalog is the list of titles every Applications surface is matched against. It
is one list for the whole container — not per connection and not per organization — and
it refreshes hourly on its own. **Devices › Applications › Jamf Patch** shows it, with a
**Sync now** button that performs the same refresh immediately. The refresh dials a public
Jamf server; no credential of yours is involved, so nothing here is a permissions problem.

1. **Untick *Only titles with devices*, then press Sync now and watch the table's *Synced*
   column.** The box is ticked by default and hides every title whose *Devices with app*
   reads 0, which on a pod before its first device sweep is every title: the table then
   says *No title has a device yet. All … are hidden*, and that is the checkbox, not the
   catalog. Only *No Jamf Patch titles synced yet.* means the catalog itself is empty. If
   the row dates move, the refresh works and the catalog is current; a table that still
   says *No Jamf Patch titles synced yet.* after a refresh that reported no error is
   reportable state **J**. The first press on a freshly started container is the slow one
   — the whole catalog is fetched title by title and takes minutes, not seconds, and
   nothing on the page cancels it. Let it finish.
2. **The button says "Sync failed. Try again."** The page does not carry the reason; the
   container log does. Three different things in that log can carry it — the sentence the
   refresh writes about itself, the hourly job's name (`hourly_jamf_patch_sync`) and the
   button's own path (`/api/jamf-patch/sync`) — and they spell the catalog three ways, so
   match all three rather than the sentence alone:

   ```bash
   docker compose logs app --since 1h | grep -iE 'jamf[ _-]patch'
   ```

   In the shipped stack each log line is one JSON record with its traceback, when there is
   one, inside it, so a matching line carries its own reason rather than pointing at
   something above it. Most of what comes back is `"message": "request"` for
   `/api/jamf-patch/titles` — the page reading the table. These are the lines that answer
   this step:
   - `The Jamf patch catalog cannot be refreshed: JAMF_PATCH_BASE_URL is set to …` → this
     container was started with that variable holding something that is not an address.
     It is **not** part of the shipped `docker-compose.yml`, so it is set only where
     somebody set it: check the environment the container is started with. Remove it to
     use the default (`https://jamf-patch.jamfcloud.com/v1`) or correct it, then
     `docker compose up -d`. Nothing was written in the meantime — whatever catalog the
     container already had still answers.
   - `"message": "request failed"` with `"path": "/api/jamf-patch/sync"` (the press you
     just made), or `Job "hourly_jamf_patch_sync (trigger: cron…)" raised an exception`
     (the hourly tick), either of them ending in a traceback whose last line names a
     connection problem — `ConnectError`, `ConnectTimeout`, `ReadTimeout`, `ProxyError`,
     a certificate failure → this container could not reach the patch server. Check
     outbound access from the container itself:
     `docker compose exec app curl -sSI https://jamf-patch.jamfcloud.com/v1/software`. A
     proxy, an egress firewall or TLS interception is the usual cause; the hourly tick
     keeps trying and the existing rows keep answering. That this failure reaches you as a
     traceback rather than a sentence is a gap on our side, not a second fault on yours.
   - `"message": "request"` with `"path": "/api/jamf-patch/sync"`, `"status_code": 200`
     and a `duration_ms` in the minutes → the refresh **finished here**; whatever gave up
     was between the button and this container. The button sends no timeout of its own and
     the shipped stack has no reverse proxy, so this is something you put in front of it.
     Reload the page — the *Synced* column will have moved.
   - `jamf patch catalog synced` and nothing else → the hourly refresh is completing. If
     the page, with *Only titles with devices* unticked, still says *No Jamf Patch titles
     synced yet.*, that is reportable state **J**.
   - nothing for `/api/jamf-patch/sync` at all — only the page's own `titles` reads, or no
     output whatever → the press never reached this container, and no hourly refresh has
     completed since it started either. The job runs at the top of each hour and not at
     startup, so *No Jamf Patch titles synced yet.* is expected for up to an hour after a
     restart — but a press that leaves no line is not. Check that the app is reachable from the browser's
     own machine (`curl -si $BASE/api/health`) and what sits in between; a press that
     still writes nothing while health answers is reportable state **J**.
3. **The table has rows and one title you expect is missing.** Untick *Only titles with
   devices* and search again: with the box ticked, a title no device has is not listed,
   and a search that finds only such titles says how many the box hid.
   - The title is there once unticked, and reads 0 under *Devices with app* for software
     you know is on your Macs → this is not a refresh problem. About 120 catalog titles
     are never matched to an installed app — device-level (*Apple macOS …*), version-only,
     and the attribute-only titles Jamf publishes no bundle identifier for
     ([`jamf-patch-matching.md`](jamf-patch-matching.md) §3) — so they read 0 on every
     fleet. A title that IS matched against and still reads 0 is step 6.
   - The title is missing with the box unticked → a title whose definition the server
     refused is skipped for that refresh and fetched again at the next one, so a gap that
     closes by itself is working as designed. A title that is published by Jamf and still
     missing from the unticked list a day later is reportable state **J**.

4. **Settings › Data Sharing lists half the fleet as software no public source knows.**
   That list calls a title unknown when no Jamf Patch title matches any of its builds and
   the loaded vulnerability epoch names none of them — so with **0 Jamf Patch titles synced
   only the vulnerability library can make a title known**, and most of a fleet reads
   unknown on a container whose catalog never synced. That is this section, not the list: it
   states both counts (*… checked against N Jamf Patch titles and M vulnerability-library
   titles*) so you are not left guessing which source is absent. Work steps 1 and 2 above
   and the list shrinks to the fleet's real long tail on the next page load. Three
   neighbours of that state, all three legible rather than blank:
   - **Empty, with both counts 0** → nothing has been matched because nothing has been
     collected: a candidate needs an installed app to be a candidate of. Sweep a connection
     (§2), then look again.
   - **Empty, with both counts above 0** → the list is right. Every title your Macs carry
     with a bundle identifier is software a public source on this container already names,
     and the exclude box needs nothing from it.
   - **One line where the panel was: *Match counts and candidates could not be loaded…*** →
     the read behind the panel failed, so no count under the box is a statement about your
     fleet. The box itself is unaffected: patterns you type still save on blur, and the
     exchange still filters on them. `docker compose logs app --since 10m` carries the
     request to `/api/system/data-sharing/exclusion-candidates` and the reason it ended;
     reload the page to ask again.

   **Local AI ranking is absent or fails (#409).** The non-AI list above remains usable.
   Ranking appears for administrators when AI features and AI-inference consent are on
   and a saved Apple FM or OpenAI-compatible endpoint resolves entirely to local/private
   addresses. Save and test that endpoint under Settings › AI, then reload Data Sharing.
   Hosted endpoints, failed DNS, and mixed public/private DNS answers are refused before
   inventory is sent. The selector names the endpoint and model before the request.
   A connection error or malformed classification leaves exclusions unchanged; retry or
   use the existing candidates directly. The share log records `exclusion_ranking` and
   field names before sending; the audit log records `ai.exclusion-ranking.sent` with
   `ranked`, `unparseable`, or `error`. Neither log stores candidate labels or model text.
   An **AI estimate** is a suggestion, not proof that an app belongs to your organization.

5. **A title's app name reads *name from the patch definition*, or *No app name*.** Both
   lines are the page saying where the name under the title came from; neither is a fault
   and neither needs anything from you. Jamf publishes no app name on 513 of its 1,553
   titles — every versioned line, *Wireshark 4.2* among them — so LoonInspect reads one
   out of the `killApps` list in the title's own patch definitions and marks that it did.
   Nothing on a marked row is less trustworthy for carrying the marker: where a title
   names several apps for one bundle ID the first is taken, which can miss, and a name no
   Mac reports matches nothing — it can never make some other app's row answer
   ([`app-catalog.md`](app-catalog.md) §2a is the rule, and the marker's hover text is its
   short form). *No app name* means nothing names an app for that title at all; it still
   matches installed apps, by bundle ID and version, and only the name-keyed lookup is
   closed to it. A title showing neither line was stored before the rule existed — the
   next refresh (step 1) reads it once more and it gains one.

6. **A title from [`jamf-patch-matching.md`](jamf-patch-matching.md) §4a reads 0 devices for
   software you know is installed** — *my Python Mac reads absent*. Jamf detects those 182 titles
   with a script on the Mac rather than from the inventory it walks, and LoonInspect matches the
   inventory. Search **Devices › Applications** for the bundle identifier on the title's row:
   - **Listed** — a Mac reports an `.app` with that identifier (Firefox, Skype, PyCharm) and the
     title should match: a 0 after a sweep is state **J**'s last clause, with that identifier.
   - **Not listed** — the software is a command-line install, a framework or a daemon (Python 3,
     the JDKs, Jamf Connect Login), so the inventory has nothing to match and those Macs read
     absent until LoonInspect reads the attribute itself. Working as built.

**J.** A refresh that reports no error leaves the table saying *No Jamf Patch titles
synced yet.*, a title Jamf publishes stays missing from the list with *Only titles with
devices* unticked for more than a day, a press of **Sync now** writes nothing to the
container log while `/api/health` answers, or — the one where the sync did happen — a
title LoonInspect matches against still reads 0 devices after a sweep while **Devices ›
Applications** lists its bundle identifier (step 6). Report what the *Synced* column
shows, the bundle identifier and the title's name if that was the symptom, the output of
`docker compose logs app --since 1h`, and the build from Settings › Support.

## 7. "Jamf Pro webhooks are not arriving"

A webhook is Jamf Pro calling LoonInspect — `POST /webhooks/jamf/<id>` with the header
from **Set up** on the connection's Webhook collection ([`jamf-webhooks.md`](jamf-webhooks.md)
sets it up). A refused webhook is refused before any run exists, so the container log is
where it speaks: a `request` line for every callback that reached the app and, beside a
refused one, a line saying why. Every refusal answers Jamf Pro with the same `401`, on
purpose — a different answer per cause would tell a stranger which connection ids are
real — so the log is the only place that says which cause it was.

Make one happen first, so there is something to read: `sudo jamf recon` on a test Mac fires
`ComputerInventoryCompleted`. Then:

```bash
docker compose logs app --since 30m | grep -E 'webhooks/jamf|jamf webhook'
```

1. **Nothing at all** — no `"path": "/webhooks/jamf/…"` request line → the callback never
   reached this container. Check, in order:
   - the Jamf webhook's URL is the address **Set up** shows, character for character;
   - a Jamf Cloud instance calls from the internet, so the address must be a public name or
     address — not `localhost`, not a private address, not a laptop (the panel warns when
     it sees one);
   - a firewall or security group in front admits the addresses Jamf Cloud calls out from
     ([Permitting Inbound/Outbound Traffic with Jamf Cloud](https://docs.jamf.com/technical-articles/Permitting_InboundOutbound_Traffic_with_Jamf_Cloud.html));
   - the certificate: whether Jamf Pro accepts one it does not trust was not tested
     ([`jamf-webhooks.md`](jamf-webhooks.md) §1), so try a certificate from a public CA;
   - in Jamf Pro, the webhook is enabled and its event is `ComputerInventoryCompleted` or
     `ComputerAdded`.

   All of those right, and a `sudo jamf recon` still leaves no line → reportable state **L**.
2. **`"status_code": 401`** → refused for its credentials. The line beside it begins
   `rejected jamf webhook:`, says what to check in words, and carries a `reason`:
   - `no_header` — the request carried no `X-API-Key`. Its `presented` field says what it
     carried instead: `none` (the webhook's Authentication Type is *None*, or its header
     object names some other header), or an `authorization-…` scheme LoonInspect could not
     read. In Jamf Pro, set Authentication
     Type to **Header Authentication** and paste the header from Set up exactly as shown:
     `{"X-API-Key":"…"}`.
   - `wrong_secret` — the header arrived and is not this connection's secret. It was
     rotated after Jamf Pro's copy was pasted, or it came from another connection's Set up.
     Paste the current header into each Jamf webhook; if nobody holds it, **Rotate** and
     paste the new one ([`jamf-webhooks.md`](jamf-webhooks.md) §6).
   - `receiving_off` — **Turn on** under Set up.
   - `no_secret_set` — **Generate secret** under Set up, then paste its header into each
     Jamf webhook.
   - `connection_inactive` — Settings › Connections shows the connection inactive, and an
     inactive connection refuses every webhook.
   - `unknown_connection` — the id at the end of the address is no connection here: copy
     the address from Set up again. The endpoint is public, so a stranger's scanner earns
     this line too; a burst of it from an address that is not Jamf's is not your webhook.

   A `reason` that names a state the connection is not in → reportable state **L**.
3. **`"status_code": 422`**, beside `refused jamf webhook: the body is not a JSON object` →
   the header was right and the body was not JSON. In Jamf Pro, set the webhook's
   **Content Type** to **JSON**.
4. **`"status_code": 200`** → the webhook arrived and was accepted.
   - `jamf webhook event does not warrant a fetch; dropped by design`, with an `event` →
     an event LoonInspect does not act on; `ComputerCheckIn` above all (#76). Point the
     webhook at `ComputerInventoryCompleted` or `ComputerAdded`.
   - `jamf webhook carried no computer id; nothing to ingest` → the event named no
     computer, so there was nothing to read.
   - neither → it made a webhook run. **Set up** shows *Last webhook run* once the panel is
     opened again, and `GET /api/runs?trigger=webhook&pageSize=5` lists it; that run's
     `jobId` leads to its log (§0).
5. **`"status_code": 502`**, beside `jamf webhook accepted, but reading that computer from
   Jamf Pro failed` → the webhook was right; the read that follows it was not. The
   traceback's last line names the status and the address:
   - anything on `/api/oauth/token` → the connection's credentials or base URL; **Test
     connection** on the connection checks both;
   - `403` → the connection's API Role, which needs `Read Computers` ([README §3](../README.md));
   - `404` on the computer's own inventory → a computer deleted since the event;
   - a timeout or connection error → Jamf Pro unreachable from this container.

   The webhook run is recorded as failed with the same error, so
   `GET /api/runs?trigger=webhook&pageSize=5` shows it too.

   A `could not renew the Jamf Pro sign-in` line (only under **Sign-in reuse: Perpetual
   cache**, on the connection's form) says the same thing before any webhook meets it:
   Jamf Pro refused the sign-in, or could not be reached. Nothing waits on the renewal —
   it backs off, doubling up to ten minutes, and each read signs in as it needs to — so
   the fix is the same as for anything on `/api/oauth/token` above: **Test connection**.
6. **`"status_code": 503`**, beside `jamf webhook refused: the stored credential is not a
   credential` → the callback was right, and this connection cannot ask Jamf Pro anything:
   what is stored against it is not a credential, so nothing was sent. The log line carries
   the whole sentence and names the connection; §12 is the walk-through, and the webhook's
   own failed run says the same thing.

**L.** Callbacks that Jamf Pro sends never produce a request line while the address, the
network and the webhook's event are right; or a refusal's `reason` names a state the
connection is not in. Report the `rejected jamf webhook` or `request` lines (they carry no
secret), the webhook's settings in Jamf Pro — never the header's value — the build from
Settings › Support, and your Jamf Pro version.

## 8. When a path ends in "report"

Include: which path and which step you reached; the run's `jobID` and the panel's lines
(or `GET /api/runs/{jobId}/log`); `docker compose logs app --since 30m`; the build,
from Settings › Support; and, for a delivery problem, the destination's `id`, `lastError`
and counts. An issue with those four things is answerable; one without them starts with a
request for them.

## 9. What this document deliberately does not contain

A step that would need the source code. Where a symptom could not be walked to a fix with
the surfaces above, the missing surface is filed as an issue against the product
([`diagnosability.md`](diagnosability.md) rule 5) rather than written here as a workaround.
The acceptance test for this document is a session with no repository and no source
following it from a broken stack to a working one; what it cannot resolve is either a
missing path or a defect, and both are the point. First run, 2026-09-10: a stack restored
beside the wrong `ENCRYPTION_KEY`, a Haiku session with only this document, the API and
`docker compose logs`, five commands, the fix named in about two minutes. Its one finding
became a filed defect — the failure reached the operator as a raw traceback and a bare
`500`, not as a sentence ([`diagnosability.md`](diagnosability.md) rule 3) — and #374
closed it the same day: a `503` whose `detail` is the sentence, shown on the page.

**The paths continue at §10.** This section and §8 are about the paths rather than
about a symptom, and they sit here because this is where they were written; nine more
paths follow.

## 10. "The update notice never appears, or names a release I do not have"

The notice is the banner at the top of every page, shown to roles that can read system
settings. It means one thing: a published release exists that this build does not contain.
It never appears for a merge to `main`, which is staging, and it never appears while the
check cannot answer. Its answer, and when it has none its reason, are on **Settings ›
Support › Updates**, with the steps to update. The check asks once a day, and again within
the hour after a failure; `docker compose restart app` makes it ask now.

1. **Read the Updates block's sentence**, under *This build*, *Latest release* and *Last checked*:
   - *Up to date: this build contains …* → there is nothing to take. A release published
     since *Last checked* appears at the next check.
   - *… is available, and this build does not contain it* → the notice is right; the
     steps are under it, dump first.
   - *Checking is off* → `UPDATE_CHECK=false` is set for this container. Remove the line
     from `.env` beside `docker-compose.yml` and run `docker compose up -d`.
   - *This build carries no commit to compare* → a development build, or an image built
     without `GIT_SHA`. Build it with the commit stamped:
     `GIT_SHA=$(git rev-parse --short HEAD) docker compose up -d --build`.
   - *GitHub could not be reached, or something else answered in its place* → from the
     host, check that the container reaches GitHub at all:
     `docker compose exec -T app python -c "import urllib.request as u; print(u.urlopen('https://api.github.com', timeout=5).status)"`
     prints `200` when it does. An error here is the network's answer, not the app's.
   - *GitHub refused the check* → its unauthenticated limit, 60 requests an hour per
     address, is shared by everything behind this instance's egress address. The container
     log carries `update check refused by the provider` once per attempt. Several
     instances behind one address use the budget up together; `UPDATE_CHECK=false` on all
     but one is the fix available today.
   - *No release has been published yet* → true until the first release. Nothing to do.
   - *GitHub does not know this build's commit* → a local commit, a fork, or a branch that
     was never pushed. Build from a release tag and it is compared again.
2. **The notice names a release you believe you have.** *This build* ends in the commit it
   was built from (`+<sha>`). The notice means GitHub said that commit does not contain the
   release's. From the checkout the image was built from, fetch the tag first, then ask git:

   ```bash
   git fetch --tags
   git merge-base --is-ancestor <tag> <sha>; echo $?
   ```

   `1` → does not contain it: the image came from an older checkout or from a branch; build
   from the tag. `0` → contains it: reportable state **N**. Anything else, with a `fatal:`
   line, is git saying it does not have the tag or the commit — fetch again, or run it in
   the checkout the image was built from.
3. **The banner went away and the release did not.** Dismissing hides it for the browser
   session only. The Needs Attention row on the Overview and the Updates block still say it.

**N.** The Updates block says a release is available while `git merge-base --is-ancestor`
says this build contains it; or its sentence names a state this instance is not in.
Report the block's four lines (build, latest release, last checked, the sentence), the
`git merge-base` command and its output, whether `UPDATE_CHECK_URL` is set, and the
`update check` lines from `docker compose logs app --since 24h`.

## 11. "The Prompt bar is missing, or it answers *AI search unavailable*"

The Prompt bar is the box labelled **Prompt** above the filters on **Devices › Changes**. It
sends the typed question — nothing else — to the card picked in its **Model** list, which names
every card saved on **Settings › AI** and the model it uses. The model answers with filter
settings, and the page moves its filters to them and runs them. Two exceptions: an answer the
page had to correct in a way that searches wider waits for you to apply it, and text the model
judged not a question about changes runs nothing and is called invalid (both step 3).
The lines under the bar are written by the page from the matching rows, never by the model.
**Clear**, beside Apply, empties
every filter, the Prompt box and its answer. The bar appears only while three things are true,
and Settings › AI names the one that is not, in its line *Changes Prompt bar: …*. Every question
writes one row to the disclosure log naming the destination and the one field that left,
`query_text`.

1. **The bar is missing.** Read the *Changes Prompt bar* line on Settings › AI:
   - *hidden — the AI features flag is off* → Settings › Feature Flags, turn **AI features** on,
     then reload the Changes page.
   - *hidden — AI-inference consent is not granted* → grant it on Settings › AI.
   - *hidden — no provider is saved* → choose a card, fill it in, **Send** once to prove it
     answers, then **Save**. On the Apple card, *Apple's on-device model takes no reasoning
     effort …* means the request named one — a script, or a page from an older build; `fm serve`
     refuses any effort on its `system` model. Save the card again from Settings › AI, which
     sends none.
   - *shown* → reload the Changes page; it reads this once, when it opens.
   - Where the bar would be, *The Prompt bar could not check its settings: …* → the page asked
     and the server failed to answer; the reason follows the colon, and
     `docker compose logs app --since 10m` has the error.

   A role without Settings asks the API the same question: `curl -s -b jar $BASE/api/changes/prompt`
   answers `available`, and when that is `false`, a `reason` of `flag_off`, `consent_off` or
   `no_provider`.
2. **The answer leads with *AI search unavailable — the filters below still work*.** The sentence
   under the lead says why:
   - *AI features are off …* or *AI-inference consent is off …* → one was switched off after the
     page opened. Step 1.
   - *No AI provider is saved …* or *… is not saved in Settings › AI* → the card was removed after
     the page opened. Save it again and reload.
   - *could not reach the endpoint …* → the app could not open a connection to the saved Base URL. For
     Apple's model on the same Mac, on the Mac: `curl -s http://127.0.0.1:1976/health` prints
     `fm serve is running` when it is; if not, run `fm serve` in Terminal. From the container:
     `docker compose exec -T app python -c "import urllib.request as u; print(u.urlopen('http://host.docker.internal:1976/health', timeout=5).read())"`.
   - *HTTP 403* with *Cross-site requests are not allowed* → `fm serve` refuses a request that
     names another host. Keep the Apple card's Base URL on `host.docker.internal`: the app then
     presents `127.0.0.1`, which `fm serve` accepts. Any other address is presented as typed.
   - *no complete reply within 30 s* → something took the connection and did not answer in time.
     The Mac answers one model request at a time for every app on it, so another app using Apple
     Intelligence makes this one wait: ask again. If it never answers, the Base URL reaches
     something that is not `fm serve` (`gateway.docker.internal`, for one, answers this way);
     **Send** on Settings › AI with the same card shows the same sentence.
   - *The API key saved on the … card cannot be read* → this server's `ENCRYPTION_KEY` is not the
     one the key was saved under, usually after a restore. The container log carries the same
     line. An admin re-enters the key on that card and saves it, or restores the original key
     ([`operations.md`](operations.md) §1).
   - *Stored credentials cannot be read: this value carries key id …* → **not** the key, and
     nothing on Settings › AI needs re-entering: the row was written by a newer build than the
     one running. Section 4 step 4.
   - *The question held only what the Prompt bar removes before sending …* → the question was
     nothing but model control tokens (`<|im_start|>`, `[INST]`, `</s>` and their kin, usually
     pasted from a chat log) or invisible characters, which are stripped before anything is sent.
     Type the question in words.
   - *The question did not reach this server* → the browser could not reach LoonInspect itself.
     `docker compose ps`, then reload.
   - *The server answered 500 without a reason* (or another status), or *…not in a form this
     page can read* → LoonInspect received the question and failed. `docker compose logs app
     --since 10m` names the error; that is reportable state **O**.
3. **The answer leads with *Could not interpret that — try the filters directly*.** The model
   answered, but not with filter settings. Rephrase around a name, a serial or a section; the
   filters work by hand whatever the model says. If *every* question ends here, the endpoint is
   not honouring the reply limit or is putting its reasoning into the answer: the page refuses a
   reply over 8,000 characters without reading it. **Send** on Settings › AI shows the reply and
   its token count; a local model needs its reasoning turned off (the card's *Reasoning effort*,
   `none`).

   **The answer leads with *The model's answer needed a correction that widens the search, so it
   was not applied*.** Not a failure, and nothing has run: the filters below the Prompt bar are
   still the ones you had. The model did answer with filter settings, but the page had to change
   one of them in a way that would match more than the model named. One of four things happened:
   - a name it gave for **Search** or **Filter to one thing** was dropped: it was not text, was
     longer than 64 characters, or held a character a name here may not;
   - it put a serial number in **Search** that the question never named — often one from its
     own instructions — which was dropped;
   - it named a section, level or change the page does not have, which was read as *any*;
   - it added a field the page does not use and put a value in it, perhaps the name.

   Run as it stood, an answer that lost its name would list every added app rather than the one
   asked about, so a correction like that waits for you. A dropped **Search** does not wait when
   the question holds one serial number in capitals, as Jamf writes it: the page fills Search
   with it, and the answer runs. The
   lines under the lead are those corrections, in the page's words. If the model also said the
   filters cannot express part of the question, its sentence follows *These filters would be as
   close as these controls allow* (step 4). *Would show changes …* is what the filters would be.
   If that is what you meant, press
   **Apply these filters**: they run as if you had set them, and the usual answer follows,
   *Corrections to the model's answer* included. If not, rephrase the question, or set the
   filters by hand. A name may hold letters and digits in any script, spaces, and
   `. _ @ ' ’ ( ) + / - & # ! , :`. One holding anything else is dropped from the answer: a
   quote, a semicolon, a percent sign, an angle bracket, a symbol such as ™, or a character
   that draws nothing (a Hangul filler, a variation selector), which would have read back as a
   plain name and matched no row. Typed into **Filter to one thing** by hand, such a name still
   searches. The audit log records such an answer as
   `ai.changes-prompt.sent` with `outcome` `proposed`; an answer that ran says `applied`.

   **The answer leads with *Invalid question — the Prompt bar can't answer it, so nothing was
   run*.** Not a failure, and nothing has run: the filters below the Prompt bar are still the
   ones you had. The model judged the text not a question about changes on your devices: a
   greeting or thanks, a question about the model itself, general knowledge or how to do
   something, arithmetic, a request to write text or code, a question about vulnerabilities,
   compliance, risk or device health, or an order to do something — uninstall an app, turn a
   setting on, lock a Mac, push an update — which the Prompt bar cannot do: it only reads the
   change log. Ask what changed instead: which Macs installed, removed or updated something, or
   what changed on one Mac. If a real question about changes gets this answer, the model
   misjudged it. It does now and then: 5 of 81 real questions in a held-out test, each asking a
   device's current state or a share of the fleet ("how much memory does VKM73DMG47 have",
   "what percent of our Macs installed Zoom"). Ask about the
   change instead ("hardware changes on VKM73DMG47", "Zoom installs"), name the device or the
   thing, or set the filters by hand. The audit log records the answer as
   `ai.changes-prompt.sent` with `outcome` `invalid` and `reason` `not_about_changes`; the
   question itself is never recorded. On a build before this state existed, such text often ran
   instead: as every change in the log, or as the closest filters to a word it held, with an
   answer box as if the question had been understood.
4. **The answer leads with *Filtered as close as these controls allow*.** Not a failure. The
   question needed something the filters cannot express — an *or*, a *not*, a date range, a
   version or other value, a comparison — and the rows are the closest the filters allow. The
   sentence under the lead is the model's own, shown as text, and the page keeps it only when
   the question contains a word of that kind. On an answer waiting for **Apply these filters**
   (step 3), the same sentence follows *These filters would be as close as these controls allow*.
   Ask the part that was left out as a second question.

   *When* is not one of those, and neither are *the last time*, *the latest*, *the most recent*
   or *the first time*. The table is ordered by observed time, newest first, so the top row is the
   last time and the answer box states the time itself. A date range with two **ends** still is —
   "before September", "between Monday and Friday" — because the feed filters *observed at or
   after* and has no `until`; a **start** is not, since 2026-09-16. Until 2026-09-15 a question with
   "last" in it — "When was the last time someone installed wireshark" — carried *Cannot express
   'when' — filters match names, not timestamps* over an answer whose first row was the answer.

   **A question can set a start, and the chip says which one.** The server reads it out of the
   question's own words — never the model, which is not asked and does not know today's date —
   against its own clock and your browser's time zone, so *today* is your day. It knows *in the
   last 24 hours*, *last 7 days*, *past week*, *3 days ago* and their kin (minutes, hours, days,
   weeks, months of 30 days, years of 365), and *today*, *yesterday*, *since yesterday*, *since
   Monday*…*since Sunday*, *this week* (from Monday), *this month*, *this year*. It reads back as
   *Observed since …*, shows as the chip, which clears it in a press, and the audit row carries
   `window: true`. Anything else sets none — "last night", "before September", a month by name —
   and the answer is over the whole log, as it was. "Yesterday" is read as its **start**, so the
   answer runs to now: that is why the model's *Cannot express a date range* still stands over
   that one and goes over "in the last 24 hours".

   **The time in the answer box.** *Observed 14/09/2026, 11:57:26* is the same value as the
   table's **Observed** column: Jamf's report time for that Mac, which is when its inventory
   first carried the change — not when someone made it. That is why the line after it names the
   inventory before it (*The inventory before it, 13/09/2026, 19:33:16, did not show this change,
   so it happened between the two*): the change happened inside that window, and the window is
   as wide as the Mac's inventory interval. With more than one row matching, the box states both
   ends (*Observed from … to …*), which is where the first time is. Each Mac's line ends with its
   own newest. Two things to know when the time reads oddly: *Its inventory time did not move, so
   this came from Jamf's copy or from what LoonInspect reads* means the two reads carry the same
   report time, so nothing on the Mac dated the change — a Jamf-side edit, or a change in what is
   collected — and our own clock bounds it instead; and an app a Mac already had when tracking
   began has no *Added* row at all, so no time here (`docs/jamf-observations.md` §3). The times
   are the browser's format in the browser's zone, the table's and the box's alike.

   **A window from a link shows as a chip, and so does every other filter without a control.**
   The Overview's feed links here with a start; the filter form has no control for it, and none
   for the ten filters added in #447 either. Every one that is on shows under the filters as a
   chip — *Observed since …*, *Found by a webhook*, *One observation*, *Moved to version 153*,
   *Model matching “Air”*, *OS version 26*, *FileVault: not encrypted*, *Jamf site 3*, *Jamf
   department 5*, *Not managed by Jamf*, *Assigned user Dana Okonkwo* — and a press clears it.
   Before this, a link's window narrowed the table with nothing on screen to say so.

   **Filtering by what the table does not show.** The feed can be filtered by the Mac as the
   observation saw it: its model, OS version and build, FileVault state, site, building,
   department, whether Jamf manages and supervises it, when it was enrolled, and the person
   assigned to it. Seven of those are query keys today — `model`, `osVersion`, `fileVault`,
   `site`, `department`, `managed`, `user` — beside three read off the row itself: `trigger`
   (which of a sweep, a manual run or a webhook found the change), `spanId` (every change found
   in one observation of one Mac, which answers "what else moved at the same time"), and
   `version` (the version a change moved *to*, by prefix, so `version=153` finds 153.0.7049.84).
   `q` also matches a Mac's UDID now, beside its name, serial and Jamf id.

   They arrive three ways: a link, the Prompt bar (which reads a Search value the fleet has no
   device for as a model, an OS version, a department name or "unmanaged", and says so in its
   corrections), and a click on a row's model or on the person assigned to it, which is how the
   rest are discovered.

   **The assigned person travels as a token** (#446). A filter URL is what an operator pastes
   into Slack, so `user=` reads `user=u_7Qa1bZ…` and not `user=Dana Okonkwo`. Typing a name still
   works; when it belongs to exactly one person the page swaps it for that person's token before
   you copy it, and the chip still reads *Assigned user Dana Okonkwo*. A token is **resolvable by
   anyone who can open the feed** — the rows still carry the names, which is where the chip gets
   one — so it is not secrecy from your own admins, it is the name not riding along in a link, a
   history or a chat log. It is **derived from `ENCRYPTION_KEY`** and scoped to one tenant, so it
   means nothing in another deployment. A token is stamped on a row when the change is derived and
   never rewritten, so rotating that key changes only the tokens on rows written after it: a link
   made before the rotation keeps filtering to the right person over the rows from before it and
   misses the rows observed after — never the wrong person. **Splunk
   is unaffected:** `loon:jamf:mac:userAndLocation` still ships `username`, `realname`, `email`
   and `position` under a frozen, additive-only vocabulary, so a saved search grouping by a person
   keeps working; to keep the person out, exclude the field at the destination.

   **A chip reading *Assigned user this link no longer names*** means the link carries a token no
   row matches and the table beneath is empty — the chip also reads this for the moment the page
   is still waiting for its answer. A token is keyed to this deployment's `ENCRYPTION_KEY` and to
   one tenant, so the usual cause is a link made in another deployment or tenant, whose tokens
   mean nothing here. Change rows are never pruned (README, *What this project prunes*), so a link
   made here keeps resolving, and after a key rotation it keeps resolving over the rows from
   before the rotation. Press × on the chip to drop the filter, then find the person from a row.

   **Asking about a department in the Prompt bar.** "What changed on Macs in Engineering :
   Product?" works when Jamf's catalog holds that department's name. The model tends to read a
   department as the name of a profile and put it in *Filter to one thing*, with *Section:
   Configuration profiles* beside it; when no app, profile, group or account has that name and
   exactly one department does, the page reads it as the department instead and clears the
   section the model guessed — unless the question named that section itself ("which apps
   changed in Finance" keeps *Applications*). *Corrections to the model's answer* lists both
   moves, the chip reads *Department “Engineering : Product”*, and the answer runs on Enter.
   Nothing moves when two Jamf connections give the same name to different departments: one
   filter cannot hold both.

   **Department chips that show a number.** *Jamf department 5* instead of the name means
   LoonInspect holds no name for that id. Names come from Jamf's department and building
   catalogs, read every hour with the group refresh and on every sweep. If the API client's role
   lacks **Read Departments** (or **Read Buildings**), those reads are refused, the names cached
   before are cleared rather than left to go stale, and the run log says *department names
   cleared: this Jamf API client cannot read departments; grant its API role Read Departments*.
   Grant the privilege; the next hourly refresh brings every name back. A read that failed for
   any other reason — Jamf down, a timeout — keeps the names from the last good read.

   Two bounds, because a filter that silently drops rows is the failure this page exists to
   avoid. A change derived before 2026-09-15 carries no device details at all, so it matches
   none of the seven — *No changes match these filters* is the honest answer, not "this Mac is
   not a MacBook Air". And a webhook's narrow read stamps only the sections it read, so a row
   can carry a model and no department. `model` and `user` match anywhere in the value,
   `osVersion` and `version` are prefixes, and the rest are exact — a site and a department are
   Jamf's own ids, which is what a Mac carries (a rename is not a change to any Mac), so the
   chip shows the id and the Prompt bar's correction names the department it resolved.
5. **The filters moved somewhere you did not mean, or nothing matches.** The filters are where the
   model put them; change any of them and the page runs again, or **Clear** to start over.
   *The answer came back after the filters changed, so it was not applied* means a filter moved
   while the model was answering; the page keeps the filters you set. Ask again to apply it. *Corrections to the model's answer*
   lists what the page changed or dropped from the model's reply before running it. *No changes
   match* under the bar, and *No changes match these filters* in the table, mean the change log
   holds no row for those filters: the bar matches names the way *Filter to one thing* does, and
   a Mac that already had an app when tracking began never shows it as *Added* — it appears only
   when something about it changes. The table says *No changes yet …* only with no filter set,
   when the log itself is empty; *No changes on this page …* means the page number in the address
   is past the last page — moving any filter, or **Clear**, starts again at page 1. The
   **Change** filter has two vocabularies: entries (Applications, profiles, accounts,
   certificates, group memberships, extension attributes, pending updates) are *Added*,
   *Removed* or *Updated*, and every other section's settings are only ever *Changed*. With a
   section chosen, the Change list greys out the kinds that section never records; choosing a
   section that rules out the Change already set puts Change back to *Any change*, and the line
   under the filters says so (*Change reset to Any change: Applications records Added, Removed
   and Updated.*). A pair from the wrong side can still arrive in a link edited by hand. It
   matches nothing, and the empty table's second line names why — *Applications records Added,
   Removed and Updated — never Changed.*, or *Hardware records only Changed values — never
   Added, Removed or Updated.* Pick a Change from that section's side, or *Any change*. The bar
   never sets such a pair.

6. **The AI lever is missing from the search box on Posture › Vulnerabilities**, or it calls a
   question invalid. The lever is the toggle labelled **AI** beside that page's search box
   (#534): the same bar, the same three causes, a different surface. It is drawn only while all
   three of step 1's conditions hold, so read the same *Changes Prompt bar* line on Settings ›
   AI and follow step 1 — the lever and the Prompt bar appear and disappear together. A role
   without Settings asks `curl -s -b jar $BASE/api/vulnerabilities/prompt`, which answers with
   the same `available` and, when that is `false`, the same `reason`. With the lever **off** —
   where it starts, in every browser that has not turned it on — the box is the plain search it
   always was, and a finding id still routes on Enter.

   An answer headed *Invalid question — the AI lever can't answer it, so nothing was run*, over
   *The model judged this not a question about the builds on this page …*, means nothing ran and
   the filters are as they were. The lever sets this page's filters and nothing else, so a
   question about **Macs, departments or sites** is invalid here, and the sentence says where it
   is answered: the device list under **Devices**. This page answers per build, never per Mac.
   Ask which apps carry findings, which are on CISA KEV, which are outside the corpus, or what
   to patch first. The audit log records it as `ai.vulnerabilities-prompt.sent` with `outcome`
   `invalid` and `reason` `not_about_vulnerabilities`; the question itself is never recorded.

**O.** The *Changes Prompt bar* line says *shown* while the bar stays missing after a reload; the
rows under an answer disagree with `GET /api/changes` run with the filters on screen; or a
question about changes is called *Invalid question* however it is worded. Report the line, the
question, the page's URL (it carries the filters), the provider, model and time from the answer's
last line, the *Corrections* list, and `docker compose logs app --since 30m`.


## 12. "Every sweep for one connection fails at once, and the run says the stored credential has no clientId"

One connection's sweeps fail, every one of them, minutes apart, from the first tick after
you noticed. Every other connection is fine. The run's error is a sentence, not a
traceback:

> Re-enter the Jamf API client for "t1 jamf" on Settings › Connections — the stored
> credential has no clientId or clientSecret.

That is the whole diagnosis. What is stored against the connection is not a credential:
the row has a credential column, it decrypts, and what comes out of it is an empty object
or one missing a field. Nothing was asked of Jamf — the sweep refuses before it opens a
connection, so this is not a Jamf outage, a privilege problem or a network problem, and
nothing is retried.

Read it against the two neighbours it is easy to confuse:

- **Section 4, step 3** is the *key* being wrong: every connection and every destination is
  unreadable at once, the page says *Stored credentials cannot be read…*, and the answer is
  to restore `ENCRYPTION_KEY`. Here the key is right; one connection's payload is not a
  credential.
- **Section 1** is a credential Jamf rejects — a real `clientId` and `clientSecret` that the
  API refuses (`401`, `invalid_client`). Here there is nothing to reject.

**The fix.**

1. **Settings › Connections.** The connection's row carries the same sentence under its
   name, so you do not have to open a run to find which connection it is. A role without
   Settings asks the API the same question:
   `curl -s -b jar $BASE/api/mdm/connections` — each connection carries
   `credentialProblem`, which is `null` on every healthy one.
2. **Edit the connection and fill in Client ID and Client Secret**, then **Save**. Both, not
   one: the sentence names the fields that are missing, and a secret cannot be recovered
   from Jamf — mint a new API client in Jamf Pro (Settings › System › API roles and clients)
   if the original is gone.
3. **Sync now.** The row's sentence disappears on the next page load — it is computed from
   the stored credential on every read, not remembered — and the run should reach `running`.
4. **Or turn the connection off.** A leftover or half-built connection that nobody meant to
   keep is fixed by clearing **Active** on it, or by deleting it. An inactive connection is
   not swept and not ticked.

**Why your alert only fired once.** A destination subscribed to `run.failed` gets **at most
one of these events per connection per UTC day**, on purpose: before that rule the outbox
carried one identical alarm per tick — 144 a day for a single unattended connection — to
every destination. Every refusal is still recorded on its run, and the run whose alarm was
withheld says so in its own log (*run.failed not emitted: this connection already reported
this failure today*). So the silence after the first alarm is not the problem clearing:
the connection's row is what says whether it is fixed.

**Webhooks refuse in the same words, and each refusal is its own run.** While the
credential is unusable, a connection answers `503` to every callback it would have acted
on — a `ComputerAdded` or `ComputerInventoryCompleted` naming a computer. A
`ComputerCheckIn` is still dropped by name before any of this and still answers `200`, so
a fleet-wide check-in webhook is not what you are looking at.
`docker compose logs app --since 30m | grep 'jamf webhook refused'` carries the same
sentence, and `GET /api/runs?trigger=webhook&pageSize=5` lists the failed runs behind it —
one per callback Jamf Pro sent or retried, which is why the run list can fill faster than
the ten-minute tick would explain. It is the same failure on a second path, not a second
failure: the ration is counted over the connection's failed runs whatever wrote them, so
one `run.failed` a day covers ticks, webhooks and any mix of the two, and the **Save** in
step 2 ends both at once.

**P.** The connection's row says nothing and `credentialProblem` is `null`, while its runs
keep failing with this sentence — or the sentence stays on the row after a successful Save
and a page reload. Report the connection's `id`, the row from
`GET /api/mdm/connections`, the failing run's `jobID` and error, and
`docker compose logs app --since 30m`.


## 13. "Settings › AI is missing, or says AI features are off"

One switch owns the whole AI area: **AI features**, on **Settings › Feature Flags**. On, the
**AI** entry is listed under Settings and the page opens. Off, the entry is gone, the address
refuses in words, and the page's own two reads answer `409`. It takes effect at once in the
session that flipped it; other open sessions see it at their next reload or sign-in.

1. **The AI entry is not under Settings.** Check whether **Data Sharing** is listed there.
   Both need the same permission, so if neither is listed it is the role, not the switch — ask
   an administrator for an account that can read system settings. If Data Sharing is listed and
   AI is not, the switch is off: turn on **AI features** on Settings › Feature Flags, which
   needs an administrator, and the entry appears without a reload.
2. **The address `/settings/ai` says *AI features are off*.** Same switch, same fix — the link
   under the sentence goes straight to Feature Flags for an account that may toggle it.
3. **It says *This area could not be checked*, and *the feature flags could not be read*.**
   That is not the switch being off: the answer is missing. This instance did not answer
   `GET /api/feature-flags`, which needs only a session, so the rest of the app is failing too.
   Reload; then read `docker compose logs app --since 15m` and § 4 above, which is the path for
   an instance that cannot serve its own settings. Nothing here is evidence about the switch.
4. **An administrator turned it on, and your session still hides it.** Each session reads the
   flags once, when it signs in. A toggle made in another browser, another tab or by another
   person reaches yours at the next reload — ⌘R. This is deliberate and not a fault.
5. **`GET /api/system/ai/providers` or `/host` answers `409`.** Each read names itself in the
   body: *AI features are off; ai_provider_table may not run* for the provider table, and
   *AI features are off; ai_host_detection may not run* for the host detection. Two code
   names, one switch — this one — and the page behind both reads is Settings › AI.

**Q.** **AI features** reads **On** on Settings › Feature Flags and Settings › AI still refuses
after a reload, or the entry is listed and the page refuses. Report what the Feature Flags row
shows, what the page says word for word, the output of
`curl -sk -o /dev/null -w '%{http_code}\n' <address>/api/system/ai/providers` run with your
session's cookies, and `docker compose logs app --since 30m`.

## 14. "Settings › AI has no Apple Foundation Models card"

That card is offered where its default can work: LoonInspect under **Docker Desktop on
an Apple Silicon Mac**, with **`host.docker.internal` resolving from inside the container**.
Apple's `fm serve` runs on the Mac, never in the container, and that name is how the
container reaches it. Anywhere else the card is withheld on purpose — it is not a feature
this build lost, and the panel **Where this container runs** says so in a sentence under its
evidence. One exception keeps it on the page anywhere: a server that holds settings saved for
that card shows it, saying on the card itself that that is why, so **Remove** stays reachable
(step 3). The **OpenAI-compatible** and **Anthropic** cards are offered everywhere.

1. **Read *Where this container runs*, and the *Evidence* line under it** — the kernel, the
   CPU implementer, and the alias. They decide whether the card is offered on the reading
   alone; a card this server holds settings for is on the page whatever they say (step 3):
   - *host.docker.internal resolves*, and the verdict names macOS → the card is offered.
     Reload the page if it is still not there.
   - *host.docker.internal does not resolve*, and the verdict names macOS → the Mac is right
     and the name is not. Docker Desktop supplies it, and this project's `docker-compose.yml`
     declares it; a container started some other way, or with its own `--dns`, may have
     neither. Check it from the host — `docker compose exec -T app getent hosts
     host.docker.internal` prints an address when the name works — then bring the stack up
     with `docker compose up -d` beside this repo's `docker-compose.yml` and reload.
   - *Docker Desktop detected; the host OS could not be told …* → Docker Desktop, but no
     Apple implementer: an Intel Mac, or Windows. Apple's model needs an Apple Silicon Mac.
   - *Runtime not recognised from inside the container.* → OrbStack, Colima, Podman, Docker
     Engine on Linux, a cloud runtime such as ECS on Fargate, or the backend run outside a
     container at all. None of them is the one runtime this cut implements.
2. **Use the OpenAI-compatible card instead.** It reaches anything that speaks the OpenAI
   chat wire: Ollama, LM Studio, vLLM, a gateway, OpenAI itself. Where the alias does not
   resolve it starts **empty** rather than on a Mac's Ollama, and the Base URL field says why
   (*the local default cannot work here*). Type an address this container can reach — not
   `localhost`, which inside a container is the container — press **Send** once to prove it
   answers, then **Save**. Anthropic's card needs no local endpoint at all.
3. **The Prompt bar names the card while the evidence says it cannot work.** *Changes Prompt
   bar: shown (uses Apple Foundation Models via Docker Desktop)* under an evidence line saying
   the alias does not resolve means this server holds settings saved for that card — from a
   Mac, or from a database restored here — and the bar will dial it and fail. That is why the
   card is on this page at all, and the card says so. Select it, press **Remove**: the card
   leaves the page with the settings, and the page moves to one still on it. Save the
   OpenAI-compatible or the Anthropic card there, then reload the Changes page. If Settings ›
   AI will not load at all, turning **ai_features** off (§13) takes the Prompt bar down with
   it, so nothing dials the saved card until the page is back.
4. **You are on that Mac and the panel disagrees.** The detection reads `/proc/version` and
   `/proc/cpuinfo` from inside the container; `curl -s -b jar $BASE/api/system/ai/host`
   answers with the verdict and the evidence it was read from. `runtime` is `docker_desktop`
   only when the kernel carries `linuxkit`, and `hostOs` is `macos` only when the CPU
   implementer is Apple's `0x61`. Neither of those on an Apple Silicon Mac under Docker
   Desktop is reportable state **R**.

**R.** *Where this container runs* reads a runtime or host OS the machine is not, under
Docker Desktop on an Apple Silicon Mac; or the alias reads *does not resolve* while `docker
compose exec -T app getent hosts host.docker.internal` answers with an address. Report the
*Evidence* line, the body of `GET /api/system/ai/host`, `docker compose exec -T app cat
/proc/version`, your Docker Desktop version, and the build from Settings › Support.


## 15. "I deleted a smart group and the Changes page says nothing"

Deliberate, and the run log says so. Deleting one group removes it from every member at once,
and one change per Mac would bury the sweep under tens of thousands of rows describing the same
click — so they collapse to level **low**, which the default *High + normal* preset does not
record at all, and the sweep writes one line per deleted object instead ([`change-log.md`](change-log.md) §1).

1. **Find the line.** Open the connection's run panel (or `GET /api/runs/{jobId}/log`) for the
   first sweep after the deletion: *smart group "…" is gone; its N per-device removal rows
   collapsed into this line at level low*, then a sentence saying whether those rows were
   recorded. `objectKind`, `objectId`, `rows`, `departedAt` and `rowsRecorded` sit beside it; a
   deleted extension attribute reads the same with `extension attribute`.
2. **Keep the rows next time — only next time.** The rows this deletion would have produced were
   never written and nothing shows them after the fact: the membership is already gone, so no later
   sweep derives its removal again. Settings › Change tracking → **Everything** keeps the *next*
   deletion's rows, at **Level: Low** on Devices › Changes — where the row names the group but not
   why, because the page prints no sentence for this cause. `objectDeparted` reads in `GET /api/changes?minLevel=low`.
3. **No line at all.** First rule out the three gates that drop the removal before the collapse sees
   it — this instance at *High only*, smart-group (or extension-attribute) changes switched off under
   Settings › Change tracking, or that group muted: each writes no rows **and** no line. Otherwise
   nothing departed. The census that finds a deletion runs at the start of the sweep, and a refused or
   collapsed one departs nobody and says so in the same run panel: a warning-level *departures reconciled*
   line with `skipped=empty_census`, `collapsed_census` or `not_readable` — the circuit breaker for an API
   role that lost **Read Smart Computer Groups**. Grant it and re-run. A line whose `objectId` names a group still in Jamf is reportable state **S**.

**S.** A collapse line for an object that still exists in Jamf. Report the line, the
`jobID`, and the build from Settings › Support.

## 16. "A Mac I deleted in Jamf is still listed, or a Mac vanished from the list"

LoonInspect never asks Jamf what was deleted; it notices what a sweep stopped returning. Only a
**clean census** may judge — a device sweep that succeeded, carried no RSQL selector and lost no
device to a failure — and a Mac it does not name enters a **seven-day tail**: still listed, still
counted, its row chipped *Leaving the fleet* and its page saying *Not returned by Jamf since ⟨date⟩;
leaves the fleet on ⟨date⟩*. Seven days later it **leaves the fleet** — out of **Devices**, out of
the device count on the Overview — and nothing is deleted: its row, observations and whole change
history stay, and **Show departed** in the filter bar (`includeDeparted=true`) reads it back chipped
*Left the fleet*. A sweep that names it again puts it straight back — by Jamf computer id, or by
**serial and UDID** on the same connection, which is how a wiped or re-enrolled Mac comes back.

1. **The Mac is still listed and you deleted it in Jamf.** Open the newest device-sweep run
   (**Runs**, or `GET /api/runs/{jobId}/log`) and read its last lines.
   - *device census: N observed, …* → the census ran. `departed 0` with this Mac among the
     `N observed` means Jamf still returned it: it was not deleted, or it lives in a
     different Jamf Pro instance than this connection points at. Check it in Jamf Pro.
   - *device census not taken; this sweep was not a clean one*, `reason=selector` → that
     collection carries an RSQL selector and proves nothing about Macs outside it. **Settings ›
     Connections › Collections**: the sweep with an empty **Selector** takes the census. Run it.
   - the same line with `reason=device_failures` → devices failed on this sweep (see
     `devicesFailed`, and a *device failed; sweep continues* line each). A device Jamf returned
     but whose ingest failed has a stale presence mark, so the night judges nobody. Fix what
     those lines name — path 1 or 2 — and the next clean sweep catches up.
   - *device census refused: only N of M Macs came back, fewer than half the fleet*, or
     *device census refused: the sweep returned no Macs at all* → departing a fleet on a short
     read is refused by design. Usually a lost privilege or a short page: path 1.
   - no census line at all on a finished sweep → reportable state **T**.
2. **A Mac vanished and nobody deleted it.** It left the fleet, which takes seven days of clean
   censuses that never named it. **Show departed** (`includeDeparted=true`) lists it again with
   `departedAt` — the first clean census that did not return it — and its page, observations and
   changes are all still there by id. If Jamf Pro still holds the Mac, ask Jamf for it with path
   2's `curl` against `/api/v4/computers-inventory`; if Jamf returns it, reportable state **T**.
3. **You re-enrolled the Mac and it is still departing.** A wipe, a rebuild or a re-enrolment mints
   a *new* Jamf computer id and keeps the board, so the return is matched by **serial and UDID
   together** on the same connection, counted as *returned N (M by serial, under a new Jamf id)*.
   The old id is then **retired**: its row serves out the tail it started, chipped *Leaving the
   fleet* until day seven — one Mac under two rows for a week — unless a sweep names that old id
   again, which puts it straight back. If Jamf later hands the **old** id back while the new one is
   the one now gone, the Mac is listed under the old id and the new one serves out its tail — the
   same picture mirrored, and nothing to fix. If yours is not in the count, read the census line's last
   clause. *…; matched by Jamf id, and by serial with UDID* → both keys were there, so compare them
   on its page against Jamf Pro's: one differs, and a **new UDID under the same serial is a
   logic-board repair**, a lineage event rather than a return. *…; matched by Jamf id only: this
   sweep's sections carry no hardware, so no serial to match on* → the collection carries neither
   **hardware** nor **extension attributes** (which force it back in); add either. A serial is
   Apple's and an instance's view of it is not, so a Mac moved to a *different* Jamf Pro departs
   here and enrols as a new Mac.
4. **Your SIEM saw nothing either way.** A Mac ships under the sourcetype `loon:departure`
   ([`splunk-setup.md`](splunk-setup.md) §7), and the census line above counts what it sent:
   `eventsEnqueued` the notices and returns, `macsRemoved` the tails it closed. A departed Mac sends
   `state: departed`, `noticeDay` 1..7, **one per UTC day**: a day with no clean census is never
   backfilled, so `noticeDay` jumps. After seven days one `state: removed` closes the tail, without
   waiting for a clean census. A sweep that names the Mac sends `subject.returned` and no notice under
   that id; a re-enrolment names a new one, so the retired id still closes and `priorJamfProID` joins
   them. Counted here, absent in Splunk, is path 3 — both names must be in `subscribedEvents`; zero is **T**.
5. **An alert closed itself, or the nightly numbers moved, and nobody touched anything.** A
   Mac leaving takes its open latches with it — the sweep is what closes a latch, and a Mac
   that left is never swept again, so one left open would read as *true of the fleet* for ever.
   The run says so on whichever line that sweep wrote — *device census: …*, or *device census not
   taken…* when it was not a clean one: *…N open alert latches closed on Macs that left the fleet;
   nothing was deleted*. **Nothing was** — `GET /api/alerts?open=false` lists the row with
   `closedReason: "device_departed"`, which is what tells it from an ordinary `app_gone` close,
   and the Mac's apps, observations and changes are all still there (closed rows then age out
   at 30 days, like run history). No `closedReason` at all means the row closed before
   2026-09-16, when the reason started being recorded; not a fault. The same day is the answer
   to the numbers: the posture tape counts the fleet without its departed Macs — device counts,
   alert counts, and every app, catalog, patch and vulnerability key that counts what a Mac
   carries ([posture-snapshot.md](posture-snapshot.md), *Departed Macs*) — so a Mac's numbers
   leave on **day seven of its tail**, not the day you deleted it in Jamf, `devices.departed_24h`
   says how many left that night, and captures written before 2026-09-16 counted deleted Macs
   and cannot be corrected. The close rides step 4's terminal: **the same sweep that sends
   `state: removed` closes the latch**, clean census or scoped, so the two surfaces move together
   and a connection swept only by a selector never ships a closed tail to a SIEM while the app
   still lists the alert. An open latch still sitting on a Mac that left *is* a fault: no device
   sweep has run since it crossed day seven (step 1), and if one has, state **T**.
6. **You want it gone for good.** Nothing removes a Mac's history today — not this, not
   deleting the connection. Honouring a Jamf deletion as an erasure is a stated, deliberate
   deferral (`future`); [`jamf-observations.md`](jamf-observations.md) §8 says what is held.

**T.** A finished, unselected, failure-free device sweep whose log has no *device census* line;
a Mac Jamf returns on the sweep's own endpoint that still departs or stays departed; a census that
departs a Mac and enqueues nothing for it (`eventsEnqueued: 0` beside `departed: 1`); or an open
alert latch still on a Mac that left the fleet after any device sweep has run since. Report the
run's `jobID` and its log, the census line if there is one, the Mac's Jamf id, the collection's
**Selector** field, and `docker compose logs app --since 30m`.

## 17. "The evidence report is empty, or every row says it was not reported"

The report is a document a person files, so it never leaves a reader to infer why it is thin: every
state below prints its own sentence in a **Read this first** box at the top of the page, above the sum.
Read the box first, then the step here. **Posture › Compliance** is the report on screen — pick the
connection, set the window — and **Download** on that page takes the same answer as one file
(`GET /api/evidence/report.html`, the object at `…/report` inside it). **Settings › Connections** keeps
a link to that page on the connection's row. Both doors need the **Auditor** role's `audit:read`.

1. **The report is refused outright**, on screen or as a download. Three refusals, each carrying its
   sentence in the red line where the report would be:
   - *This connection has no observations…* → the observation ledger is written by a **device sweep**
     and nothing else, so a connection that has only run catalog refreshes or webhook runs has none.
     §2 step 5 has the rest.
   - *The report window is empty: `start` must be earlier than `asOf`.* → on Posture › Compliance,
     **Window opens** is on or after **Dated**. Blank is the endpoint's default, not the epoch: **Dated**
     is then the ledger's last collection and **Window opens** the ninety days the row's link asks for.
   - *The evidence report cannot be rendered: the baseline rule catalogue could not be read…* → the
     report refuses rather than printing part of a catalogue, because a rule that failed to load reads
     exactly like a passing fleet. The sentence names the file it looked for, or the version it is at
     when that is a version this build does not read. Both renderings refuse, the object and the page.
     This is reportable state **U** — nothing about the fleet is wrong.
2. **The report draws, and says *No observation in this window*.** The window closes before this
   connection's first observation, or opens after its last. The connection is not broken and no Mac is
   named because none had been seen yet. Open the connection's run panel for the newest device sweep and
   read its finish time; ask again for a window that reaches it.
3. **It says *Some of this window has no observation behind it*.** Days the report holds no document
   for, counted as *no observation* rather than folded into met or unmet. **Three different facts read
   that way and the page cannot tell them apart**, so the box names all three and this step separates
   them. Find the Mac and the dates in the **Every interval** table first — the stretch is a row of its
   own, with its own start and end — then:
   - The stretch runs from the window's **opening** to that Mac's first observation → the window opens
     before the Mac was enrolled, or before this connection's ledger does. Expected on any window older
     than the connection, which the default ninety days often is. Nothing to fix.
   - The stretch runs from that Mac's **last** observation to the report's `asOf`, and other Macs kept
     reporting through those dates → that Mac has gone quiet. The sweeps ran; this one did not answer.
     §16 is a Mac that left the fleet; §1 is one the collection's **Selector** never asked about.
   - The same dates are missing for **every** Mac → no device sweep ran on them. Open the connection's
     run panel for those dates: a scheduled sweep that did not fire is §1 or §12, and one that ran and
     failed has a run row that says why.
4. **It says *This report is dated later than the last collection it could read*.** The tail between the
   last collection and `asOf` is counted as not observed rather than as the last known state carried
   forward — a Mac silent for three weeks is not a Mac that passed for three weeks. If a sweep should
   have run since the named time, that is the thing to check, not this page.
5. **It says *The runs behind the oldest part of this window are gone*.** Expected, and the one sentence
   here that reports a success. Runs are purged after `RUN_RETENTION_DAYS` (30) while the observation
   ledger has no purge path at all, so a report covering last March is sound long after the run that
   collected it stopped being listed. Nothing to fix: the evidence is the ledger, not the run row.
6. **Every verdict reads `notReported`.** Two different causes, and the box says which.
   - *…recorded under contract version X while this build's rules are written against v0* → the
     observations were written by a different contract version, and a rule's field is a path into a
     contract, so the rules are left unapplied rather than guessed at. Report the pair as state **U**.
   - No such sentence, and only *some* rows read `notReported` → those are fields the sweep's sections
     never collected, which is a fourth thing, not a failure. Widen the collection's sections (Settings ›
     Connections › Collections) and the next sweep answers them.
7. **The three-way sum reads more days than the window.** Not an error. The identity *met + unmet + not
   observed = the window* holds for **one Mac under one rule**, and every row of that table is above
   that grain, so each figure is the window multiplied by the rows folded into it: a rule's row counts
   the window once per Mac, and the fleet's row once per Mac per rule. A forty-day window over five Macs
   and ten rules is 200 on a rule's row and 2000 on the fleet's. The table's heading says **= the window
   × rows** and the paragraph above it gives both multiples and the window's own length, so the
   arithmetic can be checked on paper. The dates a *day* is counted under are in **Every interval**.
8. **It printed badly.** Print from a browser to A4 portrait with headers and footers off; the page
   carries its own margins and repeats both the refusal line and each table's heading on every sheet.
   Nothing is fetched while it renders, so a machine with no network prints the same page. A digest that
   wraps across two lines is wrapped, never shortened — every character is there.

9. **Posture › Compliance says the sum does not close, or has no connection to offer.** States the
   download cannot reach, every one of them printed on the page rather than left out.
   - *The sum does not close* → a fault, not a reading: the page checks *met + unmet + not observed = the
     window* on the exact seconds before it draws the tables, and prints both figures it got. The days
     round to two places and can land a hundredth either side (step 7); this check never reads them, so a
     mismatch is the object disagreeing with itself. Report it as state **U** with the connection, the
     window and those figures — Download takes the object it was computed from.
   - *The connections could not be read…* → the picker reads `GET /api/mdm/connections`, which needs
     `connection:read` beside the `audit:read` that opened the page. A **refused** read names that
     permission — the **Auditor** role holds both, so check the role at Settings › Accounts; any other
     failure sends you to Support. *No connection to report on* means the read worked and there is none.

**U.** The catalogue refusal, a contract version this build has no rules for, or a sum that does not close.
Report the sentence from the box, the build from Settings › Support, and `docker compose logs app --since 30m`.

## 18. "Posture is not in my sidebar, or Vulnerabilities lists nothing"

**Posture › Vulnerabilities follows the corpus.** The entry is listed once a vulnerability
corpus is answering for your organization, and hidden until then — the data decides, not a
switch. The **address is open either way**: `/posture/vulnerabilities` needs only the
inventory permission every role holds, and with nothing answering it shows the corpus
banner and its *Why this container says nothing* block, which is the same explanation the
Catalog tab carries. So a link somebody sent you works even while the entry is hidden.

1. **The entry is not there.** That is § 5 steps 1 and 2, unchanged and in that order: is
   this organization's data-sharing tier **off** (Settings › Data Sharing), and is a
   library installed (the banner, then the loader's log line)? Open
   `/posture/vulnerabilities` directly — the banner on that page answers both questions in
   words. Nothing is broken while it says so; it is what every container reads before its
   first epoch.
2. **You want it listed anyway — a lab, a demo, a first look.** Turn on the
   **Posture › Vulnerabilities** flag on Settings › Feature Flags, which needs an
   administrator. It lists the entry whether or not a corpus is answering; it does not make
   anything answer, so the page still shows the banner and its *why* block until one does.
3. **Someone turned that flag on and your session still hides it.** Each session reads the
   flags and the corpus once, when it signs in. A change made in another browser, another
   tab or by another person reaches yours at the next reload — ⌘R. Deliberate, and not a
   fault; § 13 step 4 says the same of Settings › AI.
4. **The page says *a corpus is loaded and this organization's apps are being judged
   against it*.** Also not a fault, and not a fourth state: an epoch has arrived and this
   organization's builds have not been joined to it yet, so every row would read *outside
   the corpus* and a list of them would read as *no findings*. The words are the page's own
   — *that happens the moment a corpus arrives, and the hourly refresh is the backstop* —
   and since #554 they are true for seconds: the exchange that imports the epoch runs the
   join itself, for every organization, and the log shows `vulnerability answers re-judged
   after import` right after the corpus line (§5 step 3). The hourly catalog refresh closes
   it without any Mac checking in if that pass failed; **Refresh** on Devices › Applications
   › Catalog does it now. Still saying it more than an hour after the corpus date moved,
   with the tier on, is reportable state **V**.
5. **A filter is refused rather than answered.** Filtering by findings, KEV, band or
   *outside the corpus* on an organization nothing answers for is refused: `409` from
   `GET /api/catalog?vuln=findings`, in words that name both causes and point at
   [`vulnerabilities.md`](vulnerabilities.md) §8 — *Nothing is answering for this
   organization, so a vulnerability filter has no rows to be right about*. **On the
   Vulnerabilities page you meet that refusal as the banner, not as that sentence**: the
   page asks for findings on every load, so a refused read leaves the corpus banner and its
   *why* block standing alone — step 1's screen, reached by a different road. The words
   themselves are for whoever reads the API or the access log — and for the Devices list,
   which prints them (step 9). It is refused rather than answered empty on purpose: an
   empty list under *findings* reads as *nothing found*, which is the one thing this product
   must never say about apps nobody looked at. Step 1 is the fix.
6. **The page ends with the lists: there is no *By the numbers* at the foot.** Not a fault.
   Those four figures are rows of the nightly posture capture, which is read under
   **audit:read** — a permission the viewer role does not hold — and the band is planned
   against that permission rather than rendered into a refusal, so the account is shown every
   list and no band. Sign in as a role that holds it (analyst, auditor, administrator) to see
   them. A band that *is* there with a dash for a figure is a different thing, and the sentence
   under it says so: that key wrote no row that night, which is never a zero.
7. ***Longest exposed* is empty, or shows no age, while *Most exposed* lists builds.** The band
   says which of three things happened; read its sentence. *The longest-exposed list could not be
   read, so it is not shown.* → it is a **separate request** from the list above, and either can
   fail while the other answers; reload. *No build with findings here carries a publication date.*
   → the band is **always** the builds with findings, whichever *Popular filter* narrows the ranked
   list above (its hint says so), so under *Outside the corpus*, *No findings*, or a search matching
   only such builds it is right to be empty — and the chips ride in the address, so clear them
   rather than reloading. That sentence with **no chip pressed and the search box empty**, or every
   row reading **—** under the age, is ours: every finding the corpus serves carries a publication
   date, so nothing about your fleet is wrong and nothing here will fix it: reportable state **W**.
8. ***Easily patchable* is empty though Jamf Patch lists newer versions.** Three causes, in this
   order, and the first is the usual one. **The newer release has not been judged yet.** The
   release Jamf names moves on the Jamf clock and the corpus answers on its own, so between the
   two a build carries a newer version with no answer about it — and a build with nothing to
   compare is not ranked. **Refresh** on Devices › Applications › Catalog does it now; the hourly
   catalog refresh does it anyway. **The newer release is outside the corpus.** The corpus holds
   no row for it, which the application record prints in the warning colour as *updating to X: not
   in the corpus of …*; a release nobody assessed never counts as closing anything, so the build
   waits here until the corpus covers it. Nothing to repair. **The update opens more than it
   closes.** The newer build carries more findings than the one installed — the fleet's own
   Wireshark did, 17 against 94 — and this section lists what an update would *close*, so such a
   build is left off rather than ranked last. The application record's own line prints both
   directions, and *Most exposed* still lists the build. None of the three is a fault.
9. **The Devices list prints that sentence where its Macs should be.**
   `GET /api/devices?vuln=findings|kev` is the same refusal one grain up (#535), and it is
   reached the other way round — by a link somebody pasted, on an organization nothing
   answers for, rather than by opening a page — so the list prints the words themselves in
   place of its rows. Nothing beneath them counts anything: a refused question has no
   total, so the count and the pager are gone rather than reading *0 devices total*. The
   filter bar offers no *With findings* / *On KEV* chips here, because a corpus has to
   answer before there is anything to select; what it does offer is **the one chip the link
   carried, with an ×**. Click it and the list answers unfiltered, which is what the
   sentence's own last clause tells you to do. Then step 1, for why nothing answers.
10. **You looked up a finding id you know is on a Mac, and the page found nothing.** Type an id in
    the search box and press Enter, or follow one from an app's row, and the page lists the builds
    whose stored answer *names* it. Three things keep an id off those lists, in this order. **The
    list it would be named on is capped.** A build's id list holds ~50, KEV first, while the count
    beside it counts every finding ([`vulnerabilities.md`](vulnerabilities.md) §4e) — so an id past
    the cap is counted on that build and named nowhere, where no lookup can see it. The page says
    how many of your builds are capped above its results; a number there is the likeliest answer.
    **The build's answer came from a corpus that has since moved.** A row judged by an epoch that is
    no longer answering reads *outside the corpus* whatever ids it stores, so it is not searched;
    the hourly catalog refresh rewrites it, and **Refresh** on Devices › Applications › Catalog does
    it now. **The build reads *outside the corpus*.** The corpus holds no row for that exact build,
    so nothing was ever named for it — not a clean bill, and not a missing id. None of the three is
    a fault, and the page never says *not on your fleet* for any of them.
11. ***No Jamf fix path* lists nothing.** Read the sentence, because that chip's empty state is
    the **good** news it exists to look for: *every build with findings here is matched to a Jamf
    Patch title, so none is left without a fix path*. The chip is the builds carrying findings
    that **no** Patch title covers — findings with no managed remediation — so an empty list
    means every one of them has a title to push, which is a fleet in better shape than the chip
    was pressed to find. Nothing to repair, and nothing is hidden: clear the chip and *Most
    exposed* lists those builds again with their counts. Two neighbours worth telling apart. With
    a **search term or a band** beside the chip the sentence is the ordinary *no build in this
    catalog matches that filter* instead, because a claim about every build with findings is not
    one a narrowed set may make. And a build with **no findings** never appears here whatever its
    title status — this is `findings` narrowed by the fix path, not a list of unmatched builds;
    § 6 is where a title that should have matched and did not belongs. **If you are
    reading *no build the fleet carries has a finding against it in this corpus* under this chip,
    that is ours and not your fleet**: the chip shipped on 2026-09-17 saying the unnarrowed
    list's sentence, which is false wherever *Most exposed* above it lists a build, and the
    release that follows corrects it.
12. ***Seen here* is younger than *Oldest published*, or is a dash.** Younger is the design, and
    usually much younger: the two columns are two clocks. **Oldest published** counts from the day
    the world published the finding; **Seen here** from the first time *this container* saw it on
    one of your Macs, so on a fleet you connected last month a build reads *900 days* beside *20
    days* and both are right — the second uses your fleet's history. When findings are
    first checked for an existing Mac, initial records can use reconstructed dates:
    the build's recorded arrival, otherwise the Mac's earliest recorded observation,
    otherwise the date of that check.
    These dates estimate history rather than prove when a finding was first detected;
    later findings use their own observation and existing dates are not rewritten.
    A **dash** is an absence and never a zero, with two checks behind it. **Findings have
    never been checked for a Mac carrying this build.** Open its device page and read
    **Findings first checked**: a sentence saying findings have not been checked confirms
    this state. A timestamp means its first check completed, even if it found no findings;
    it is not the first detected date of a CVE and does not move on subsequent sweeps. It is
    the pod's clock at that check, not the Mac's report time: a marker earlier than the day
    this pod's finding ledger first ran (a pod upgraded across #597 before #646) was copied
    from the report time at the first check and is not rewritten.
    Run a device sweep to record the initial check (§ 2 for a run that reports nothing,
    § 12 for one connection whose sweeps all fail). A recent **LoonInspect last read it**
    timestamp alone does not prove findings were checked.
    **The id is past that build's cap** — a list holds ~50 while the count counts every finding
    (step 10), so an id nobody named is an id nothing can record, which the Lookup page words as
    *Not tracked by id here* and not as *no Macs*. Neither is a fault; a dash beside a findings
    count on a build whose carrying Macs all have a **Findings first checked** timestamp
    is neither, and is ours — report the app and version, its findings count, and the
    Mac's four clocks.

**V.** The page says *being judged against it* more than an hour after the corpus date
moved, with the tier on and the hourly refresh running. Report the date the banner shows,
what **Refresh** on the Catalog tab did, and `docker compose logs app --since 2h |
grep -iE "vulnerability library|re-judged after import"` — the second pattern is the line
the import writes per organization, or the `NOT re-judged` line naming why it did not.

**W.** *Longest exposed* says *no build with findings here carries a publication date*, or carries
no age at all, while *Most exposed* lists builds with **no chip pressed and the search box empty**.
Report the corpus date, one app name and version from *Most exposed*, and what that build's row
says under **Oldest published**.

## Inventory AI summaries

Inventory delivery does not wait for its summary. For absent or late summaries, provider
selection, one-hour expiry, overload/capacity logs, and Splunk time correlation, follow
[inventory summary troubleshooting](inventory-summaries.md#metrics-and-diagnostics).
`No updates` means a comparable observation changed none of the declared evidence scope;
it never substitutes for an expired job or incomplete observation. The scope is apps and their
findings, OS version and build, FileVault, SIP, Gatekeeper, the firewall, and extension attribute
values (#644). The device-history card names it in the sentence, and adds which ledger sections
the observation did record changes in.

**An extension attribute changed, but the AI says “No updates”.** Three checks, in order. First,
Settings → Change Log: the definition is muted, or the current level does not log extension
attribute updates — the summary follows exactly that policy, and a muted definition is never
evidence. Second, the collection's quarantine (Settings → Connections → the collection): a
quarantined definition never reaches the snapshot. Third, the point before it: the first
observation of a device after the upgrade to #644, or after a definition is created, reads
“AI comparison baseline established” — there was no earlier value to compare — and the change
is briefed from the next observation on. If the card reads “baseline” on every observation,
the section is dropping out of the aperture between reads; the Changes page shows which.

Only meaningful completed/cached changes produce a SIEM summary event. No-update, baseline,
incomplete and drop outcomes are local counters/state. Open Overview’s diagnostic reasons for
the next check; unexpected-error container logs carry safe exception types and stack locations.

## Device history does not show a value or summary

On the device page, check the selected observation and its collection time. “Not observed” means
that field was missing; “Not collected in this observation” means the recorded collection did not
include its section. “Disabled in Change Log” is a display-policy choice: enable that field in
Settings → Change Log or replace the slot. Layouts are personal to the active tenant.

**The newest state is dated today, but its Observed clock is days old.** Not a fault. A dot, the
*Last recorded change* line and the Recent changes table carry the collection clock, when
LoonInspect recorded the state; *Observed* is the Mac's own report time in Jamf. The two part when
Jamf's record changes without the Mac submitting inventory: an extension attribute edited in Jamf,
a field Jamf fills on the server, or an intelligence reassessment (*Assessed*). Read the top band:
if *Inventory reported by Jamf* has not moved for days while *Jamf last heard from the Mac* has,
the Mac checks in but does not submit inventory, which is its Jamf inventory-update policy and
not this pod. The Changes page dates rows by the report time (its *Observed* column); this page
dates them by collection. The same change carries both, and its row's tooltip names the other.

“Not recorded” for historical findings means no assessment evidence was retained at that point.
It does not mean zero findings. New ingestion records it automatically; the optional retained-event
import in [Device history](device-history.md) can recover receipts still held by the pod.

An unavailable AI summary may predate source-correlated history or have lost its source before
upgrade. The card never generates a replacement on read. For pending, dropped or failed summaries,
check Overview → Inventory AI diagnostics, then Settings → AI provider test, master flag, and
inference consent. The deterministic values and recorded-change link remain usable if AI fails.

If loading fails, use Retry; if saving fails, recheck the Change Log policy and sign-in membership,
then reopen Customize. Inspect the API response status and application logs if it persists. Do not
paste inventory bodies, credentials, or generated summaries into a public support issue.

## 19. Device-page update from Jamf

“Update this device” reads the computer already stored in Jamf; it does not ask the Mac
to collect inventory. If the inventory date stays unchanged after success, check that
computer's record through the adjacent Jamf link. “Another device update is running”
means a targeted read already holds this connection; retry when it finishes. A timeout,
missing Jamf computer, or connection failure keeps the saved inventory and gives a
visible error. Check Settings › Connections for activity and credential status, then
retry. The run log records the failed `device_refresh` attempt. A missing button means
the account lacks `device:sync` or the device has no supported Jamf connection.

## Paid intelligence preview (#622)

Settings > Data sharing > Intelligence access separates paid update access from
upload consent. Activation and rotation are explicit administrator actions; no MDM
connection license is transmitted, and activation never enables inventory sharing.

- The panel appears only with `INTELLIGENCE_ACCESS=true`,
  `VULN_RELEASE_RETENTION=true` and `VULN_TENANT_SELECTION=true`. All remain off by
  default. Enable only for a reviewed pilot after Support's deployed IAM/privacy
  checks; this is not a v1.x rollout instruction. Configure `INTELLIGENCE_ENDPOINT`
  as the trusted HTTPS service origin, without a path, credentials or query. The
  default is `https://api.loonsec.io`; use the operator-confirmed staging/production
  origin during Support's domain transition. Endpoint redirects are refused.
- **Activation:** enter the one-time `loon_act_` secret from support. It is sent
  only with protocol/client version, not inventory or submission identity. The
  returned paid credential is encrypted using this instance's `ENCRYPTION_KEY` and
  never returned to the browser. A successful activation immediately attempts a
  refresh. A lost response can consume the activation without saving its result;
  obtain a new activation from support rather than repeatedly reusing it.
- **Rotate credential:** explicitly replaces the saved bearer. A failed replacement
  preserves the prior local credential, but a lost service response may mean it was
  retired remotely; ask support for recovery. No automatic rotation is scheduled.
- **Refresh:** requests only a paid bearer, protocol/client version and stable
  channel, then downloads/verifies the signed corpus. No contribution UUID, fleet
  count or MDM field is sent. Scheduled attempts occur at most once per day per
  tenant while configured; Refresh now retries explicitly. `COMMUNITY_SHARING=false`
  does not disable paid refresh. `INTELLIGENCE_ACCESS=false` stops paid requests.
  Keep tenant selection enabled to continue serving acquired paid intelligence;
  disabling `VULN_TENANT_SELECTION` restores the legacy consent gate and is not
  the paid-pilot network stop switch.
- **Expired/revoked/invalid credential:** new updates stop. Contact support about
  renewal, extension or replacement; local selection, assessments and historical
  evidence are not deleted. The next refresh observes renewal; do not toggle consent
  to recover paid access. Last reported access is cached service state, not a
  continuously verified entitlement.
- **Service unavailable/invalid reply:** check service configuration and network,
  then retry. This does not mean expiry, revocation or zero vulnerabilities. Error
  text never quotes upstream bodies or bearer/capability values.
- **Download/assessment failed:** check database availability and free storage,
  then Refresh now. Last completed paid refresh advances only after acquisition
  and assessment/selection succeed. Previous selections survive failed imports.
- **Stop paid updates locally:** removes the saved credential and prevents new paid
  requests. It does not cancel the purchase or erase held intelligence. A request
  already in flight can finish. Reactivation requires support's activation secret.

The panel distinguishes last attempt, completed paid refresh, selected corpus and
publisher source timestamp. A recent download is not proof of fresh upstream data;
unknown applications are not clean and stale findings do not become resolved. The
existing vulnerability/coverage views retain their assessed-build denominator.
Never include activation inputs, request headers or signed download URLs in support
bundles. Losing `ENCRYPTION_KEY` also loses access to saved paid credentials; preserve
it with the backup as described in operations.md.

The contribution receipt preview is separate (next section). The paid preview never opts an
exchange into receipts, and contributor migration and deployed privacy verification remain
#622/#10 release gates. Both routes may deliver the same corpus without sharing their
request identities.

## Contribution receipts (#622)

A consenting exchange can earn a **contribution receipt**. For 30 days after the
contribution the service accepted, the receipt lets the service deliver the corpus
without another upload (Support's participation contract). This is a default-off
preview. It needs all of:

- `CONTRIBUTION_RECEIPTS=true`, together with `VULN_TENANT_SELECTION=true` and
  `VULN_RELEASE_RETENTION=true`;
- a `SHARING_ENDPOINT` over HTTPS;
- receipts enabled on the service.

This build earns, stores, redeems and withdraws receipts.

- **What leaves.** The exchange body gains `"participation_receipt": true`, which the
  share log shows. The receipt the service returns is stored encrypted under
  `ENCRYPTION_KEY` on the consent row. It never appears in the share log, a log line, a
  support bundle or the browser. `GET /api/system/data-sharing` reports its presence,
  dates and withdrawal progress under `participation`.
- **Turning sharing off, or resetting the submission UUID,** stops uploads at once and
  marks the receipt `withdrawal_pending`. The scheduler sends the withdrawal within one
  tick, then retries every ten minutes until the service acknowledges it. `withdrawn`
  means the service invalidated every receipt this identity earned. `ended` means the
  receipt had already expired or was unknown to the service, so nothing was left to
  withdraw.
- **"Upload held: sharing was switched off earlier…"** appears as a failed share-log row
  with no payload; nothing left the box. Sharing was turned back on before the service
  acknowledged the earlier withdrawal. The withdrawal must land first, or it could cancel
  the receipt the new upload earns. The status's `participation.error`, and the container
  log's `contribution withdrawal not acknowledged` line, give the reason:
  - **HTTP 503:** the service's receipt preview is off or its store is unavailable. Retry
    later.
  - **HTTP 404 or a bare 403:** no receipt service answers at the address that issued
    the receipt. Contact support if that service moved.
  - **"Could not reach":** a DNS or network problem.
  - **HTTP 400:** this build is out of date.

  Send now retries the withdrawal immediately and uploads once it is acknowledged.
- **Fetching without an upload.** A day's upload can fail, its answer can name no corpus,
  or the corpus it named can go unacquired. When that happens, the scheduler redeems the
  receipt within a tick. It sends only the receipt and the contract version: no
  inventory, no submission UUID, no paid credential. The corpus then arrives through the
  exchange's own import and selection path.
  - A failed redemption is retried hourly, and never after the receipt's fixed 30-day
    deadline.
  - It never runs while sharing is off, `COMMUNITY_SHARING=false`, or a withdrawal is
    waiting.
  - The status shows `lastRedeemedAt` and `retryAfter`.
  - `contribution receipt could not fetch the corpus` in the container log carries the
    same reasons as the withdrawal (HTTP 503, 404 or a bare 403, "Could not reach", 400)
    and changes nothing held.
- **`contribution receipt dropped`:** the service no longer honours the receipt. The
  reason is one of:
  - `unknown` (HTTP 401);
  - `expired`: the 30-day deadline passed;
  - `withdrawn`: another copy of this instance withdrew, for example a restored backup.

  Local consent is unchanged, and the next accepted exchange earns a new receipt. Held
  intelligence stays usable.
- **`contribution receipt ignored` in the container log:** an accepted exchange carried a
  receipt block that does not match the contract. The exchange still counted, and any
  receipt already held stays in use. Report it to support if it repeats.
- The receipt is linkable to this instance's submission UUID, never to a paid account,
  and it is not anonymity. Withdrawal ends receipt eligibility; it does not erase
  snapshots the service already holds. A download link issued before the withdrawal stays
  usable for up to 15 minutes.
