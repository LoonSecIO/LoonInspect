# Troubleshooting: the step-throughs

Status: **ruled**, 2026-09-10 ([#290](https://github.com/LoonSecIO/LoonInspect/issues/290)) ·
The language these paths are written in is [`diagnosability.md`](diagnosability.md) ·
Every step below uses only what a fresh operator has: the app, its API,
`docker compose logs`, and the run log. A step that needed source code was not written;
it was filed.

Each path is ordered — *check this; if X, then that* — and ends in a fix or in a **named,
reportable state**. When you reach a reportable state, §8 says what to include.

**What is in here.** The paths run §1–§7 and §10–§33, in the order they were written
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

- **§20** ["Sign-in asks for a six-digit code, or refuses the one I
  typed"](#20-sign-in-asks-for-a-six-digit-code-or-refuses-the-one-i-typed)
- **§21** ["Request coverage or Report an incorrect match is refused, or a case never shows a
  status"](#21-request-coverage-or-report-an-incorrect-match-is-refused-or-a-case-never-shows-a-status)
- **§22** ["Patch policy is not in my sidebar, an app cannot be picked, or its file was
  refused"](#22-patch-policy-is-not-in-my-sidebar-an-app-cannot-be-picked-or-its-file-was-refused)
- **§23** ["Out of policy is missing, a title is not judged, or the rule draft fills
  nothing"](#23-out-of-policy-is-missing-a-title-is-not-judged-or-the-rule-draft-fills-nothing)
- **§24** ["The change log keeps growing with `CHANGE_LOG_RETENTION_DAYS` set, or the Changes
  page lost history"](#24-the-change-log-keeps-growing-with-change_log_retention_days-set-or-the-changes-page-lost-history)
- **§25** ["LoonInspect.app will not open, or opens and says it could not
  start"](#25-looninspectapp-will-not-open-or-opens-and-says-it-could-not-start)
- **§26** ["A promoted application is not being sent, or Promote is
  refused"](#26-a-promoted-application-is-not-being-sent-or-promote-is-refused)
- **§27** ["The Fleet catalog tab is missing, empty, or says its last check did not get an
  answer"](#27-the-fleet-catalog-tab-is-missing-empty-or-says-its-last-check-did-not-get-an-answer)

- **§28** ["Support does not show the Mac app version or build"](#28-support-does-not-show-the-mac-app-version-or-build)
- **§29** ["Codex or Claude cannot use LoonInspect"](#29-codex-or-claude-cannot-use-looninspect)
- **§30** [Installed application patch plans](#30-installed-application-patch-plans)
- **§31** [Change filters do not find an OS version or time window](#31-change-filters-do-not-find-an-os-version-or-time-window)
- **§32** ["LoonSec's patch-policy data has not arrived, is old, or was
  refused"](#32-loonsecs-patch-policy-data-has-not-arrived-is-old-or-was-refused)
- **§33** ["A patch-policy walk is refused, or Jamf or Fleet cannot date
  it"](#33-a-patch-policy-walk-is-refused-or-jamf-or-fleet-cannot-date-it)

**The reportable states**, lettered in the order they were written, so they do not run in
section order and never will — code, tests and the README cite them where they are. When a
ticket names one, this says which path it came off. After **Z** the letters run on the way
spreadsheet columns do — **AA**, **AB**, … **AZ**, **BA** — and never start again at **A**.

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
| **X** | §20 | No phone, no recovery codes, and no other administrator to remove the second factor |
| **Y** | §21 | A case's key and the fresh one minted in its place both refused as naming another submission |
| **Z** | §22 | A reference replay that shipped with the build is refused after a reload, or none ships |
| **AA** | §32 | LoonSec names no patch-policy document, or only an old one, two days running |
| **AB** | §32 | A patch-policy document is refused by its check two exchanges running, or fails unexpectedly |
| **AC** | §32 | The patch-policy link is refused, or is not a link, two exchanges running, with the clock right |
| **AD** | §33 | A patch-policy walk refused because LoonSec's data does not hold up: its totals disagree, none match, it fails the walk's check, it leaves a held line undated, or a channel it names misses builds |
| **AE** | §33 | A patch-policy walk refused as a defect in LoonInspect: its own totals disagree, a timeline or request it built is refused, or the page cannot read or draw it |

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
tried again, and what to check. The paths below quote it at the default `LOG_LEVEL=INFO`:
with `LOG_LEVEL` set to `WARNING` or above in `.env`, informational lines such as
`scheduler started` are never written, so an empty `grep` for one answers nothing until
the level is back at `INFO`.

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
| *The last check, … did not get an answer.* above the Fleet catalog table | §27 step 3 |
| *Version history: … read* not climbing, or a line under it that begins "Paused until" | §27 step 8 |
| *The last version history read, … did not finish.* above the Fleet catalog table | §27 step 9 |

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
   - `failed`, and the error begins **reclaimed: no heartbeat** → step 7.
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
7. **The panel reports `reclaimed: no heartbeat within 300s — progress was not observed`.**
   Another acquisition released a stale run. Work through these checks in order; replace
   `<jobId>` with that run's id and `<container>` with the server container name.

   1. Read the run's lines and locate its opening line:
      ```sh
      curl -s -H "Authorization: Bearer $LOON_API_TOKEN" "$LOON_URL/api/runs/<jobId>/log"
      docker logs <container> 2>&1 | rg '<jobId>' | rg 'run started|heartbeat refused'
      ```
      `heartbeat refused` means the old worker was still alive when reclaim occurred;
      its work was stopped to preserve the replacement run's ownership.
   2. Compare the container start timestamp with the run's `run started` timestamp:
      ```sh
      docker inspect --format '{{.State.StartedAt}}' <container>
      ```
      A later container start explains a worker that disappeared during a restart. An
      earlier start means to investigate a stalled live worker; continue below.
   3. Check progress and database connectivity:
      ```sh
      docker logs <container> 2>&1 | rg '<jobId>' | rg 'Run progress stopped|The run heartbeat could not be saved'
      ```
      `Run progress stopped; heartbeat keeper stopped` means no worker progress for the
      stale window. Inspect the last run line and Jamf connectivity. `The run heartbeat
      could not be saved` means the independent heartbeat write failed; check database
      availability and lock waits. The keeper stops inventing progress for a stuck worker.
   4. Check whether late work was refused:
      ```sh
      docker logs <container> 2>&1 | rg '<jobId>' | rg 'was reclaimed before its observations could be saved'
      curl -s -H "Authorization: Bearer $LOON_API_TOKEN" "$LOON_URL/api/runs/<jobId>/log" | rg 'finish refused: this run was reclaimed; a late result was discarded'
      ```
      `was reclaimed before its observations could be saved` means the inventory write
      was rolled back. `finish refused: this run was reclaimed; a late result was discarded`
      means the final close was refused; the reclaim verdict remains authoritative.
   5. Correct the identified connectivity or worker problem, then Run now. If a scheduled
      collection reports contention, inspect its collection and connection ids:
      ```sh
      docker logs <container> 2>&1 | rg 'The scheduled collection will retry on the next tick' | rg 'collection_id|connection_id'
      ```
      The tick restores only its own claim and retries next minute. Check active runs if
      it repeats. Raising the stale timeout is a temporary workaround; repeated reclaim
      with a live worker is reportable state **A**.

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
   - **`device_sweep`** → step 2. One whose `status` is `failed` and whose error begins
     *reclaimed* → §1 step 7.
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
   Upstream response bodies are withheld from delivery errors because they can echo
   credentials or inventory. Use the HTTP status and the stated next check. For an
   Elastic item rejection, check index mappings and write permissions in the receiver's
   service logs; an HTTP 200 can still contain a rejected item. A connection failure says
   which, without copying credential-bearing URLs: *Connection refused…* (nothing
   listening at that address and port), *The endpoint's host name did not resolve…* (the
   name or DNS), *TLS certificate verification failed…* ([`splunk-setup.md`](splunk-setup.md)
   §5), or *Connection failed…* for anything else.
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
     line per process that runs them, at the default `LOG_LEVEL=INFO`; at `WARNING` or
     above that line is never written either way, so an empty grep answers nothing until
     the level is back at `INFO` (§0). At `INFO`, read `scheduler_enabled` on the
     `starting` line instead — a direct value, not an inference from one line's absence
     ([`operations.md` §7](operations.md#7-more-than-one-app-process)). The second reason
     is the next bullet. Still rising with neither line → reportable **D**,
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
   - `docker build` (or `docker compose up --build`) refused with `failed to parse platform :
     "" is an invalid OS component of ""` → the Dockerfile's `FROM --platform=$BUILDPLATFORM
     …` line (#715) needs BuildKit, which is Docker's default but is not guaranteed: remove
     `DOCKER_BUILDKIT=0` from the environment if it is set, or install the buildx plugin
     (`docker buildx version` should print one rather than refuse). Retry the build.
   - `docker compose up` refused with `set POSTGRES_PASSWORD in .env` (or
     `POSTGRES_APP_PASSWORD`, or `ENCRYPTION_KEY`) → the `.env` beside
     `docker-compose.yml` lacks one of the three required values. Set it
     (`backend/.env.example` names all three), `docker compose up -d`.
   - `db` not healthy → `docker compose logs db`; a full volume says so only there
     ([`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) §3).
   - `app` restarting or unhealthy with `db` healthy → step 2.
2. **The app's log.** `docker compose logs app --tail 100`:
   - *The database operation failed* in a run or request log → check database health,
     free storage and whether startup migrations completed for the running build. The
     error retains its type and, when supplied by the database, a five-character
     `SQLSTATE` code. Report those with the run's `jobID` or request ID if it repeats.
     SQL text, bound values and database server detail are withheld from these error
     diagnostics because they can contain inventory or credentials; application stack
     locations remain available. Bound parameters are also hidden in SQL debug logs.
     *Application startup failed* with this diagnosis means initialization stopped;
     fix the database health or migration problem before restarting the app.
     *Application shutdown failed* with this diagnosis means shutdown cleanup failed;
     check database health and the adjacent safe stack locations before restarting.
     Startup and shutdown tracebacks follow the same value-withholding rule.
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
   - *This database was upgraded by a newer release … which recorded that only v1.2.0 or later
     can read it; this image is v1.1.0 (build …), so it will not start on it* → the image is
     older than the database, and the release that upgraded it recorded that this one cannot
     read what it left. The sentence names both releases, what the database needs and what is
     running, so there is nothing to look up. Put an image of the named release or a later one
     back (`git checkout` its tag, `docker compose up -d --build`), or restore the dump taken
     before that upgrade beside this image ([`operations.md`](operations.md) §5). Do not edit
     `schema_release` or `alembic_version` to make it start: the stamp is right.
   - `1 validation error for Settings` whose next lines name `DATABASE_URL` and say
     *append ?ssl=require* → `DATABASE_MODE=external` needs the URL to ask for TLS
     (`?ssl=require`, `verify-ca` or `verify-full`). If the lines say *asyncpg spells the
     TLS parameter `ssl`, not `sslmode`* → the URL used libpq's spelling, which asyncpg
     does not read. Fix the URL in `.env`, `docker compose up -d`.
   - `1 validation error for Settings` whose next lines name `SYNC_TIMEZONE` and say *must
     be a canonical tz database name in Area/Location form* → the shipped image has no
     `tzdata-legacy` package, so a legacy alias such as `US/Central` or `CST6CDT` is a real
     tz database name that this image does not load. Both are Central time; its canonical
     name is `America/Chicago`. Set `SYNC_TIMEZONE` in `.env` to the canonical name for
     your zone, then `docker compose up -d`.
   - *ENCRYPTION_KEY_PREVIOUS is set but is not a valid Fernet key* → a rotation
     ([`operations.md`](operations.md) §1) named the old key wrongly. Copy it exactly from
     where it was stored, or unset it if no rotation is under way; `docker compose up -d`.
   - *ENCRYPTION_KEY_PREVIOUS is the same key as ENCRYPTION_KEY* → the new key was never
     generated, or was pasted into both. Generate one, put it in `ENCRYPTION_KEY` with the old
     key in `ENCRYPTION_KEY_PREVIOUS`; `docker compose up -d`.
   - it started, and `docker compose logs app | grep "ENCRYPTION_KEY rotation"` says
     *complete* → remove `ENCRYPTION_KEY_PREVIOUS` from `.env` and `docker compose up -d`.
     *incomplete* → the line names the table and column whose values open under neither key:
     they were written under a third key (a restore from another instance, usually); put that
     key in `ENCRYPTION_KEY_PREVIOUS` and restart, or re-enter those secrets
     ([`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) §5). *did not run* → the database was not
     reachable at start; every value still opens under either key, and the rewrite runs again
     at the next start — step 1.
   - *The database role this instance connected as is a superuser* (or *a role with
     BYPASSRLS*) *, so row-level security would not apply to it* → `DATABASE_URL` names the
     master or `postgres` user, and the app refuses before any migration. Prepare the
     application role with `looninspect-db-init` and put its URL in `.env`
     ([`operations.md`](operations.md) §8).
   - *The database role this instance connected as cannot create tables in schema public*
     → the role exists, but `looninspect-db-init` never ran against this database, or ran
     as a user that could not hand over the schema. Run it as the master user
     ([`operations.md`](operations.md) §8), then `docker compose up -d`.
   - `another process is migrating this database; waiting for it to finish before starting`,
     and it stays there → another app container holds the migration lock. `docker compose
     ps` shows it; let its migration finish (the `e621c4a8b903` note above says how long a
     slow one takes). A process that died released the lock with its connection.
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
5. **An administrator created with `INITIAL_ADMIN_EMAIL` cannot sign in because its
   `.local` or `.test` address is refused with 422.** Upgrade to a build containing
   INSPECT-815, then sign in with the existing address and password. The fix accepts
   stored account identifiers without requiring a public mail domain; it does not
   recreate accounts or reset passwords. Keep the existing volumes and instance key.
   Surrounding spaces and letter case are ignored just as at bootstrap. A 401 still
   means invalid credentials or an inactive account; a 429 means wait for the lockout
   to expire. Internationalized addresses created through the wizard or Accounts keep
   their existing email normalization at sign-in. If both the entered spelling and
   its normalized spelling belong to separate accounts, the entered spelling selects
   its own account; its password, active status and MFA requirements still apply.
   Every spelling of one normalized address shares one lockout counter, even when
   those spellings select separate accounts. Creating a
   new account through the wizard or Settings › Accounts keeps
   its existing mail-address validation; that creation policy is separate from
   authenticating an account already stored by environment bootstrap.
6. Healthy and signed in, and something else is unreadable → reportable **G**.

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
6. **Settings › Data Sharing says the last exchange *failed*.** If nothing ran on its
   clock at all — no exchange, ever, not even a failed one — check `scheduler_enabled` on
   the `starting` line first (`docker compose logs app | grep starting`):
   `SCHEDULER_ENABLED=false` makes this container web-only (§3), and **Send now** below is
   the only way an exchange runs while it is off. The reason is printed beneath *Last
   exchange*. It names the host the container dialled — `api.next.loonsec.io`
   unless `SHARING_ENDPOINT` is set, in `.env` or a hosted pod's template — and ends with
   how many times the run tried. **Send now**, in the same page's *Exactly what would be
   sent* box, runs an exchange on demand and shows the row it wrote, so each check below
   can be proved fixed in a click instead of a day. To see who answers at that address
   from inside the container — it sends `{}`, nothing of the fleet:

   ```bash
   docker compose exec app python -c 'import sys, urllib.request as u, urllib.error as e
   try: print(u.urlopen(u.Request(sys.argv[1], b"{}", {"Content-Type": "application/json"}), timeout=10).status)
   except e.HTTPError as x: print(x.code, x.read().decode()[:200])' https://api.next.loonsec.io/v1/exchange
   ```

   The collector answers that with `400 {"error": "unsupported contract"}`; any other
   answer is not the collector. The address at the end of the command is the default: an
   instance with `SHARING_ENDPOINT` set probes that value instead, whole — the
   container posts to it exactly as set and adds no path.
   - `The collector at api.loonsec.io answered HTTP 403` → that name is not the collector yet: until LoonSec reclaims
     it, an older account's API answers there. An image built before 2026-09-25, whose
     default was that name, or a `SHARING_ENDPOINT` set to it, reads this on every
     exchange. Set `SHARING_ENDPOINT` to `https://api.next.loonsec.io/v1/exchange` or
     update the image. Nothing is lost: each day's snapshot replaces the last in full, and
     the first exchange at the right address reads `sent`. From `api.next.loonsec.io` the
     same line is reportable state **M**. From any other host, a `403` or `404` means
     there is no collector at that path: check `SHARING_ENDPOINT`.
   - `Could not connect to <host>: …` → the container could not reach the host at all,
     and the text after the colon says how. `The endpoint's host name did not resolve` is
     DNS — `docker compose exec app getent hosts <host>` prints nothing when the container
     cannot resolve it. `Connection refused` is nothing listening at that address.
     `TLS certificate verification failed` is something between this container and the
     collector presenting its own certificate, usually a TLS-inspecting proxy: exempt the
     host from inspection. `Connection failed` is none of those three: check egress to
     that host.
   - `No answer from <host> within 10 seconds.` → an egress firewall dropping the
     connection, or the collector down; the probe above tells them apart. An air-gapped
     instance with sharing on reads this every day, and that is a supported configuration.
   - `<host> answered 200 with a body that is not JSON …`, or `answered HTTP 302`
     (*Something other than the collector answered …*) → a proxy or a captive portal.
     The probe above shows who.
   Response text, redirect targets and raw transport exceptions are withheld from the
   share log, because they can echo what was sent. The probe above prints what answers
   at that address to a body of `{}`, which carries nothing of the fleet.
   - `answered HTTP 400` or `answered HTTP 413` (*The collector refused what this
     container sent. Report the status to support (state M).*) → reportable state **M**:
     the container built something the collector will not take, which is ours to fix.
   - `answered HTTP 429` or `answered HTTP 5…` (*The collector is throttling or
     unavailable …*) → nothing to fix on this side; the next exchange tries again. The
     same line for more than a day is reportable state **M**.

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
a `429` or `5xx` for more than a day, or a `403`/`404` from `api.next.loonsec.io`, the
production collector. Report the reason printed under *Last exchange* (the same sentence is
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
**Sync now** button that performs the same refresh immediately. By default the refresh dials
a public Jamf server without your credentials. If `JAMF_PATCH_BASE_URL` names a private mirror,
check that mirror’s authentication and access requirements as well as connectivity. The first
probe below targets the public default, and its success does not verify a configured mirror; the
second asks the configured address.

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
2. **A line appears under the button: a sentence beginning *The Jamf patch catalog cannot
   be refreshed*, or the bare *Sync failed. Try again.*** These are two states. The sentence
   means the press reached this container and the container could not read the catalog;
   it is the whole reason, and the same line is in the container log, where the hourly
   refresh writes its own copy — one line, no traceback — when it is the one that fails.
   The bare line means the page was given no reason: the press never reached this
   container, or what came back was not this container's answer. The container log tells
   the two apart. Three different things in that log can carry the reason — the sentence
   itself, the hourly job's name (`hourly_jamf_patch_sync`) and the button's own path
   (`/api/jamf-patch/sync`) — and they spell the catalog three ways, so match all three
   rather than the sentence alone:

   ```bash
   docker compose logs app --since 1h | grep -iE 'jamf[ _-]patch'
   ```

   In the shipped stack each log line is one JSON record with its traceback, when there is
   one, inside it, so a matching line carries its own reason rather than pointing at
   something above it. Most of what comes back is `"message": "request"` for
   `/api/jamf-patch/titles` — the page reading the table. These are the lines that answer
   this step. The first four are the sentence, the same under the button and in the log:
   - `The Jamf patch catalog cannot be refreshed: JAMF_PATCH_BASE_URL is set to …` → this
     container was started with that variable holding something that is not an address.
     On the shipped stack it comes from the `.env` beside `docker-compose.yml`; anywhere
     else, from the environment the container is started with. Remove it to use the
     default (`https://jamf-patch.jamfcloud.com/v1`) or correct it, then
     `docker compose up -d`. Nothing was written in the meantime — whatever catalog the
     container already had still answers.
     The value itself is withheld because a private mirror address can contain credentials.
   - `The Jamf patch catalog cannot be refreshed: jamf-patch.jamfcloud.com did not answer
     (ConnectError: …)` — or `ConnectTimeout`, `ReadTimeout`, `ProxyError` in the brackets
     → this container could not reach the patch server: the name did not resolve, or a
     proxy, an egress firewall or TLS interception stood in the way, and the words in the
     brackets are the operating system's own and say which. When `JAMF_PATCH_BASE_URL`
     holds a username, password, query or fragment, the brackets hold the name alone, such
     as `(ConnectError)`, so that no error's words can repeat them; the second probe below
     prints those words in your own shell. Check `JAMF_PATCH_BASE_URL` and
     ask the container itself. The shipped image carries no `curl`, so ask with Python,
     which honours the same `HTTPS_PROXY` the app does:

     ```bash
     docker compose exec app python -c "import urllib.request as u; r = u.urlopen('https://jamf-patch.jamfcloud.com/v1/software', timeout=15); print(r.status, r.read(60))"
     ```

     If `JAMF_PATCH_BASE_URL` names a mirror, ask that address instead. This probe reads it
     from the container's own environment, so nothing in it is typed on your command line,
     and it fetches with the app's own HTTP library:

     ```bash
     docker compose exec app uv run --frozen --no-sync --no-dev python -c "import os, httpx; r = httpx.get(os.environ['JAMF_PATCH_BASE_URL'].rstrip('/') + '/software', timeout=15); print(r.status_code, r.content[:60])"
     ```

     `200 b'[{"…` is the catalog, and the next press will work; anything else is the
     network's answer, in the same words the sentence used when it carried them — fix
     that, not the app. The
     sentence says what it leaves behind, and it is true: nothing was written, the titles
     already synced keep answering, and the hourly refresh keeps trying. (The hourly
     refresh prints the sentence rather than a traceback for the same reason the button
     does; a container started before this change prints `Job "hourly_jamf_patch_sync
     (trigger: cron…)" raised an exception` and a traceback ending in one of those names
     instead, and the probe above is the same.)
   - `The Jamf patch catalog cannot be refreshed: jamf-patch.jamfcloud.com answered 503
     instead of the catalog` (any status) → the host was reached and something there
     refused. Two causes, told apart by where the address opens: an outage at Jamf
     refuses your own browser too, and clears on its own — wait, then press again; a
     status the probe above gets from the container while the same address opens from
     your browser is a proxy answering in Jamf's place, and its allow-list needs the host.
   - `The Jamf patch catalog cannot be refreshed: jamf-patch.jamfcloud.com answered, but
     not with the catalog` → something between this container and the host — a proxy or
     a captive portal — put a page where the catalog should be. The probe prints the first
     bytes of what it got; `<html` or `<!DOCTYPE` names the proxy, and the fix is on it.
   Catalog diagnostics and patch-plan source links omit URL userinfo, query and fragment.
   The deployment still uses its original configured URL for fetching. A link that needs
   authentication or query routing may therefore stop at the mirror's public address;
   check that configuration privately. An unparseable source URL is withheld entirely.
   Older plan snapshots remain stored unchanged, while API/PDF/AI presentation applies
   this rule. The report checksum covers the sanitized displayed body; see
   [patch-plan report integrity](application-patch-plans.md#auditor-pdf-and-api).
   - `"message": "request failed"` with `"path": "/api/jamf-patch/sync"`, or
     `Job "hourly_jamf_patch_sync (trigger: cron…)" raised an exception`, ending in a
     traceback that is not one of the connection names above → a failure of a kind the
     sentences do not cover. That it reaches you as a traceback rather than a sentence is a
     gap on our side, not a second fault on yours: reportable state **J**, with that line.
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
   use the existing candidates directly. The share log records `exclusion_ranking`, the
   model asked for and field names before sending; the audit log records
   `ai.exclusion-ranking.sent` with `ranked`, `unparseable`, or `error`. Neither log stores
   candidate labels or model text.
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

7. **The table hasn't moved in over an hour, and nothing above explains it.** The hourly
   refresh runs on the scheduler; check `scheduler_enabled` on the `starting` line
   (`docker compose logs app | grep starting`) before reporting anything: a container
   started with `SCHEDULER_ENABLED=false` is web-only (§3) and runs no hourly sync at all,
   though **Sync now** (step 1) still refreshes it — the button calls the same work
   directly rather than through the clock.

**J.** A refresh that reports no error leaves the table saying *No Jamf Patch titles
synced yet.*, a title Jamf publishes stays missing from the list with *Only titles with
devices* unticked for more than a day, a press of **Sync now** writes nothing to the
container log while `/api/health` answers, a press answers *Sync failed. Try again.* and
leaves a `request failed` traceback that no sentence in step 2 covers, or — the one where
the sync did happen — a
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
   the header was right and the body was malformed, too deeply nested, or not a JSON object. In Jamf Pro, set the webhook's
   **Content Type** to **JSON**.
4. **`"status_code": 200`** → the webhook arrived and was accepted.
   - `jamf webhook event does not warrant a fetch; dropped by design`, with an `event` →
     an event LoonInspect does not act on; `ComputerCheckIn` above all (#76). Point the
     webhook at `ComputerInventoryCompleted` or `ComputerAdded`.
   - `jamf webhook carried no computer id; nothing to ingest` → the event named no
     computer with a valid decimal Jamf ID, so there was nothing to read. No run or inventory is written.
   - neither → it made a webhook run. **Set up** shows *Last webhook run* once the panel is
     opened again, and `GET /api/runs?trigger=webhook&pageSize=5` lists it; that run's
     `jobId` leads to its log (§0).
5. **`"status_code": 502`**, beside `jamf webhook accepted, but reading that computer from
   Jamf Pro failed` → the webhook was right; the read that follows it was not. The
   run's error names the operation and the next check:
   - anything on `/api/oauth/token` → the connection's credentials or base URL; **Test
     connection** on the connection checks both;
   - `403` → the connection's API Role, which needs `Read Computers` ([README §3](../README.md));
   - `404` on the computer's own inventory → a computer deleted since the event;
   - a timeout or connection error → Jamf Pro unreachable from this container;
   - an invalid token or computer response → check the base URL and any intervening
     proxy, then **Test connection**. Invalid optional version/settings reads record
     an absent aperture value; token failures propagate rather than being retried for
     each optional resource;
   - `configured time limit` → the optional webhook budget expired. Check this run
     before retrying: a commit can complete just before the timeout. Recover with Run
     now or the scheduled sweep if sender redelivery has not been verified.

   The webhook run is recorded as failed with the same error, so
   `GET /api/runs?trigger=webhook&pageSize=5` shows it too.

   A `could not renew the Jamf Pro sign-in` line (only under **Sign-in reuse: Perpetual
   cache**, on the connection's form) says the same thing before any webhook meets it:
   Jamf Pro refused the sign-in, or could not be reached. Nothing waits on the renewal —
   it backs off, doubling up to ten minutes. Reads share a five-second cooldown only for credential/endpoint rejections or invalid token bodies;
   cancelled requests, transport errors and 5xx replies do not delay the next caller. For persistent refusals,
   the fix is the same as for anything on `/api/oauth/token` above: **Test connection**.
6. **`"status_code": 503`**, beside `jamf webhook refused: the stored credential is not a
   credential` → the callback was right, and this connection cannot ask Jamf Pro anything:
   what is stored against it is not a credential, so nothing was sent. The log line carries
   the whole sentence and names the connection; §12 is the walk-through, and the webhook's
   own failed run says the same thing.

   `Run close bookkeeping timed out` means the terminal verdict committed, but a closing
   event or log may be absent. Check database connectivity and the run’s recorded counts.
   `The webhook could not close its run` means release failed; check database connectivity,
   then the next acquisition can reclaim a stale running row. `Inventory was saved; the
   run’s close was interrupted` means the inventory succeeded; check the run’s log.

   `invalid computer inventory` with `unexpected shape` names the malformed section;
   `invalid token response from /api/oauth/token` names a malformed sign-in reply. Check
   the connection base URL and run **Test connection**. `rejected computer id` logs only
   presence, type and length: check the sender’s id format. `invalid smart-group id`
   means that group was skipped; inspect the smart-group list in Jamf Pro.

   `408` with `Webhook body timed out` means the authenticated body did not arrive within
   five seconds. Check the sender and proxy connection; this request opened no run.

   `Another inventory write overlapped this delivery` is a retryable shared-row conflict.
   Retry shortly; if it recurs, check the connection’s active runs and database logs for
   competing writers. No partial device write is retained.

   A different `503` can mean `Webhook capacity is busy`, a computer write lock could
   not be obtained, or run acquisition stayed busy through its retry. These carry
   `Retry-After: 1`. Admission allows eight reactive events per worker, counted after
   authentication and event filtering; a computer write waits at most five seconds for its
   lock. Check active runs and Jamf response times, then retry. No inventory success is acknowledged for refused work.
   A tick that exhausts run acquisition restores its own claim for retry on the next
   tick. For timeout configuration and delivery recovery, see [`jamf-webhooks.md`](jamf-webhooks.md) §9.

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
Support › Updates**, with the steps to update. The check runs on the scheduler, and no time
of day is this instance's own: its first check is owed at a moment drawn at random within its
first 24 hours, each answer owes the next 20 to 23 hours later at a moment drawn afresh, and a
check that got no answer is asked again an hour later. One that came due while the instance
was off is asked once it runs again. A page only reads the answer it stored, so neither
opening the block nor `docker compose restart app` brings a check forward, and a container
started with `SCHEDULER_ENABLED=false` never asks ([`operations.md`](operations.md) §7).
It asks LoonSec's update service, `api.next.loonsec.io`, unless `UPDATE_CHECK_URL` names another provider
(the container log's `update check on` line at startup names the host), and compares releases by number.
LoonInspect.app has no `.env` and no container: its banner and block print the app's own steps and
sentences, and §25 step 9 names its switch, its log and where their step-through differs.

Under the block's sentence, *What the check sends* is read from the instance too: *Host*, the host
asked and its shape (LoonSec's update service's, one `POST` carrying a body; or a GitHub-shaped
address's, two `GET`s and no body); *Next check*, when one is owed; *The last check sent*, that
check's literal body, answered or not, which went wherever `UPDATE_CHECK_URL` pointed then; and *The
next check would send*, the body built now, with no `last` before the first answered check. An empty
slot says why.

1. **Read the Updates block's sentence**, under *This build*, *Latest release* and *Last checked*, then *What the check sends*:
   - *Up to date: this build contains …* → there is nothing to take. A release published
     since *Last checked* appears at the next check.
   - *… is available, and this build does not contain it* → the notice is right; the
     steps are under it, dump first.
   - *Checking is off* → `UPDATE_CHECK=false` is set for this container. Remove the line
     from `.env` beside `docker-compose.yml` and run `docker compose up -d`.
   - *This build asks nothing* → a development build, run from a tree with no build stamp; or an
     image built without `GIT_SHA` while `UPDATE_CHECK_URL` names a GitHub-shaped address, which
     compares commits (LoonSec's update service needs none, and asks such an image like any other).
     Build it with the commit stamped: `GIT_SHA=$(git rev-parse --short HEAD) docker compose up -d --build`.
   - *No check of this build has run yet* → a fresh install, an update from a release before v1.2.0, or any update or rebuild asking a GitHub-shaped provider, waiting for a
     moment drawn at random less than a day away. Longer: a container must run the scheduler
     (`scheduler_enabled` is `true` on its `starting` line), and its log's
     `update check could not run` says why.
   - *The update check got no answer it could read* → first read the container log for
     `UPDATE_CHECK_URL cannot be asked as an address`. That line names what is wrong with the
     value (a port no host has, a character an address cannot hold), nothing was sent, and the
     correction is the next bullet's. Without that line, from the host, check that the
     container reaches the host its `update check on` line names, here the default:
     `docker compose exec -T app python -c "import urllib.request as u; print(u.urlopen('https://api.next.loonsec.io/v1/update', timeout=5).status)"`
     prints a status, or ends `HTTP Error` with one, when it does; any other error is the
     network's answer, not the app's. Reached, the answer was not one the check reads: a proxy's
     page, a redirect (never followed), or a provider that is not LoonSec's. It asks again in an hour; when only the release it named could not be read, at the next daily check.
   - *Host* reads *UPDATE_CHECK_URL's unreadable address* → `UPDATE_CHECK_URL` in `.env` holds a
     value the check cannot read as an address, and the `update check on` line names it the same
     way. Correct it to a whole address, scheme and host included, or remove the line to ask
     LoonSec's update service, then run `docker compose up -d`.
   - *Owed now* under *Next check*, still there a minute later → no process runs the scheduler
     (`scheduler_enabled` is `true` on a container's `starting` line), or that container's log
     says `update check could not run` and why.
   - `update check unreachable` in the log names the provider-side failure and the
     check retries in an hour. **Redirect or proxy port outside the supported range:**
     correct the provider's redirect target or the port in `HTTPS_PROXY` / `ALL_PROXY`.
     **Proxy transport unavailable:** this build does not include SOCKS support; use
     an HTTP proxy or remove the unsupported proxy setting. **JSON nesting limit:**
     the provider or an intervening proxy returned an excessively nested response;
     correct its response format. **TLS trust store could not be loaded:** the file
     `SSL_CERT_FILE` names is missing, unreadable or not a PEM bundle; correct the
     mount or the path ([`splunk-setup.md`](splunk-setup.md) §5 builds the bundle).
     Addresses, proxy credentials and response text are
     withheld from these diagnostics. Recreate the container after changing its
     environment (`docker compose up -d`); a restart does not re-read `.env`. No route
     to the provider, or an answer that is not JSON (a captive portal's page), logs
     this line only at `LOG_LEVEL=DEBUG`: an offline or air-gapped instance meets it
     every hour, and *The update check got no answer it could read* above is its step-through.
   - `update check could not run: it could not read or save its database state` → check database health
     and connectivity. `update check could not run because of an unexpected internal failure` → report the
     error type, the stack locations logged with it (file, line and function only), and the
     build shown in Settings › Support. These leave the last stored answer in place;
     provider failures above instead store `unreachable` and the next hourly retry.
   - *The provider refused the check* → the container log says which, once per attempt.
     `update check refused (429) by LoonSec's update service` is that service's limit, shared
     by every instance: the check asks again in an hour, and there is nothing to change here.
     `update check refused by the provider` is GitHub's unauthenticated limit, 60 requests an hour per
     address, shared by everything behind this instance's egress address. Several
     instances behind one address use the budget up together; `UPDATE_CHECK=false` on all
     but one is the fix available today.
   - *No release named yet* → LoonSec's update service has read no published release yet, or a
     GitHub-shaped address has none published. The next daily check asks again; nothing to do.
     Still there a day after the Releases page lists one, from LoonSec's service: report it (§8).
   - *GitHub does not know this build's commit* → a local commit, a fork, or a branch that
     was never pushed. Build from a release tag and it is compared again.
2. **The notice names a release you believe you have.** From LoonSec's update service, this build's release
   is lower: build from the release's tag. From a GitHub-shaped `UPDATE_CHECK_URL`: *This build* ends in the commit it
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
4. **An install that pulls its images** (`docker-compose.pull.yml` in `COMPOSE_FILE`, in the
   `.env` beside `docker-compose.yml`) runs the release that `LOONINSPECT_VERSION` names there,
   whatever is checked out:
   - The notice stayed after the Updates block's steps → their build line has nothing to build
     on this install. Set `LOONINSPECT_VERSION` in `.env` to the release's tag, then
     `docker compose pull && docker compose up -d`.
   - `docker compose pull`, signed in to `ghcr.io`, stops at `not found` (some Docker versions
     say `manifest unknown`) → no image carries that tag. `v1.0.0` and earlier have none; the
     tag is spelled the way the Releases page spells it, `v` included; and a release's images
     arrive a few minutes after it is published. Correct `LOONINSPECT_VERSION` and pull again.
   - It stops at `unauthorized` (some Docker versions say `denied`) → the registry will not
     show this host the image. The two images are private, though the repository is public, so
     a pull needs Docker signed in to `ghcr.io` as a GitHub account the project has given read
     access to them (README step 4). Without a sign-in the registry gives this answer for
     every tag, one that does not exist included, so it says nothing yet about
     `LOONINSPECT_VERSION`. In order:
     - **Sign in on this host**: `docker login ghcr.io -u <your GitHub username>`, and at
       `Password:` a personal access token (classic) that carries `read:packages`, not the
       account's password. `Login Succeeded` is the answer to wait for; then pull again. A
       sign-in that worked before stops when its token expires or is revoked: make a new token
       and sign in again.
     - **Signed in, and still refused** → the account or the token cannot read the package. The
       account reads it only when the project has given it read access: the repository is
       public, so being able to open it on github.com shows nothing about the images. If the
       account has no such access, ask the project for it, or build from source as below. The
       token has to be a classic one with `read:packages`; this registry takes no other kind.
     - **Both hold** → check the names. `docker compose config --images` prints what it
       pulls: `ghcr.io/loonsecio/looninspect`, and with the bundled database
       `ghcr.io/loonsecio/looninspect-db` too (with the external one, the app alone), the tag
       after the colon. With those names and a tag the Releases page lists, the refusal is the
       project's: report it (§8) with the tag and the pull's output.

     Meanwhile, or on a host that cannot sign in, build the same tag from source: take
     `docker-compose.pull.yml` out of the `COMPOSE_FILE` line in `.env` and keep the rest. With
     the external database the line then reads `docker-compose.yml:docker-compose.external.yml`;
     deleting the whole line would start the bundled Postgres in place of your server. With the
     bundled one the line can go. Then
     `GIT_SHA=$(git rev-parse --short HEAD) docker compose up -d --build`; the volumes are the
     same.
   - `required variable LOONINSPECT_VERSION is missing a value` → `.env` has no
     `LOONINSPECT_VERSION` line. Add it, with the tag.
5. **A *Publish images* run timed out**: its page says *The job has exceeded the maximum
   execution time* (for whoever publishes the releases). That commit's images are missing, so
   a release of it has nothing to copy and step 4's pull stops at `not found`. A run that
   works takes under six minutes and the job stops at 45: the build hung.
   - **Re-run jobs** on the run's page. Each repository is checked and rebuilt on its own
     (#716): a run that timed out in *Build and push app image* published neither image, so
     the re-run builds both; a run that timed out later, in *Build and push database sidecar
     image*, already published the app image, so the re-run pushes only the database one.
     Either way the re-run publishes exactly what ECR is still missing; then re-run any
     *Release* run that failed for want of them, as its error says.
   - The re-run times out too → name the step it hung in. In *Build and push app image*, the
     last line of the form `#N [platform stage step/steps] …` whose `#N` never reaches `DONE`
     is that step, and a `qemu: uncaught target signal` line under the same `#N` means the
     emulator crashed there. #714's was
     `#43 [linux/arm64 frontend-build 4/6] RUN npm ci --no-audit --no-fund`. Open an issue
     with that line and the run's link.
   - **The "already published?" check itself is refused** (#694), before either build runs:
     *Check whether each image is already published* (or *Release*'s *Add the version tag to
     looninspect and looninspect-db*) fails with
     `::error::Checking whether <repo>:<sha> is already published failed …` (or, on
     *Release*, `::error::Asking ECR for <repo>:<sha> failed …`). That is not a missing
     image — the line printed just above the sentence is the AWS error the check could not
     get past. Check the push role's `ecr:DescribeImages` (`ecr:BatchGetImage` on *Release*)
     grant on the named repository, that the run's region is where the repositories live,
     and whether ECR is throttling (wait a few minutes and re-run). A genuine miss never
     reaches this sentence: it reads as not-yet-published and the build or the tag proceeds.
6. **A notice at the top of every page says the update check now asks LoonSec, or *Dismiss for
   everyone* leaves it up.** An instance that held an account when it was updated to v1.2.0 tells
   accounts that can change system settings, once, what the check now sends; a fresh install says it
   on the setup page instead and never shows this notice. It waits while the check is off or
   `UPDATE_CHECK_URL` names a GitHub-shaped address, and appears once the check asks LoonSec's update
   service. *Dismiss for everyone* clears it for every administrator, for good.
   - *Not dismissed: this instance refused it…* → this account lost the permission to change system
     settings after the page loaded. Reload: the notice is gone for this account, and an administrator
     who holds the permission dismisses it.
   - *Not dismissed: this instance answered with an error (HTTP …)* → try again; if it fails again,
     `docker compose logs app` (LoonInspect.app: `logs/backend.log`) at that minute says why.
   - *Not dismissed: no answer this page could read came back…* → the browser did not reach the
     instance, or something else answered for it, such as a proxy's page. Check that it runs
     (`docker compose ps`, or LoonInspect.app open) and that this browser reaches its address, then try again.
   - Dismissed, and back → the database went back to before the dismissal: a dump restored, or a
     downgrade below v1.2.0 and the update again. Dismiss it again.

**N.** The Updates block says a release is available while `git merge-base --is-ancestor`
says this build contains it, or, from LoonSec's update service, for a build of that release's
tag; or its sentence names a state this instance is not in.
Report the block's four lines (build, latest release, last checked, the sentence), the
`git merge-base` command and its output, whether `UPDATE_CHECK_URL` is set, and the
`update check` lines from `docker compose logs app --since 24h`.

## 11. "The Prompt bar is missing, or it answers *AI search unavailable*"

The Prompt bar is the box labelled **Prompt** below the deterministic filters on **Devices › Changes**. It
sends the typed question — nothing else — to the card picked in its **Model** list, which names
every card saved on **Settings › AI** and the model it uses. The model answers with filter
settings, and the page moves its filters to them and runs them. Two exceptions: an answer the
page had to correct in a way that searches wider waits for you to apply it, and text the model
judged not a question about changes runs nothing and is called invalid (both step 3).
The lines under the bar are written by the page from the matching rows, never by the model.
**Clear**, beside Apply, empties
every filter, the Prompt box and its answer. The bar appears only while three things are true,
and Settings › AI names the one that is not, in its line *Changes Prompt bar: …*. Every question
writes one row to the disclosure log naming the destination, the model asked for and the one
field that left, `query_text`.

1. **The bar is missing.** Read the *Changes Prompt bar* line on Settings › AI:
   - *hidden — the AI features flag is off* → Settings › Feature Flags, turn **AI features** on,
     then reload the Changes page.
   - *hidden — AI-inference consent is not granted* → grant it on Settings › AI.
   - *hidden — no provider is saved* → choose a card, fill it in, **Send** once to prove it
     answers, then **Save**. On the Apple card, *Apple's on-device model takes no reasoning
     effort …* means the request named one — a script, or a page from an older build; `fm serve`
     refuses any effort on its `system` model. Save the card again from Settings › AI, which
     sends none.
     *The Apple card uses only Apple's on-device model, system …*, under **Model** or after
     Send or Save, means the field names another: usually `pcc`, which `fm serve` also lists.
     That is Private Cloud Compute, which sends the prompt to Apple's servers. An admin saves
     the card again in Settings › AI with the model `system`.
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
   - *Connection refused*, *Connection failed* or *The endpoint's host name did not resolve* → the app could not
     open a connection to the saved Base URL; *refused* is nothing listening at its port. For
     Apple's model on the same Mac, on the Mac: `curl -s http://127.0.0.1:1976/health` prints
     `fm serve is running` when it is; if not, run `fm serve` in Terminal. From the container:
     `docker compose exec -T app python -c "import urllib.request as u; print(u.urlopen('http://host.docker.internal:1976/health', timeout=5).read())"`.
   - *HTTP 401 / 403* → check the saved key and its permissions. On the Apple card,
     `fm serve` also refuses a request that
     names another host. Keep the Apple card's Base URL on `host.docker.internal`: the app then
     presents `127.0.0.1`, which `fm serve` accepts. Any other address is presented as typed.
     Upstream error text is withheld because it can echo the saved key or prompt. Check
     the provider's service logs if the status and next check do not resolve it.
   - *The Apple card uses only Apple's on-device model, system …* → the Apple card was saved
     naming another model, usually `pcc` (Private Cloud Compute, on Apple's servers), by a build
     that allowed it. Nothing was sent, and the share log has no row for the question. An admin
     saves the card again in Settings › AI with the model `system`. The Vulnerabilities
     lever, the rule draft (§23) and exclusion ranking on Data Sharing answer the same sentence,
     and an inventory summary records `apple_model_refused`.
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
   was not applied*.** Not a failure, and nothing has run: the filters above the Prompt bar are
   still the ones you had. The model did answer with filter settings, but the page had to change
   one of them in a way that would match more than the model named. One of four things happened:
   - a name it gave for **Device search** or **Named-entry search** was dropped: it was not text, was
     longer than 64 characters, or held a character a name here may not;
   - it put a serial number in **Device search** that the question never named — often one from its
     own instructions — which was dropped;
   - it named a section, level or change the page does not have, which was read as *any*;
   - it added a field the page does not use and put a value in it, perhaps the name.

   Run as it stood, an answer that lost its name would list every added app rather than the one
   asked about, so a correction like that waits for you. A dropped **Device search** does not
   wait when the question holds one serial number in capitals, as Jamf writes it: the page
   fills Device search with it, and the answer runs. The
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
   plain name and matched no row. Typed into **Named-entry search** by hand, such a name still
   searches. The audit log records such an answer as
   `ai.changes-prompt.sent` with `outcome` `proposed`; an answer that ran says `applied`.

   **The answer leads with *Invalid question — the Prompt bar can't answer it, so nothing was
   run*.** Not a failure, and nothing has run: the filters above the Prompt bar are still the
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

   They arrive three ways: a link, the Prompt bar (which reads a Device search value the fleet has no
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
   mean nothing here. Change rows are kept for ever unless `CHANGE_LOG_RETENTION_DAYS` bounds
   them (README, *What this project prunes*), so a link made here keeps resolving over the rows
   the clock has left, and after a key rotation it keeps resolving over the rows from before the
   rotation. Press × on the chip to drop the filter, then find the person from a row.

   **Asking about a department in the Prompt bar.** "What changed on Macs in Engineering :
   Product?" works when Jamf's catalog holds that department's name. The model tends to read a
   department as the name of a profile and put it in *Named-entry search*, with *Section:
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
   holds no row for those filters: the bar matches names the way *Named-entry search* does, and
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

**A value's detail says “The previous value could not be read.”** Its read of earlier states failed:
the sign-in expired, the pod did not answer, or that state left this device's history. Use its Retry,
then reload the page; a card that then says “Device history could not be loaded” is the Retry step below.
“No different value in the 200 recorded states before this one” is that read's bound, not the start of
history: page back with *← Older* and open the detail on an older state to read further back.

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

Settings > Intelligence Access separates paid update access from upload consent. The
sidebar lists it, for accounts that can read system settings, where the instance offers
this preview or [contribution receipts](#contribution-receipts-622), and, for
administrators, while this organization holds a case (a coverage request or match
report) neither withdrawn nor expired, nor closed over 90 days ago
([§21](#21-request-coverage-or-report-an-incorrect-match-is-refused-or-a-case-never-shows-a-status)
step 9); Data sharing links to it where the preview or receipts are on. Otherwise, or
after a failed read (below), the entry hides and the page still opens at
`/settings/intelligence-access`. Activation and rotation are explicit administrator
actions; no MDM connection license is transmitted, and activation never enables
inventory sharing.

- The panel appears only with `INTELLIGENCE_ACCESS=true`,
  `VULN_RELEASE_RETENTION=true` and `VULN_TENANT_SELECTION=true`. All remain off by
  default. *Request coverage* and *Report an incorrect match* need a fourth,
  `INTELLIGENCE_SUBMISSIONS=true`, off by default even where those three are on
  ([§21](#21-request-coverage-or-report-an-incorrect-match-is-refused-or-a-case-never-shows-a-status)
  steps 1 and 9). Enable only for a reviewed pilot after Support's deployed IAM/privacy
  checks; this is not a v1.x rollout instruction. Configure `INTELLIGENCE_ENDPOINT`
  as the trusted HTTPS service origin, without a path, credentials or query. The
  default is `https://api.next.loonsec.io`, the production service on its interim
  name; set the operator-confirmed staging origin for a pilot against staging.
  `https://api.loonsec.io` is not yet that service and answers `403` until the name is
  reclaimed. Endpoint redirects are refused.
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
- **Expired/revoked/invalid credential:** new updates stop. A revoke clears the
  "updates authorized until" date, because the service revokes without one. Contact support about
  renewal, extension or replacement; local selection, assessments and historical
  evidence are not deleted. The next refresh observes renewal; do not toggle consent
  to recover paid access. Last reported access is cached service state, not a
  continuously verified entitlement.
- **"No paid-access service answers at … (HTTP 404)" or "… refused the request
  without an intelligence-service answer (HTTP 403)":** `INTELLIGENCE_ENDPOINT`
  names an address that does not serve the paid routes. A path may be included, the
  origin mistyped, or the service there not yet deployed with them. An image from before
  2026-09-25 defaulted to `https://api.loonsec.io`, which answers every path with 403
  until that name is reclaimed. Set the origin support confirmed (origin only, no path),
  recreate the container, then activate or Refresh now. An activation secret refused
  this way was not used.
- **"The intelligence service did not accept this activation secret (HTTP 401)":**
  the secret was mistyped (copy the whole `loon_act_` value), already activated once,
  expired unused, or revoked. Ask support for a new one; nothing was saved locally.
  When the sentence ends "Current paid access is unchanged", this instance was already
  activated: usually a second Activate with a secret the first one spent. The panel's
  state still says what access is in force; Refresh now clears the message.
- **"Paste only the one-time activation secret from support…":** what was entered is
  not the 52-character value that begins `loon_act_`, so nothing was sent and nothing
  was spent. Paste only that value from support's file. Surrounding quotes and spaces
  are removed automatically.
- **"… not serving paid access right now (HTTP 503)":** the service cannot answer
  for paid access. Its preview may be switched off, or its entitlement store or corpus
  may be unavailable. This is not an expiry or revocation. Retry later; contact
  support if it persists. An activation secret refused this way was not used.
- **"… rejected the request as outside its contract (HTTP 400)":** this build and the
  service disagree about the v2 request. Update LoonInspect, then contact support if
  it repeats.
- **"The entitlement changed while the service answered (HTTP 409)":** a staff change
  or a concurrent rotation raced the request. Retry.
- **"The intelligence service answered HTTP 5xx" (any other code) or "Could not reach
  the intelligence service at …":** a gateway failure, timeout, DNS or network
  problem. Check DNS and outbound HTTPS to the named origin, then retry. If the failed
  request was an activation or rotation, the service may have finished it before the
  reply was lost: when a retried activation is then refused with HTTP 401, ask support
  for recovery instead of trying again.
- **"Intelligence service returned an invalid reply":** the answer did not match the
  v2 contract. Retry, and report it to support if it repeats. None of these failures
  means expiry, revocation or zero vulnerabilities.
- Each failure above also writes `paid intelligence request failed` to the container
  log (`docker compose logs app`), with `operation` (`activate`, `rotate` or
  `refresh`), `reason` and the same sentence. Error text never quotes upstream bodies
  or bearer/capability values.
- **"Intelligence access could not be loaded. Reload or contact support.":** the paid
  panel's read of `GET /api/system/intelligence` failed, and this sentence stands in its
  place. The sidebar entry needs the same read, so it hides too once a reload fails, and
  the page stays at `/settings/intelligence-access`. Still there after a reload:
  `docker compose logs app --since 30m | grep '"/api/system/intelligence"'`. No line
  from the reload means the read never reached the app: it was restarting or
  unreachable, or [a proxy in front](#a-proxy-in-front-answers-for-itself) answered for
  it. A `"status_code": 200` means its answer never reached the page, so look at what
  sits between. A `"status_code"` of 500 or more is the app failing the read: report
  those lines (§8).
- **"The paid corpus could not be downloaded, verified or stored":** the container
  log's `vulnerability library` warning just before it names why (§5). Fix that, then
  Refresh now. **"The intelligence update could not be assessed":** check database
  availability and free storage, then Refresh now; the log line `paid intelligence
  update not applied` names the error type. Last completed paid refresh advances only
  after acquisition and assessment/selection succeed. Previous selections survive
  failed imports.
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
- **Where to read it.** Settings › Intelligence Access shows the receipt in its
  *Community contribution* panel, beside *Paid access*: whether one is held (never the
  receipt), its state in words, when the contribution was accepted, *Updates authorized
  until*, the last and next fetch with the receipt, the withdrawal's progress while it
  waits, and the last error sentence (`participation.error`). The panel needs receipts,
  not the paid preview, and the sidebar lists the page wherever receipts are on
  ([the whole rule](#paid-intelligence-preview-622)). The panel is absent where receipts
  are off, unless a receipt is still held or a withdrawal still waits. Those two do not
  list the page, so where nothing else does, open `/settings/intelligence-access`.
  - ***No receipt yet* after an exchange:** press Send now on Data sharing and read the
    payload of the row it shows (a `sent` row in the share log from after receipts were
    turned on serves too). Without `"participation_receipt": true` this instance did not
    ask: receipts are off here (the panel then says so), or `SHARING_ENDPOINT` is not an
    `https://` address free of a user name and password. With it, the service accepted
    the upload without issuing a receipt; its receipts may be off, so contact support. A
    `contribution receipt ignored` line in the container log means it sent one this build
    could not read (below).
  - ***Held, not in use*:** the receipt is inside its 30 days, and the line above the
    panel's list names what stops it: receipts off in this instance's configuration, or
    `COMMUNITY_SHARING=false`. It fetches nothing until that changes; a withdrawal still
    completes.
  - ***Past its deadline*:** the held receipt's 30 days are over, so it fetches nothing,
    and no accepted exchange has earned a newer one since. Data sharing's *Last exchange*
    says whether uploads are failing; when they are sent, the *No receipt yet* step
    applies.
  - ***Next fetch with the receipt* reads *None scheduled*** after an exchange that
    brought the corpus, and whenever the receipt cannot be used: a withdrawal waiting, its
    deadline passed, receipts or sharing off, or `COMMUNITY_SHARING=false`.
  - ***The contribution receipt's state could not be read. Reload the page; if it keeps
    failing, read docker compose logs app.*** in place of the panel: it reads the same
    status as Settings › Data Sharing, and that read failed without a reason. A refusal
    that gives one, such as *Insufficient permissions*, shows that sentence instead.
    Still there after a reload:
    `docker compose logs app --since 30m | grep '"/api/system/data-sharing"'`. No line
    from the reload means the read never reached the app: it was restarting or
    unreachable, or [a proxy in front](#a-proxy-in-front-answers-for-itself) answered for
    it. A `"status_code": 200` means its answer never reached the page, so look at what
    sits between. A `"status_code"` of 500 or more is the app failing the read: report
    those lines (§8).
- **Turning sharing off, or resetting the submission UUID,** stops uploads at once and
  marks the receipt `withdrawal_pending`. The scheduler sends the withdrawal within one
  tick, then retries every ten minutes until the service acknowledges it. `withdrawn`
  means the service invalidated every receipt this identity earned. `ended` means the
  receipt had already expired or was unknown to the service, so nothing was left to
  withdraw.
- **"Upload held: sharing was switched off earlier…"** appears as a failed share-log row
  with no payload; nothing left the box. Sharing was turned back on before the service
  acknowledged the earlier withdrawal. The withdrawal must land first, or it could cancel
  the receipt the new upload earns. The *Community contribution* panel it names shows the
  reason as its last error sentence (`participation.error`), and so does the container
  log's `contribution withdrawal not acknowledged` line:
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
  - The panel shows the last and the next redemption as *Last fetched with the receipt*
    and *Next fetch with the receipt* (`lastRedeemedAt` and `retryAfter` on the status).
  - `contribution receipt could not fetch the corpus` in the container log carries the
    same reasons as the withdrawal (HTTP 503, 404 or a bare 403, "Could not reach", 400)
    and changes nothing held.
- **Paid access beside a receipt.** Both can be present, and neither turns the other on
  or off: activating paid access never changes sharing, switching sharing off withdraws
  the receipt and leaves paid access in place, and *Stop paid updates locally* leaves the
  receipt. Each keeps refreshing on its own schedule: paid access once a day, the receipt
  only after an exchange that did not bring the corpus. Each selects the release it
  brings, so *Selected corpus* under *Paid access* is whichever arrived last. No request
  carries both the paid credential and the receipt.
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

## 20. "Sign-in asks for a six-digit code, or refuses the one I typed"

An account that enrolled a second factor (My Account, #653) signs in in two steps: the
password, then a six-digit code from the authenticator app, or one recovery code.
Setting one up and replacing its recovery codes, under *Two-step sign-in* on My Account, are
steps 8–14. Each refusal is quoted as it reads: the server's own sentence, or the page's where
the step says so.

1. **The code.** Six digits from the authenticator entry named *LoonInspect*, changing
   every 30 seconds; one code either side is accepted for a drifting clock, and a code
   that already signed you in is refused, because a code works once. Wait for the next.
2. ***The sign-in challenge has expired or is not valid.*** The second step has five
   minutes from the password step. Start again from the password.
3. **No phone.** A recovery code, shown once when the factor was confirmed, signs you in
   in place of the code; each works once, hyphens and case do not matter, and
   My Account says how many remain; its *New recovery codes*, for a fresh code from the phone,
   replaces all ten. With neither phone nor codes, another
   administrator removes the factor (step 7; a password reset does not), or reportable **X**.
4. ***Too many failed attempts.*** Wrong codes count against the same lockout as wrong
   passwords, for the same address and client. Wait it out; nothing to reset.
5. ***Your administrator requires two-step sign-in for this account.*** Every page opens My
   Account and says so there: the policy (Settings › Accounts) asks this account for a
   factor, and until a code confirms one only My Account's set-up, `/api/auth/me` and
   signing out answer. Set it up; that includes the administrator who turned it on.
   Still there once the recovery codes show? Save them, then reload the page.
6. **The break-glass account is not asked**, by design and under every policy: it is the way
   in when phones are lost. Its sign-in says `the policy exempts it` in the container log.
7. **An administrator removed my second factor** (Accounts › *Remove second factor*, never
   one's own; `auth.mfa.removed` in the audit log names who). Every session ended, and the
   old *LoonInspect* entry and recovery codes are dead: sign in with the password (step 5 if the policy asks).
8. ***Whether two-step sign-in is on for this account could not be read, which is not the same
   as off. Reload the page; if it keeps happening, LoonInspect is not answering, and
   Settings › Support says where to report that.*** The page's own sentence: the status read had
   no answer it could use, so the section offers neither *Set up* nor *New recovery codes*. Save
   any recovery codes still showing below it (step 12), then reload; the sign-in page instead
   means the session had ended, so sign in and come back. Still there while other pages answer:
   `docker compose logs app --since 30m | grep /api/auth/mfa`. No line from the reload means the
   read never reached the app, and a `"status_code": 200` means its answer never reached the
   page: either way, look at what sits between ([a proxy in front](#a-proxy-in-front-answers-for-itself)).
   A `"status_code"` of 500 or more: report those lines (§8).
9. ***That code was not accepted. Scan the QR code again, check the phone's clock, and type the
   current code.*** *Turn on* refused the code and keeps the QR code up; wrong codes here do not
   count toward step 4's lockout. Check, in order:
   - the code showing now, not one about to change;
   - the clocks: the phone's set to automatic time, and the server's, which
     `docker compose exec -T app date -u` prints in UTC, within half a minute of it. Further
     apart refuses some codes and a minute apart refuses every one, at sign-in too (step 1):
     set the clock of the machine the container runs on;
   - the entry: only the one this QR code made works, and an earlier set-up here left one that
     looks the same. Scan again, use the newest entry, and delete the stale ones. A key typed in
     by hand goes in as time-based, six digits, every 30 seconds;
   - still refused: *Set up* was pressed again in another tab or window, which replaced this QR
     code. *Cancel*, *Set up*, delete the old entry and scan the new QR code.
10. ***A second factor is already enrolled on this account. Remove it before enrolling
    another.*** (*Set up*) or ***There is no enrolment waiting for a code. Start one first.***
    (*Turn on*). The panel closes and the status is read again: set-up was finished after this
    page read it, in another tab or window, or by a *Turn on* whose answer was lost (step 11).
    The section reads *On since …*, and sign-in now asks for the code. Its recovery codes were
    shown once where it finished, or never: without them, *New recovery codes* now (step 3).
    You cannot remove your own factor (Accounts answers *You cannot remove your own second
    factor here. Ask another administrator to remove it.*): for a new phone, another
    administrator removes it (step 7), then *Set up*. If nobody you know set it up,
    `auth.mfa.enrolled` in the audit log has when and from which address: change your password,
    which signs out every other session, then have the factor removed. If the section reads
    *Off* instead, *Set up* again.
11. ***Not authenticated*** or ***LoonInspect's answer did not arrive or could not be read.
    Reload the page to see whether two-step sign-in is on, then try again.***, under any form.
    The first is the server's: this browser's session ended (signed out in another tab, idle
    past the session lifetime, an hour unless changed, or ended by a password change in another
    session or by an administrator). A reload shows the sign-in page; a set-up it cut short
    starts again with a new QR code, so delete the old entry. The second is the page's own: no
    answer came, or one without a sentence. The app was restarting,
    [a proxy in front](#a-proxy-in-front-answers-for-itself) answered for it, or the app failed:
    a `"status_code"` of 500 or more on its `/api/auth/mfa/…` line in
    `docker compose logs app --since 30m`, to report (§8). The request may have landed anyway:
    *On since …* after the reload means a *Turn on* went through unseen, and a
    *Replace my codes* whose answer was lost may have ended the old codes. Either way,
    *New recovery codes* now, with the next code.
12. **The recovery codes** show once, under *Two-step sign-in is on. Save your recovery codes
    now.* *I have saved these*, leaving the page or a reload drops them for good: save them
    before any reload a step here asks for. ***This browser refused to copy. Select the codes
    above and copy them yourself.*** is the page's own: the usual cause is a page served over
    plain HTTP at an address other than `localhost`, where browsers do not let a page copy.
    Select them by hand. Never saved: *New recovery codes* (step 3).
13. ***That code was not accepted: the current six digits from the authenticator app, each good
    once.*** *Replace my codes* refused the code. A recovery code does not work here, and a code
    already used, the one that just signed you in included, is spent: wait for the next. Step
    9's clocks apply. Each wrong code counts toward step 4's lockout, and this form shows its
    ***Too many failed attempts. Try again later.*** as well. ***This account has no second
    factor. Set one up first.***: no factor is on, so there are no codes to replace; reload, and
    the section offers *Set up*.
14. ***Two-factor enrolment requires a signed-in browser session***: an API token asked.
    `POST /api/auth/mfa/enrol`, `/confirm` and `/recovery-codes` (setting up, turning on and
    replacing recovery codes) answer only a signed-in browser, by design: a leaked token must not
    add a factor its owner does not hold. Sign in in a browser and use My Account.

**X.** Phone and recovery codes are gone, and no other administrator, break-glass included, can
remove the factor. Report the account's email (§8); the account keeps its data meanwhile.


## 21. "Request coverage or Report an incorrect match is refused, or a case never shows a status"

A case (#623) leaves under a key this instance keeps encrypted and never shows. The dialog behind *Request
coverage* and *Report an incorrect match*, on Posture › Vulnerabilities, shows each refusal as the server's
sentence. The case list on Settings › Intelligence Access, for administrators, shows each case's state, the
reviewer's note and its last failure as one sentence: `state`, `note` and `lastError` on `GET /api/submissions`,
and `submission case not settled` in `docker compose logs app`. A case reads `pending` (*Not yet received*)
until the service acknowledges it. The audit log has `submission.*` for each act.
The sentence is the last act's: a withdrawal's once `withdrawnAt` is set (step 8), else a send's while
`pending`, else a status read's. Where a step says to repeat the act, repeat that one: Send in the row's dialog,
*Refresh status* or *Withdraw* on the case list. A repeated Send reaches the same `pending` case only when every
field is the same, the optional URL, text and contact included. The dialog opens with those three empty, so a
Send with a different URL, text or contact makes a second case; on the case list, withdraw the one you do not
want. A line that ends *read docker compose logs app* means no sentence came back from this instance
(restarting, unreachable, or [a proxy in front](#a-proxy-in-front-answers-for-itself) answered for it): read
that log, then repeat the act.

1. **Refused before anything was stored.** *"…INTELLIGENCE_ACCESS is off here"*: submissions belong to
   the v2 preview, off by default ([Paid intelligence preview](#paid-intelligence-preview-622)).
   *"…INTELLIGENCE_SUBMISSIONS is off here"*: sending cases has its own switch, off by default even where
   the preview is on. Where this instance should send them, set `INTELLIGENCE_SUBMISSIONS=true` in the
   `.env` beside `docker-compose.yml`, recreate the container (`docker compose up -d`) and reload the page,
   then repeat the act.
   *"…give permission…"*: confirm the preview. *"…data-sharing exclusion list…"*: the one-time override
   sends this case only; the list stays. A 403: only an administrator sends, reads or withdraws a case.
   *"String should have at most 64 characters"* (or 256): the row's version, or its name or its bundle
   identifier, is longer than a case takes.
2. ***"…(HTTP 400). It said: …"***: the quoted sentence names the rule a field broke (a URL naming an IP
   address or a `.local` host; a hidden character is caught here first, step 10). The quote never repeats a
   case key or what was written in the URL, text or contact fields: those read *[case key withheld]* and
   *[withheld]*. Nothing was stored there:
   send a corrected case (the dialog's fields stay locked, so close it and press the row's action again), and
   withdraw this one on the case list. The dialog's own *Use an address that starts with https://…* is
   checked before any request: Preview stays off until the URL reads so.
3. ***"…HTTP 503. It said: "Submissions are not enabled…"***: the service has not opened submissions;
   repeat the act once support says it has. ***"…HTTP 503… Try again after … UTC"***: the day's 100
   new cases, shared by every instance, are spent; repeat the act after that time, under the case's key.
4. ***"…a fresh one (HTTP 409)"***: the key collided, and so did the fresh one minted in its place: **Y**.
5. ***"…HTTP 429"*** or ***"Asked too soon…"***: a case's status is read once a minute at most, and not
   before a time the service gave. Wait the seconds named; *Refresh status* counts its wait down.
6. ***"No submissions service answers at…"*** or ***"No answer came from…"***: check `INTELLIGENCE_ENDPOINT`
   (the HTTPS origin support confirmed), DNS, TLS (no proxy is taken from the environment, so an
   intercepting one fails) and egress to that host. Then repeat the act; a send goes again as the
   identical request.
7. **`received`, then nothing**: review is manual (`reviewing`, `needs_information` with the reviewer's
   `note`, `accepted` but not yet covered, then `declined`, or `published` with `release` and
   `coverage`). **`expired`**: the service deleted the case 90 days after it closed; ask again in a new one.
8. **`withdrawnAt` set while `state` is neither `withdrawn` nor `expired`** (the list's *Withdrawn here on …*):
   no answer has confirmed the withdrawal. The text, URL and contact are gone here and the case is never sent
   again, but the service may still hold them. Withdraw again (the service answers a repeat with 200), or, once
   past `pending`, ask for status: one that reads `withdrawn` or `expired` settles it too. Send is not the fix:
   it makes a new case, and what it carries leaves again.
9. **The *Request coverage* or *Report an incorrect match* action is not on the row.** Both are on
   Posture › Vulnerabilities only: the Catalog tab, a device's page, an application's record and the Lookup
   page show the same words without either. Both are for administrators (`SYSTEM_WRITE`), only while the v2
   preview is on (`INTELLIGENCE_ACCESS`, `VULN_RELEASE_RETENTION` and `VULN_TENANT_SELECTION`:
   [Paid intelligence preview](#paid-intelligence-preview-622))
   together with a fourth switch, `INTELLIGENCE_SUBMISSIONS`, off by default (step 1),
   and only for a build with a version on a platform the service takes: macOS, iOS, iPadOS, tvOS or visionOS.
   *Request coverage* is on a row that page's *Outside the corpus* chip lists (`unknown_app`). *Report an
   incorrect match* is on a row with findings while the heading reads *Vulnerability corpus as of …*: the page's
   answer then names the release behind them (`corpusRelease`), which the report sends. While the preview is
   off the case list stays on Settings › Intelligence Access, to refresh and withdraw, and the sidebar keeps the
   entry for administrators while a case is neither withdrawn nor expired, nor closed (`closedAt`) over 90 days
   ago (`casesToWithdraw` on `GET /api/system/intelligence`), or where contribution receipts are on; with
   neither, the entry hides and the list stays at `/settings/intelligence-access`. The service deletes a case 90
   days after it closes (step 7), so once a case expired or closed that long ago a withdrawal has nothing left to
   delete there, and the nightly cleanup clears what was written on it here (step 11).
   With the preview on and `INTELLIGENCE_SUBMISSIONS` off, the entry and the case list stay, and the list says
   *New cases cannot be sent…*.
10. ***"…has U+200B at character 12, which a case cannot carry…"*** (any code point, any place), under a
    field of the dialog while *Preview* stays off, or as Preview's or Send's refusal: that field holds a
    hidden character, and nothing has left this instance. A case carries no format character but the joiners
    U+200C (inside Persian and other words) and U+200D (inside emoji sequences), no unpaired surrogate, no
    line or paragraph separator, and no control character, though `text` may carry newline and tab; the
    service refuses the same. Such a character usually comes with pasted words: a zero-width space (U+200B),
    a direction mark or override (U+200E, U+202E) or a soft hyphen (U+00AD). In `text` or `contact`, delete
    it: the place counts code points from 1 (a plain emoji is one), and retyping the words around it works too.
    *Preview* comes back once no field names one. In `app_name` or `bundle_id` (*"…It comes from the
    inventory…"*), the character is in the build's name or bundle identifier as the inventory reports it,
    which the dialog cannot change, so no case can name that build. *"…is blank…"*: a request made outside
    the dialog sent a field of only spaces, tabs or line breaks; the dialog leaves such a field out.
11. **A case's URL, text and contact are gone (`null` on `GET /api/submissions`), and the case is still
    listed.** This instance keeps what was written on a case no longer than the service does: 90 days after
    the case closed (`closedAt`, once it reads *Declined* or *Published*), or once it reads *Expired, deleted
    by the service*, the nightly cleanup clears those three here. The app, versions, state, dates, `release`,
    `coverage` and the reviewer's note stay, so the case list, which never shows the three, looks the same.
    `docker compose logs app` has one line a night for each organization, *cleared the URL, text and contact
    of submission cases closed over 90 days ago or expired*, with its `count`. *submission cleanup failed for
    this tenant…* means that night cleared nothing: check `docker compose ps db`; the next night tries again.
    The clock runs from a closing this instance has read, and nothing asks the service on its own, so a case
    that closed while nobody pressed *Refresh status* keeps its words here until someone does: press it on a
    case whose answer is long overdue. One the service has already deleted then reads *Expired…*, and its
    words go the next night.

**Y.** Random keys do not collide twice. Report the case's `id` and its sentence (§8); nothing was stored there.

## 22. "Patch policy is not in my sidebar, an app cannot be picked, or its file was refused"

Posture › Patch policy (#614, first slice) is a **reference analysis**: one hypothetical Mac that
runs one app, replayed against public CVE records under each stop of a patch-policy slider. It is
not this organization's exposure. It reads no inventory, sends nothing, and stores nothing. The page
is at `/posture/patch-policy` and needs **app:read**, which every role holds.

The page has two modes. Once LoonSec's patch-policy data (§32) is held for this organization, it
walks that data day by day, with a source toggle (Public, Jamf, Fleet) and a day graph: that page is
§33. Until then it draws the **reference replays**: files that ship inside the build, the same for
every organization, each naming the public release record its dates come from. This path is about
the replays, and step 11 about how the page chooses between the two.

1. **The entry is not in the sidebar.** It is listed under Posture, last, for every account that
   holds **app:read**, with nothing to switch on. An administrator checks Settings › Feature Flags:
   if it still lists **Posture › Patch policy (reference)**, the instance runs an older build that
   lists the entry only while that flag is on, so turn it on and reload (§18 step 3), or update the
   instance. If the flag is not listed, a missing entry means the account lacks app:read:
   `GET /api/auth/me` lists the account's permissions. The address opens either way for an
   account that holds it, so a link somebody sent still works.
2. **Only a few apps can be picked; every other app reads *No reference replay yet*.** Not a fault.
   An app is selectable once a replay file for it ships with the build. *No reference replay yet*
   means nobody has replayed that app. It never means the app has no vulnerabilities, and the page
   prints no count for it. Firefox and Thunderbird are replayed on their release channel only: an
   ESR title shares its app's bundle ID, so the list shows it under that app's row, and the page
   says *… ESR is not replayed yet*. If no app can be picked and the page says *No reference
   replay ships with this build*, the build carries no replay file at all: that is reportable state
   **Z**, below.
3. **The list has only the apps with a replay, under a sentence about Jamf's patch catalog.** The
   other rows come from the Jamf Patch titles this instance has synced, and the sentence says which
   of two things happened. *…holds no titles on this instance yet…* → no catalog refresh has
   finished. The refresh runs at the top of every hour and needs no Jamf Pro connection: that is
   §6. *…could not be read… a failed read, not an empty catalog* → the list request failed;
   `GET /api/jamf-patch/titles?pageSize=1` says with what status. A `403` is an account without
   `app:read`; anything else is §4. The replay itself does not need the catalog and is drawn
   either way.
4. **Where the replay would be, the page says *The reference replay for … is not shown, because its
   file was refused*.** The page checks the file before drawing any of it and refuses it whole, and
   the next sentence is the reason:
   - *The file did not load, or what loaded is not a replay* → the browser could not fetch the
     file's chunk, usually a page left open across an update of the instance. Reload.
   - *Its kind is …* or *Its schema is …* → the file is another kind of document, or a version of
     the replay this build does not read. *Its schema is 1, the earlier replay format…* is a file
     with no `timeline` block, the part of the file this page reads to name and link where its
     release dates come from; this build reads only replays that have one.
   - *Its CVE clock is …* → the file places each CVE on a clock other than NVD's publication date
     (its `cve_clock` is not `published`). The page's words state that one clock, so the file is
     refused rather than drawn under words that would misstate it.
   - *It lacks …* → a value the page draws is absent from the file; the sentence names it. A file
     must name its release-date source (`timeline.name`), say what one of its dates means
     (`timeline.clock`) and when that source was fetched (`timeline.fetched_at`), state its CVE
     clock (`cve_clock`, defined in `clocks.published`), and say which release line the Mac is
     held to (`branch_choice.held_at_branch`).
   - *Its own totals disagree (…)* → the file's counts do not add up, in the file's own key names:
     for every policy, `never_seen` plus `exposed` is `counts.cves_replayed`; the excluded counts
     sum to `counts.cves_excluded`; and the per-CVE rows count to the same totals as the headline.

   Reload once. None of the last four can be fixed on the instance, because the file is part of the
   build and no setting or data of yours is read: the same sentence after a reload is reportable
   state **Z**, below.
5. **The numbers differ from another copy of the same analysis.** Compare the **Run** line under
   *Evidence*: it is the replay's own identifier, and two pages showing the same run show the same
   numbers. A different run is a different release record, a different window, or a later read of
   NVD's records. *Evidence* prints the first two: the window, and the record's fetch time and
   SHA-256 under *Release dates*. It does not print when NVD's records were read, so two runs whose
   window and release record match differ by that read. Not a fault of the instance.
6. **A date looks a day or two off the vendor's own release notes.** Every release date on this page
   comes from the release record that *Evidence › Release dates* names and links, and the line
   under it says, in the file's words, what one of its dates means: for example the first day a
   build was served, or the date of a release tag. A record of that kind and a release note can
   differ by a day or two. *Definitions and clocks, in the file's own words* at the foot of the
   page states each clock and each counting rule.
7. **A CVE is counted from a day before NVD said which versions it affects.** The page's CVE clock
   is NVD's publication date, and it says so twice: in the box at the top of the replay, and under
   *Evidence › CVE clock*. Each CVE counts from the UTC day NVD published it, even when NVD named
   the affected versions days later, so a Mac can be counted exposed on a day NVD's record could
   not yet have matched the CVE to it. That is the clock the page states, not a fault.
8. **One replay ends earlier than the others** (*This replay ends on …, before the … it was asked
   to reach*). The file cut its own window short rather than count days it could not date, and
   *Evidence › Window* prints its reason in the file's words. Google Chrome's is the usual case:
   its Mac installs a new major version no earlier than the day Google promotes it to stable, so
   its window stops the day before a major whose promotion day had not been read when the file
   was made. A later build carries a later file. Not a fault of the instance.
9. **The newest weeks replay few CVEs, and many are excluded as *NVD has not yet listed which
   versions are affected*.** NVD often publishes a CVE before it lists the versions the CVE
   affects. A CVE in that state cannot be placed, so it is excluded and counted in the *Excluded*
   table, never guessed; excluded is not safe. A later file replays it only if NVD has listed its
   versions by then, and the list of excluded CVEs says what to expect in its *NVD status when the
   file was made* column. *Awaiting Analysis* and *Undergoing Analysis* are records NVD has received
   and not finished. *Deferred* is NVD's mark for a record it does not plan to prioritize for that
   work, so it may stay excluded; in the files this build ships, most of Firefox's and
   Thunderbird's exclusions of this kind are *Deferred*. *Analyzed* is a record NVD finished without
   listing a version of this app. Not a fault of the instance.
10. **A CVE's *Fix* cell lists several fixes, some dated long before the CVE.** NVD can state
    several affected ranges for one CVE, for example one for each Firefox ESR line beside the
    release channel's, and the replay gives each range its own fix: the first release on this
    replay's release timeline at or past the range's end. Each fix is printed with the range it
    closes, in NVD's bounds. The one that matters to this Mac is the range its versions fell in,
    which the file has already judged: the *Outcome* beside it names the release that cleared the
    CVE, where one did. Not a fault of the instance.

11. **The page opens with a sentence about LoonSec's patch-policy data, then draws a reference
    replay.** The page asked this instance for LoonSec's data first (`GET /api/patch-policy/apps`)
    and is drawing the replays in its place. The first sentence says which of two things happened:
    - It is the same sentence Settings › Support › **LoonSec patch-policy data** shows, followed by
      *…Until this instance holds LoonSec's data, this page shows the reference replays that ship
      with this build instead…* → no copy of LoonSec's data answers for this organization: data
      sharing is off (nothing arrives until it is turned on), nothing has arrived yet, or every copy
      was refused. §32 walks that sentence. Once a copy is held, the page walks it on the next load
      (§33).
    - *The state of LoonSec's patch-policy data could not be read from this instance (…)* → the request
      failed, which is not missing data. The bracket gives what answered: `HTTP 403` is an account
      without **app:read**; *no answer* is a container that did not answer, which is §4; any other
      status, with the container up, is reportable state **AE**.

    Either way the replay underneath is complete and correct on its own terms. Nothing on this page
    mixes the two: a replay is never drawn under the walk's words, or a walk under the replay's.

**Z.** A reference replay that shipped with the build is refused, and reads the same after a reload,
or the page says no reference replay ships with the build. Report the page's sentence as it is
worded, the app that was picked, and the build from Settings › Support (§8). Nothing of the
organization's is involved, so there is no run or log to attach.

## 23. "Out of policy is missing, a title is not judged, or the rule draft fills nothing"

Devices › Applications › Jamf Patch judges devices against the **confirmed rules** under the
stated patching policy, and against nothing else. The statement is text for a reader and judges
nothing ([`jamf-patch-matching.md`](jamf-patch-matching.md) §8). A rule has three limits: a newer
release listed for more than *N* days; a shorter *N* for a build that carries a critical or high
finding; and more than *N* newer releases listed. Any one exceeded puts a device out of policy on
that title. Reading needs **app:read**; confirming a rule, a title's
own rule, or drafting one needs **system:write**.

1. **There is no *Out of policy* column on the list.** No rule judges any title: *Confirmed rules*
   reads *No rule is confirmed*. Press **Confirm a rule** there. The button is absent for an account
   without `system:write`. `GET /api/settings/patching-policy` answers `rules.default: null` and
   `rules.overrides: []` in this state.
2. **A row reads `—` under *Out of policy*.** One of three things, and the row says which. *Devices
   with app* is `0` → no device has an app matched to the title, so there is nobody to judge (§6
   covers a title that is never matched). Only *titles with their own rule* are listed under
   *Confirmed rules* and this is not one → no organization-wide rule is confirmed, and this title has
   none of its own. A row reading **exempt** is a title somebody exempted: it is not judged, and it
   is not counted as within policy either.
3. **A title's number differs from *Devices with app* minus *Devices on latest*.** It should. Out of
   policy counts only devices whose installed version Jamf lists and that are **behind** by more than
   the rule allows. A device ahead of the catalog (a beta, an auto-updater) is within policy. A
   device on a version Jamf does not list and that is not ahead reads *Not judged: Jamf does not list
   this version* on the title's page, and is in neither count.
4. **A version reads *Out of policy since …* and looks too early or too late.** The date is the
   release date Jamf's patch catalog gives the first version newer than that one, plus the rule's
   days. It is the catalog's clock, not the vendor's release notes and not when a device last
   checked in. The title's *Version history* table has the release dates it was computed from.
5. **A build I know has critical findings was given the longer limit.** The limit for critical
   and high findings applies only to a build the vulnerability corpus has assessed. Two readings:
   - Under *Confirmed rules*, or in the title's *Patching policy* card: *No vulnerability corpus is
     answering for this organization…* → nothing is assessed, so every build is judged by the
     ordinary limit. §5 is the path for a corpus that is not answering.
   - The version's *Policy* cell ends *the corpus has not assessed this build, so the ordinary limit
     applies* → the corpus is answering and holds no row for this build; its *Vulnerability* cell
     reads *Outside the corpus*. That is the corpus's edge, not a fault here.
6. **A title is judged by a rule I did not expect.** The title's page says which under *Patching
   policy*: *Judged by the organization's rule*, or *This title has its own rule, in place of the
   organization's*. A title's own rule replaces the organization's whole rule for that title; it
   does not merge with it. **Use the organization's rule** removes it.
7. **Saving a title's own rule answers *No Jamf Patch title has the id …*.** The catalog no longer
   lists that title. Open the title from the Jamf Patch list rather than from a saved address; if
   the list is empty, that is §6.
8. **There is no *Draft from the statement* button.** It is drawn in the rule editor only when all
   of these hold: the account has `system:write`; a policy is stated; **AI features** is on
   (Settings › Feature Flags); **AI inference** consent is on (Settings › Data Sharing); and a
   provider is saved (Settings › AI). `GET /api/settings/patching-policy/rule/draft` answers
   `reason: flag_off`, `consent_off` or `no_provider` for the first one that is off. §11 and §13 are
   the same three switches. The two boxes work without it.
9. **The draft left a box empty, or both.** Read the lines under the boxes. Each is one of these:
   - *The model proposed N …, which the statement's own words do not state* → the model answered
     with a number that is not in the statement. The draft keeps only numbers the statement states,
     so the box is empty. Type the limit you mean.
   - *…which the statement gives only for critical, high-severity, exploited or emergency updates*
     → the model put a special case's time in the ordinary box. It is not kept there.
   - *The statement gives critical and high findings different times* → a rule has one limit for
     both. Type the one you mean; the shorter is the stricter.
   - *The statement gives N days for … and that box is empty. Type it if it is the limit you mean*
     → the draft found the number and will not choose it for you.
   - *The statement states no number of days or versions in words the draft reads* → the statement
     has no number, or states it in a phrasing or a language the draft does not read. It reads
     English, and numbers written as digits or as the words one to twelve, fourteen, fifteen,
     twenty, thirty, sixty and ninety, before *hours*, *days*, *weeks*, *months*, *quarter* or
     *year*.
10. **The draft answers *The stated policy does not read as being about keeping software up to
   date*.** Either the model judged it so, or the statement has none of the words a patching policy
   uses (update, patch, version, release, software, app). Nothing was drafted and nothing was saved.
   Type the limits yourself, or reword the statement and draft again.
11. **The draft answers *The model's answer was not a rule draft*, or names an endpoint failure.**
    The provider answered something that is not the two limits, or did not answer. Settings › AI
    has the provider's own test box; §11 covers an endpoint that cannot be reached. The audit log
    records each draft as `ai.patch-policy-rules.sent` with its `outcome`.

12. **A rule shows no *Drawn from …* line although it was started from a published requirement.**
    The line is kept only while the rule is that requirement's own, limit for limit. A box changed
    before Confirm, or the rule edited since, makes it the organization's own rule with no source
    recorded; the editor says so before Confirm (*The boxes no longer say what this requirement
    says*). Start again from the requirement and confirm it unchanged. Saving through the API with
    a `basis` the limits do not match answers *…cannot be recorded as drawn from it*.

Nothing a draft returns is saved. A rule exists only after **Confirm**, which the audit log records
as `patching-policy.updated` with the limits.

## 24. "The change log keeps growing with `CHANGE_LOG_RETENTION_DAYS` set, or the Changes page lost history"

The change log has one clock, off by default (#785, [`change-log.md`](change-log.md) §6). Both
complaints are the same check run in opposite directions.

1. **What the running process read.** `docker compose logs app | grep change_log_retention_days`
   prints the `starting` line with the value in force. `0` → the clock is off and nothing is
   deleted, whatever `.env` says now: the app reads it at start, so `docker compose up -d` after
   editing `.env`. A number you did not set → it is set in `.env` beside `docker-compose.yml`, or
   in the pod's task definition; that is where a lost history came from.
2. **Did last night's purge run?** `docker compose logs app | grep "change-log"`:
   - *purged old change-log rows* with `count` and `retention_days` → it ran. Disk not given back
     is expected: the purge keeps the table from growing past the window, and the pages it frees
     are reused by the next day's rows ([`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) §1 has the
     `VACUUM FULL` that returns them, and its lock).
   - *change-log purge failed for this tenant* → the line names the next check: the database
     container's health and free space (§4, [`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) §3). Nothing
     was deleted for that tenant that night; the run and alert purges still ran.
   - neither line, and the value is set → either no row was old enough yet (the first night
     deletes only what is older than the window), or no process with the scheduler was up at
     02:50: `docker compose logs app | grep scheduler_enabled` — a web-only process
     (`SCHEDULER_ENABLED=false`, [`operations.md`](operations.md) §7) purges nothing.
3. **Rows that are gone are gone.** The clock did what it was set to. The observation ledger still
   holds the evidence those rows were derived from, but the Changes page does not re-derive, and
   the artifact search reads only the rows that remain. A dump from before the purge is the way
   back ([`operations.md`](operations.md) §3); set the value you meant before restoring it.

## 25. "LoonInspect.app will not open, or opens and says it could not start"

The macOS app ([`macos-app.md`](macos-app.md)) is the container's backend, frontend and
PostgreSQL running as child processes of a small shell, on one Mac. Its database and service logs
are under `~/Library/Application Support/LoonInspect`: the database in `pgdata`, and in `logs` the four
files every sentence below names. **LoonInspect › Show Logs in Finder** opens that folder, and
**LoonInspect › About LoonInspect** shows the version and build number a report needs.
**Help › Using LoonInspect on This Mac** explains the local instance, network connections, the
daily update check and manual updates. The startup screen names its current phase; a failure offers **Show Logs** and
**Quit**. Read the failure before quitting, correct its cause, then reopen the app.

**Maintainer: build or notarization fails.** In Actions, open **macOS release** and the failed
step. The same script messages appear in a local terminal.

If `could not sign` names a bundled executable, read the `codesign` diagnostic immediately
above it. A missing identity or `errSecInternalComponent` can mean the signing keychain is
locked, missing from the keychain search list, or its private key does not permit `codesign`.
The Action unlocks its temporary keychain, adds it to the search list for the job, and restores
the original list during cleanup. A timestamp-service or network error calls for checking
Apple/network availability; changing Apple-ID notarization credentials does not fix code signing.

- *uv 0.9.30 is required* → install the exact native exporter named in `macos/README.md` and
  put it on `PATH`. Docker is no longer needed to export dependencies.
- *not on main*, *versions differ*, or *tag does not match* → run the workflow from main, and
  give it a tag whose version is the one `Info.plist` and backend `RELEASE` both name (a
  candidate adds `-rc.N`). Fix versions in a pull request; do not move a published tag.
- *is already published*, *already names* (the tag is on another commit), or *was made from*
  (a draft from another commit) → the tag given to the run cannot be used as it stands, and
  nothing was uploaded. A published release takes no more files, because this repository's
  releases are immutable, and a published tag never moves: run **macOS release** again from
  main with the next version (after a candidate, the next `-rc.N`). A stale draft is the one
  case with another way out: delete it under **Releases** and run again. *There are N drafts
  named…* → delete all but the one you mean to keep, or all of them, and run again.
- *was published without LoonInspect-…* (the **macOS release** run a publication starts) → the
  release was published before the Mac app was on it, usually because it was created
  directly instead of from the draft the workflow makes. Nothing can add the files now. The
  container images are not affected. Publish the next version from a draft: run **macOS
  release** from main with that tag, read the draft it makes, and publish that
  (`macos/README.md`, GitHub Actions).
- *was published with … still marked to be filled in at the tag* (the **macOS release** run a
  publication starts) → the release's notes kept lines meant to be filled in before
  publication, and the error lists each one beneath it, by its line in the notes. Unlike its
  files, the body of an immutable release can still be edited: under **Releases**, edit that
  release, fill in each line (a `Release commit:` line takes the commit the tag names), save,
  and re-run the failed job, which reads the notes again.
- *the question went unanswered* → GitHub did not answer the job, which is not the same as
  there being no release or no tag; the line above it is GitHub's own error. Nothing was
  uploaded. Re-run the failed job; if it says so again, check GitHub's status and that the
  **draft** job still has `contents: write`. In the draft run's notice, about `Publish images`,
  the same words are not a failure: the draft is ready and only that question went unanswered.
  Check that the **draft** job has `actions: read`, and before publishing look under
  **Actions › Publish images** for a successful run of the commit.
- *do not match their SHA256SUMS* (the **draft** job) → the built files changed between the
  build job and the draft job, so nothing was uploaded. Run the workflow again.
- *GitHub refused the draft release*, *refused the files*, or *does not hold … whole* → the
  release is still a draft and nothing is published. Run the workflow again with the same
  tag: a second run of the same commit replaces the draft's files. If the refusal names a
  repository rule, the draft job has been asked to create a tag, which it never should: read
  the line above the error and report it (§8).
- *clean checkout* or *modified tree* → commit all intended inputs, including new files, and
  rebuild from that commit. Do not use `ALLOW_DIRTY` to publish a release.
- *Missing MACOS_CERTIFICATE…*, *exactly one Developer ID…*, or *not signed by team…* → check
  the `macos-release` environment secrets. The P12 must include the private key and a Developer
  ID Application certificate for `6CWZ5GA79H`; check its export password and expiration. A
  developer/Apple Development certificate is not a Developer ID distribution certificate.
- *could not authenticate*, *No Keychain password item*, or a failed **Import signing…** step
  → check that `APPLE_NOTARY_AUTH` selects `apple-id` or `api-key`, then check the selected
  credentials: the API key ID and issuer (omit issuer for an individual key), or the Apple ID's
  app-specific password, and Apple team access. For a local profile, run the credential command
  in `macos/README.md` again. A CI run waiting before any steps needs its environment access
  checked: allow main and `v*` tags and satisfy any configured reviewer requirement.
- *Apple answered Invalid/Rejected* → download the `macos-notarization-…` artifact and read
  `notarize-app.log` or `notarize-dmg.log`. Locally those files are under `macos/build`. Apple
  identifies the file and missing signature, runtime option or timestamp; fix and rebuild.
- *submission … is not accepted*, a timeout, or an upload error → retain `notarize-*.json`.
  An ID means Apple received the submission; the script prints an `info` command to check it.
  CI deletes its temporary keychain, so use the ID with your **local** notary profile instead.
  If Apple still reports `In Progress`, wait and check again. If there is no ID, check the
  authentication/network error and retry. Rerunning the script uploads a new submission.
- A **stapler** or **spctl** failure after acceptance → no draft was made and no file uploaded.
  Check the named file, verify its signature with `codesign --verify --strict`, and retry after
  resolving any Apple network error. Do not publish an artifact from a failed verification.
- *do not match the SHA256SUMS published beside them* (at publication) → do not point anyone
  at that release's disk image. Compare the three files with the `LoonInspect-…-arm64`
  artifact of the run that made the draft, which is kept for 14 days; nothing can replace a
  published file, so publish the next version from a fresh draft.

1. **macOS refuses to open it** — *"LoonInspect" can't be opened because Apple cannot check it for
   malicious software*, or *is damaged and can't be opened*. Ask Gatekeeper what it thinks, in
   Terminal:

   ```
   spctl --assess --type execute --verbose=2 /Applications/LoonInspect.app
   ```

   - `accepted` … `source=Notarized Developer ID` → the copy is fine; the message was about the
     disk image or a download that did not finish. Eject the image, copy the app again, open it.
   - `rejected` … `source=Unnotarized Developer ID` → a Developer ID build that Apple has not
     notarized: a build that skipped `macos/scripts/notarize.sh`. Not a release; ask for the
     release's disk image, whose image and app both carry a stapled ticket.
   - `rejected` … `source=no usable signature` → an ad-hoc build copied from the Mac that built
     it. It runs only there. Build it on this Mac, or use the release's disk image.
   - `rejected` … `source=obsolete resource envelope`, or `codesign --verify --strict --deep
     /Applications/LoonInspect.app` names a file → the bundle was modified after it was signed
     (a file edited or added inside it). Copy it from the disk image again.

   Removing the quarantine attribute by hand opens an unnotarized build; it is not the fix for a
   release, and it is not what a release needs.

2. **The window reads "LoonInspect could not start"**, and a sentence under it. The sentence says
   what failed and names the log that says why. `logs/shell.log` holds the order of events,
   one line each, and the sentence is its last `ERROR` line.
   - *Another LoonInspect is already running from …* → there is one, with or without a window.
     Activity Monitor › LoonInspect; quit it, then open this one. The lock is held by the running
     process itself, so nothing stale can hold it after a crash.
   - *The database in … exists, but ENCRYPTION_KEY is missing from the login keychain (service
     LoonInspect)* → the data directory survived something the keychain did not: a new Mac from
     a file copy, a keychain reset, a user account migrated without its login keychain. The three
     items (`ENCRYPTION_KEY`, `postgres-looninspect_app`, `postgres-looninspect`, service
     `LoonInspect`) come back from a keychain backup, and from nowhere else; `macos-app.md` ›
     Backup is why the key is part of one. Without them, the only start is empty: move
     `~/Library/Application Support/LoonInspect` aside and open the app again, and the
     connections, the ledger and the users in that directory are gone with it.
   - *Reading ENCRYPTION_KEY from the login keychain failed (security exited …). Check that the
     login keychain is unlocked.* → Keychain Access: the login keychain is locked, or is not the
     default. Unlock it and open the app again.
   - *First launch could not create the database: initdb exited …* (or *CREATE DATABASE*, or
     *application role*) → `logs/initdb.log` holds the tool's own output under a `==` line. The
     two causes seen: no free disk, and a support directory this user cannot write (a restored
     folder owned by another account). Nothing was kept; fix the cause and open the app, which
     starts the first launch over.
   - *Postgres exited while starting (status …). Its log is …/postgres.log; the last lines:* →
     the lines are the answer. *No space left on device* is KNOWN_ISSUES.md §3 on a laptop;
     *lock file "postmaster.pid" already exists* with a PID that is alive means a Postgres from
     an earlier session the shell could not stop; quit it from Activity Monitor and open the app
     again.
   - *Postgres did not report ready within 60 s* → a disk so slow or so full that recovery after
     a crash did not finish. `postgres.log` says *redo in progress*; wait for it to end, then
     open the app again.
   - *The backend exited while starting (status …). Its log is …/backend.log; the last lines:* →
     `backend.log` is the container's JSON log, line for line. The last line whose `level` is
     `ERROR` names the failure as §4 names it for the container; a migration that failed says
     which revision, and §4 step 3 applies as written.
   - *The backend did not answer /api/health with 200 within 180 s* → a first launch runs every
     migration, and later launches run the new ones; 180 s is many times what either takes
     (`macos-app.md` › Measurements). `backend.log` says what it was doing. Report it, with the
     last 50 lines of `backend.log` and all of `shell.log`.
   - *The database socket would be …, N bytes, and macOS allows 103 for a Unix socket path; the
     fallback /tmp/io.loonsec.looninspect.<uid> exists and is not a directory owned by this user*
     → a long home directory path sends the socket under `/tmp`, and something else holds that
     name. The sentence says what to remove.
   - *postgres exited unexpectedly* or *backend exited unexpectedly (status …)*, after it was
     running → the named log's last lines, then quit and open the app again, which starts both.
3. **The window stays on the startup screen or is blank.** If startup is still running, check
   its phase and the log it names; first launch includes database preparation and migrations.
   Once the local server is ready, **View › Reload Window** (⌘R) loads its local app address again,
   including when the window currently shows an error page. If that does not help,
   **LoonInspect › Open in Browser**: the same page in Safari means the server is
   up and the window is what failed, which is WebKit's and worth a report with `shell.log` (its
   *window shows* line says what the page reported). The port is in `run/port` under the support
   directory, and `curl http://127.0.0.1:$(cat ~/Library/Application\ Support/LoonInspect/run/port)/api/health`
   answers `{"status":"ok"}` when the server is fine.
4. **Setup asks for a claim token.** The page was opened in a browser rather than in the app's
   window. Setup is meant to happen in the window, which holds this session's token; in a
   browser the token is the *claim token* line of `logs/backend.log`, as it is for the container.
5. **After putting an older app back, it will not start, and `backend.log` names a newer
   database.** The same rule as the image ([`operations.md`](operations.md) §5): an app that finds
   a schema revision it does not carry reads the database's release record. *…so it starts
   without migrating* is not a failure: the record says this release can read the schema, as
   1.0.0 can read what 1.1.0 left. *…so it will not start on it* names two releases, the one the
   database needs and the one this app is (`backend_release` in
   `Contents/Resources/build-manifest.json`): put the later version back, or restore the copy of
   `pgdata` taken before the update ([`macos-app.md`](macos-app.md#backup)).
6. **Reinstalling still asks for the old account, or says the email/password is incorrect.**
   Replacing or deleting the app leaves its local database and account intact. Use the account
   created on this Mac; a different installation's password does not automatically apply here.
   For a deliberate full reset, use the standalone **LoonInspect-Uninstall** helper in the v1.4
   disk image or app's `Contents/Resources`, as described in
   [`macos/README.md`](../macos/README.md#where-it-keeps-things-and-how-to-start-over).
   Run as your normal macOS user, without `sudo`; the default/`--dry-run` lists the scope without
   changing anything. `--uninstall` requires a backup decision and typed user-specific confirmation.
   Follow [clean-uninstall troubleshooting](#macos-clean-uninstall-and-reinstall) for refusals or
   partial completion. Shared app bundles owned by someone else remain: ask the Mac administrator
   to remove those separately if needed. After **Local reset complete**, reinstall and create a
   new local administrator. Eject old disk images and avoid opening another copy during reset.

   A restorable database backup is `pgdata` copied while the app is quit plus the matching
   `ENCRYPTION_KEY`, `postgres-looninspect_app` and `postgres-looninspect` Keychain items.
   Copying a DMG to another Mac installs the software; it does not transfer that instance's data
   or its Keychain. See [`macos-app.md` › Backup](macos-app.md#backup).
7. **An export did not appear where expected.** Downloads from the app's window open a save
   dialog. Choose a writable location and wait for the completion message. Cancelling the dialog
   cancels the download. If the download reports a failure, read the message and retry the export
   after checking the chosen folder and available disk space; a selected filename alone does not
   mean the file finished downloading.
8. **Collection stopped after closing the lid, or Jamf cannot reach a webhook address.** Closing
   only the window leaves LoonInspect running; quitting stops its services and sleep pauses them.
   The native app serves its UI on this Mac's loopback address, which Jamf cannot reach. Use a
   reachable server deployment for incoming webhooks and continuous collection. Outbound Jamf
   reads and configured SIEM delivery still work while the Mac app is running and awake.
9. **The update notice never appears, or Settings › Support › Updates reads *Checking is off*.**
   The app's switch is **LoonInspect › Check for Updates Daily**; a check mark is on. At every
   start `logs/shell.log` says what the backend was told: *update check: the backend is told
   INSTANCE_KIND=mac-app and UPDATE_CHECK=…, from …*. The banner and the block print the app's own
   steps, those of [`macos-app.md` › Updates](macos-app.md#updates), and the app's own sentences,
   which open as the container's do; where their step-through differs from §10's, it is here.
   - No check mark → choose it. The window reads *Restarting LoonInspect* and reloads; the check
     is then owed as §10 says, and asked only while the app is open and the Mac awake.
   - The item is dimmed, or the line says *from the app's environment, over Check for Updates
     Daily* → the app was started with `UPDATE_CHECK` in its environment, which wins over the
     check mark. Quit, and open it from Finder or the Dock; `launchctl getenv UPDATE_CHECK`
     prints a value set for every app, which `launchctl unsetenv UPDATE_CHECK` removes.
   - *The local service stopped* and *Check for Updates Daily changed, and the local server did
     not come back:* → the rest of the sentence is one of step 2's. Quit and open the app: it
     starts with the new choice.
   - *This build asks nothing* → the bundle carries no build stamp, which `macos/scripts/build-app.sh`
     gives every app it builds, so it was put together another way. Install the release's disk image.
   - *Host* reads *UPDATE_CHECK_URL's unreadable address* → the app was started with that
     `UPDATE_CHECK_URL` in its environment. Quit, and open it from Finder or the Dock;
     `launchctl getenv UPDATE_CHECK_URL` prints one set for every app, which
     `launchctl unsetenv UPDATE_CHECK_URL` removes.
   - *… is available, and this build does not contain it* → nothing is wrong. The steps under it
     are the app's: quit, open the newer disk image, drag LoonInspect onto Applications, open it.
     §10's compose steps and its dump are the container's and do not apply here; the app's
     backup is the copy [`macos-app.md` › Backup](macos-app.md#backup) gives.
   - Any other sentence → §10 step 1, with `logs/backend.log` for the container log
     (`grep 'update check' ~/Library/Application\ Support/LoonInspect/logs/backend.log`) and
     `curl -sS -o /dev/null -w '%{http_code}\n' https://api.next.loonsec.io/v1/update` in
     Terminal, which prints a status when this Mac reaches the host. *No check of this build has
     run yet* lasts longer on a Mac seldom open: the first check waits for its moment, then for
     the app to be open.

10. **Find has no match, or its page/AI shortcut is unavailable.** Open **Edit → Find → Find in
    Page…** (⌘F). It reads loaded text only. Check **Match case**, expand the relevant section,
    or use the page's own search and pagination to load other results. A password field or hidden
    content is not searchable. **Page content changed** means the previous answer is stale;
    press Return to search the updated page.
    - **Go to page search** appears only when this page exposes an available search control.
      It focuses the existing control and preserves its query; it does not submit it.
    - **Go to AI search** appears only for a page's existing AI prompt or lever. For missing
      Changes/Vulnerabilities AI controls, follow §11 and Settings → AI's status: the feature
      flag, inference consent, and a saved provider still decide availability. Opening Find
      or typing in it never calls a provider.
    - **That search control is no longer available** means the page changed or disabled it
      before the handoff. Wait for loading to finish and reopen Find. If it persists while
      the control is visible and enabled, report the page and app build; local text finding
      remains available.
    - A dimmed Find menu means the app is starting, restarting, or showing recovery. Wait for
      the page or follow the startup/recovery steps above. After recovery, retry ⌘F.


11. **Back or Forward is dimmed, or the title bar uses the wrong theme.** These buttons use the
    current app window's history; a new window need not have a previous page. Wait for loading
    or recovery to finish, then try **View → Back** (⌘[) or **Forward** (⌘]). A trackpad gesture
    also depends on the macOS trackpad settings. The title bar follows the workspace's Appearance
    choice, even if macOS uses a different theme. Change Appearance in the app; if the page changes
    but the native bar does not, report the app build and the chosen app/macOS themes. **Reload
    Window** keeps the current route and query. Save important work before reloading or quitting;
    a page's explicit confirmation sheet does not guarantee a browser unload warning.

## 26. "A promoted application is not being sent, or Promote is refused"

A promotion (#793, [`data-sharing.md`](data-sharing.md#promoted-applications)) is an administrator's
choice that one installed application's name, bundle ID and versions leave in plain text with each
exchange. **Promoted applications** on Settings › Data Sharing lists each choice with what the next
exchange does with it (`GET /api/system/data-sharing/promotions`: `paused` for the whole list,
`held` and `excludedBy` per title), a refusal is shown as the server's sentence, and the audit log
has `sharing.promotion.added` and `sharing.promotion.removed` for each act. Nothing here needs a log.

1. **There is no Promoted applications section on Settings › Data Sharing.** The area is off and
   nothing is promoted. An administrator turns on **Promote applications** under Settings › Feature
   Flags, then reloads the page. A role without the system read permission does not see Data
   Sharing at all.
2. **The section says nothing below is being sent.** It names which of three things stops every
   promotion, and each has one fix:
   - *Promoting is switched off under Settings › Feature Flags…* → turn **Promote applications**
     back on. The choices were kept; the flag stops the sending, and Withdraw still works.
   - *COMMUNITY_SHARING=false is set…* → the environment override stops every exchange. Remove
     the line from the `.env` beside `docker-compose.yml` and recreate the container (§5 step 6
     has the same override for the exchange as a whole).
   - *Sharing is off for this organization…* → choose **Share keys only** or the reveal tier
     under Participation. A promotion needs an exchange to ride, and either tier sends one.
3. **One row reads *Held back*.** The rest are leaving; this title is not.
   - *…it matches the excluded pattern …* → the exclude list wins over a promotion. Remove that
     pattern under Excluded bundle IDs to send the title, or withdraw the promotion to agree
     with the pattern.
   - *…no Mac has it installed now* → there is no version to state, so nothing is sent. It
     resumes by itself when a sweep finds the title again. A renamed application is a different
     title (the key hashes the name): promote it under its new name.
4. **Promote was refused.** The sentence under the heading is the server's, and nothing was stored.
   - *…promoting applications is switched off…* → step 1.
   - *…no device in this organization has that application installed now, or it has no bundle
     identifier* → only an installed title with a bundle ID can be promoted. Reload the page and
     choose from the list, which is read from inventory as it is now.
   - *…matches the excluded pattern …* → step 3's first case, before the click instead of after.
   - *…200 applications are promoted already…* → withdraw one first. The limit is per organization.
   - A 403 → promoting and withdrawing need the system write permission, like the tier.
5. **The row reads *Sent by name* and the preview shows no `promotions`.** The preview is the body
   as it was when the button was pressed. Press **Show the payload** again.
   The array lists each promoted title once, with one `versions` row per installed version and
   platform. Still absent, with the row reading *Sent by name* → report it with the listing's JSON
   and the preview (§8); the two are built from the same rows and must agree.
6. ***Last exchange* says *promoted applications shed*.** The collector answered `413`: the request
   with the names was larger than it accepts. The run gave up the names and sent the snapshot,
   which is what the share-log row's `promotionsShed: true` records beside the body it had
   assembled. It repeats each day until the body fits: withdraw promotions you no longer need. A
   fleet whose snapshot alone is refused is §5 step 6, not this.
7. **It is being sent, and Posture › Vulnerabilities still reads *Outside the corpus* for it.** A
   promotion is a contribution, not a request with a status: the title is assessed here when a
   published release covers it, and this instance cannot see the service's side of that. Nothing
   on this instance is wrong. Where a tracked answer is wanted, **Request coverage** on Posture ›
   Vulnerabilities opens a case that has one (§21).

## 27. "The Fleet catalog tab is missing, empty, or says its last check did not get an answer"

**Devices › Applications › Fleet catalog** opens on **Migration review**, the installed apps on the
Macs in the device filter against Fleet's and Jamf's catalogs (step 12). Its other view, **Fleet
titles**, lists the Mac apps Fleet maintains beside what this organization has installed
([`fleet-catalog.md`](fleet-catalog.md), #794); steps 2 to 10 are about it. Fleet's list is one copy
for the whole instance, read from Fleet's public repository on GitHub once a day, and only
while the **Fleet catalog (maintained apps)** flag is on. No credential of yours is involved, so
nothing here is a permissions problem in Jamf.

1. **The tab is not there.** The flag is per organization and ships off. An administrator turns
   on **Fleet catalog (maintained apps)** under Settings › Feature Flags, and the tab is listed
   at once. Its address opened with the flag off reads *The Fleet catalog is off*, which is this
   step. *This area could not be checked* is not: the flags themselves could not be read, so
   reload, and if it stays, §4.
2. **The tab says *Fleet's catalog has not been read yet.*** No check has run since the flag was
   turned on. The scheduled check looks at twenty past each hour. **Check now**, for an Analyst
   or an Admin, reads the catalog at once; the first read fetches every title and takes about
   fifteen seconds. If an hour passes with no press and it still has not been read, see whether
   any process has the scheduler: `docker compose logs app | grep scheduler_enabled`. A web-only
   process (`SCHEDULER_ENABLED=false`, [`operations.md`](operations.md) §7) never checks on its
   own; **Check now** still works there.
3. **The status line says *The last check, …, did not get an answer.*** The sentence under it is
   the whole reason, and the titles read before it are still listed, as of the date the line
   gives. The same sentence is in the container log:
   `docker compose logs app | grep "Fleet catalog check failed"`. A failed check is tried again
   within the hour. By how the sentence opens:
   - *api.github.com refused the request* → GitHub's limit for requests without a sign-in, 60
     an hour for each address, shared by every instance and every other tool behind the same
     address; an update check draws on it only when `UPDATE_CHECK_URL` names GitHub (§10). One refusal needs nothing. Refused every
     hour means many things share this address: leave the flag on only where the tab is used.
   - *raw.githubusercontent.com refused the request* → GitHub slowed file reads from this
     address part-way through. The sentence says how many manifests were read and kept; the
     next check reads the rest.
   - *No answer from …*, or *… answered 502* (or another number) *…, where GitHub answers 200*
     → this container cannot reach GitHub, or something in between answered for it. From
     inside the container:
     `docker compose exec -T app python -c "import urllib.request as u; print(u.urlopen('https://api.github.com', timeout=5).status)"`
     prints `200` when the way out is open. Anything else is DNS, a proxy or an egress
     firewall between the container and `api.github.com` and `raw.githubusercontent.com` on
     port 443. An air-gapped instance stays in this state for as long as the flag is on; turn
     the flag off.
   - *… resolves to …, so this container did not dial it* → the container's DNS or hosts file
     answers one of GitHub's names with a loopback or link-local address. Fix the resolver;
     the product will not dial those addresses under any name.
   - *… with a body that is not JSON*, or *… with a redirect* → something answered in GitHub's
     place: a captive portal, a proxy's sign-in page. The command above shows what the
     container gets.
   - *GitHub answered, but …* → GitHub was reached and what it returned is not the catalog
     this build reads: the folder is gone, it holds no Mac manifest, or GitHub cut its listing
     short. Fleet has changed how it publishes the catalog. Update LoonInspect; on the latest
     release, report it (§8) with the sentence, and turn the flag off to stop the hourly retry.
4. **The check answered and the table is empty.** Read which sentence the table shows.
   - *Fleet lists … Mac apps, and none is on a Mac the device filter above selects* → the
     catalog is there and nothing matched. Widen the device filter above the table, or press
     **Clear filter**, which selects every current Jamf Mac; then untick **Only titles installed
     here** to see the whole catalog.
     A title matches an installed app by its exact bundle ID, on Macs only, so an organization
     with no device sweep yet matches nothing (§1). For one title you know is installed,
     compare its bundle ID under Devices › Applications with the tab's, letter for letter:
     `com.Example.App` is not `com.example.app`.
   - *No installed title matches this search* → the search missed among installed titles;
     untick the box to search the whole catalog.
   - *Nothing to list yet: no check has been able to read Fleet's catalog* → every check so far
     failed; step 3.
5. **A count under *Macs behind* or *Macs in scope* looks wrong.** A Mac is behind when any copy of the app on it
   is older than *Fleet's latest*, compared on the numbers in the version string. So a Mac with
   a second, stale copy is behind; a Mac on a build newer than Fleet lists is not; and *Fleet's
   latest* is what Fleet last recorded, which can trail the vendor by a day or more. Whether a
   finding follows from a version is not this tab's question: it judges nothing but older or
   not.
   - *Macs with app* and *Macs behind* count every Mac the organization has collected. *Macs in
     scope* counts only the current Jamf Macs the device filter above selects, so it is never
     more than *Macs with app*, and it can be lower even with no filter applied: departed and
     non-Jamf Macs count only under *Macs with app*. A release and its ESR channel share a
     bundle ID, so they count the same Macs.
   - *Unknown* under *Macs in scope* → Fleet listed the title after the counts for the filter
     were read. **Check now** reads them again; otherwise, reload the page.
6. **The status line ends with manifests that *could not be read … and were left as held*, or
   says *The held snapshot still has unread Mac titles*.** The check succeeded. The named
   titles are ones this build could not read: a manifest or an index entry it cannot read, or
   a title the file listing and the index disagree about. They keep what they showed, or stay
   unlisted if they were new, until Fleet next changes its catalog, and the titles held are
   partial ([`fleet-catalog.md`](fleet-catalog.md#complete-or-partial)). While Fleet changes
   nothing, each later check's line reads
   *The catalog tree is unchanged. The held snapshot still has unread Mac titles. They are checked again when Fleet changes its catalog.*
   That is the same state, not a new failure, and on its own it needs nothing. Three cases do:
   - *unrecognized Mac manifest path* or *unrecognized Mac index entry* among the names → Fleet
     listed a Mac title in a form this build cannot read. Update LoonInspect. On the latest
     release, report it (§8) with the sentence.
   - *Fleet catalog is unread or incomplete; absence cannot establish lack of coverage.* under a
     saved patch plan's **Open review items at plan creation**, or in its PDF → the plan was
     built while the titles held were unread or partial, so it drew no conclusion from Fleet:
     a Fleet title it found is listed for identity review, and no Fleet version became its
     target. A saved plan keeps the item. Once the status line shows a check that got an
     answer and carries neither sentence, build a new plan (§30). Until then, check the app's
     Fleet title by hand with its **Fleet source** link on this tab; a title the tab does not
     list is not proof that Fleet has none.
   - A plan shows that item while the status line carries no sentence → the instance was
     upgraded to 1.3.0 after its last check, and the upgrade marks a catalog that had been
     read as partial, once. The next scheduled check, within the hour, or **Check now**
     clears it, reading only the manifests the instance lacks. If the line reads
     *Fleet's catalog has not been read yet*, that is step 2; *did not get an answer* is step 3.
7. **Turning it off.** With the flag off for an organization, its tab is gone and the API
   answers it no titles. Once no organization on the instance has the flag on, the instance
   stops asking GitHub. The titles it held stay in the database and are brought up to date by
   the first check after the flag is turned on again. The version history stops being read at
   the same moment (step 8), and what it held stays.
8. **The version history line is not moving, or says *Paused until …*.** The history of each
   title installed here is read from Fleet's commits in the background (#838,
   [`fleet-catalog.md`](fleet-catalog.md#version-history)): one title at a time, about two
   minutes apart, the most-installed first, so *Version history: 12 of the 140 titles installed
   here read* climbs by twenty to thirty an hour at best. It reads only while the flag is on for
   some organization, only titles on a Mac in such an organization, and only after the daily
   check has read the catalog (step 2). The line counts the whole organization, whatever device
   filter is applied above the table.
   - *Paused until …* → GitHub said 20 or fewer of this address's 60 requests an hour were
     left, and the history leaves those to the daily check, **Check now** and every other tool
     behind the address. It carries on by itself at the time given. Paused every hour means
     something else behind this address spends GitHub's allowance: another instance, or a CI
     runner or script on the same network. `docker compose logs app | grep "version history"`
     shows each title it read and what it cost.
   - Not moving and not paused → `docker compose logs app | grep "version history"`. No lines at
     all after the flag was turned on: the process has no scheduler (step 2's
     `SCHEDULER_ENABLED`), and a title's **Read history** still works there. A line *could not
     run* names the database: §4.
9. **The status line says *The last version history read, … did not finish.*** The sentence
   after it is the reason, and it is one of the daily check's (step 3 has each, by how it
   opens). The background pauses for a quarter of an hour and then reads a different title:
   the one that failed waits an hour, so a single manifest GitHub keeps refusing never holds up
   the rest. Nothing is marked read and nothing already held is removed, so once the cause is
   fixed every title is read. The same sentence every quarter of an hour for different titles
   is a cause outside the instance (a proxy, an egress rule); the same title every hour is that
   title, and its sentence names the manifest.
10. **A title's history leaves out a version, or the last column says *Not dated*.** A version
    is listed only where Fleet's commits show it arriving: replacing another version, or the
    title's first change. The title's history says why one is missing: a manifest this build
    could not read at some change (the version after it is left out), or a history longer than
    the read's thousand changes (its oldest version is left out). A version that left and came
    back shows the move this instance saw, not its first arrival. Nothing to do; **Read again**
    cannot see further than the commits do. The dates are when Fleet's catalog
    took each version, hours to a day after Homebrew and the vendor, never before.
11. **An app's or a title's migration detail is refused, or its `impact` is null.**
    `GET /api/fleet-catalog/migration/apps/<appHash>` and `…/titles/<slug>` answer for the Macs
    the device filter (`deviceScope`) selects ([`fleet-catalog.md`](fleet-catalog.md), *Migration
    detail*). By the refusal:
    - *Fleet's catalog is not read while the Fleet catalog flag is off for this organization.*
      (409) → step 1.
    - *No Mac the device filter selects has this app in its inventory* (404) → the filter's
      connection, a contact or inventory window, or another condition leaves out every Mac with
      the app. Widen or clear `deviceScope`; **Devices › Applications › Installed** under the same
      filter lists the app once a selected Mac has it. An app removed from every Mac answers this
      under any filter.
    - *Fleet's catalog, as this instance last read it, holds no Mac title …* (404) → the copy this
      instance holds has no such slug; a title Fleet stopped listing is removed with its history.
      **Check now** reads the catalog again (steps 2 and 3).
    - *Fleet's version history, as this instance holds it, does not list …* (422) → `targetVersion`
      is neither Fleet's latest nor in the title's history. Leave it out for the latest or choose a
      listed version; **Read history** reads it again (step 8; step 10 for a version it leaves out).

    With `impact: null`, `impactUnavailable` names why: `catalog_incomplete`, the snapshot is
    partial or unread (steps 2, 3 and 6); `no_fleet_title`, no Fleet Mac title has the app's bundle
    ID (compare them as step 4 does); `identity_review`, the app has no bundle ID, two Fleet titles
    share it, several Jamf Patch titles match it or a match rests on an extension attribute
    (`jamfTitles` lists the matching titles this instance has synced, so an app naming titles it has
    not synced reads `identity_review` with `jamfTitles` empty; settle the title under
    **Devices › Applications › Jamf Patch**); or
    `unordered_target`, the target holds no number (choose a numeric version from the history; a
    qualified one such as `2.0-beta` is answered, counting each Mac it cannot order as unknown).
12. **Migration review is empty, or a sentence stands above or in place of its list.** It counts the
    Macs the device filter above it selects, every current Jamf Mac when none is applied
    ([`fleet-catalog.md`](fleet-catalog.md#migration-review)); **Fleet titles** reads the same report, so the sentences beside **Retry** show on both views. By the sentence:
    - *No current Jamf Mac is on record for the filter’s Jamf connection, so there is nothing to review. Apps appear here once a device sweep collects a Mac.* → §1.
    - *No Mac matches the device filter. Widen or clear the filter.*, or beside **Retry**
      *The device filter is invalid. Check each condition or clear the filter and try again.*
      → **Clear filter** in the device filter above, then §30.
    - *The Macs in the device filter have no installed apps on record. Installed Apps, with the same filter, shows what their last sweep collected.*
      → **Installed Apps** under the same filter. Apps there and none here is §8.
    - *No installed app matches this search and Show choice. Clear the search or choose All installed apps.* → as it says.
    - *The installed apps for this device filter could not be read. Check connectivity and retry; this does not mean no app needs review.*
      → no answer came: reload the page, and if it stays, §4. *Insufficient permissions* beside
      **Retry** instead → the account lacks `app:read` or `device:read`, which every built-in role holds.
    - *Fleet’s catalog was read only in part, so a title or release channel may be missing. The Fleet catalog’s status line says why.*
      or *Fleet coverage is unknown: Fleet’s catalog has not been read yet. The Fleet catalog’s status line says why.*
      → the status line on **Fleet titles**: steps 2, 3 and 6.
    - *Jamf Patch coverage is unknown: no Jamf Patch titles are synced yet, so no app is counted as outside both catalogs. Open Devices › Applications › Jamf Patch and press Sync now.* → §6.

    *Unknown* beside **Outside both catalogs** is not zero: an app is outside both only once Fleet's
    catalog is read whole and Jamf Patch titles are synced, and the sentence above says which is not.
    In a row, *Coverage unknown* → open the app, whose page says why (step 13); *No exact comparison* → no build behind
    Fleet's latest could be compared finding by finding (the corpus is off, a version is outside it, or a list is capped): §5.
13. **An app's or a title's page shows a sentence where you expected its evidence.** A name on Migration review or
    **Fleet titles** opens its page with the list's query, which reads step 11's detail for the same device filter. By the sentence:
    - *This Fleet catalog record could not be read. Retry, or reload the Fleet catalog list; if the list fails too, the instance is not answering.*
      → reload the list; if it fails too, step 1, then §4. *The Fleet catalog is off for this organization.* is step 1, and any other
      sentence beside **Retry** is the server's own refusal: step 12 for the device filter's, step 11 for the rest.
    - *No Jamf Patch title could match: the Jamf Patch catalog has not been synced. Open Devices › Applications › Jamf Patch and press Sync now.* → §6.
    - *Jamf Patch matching has not finished for every record here. The next device sweep finishes it, or Sync now under Devices › Applications › Jamf Patch.*
      → the next device sweep, or **Sync now**.
    - *No Jamf Patch title this instance has synced matches these installations.* → search **Devices › Applications › Jamf Patch** for the app
      with *Only titles with devices* unticked. No title there means Jamf publishes none for it; a title there that matches none of these Macs is §6 step 6.
    - *Several channels or identities can fit the inventory evidence. Confirm the intended channel before planning an update.*
      → open each title under **Fleet channels** and compare its manifest and history with the installed build.
    - *Fleet coverage is unknown: the inventory reports no bundle identifier for this app, and Fleet titles are matched by bundle identifier.*
      (the header reads *Bundle identifier unavailable*) → the **Application record**, for what the Mac reported.
      *Fleet coverage is unknown: Fleet’s catalog has not been read whole, so a title for this app may be missing.* → steps 2, 3 and 6.
    - *The Fleet catalog has no matching macOS title for this inventory identity.* → compare bundle IDs letter for letter, as in step 4.
    - *No matching installations were observed in the selected scope.* on a title page → widen the scope on the list and open the title again.
    - *This history has gaps, so these counts cover only the versions it could date. The read's status under this chart says why.* → step 10.
    - *No dated version matches this search.* → clear the search; step 10 explains an undated version.
14. **An app's or a title's page gives a verdict, findings or observed upgrades that read wrong.** The header's verdict line and
    **Patching policy** are Migration review's words for the same app, judged against Fleet's latest version; a build's patch-rule
    verdict is the Jamf Patch title page's (§23). How often Fleet updates the title is under **Detection and policy evidence**, what
    the vulnerability corpus holds for each installed build under **Findings on installed builds**, and the upgrades the change log
    recorded at the foot of **Installed builds**. By the sentence:
    - *How often Fleet updates this title is unknown until its release history is read.* → step 8; **Read history** on the same page
      reads it now, for `patch:catalog-sync`.
    - *Vulnerabilities: not assessed* under **Findings on installed builds** → §5 steps 1 and 2; *Outside the corpus* → §5. The counts
      are distinct builds on the Macs in the device filter, so a build on 500 Macs counts once where Installed Apps counts 500.
    - *Each Mac keeps its own copy of a build’s answer, which the hourly refresh brings up to date, so for up to an hour after a corpus release or a sweep these counts can differ from the verdict above.*
      → right after a corpus release or a device sweep, the findings can read *Outside the corpus* or *Vulnerabilities: not assessed*
      while the verdict line or **Patching policy** already counts a finding, or the reverse. The two read different copies of a
      build's answer, the findings each Mac's and the verdict the build's own; they agree after the hourly refresh, and **Sync now**
      under Devices › Applications › Jamf Patch runs it at once (`patch:catalog-sync`). Still apart after that: §5 step 3.
    - *0 recorded version changes on 0 Macs in the last 90 days.*, under it
      *A 0 here can mean the change log is not recording applications (Settings › Change tracking), and a change log kept under 90 days counts only the days it keeps.*
      → Settings › Change tracking: *High only* records no application changes; *High + normal*, the default, does. A Mac's changes
      count from its second sweep, and only Macs the device filter selects count, so widen or clear the filter.
      `CHANGE_LOG_RETENTION_DAYS` under 90 leaves fewer days to count, whatever the sentence's 90 says (§24 step 1 prints the value).
    - *No recorded upgrade on these Macs in this window could be paired with a version Fleet’s history has dated.* → the history on the
      same page says *Not read yet* (step 8), or the versions the Macs moved to are ones it could not date (step 10). Versions that are
      not plain dotted numbers, a short version that disagrees with the version, and a first upgrade recorded before Fleet dated the
      version are left out on purpose ([`fleet-catalog.md`](fleet-catalog.md#observed-upgrades)).
    - *Upgrade timing is measured only for an app matched to one Fleet title.* → the header says why, and step 13 routes it: several
      Fleet channels or Jamf Patch titles fit (open the intended one under **Fleet channels**), Fleet's catalog was not read whole
      (steps 3 and 6), or no Fleet title carries the bundle ID (step 4).
    - No **Build a patch plan for these Macs** → it needs `patch:plan-write` (Admin, Analyst) and a Mac in the device filter with the
      app. The plan opens with the page's device filter (§30).

Still wrong after these: report it (§8) with the status line's sentence, the *Fleet catalog*
and *version history* lines of the container log, and the build.

## 28. "Support does not show the Mac app version or build"

Open **LoonInspect → About LoonInspect** and compare its version and build with
**Settings → Support**. The sidebar shows the app release; Support keeps the app version,
app build, and backend build separate, and Copy includes all three.

- **Not recorded** means this package did not include that app field. Use the value in About
  LoonInspect in the report, together with the backend build. Do not infer a release from the
  backend's date-plus-commit stamp. A newly packaged app includes the fields.
- A blank build block means Support has not read the running service's identity. Check that
  LoonInspect is running and reopen Support. If it stays blank, include the About values and
  that failed read in the report. For a container, include the deployed image tag instead.

### Missing macOS adoption or eligibility evidence

Open Posture → macOS and select the reporting date in UTC. Counts carry the latest retained inventory forward for each Mac. The device history shows when Jamf reported each version and build. A blank interval before the first observation has no inventory evidence. Check that the collection reads Hardware and Operating System.

The release markers and hardware catalog use the [SOFA macOS feed maintained by Mac Admins Open Source](https://sofa.macadmins.io/). The SOFA timestamp identifies the local compatibility catalog used for the selected day. An administrator can refresh the catalog on the macOS page. Check outbound HTTPS to sofafeed.macadmins.io and write access to SOFA_CACHE_DIR if refresh fails. Historical days before the earliest retained catalog have unknown eligibility.

### Recent Jamf activity and daily coverage

In Connections → Collections add a **Recent Jamf activity** collection. Set the same device filter, sections and extension attribute quarantine as the daily crawl for comparable results. Each quarter-hourly poll catches up from the last fully successful window, with a two-minute overlap. The first window covers the preceding 17 minutes. If a poll fails, check its run log for Jamf version privileges, unsupported filters, paging or rate limits. The daily sweep keeps its own schedule.

Open **Daily coverage** beside the daily crawl. A covered miss means the crawl first recorded a changed section with an inventory report time inside a completed, comparable poll window. Jamf can expose that inventory later than its report time. Open the poll or crawl log and the device history to investigate. Pending, failed or partial crawls have incomplete coverage. A baseline, a contact without changed inventory, and an uncovered time interval each have a separate meaning.

### AI Activity: missing usage or work falling behind

Open **Overview → AI Activity**, or **Settings → AI Activity**. Its historical range is
UTC, inclusive, and limited to 90 days. **Live workload** always describes the current
15-minute interval; changing the historical range does not change the live interval.
The view requires `system:read`; it remains readable with AI disabled so retained
history and the disabled state are available. Provider setup and inference keep their
existing permission, feature-flag and consent checks.

1. **Check freshness first.** Read the live as-of time. A failed read, or a reading this
   browser received at least 45 seconds ago, is measurement unavailable, not a healthy
   empty queue. Use Refresh, then check the
   app/API connection and `docker compose logs app`. A server warning beginning
   “AI usage could not be saved” means some metadata was lost; its parenthesis says why.
   “the write took longer than 2 seconds” means database load or latency: check the
   database's health and response time. Any other text there is an error type, such as
   `ProgrammingError`: check that startup migrations completed, and if they did, report
   the error type with the line's `stack`. No prompts or response bodies belong in that warning.
   A recovered write preserves the gap marker. Historical periods intersecting the
   known gap remain marked incomplete; the live verdict recovers after a complete
   subsequent 15-minute interval. A process that dies before persisting a failure
   marker cannot report that lost measurement later.
2. **Check whether work can run.** Not running means AI or inference consent is off,
   or nothing is processing inventory work: the container answering has
   `SCHEDULER_ENABLED` off, an inventory summary has waited over two minutes, and no
   inventory attempt has started for five. A web-only container beside one that runs the
   scheduler shows the other verdicts while that one starts attempts. Read
   `scheduler_enabled` on each container's `starting` line,
   `docker compose logs app | grep scheduler_enabled`; one must say `true`. No provider configured
   means an administrator must save and test one in Settings → AI. The panel states
   which condition applies. Read-only operators ask an administrator to change setup.
3. **Read the evidence behind the verdict.** Backlog growing means there is waiting
   work and more logical arrivals than useful completions in the same complete
   15-minute interval. Work waiting too long means the oldest waiting age exceeds
   120 seconds. Check provider tests, worker availability and FM's shared local lane.
   Work appears stalled means active work exceeded its declared deadline; verify the
   worker and provider before retrying. Interactive work stays visibly stalled for a
   120-second grace after its deadline. Restart a stopped worker and keep scheduled
   maintenance enabled: it then expires abandoned interactive work in bounded batches,
   records unfinished attempts as interrupted, and clears their active counts. It does
   not retry inference. Missing dispatch/duration evidence after a crash stays unknown.
   Inventory jobs retain their existing lease/expiry recovery. Reclaiming a lease
   records an unfinished prior attempt as Interrupted before retrying or dropping the
   job; recorded dispatch is preserved, while lost request durations stay unknown.
   The initial partial interval says Collecting a baseline. A queue count alone is not evidence of overload, and no ETA is inferred.
4. **Separate attempts from useful work.** Rate limits mean a 429 refusal; inspect
   provider capacity/reset and inventory retries. Authentication/access refusals call
   for checking the configured credential and provider permissions. Request timeouts
   call for checking provider availability and response time. A waiting timeout means
   no request was handed to the HTTP transport. Unusable replies were rejected by the
   requesting feature. Expired inventory work needs fresh inventory; it is not silently
   counted as completed. An answered attempt is useful only when its feature accepts it.
5. **Read coverage before comparing totals.** A retry adds an attempt to one logical
   job. A cache hit adds useful work but no provider dispatch. A selected fallback is
   marked on its actual attempt; it does not manufacture an extra call. Historical
   attempt totals/trends use the UTC day of finalization. Logical arrivals use arrival
   time; completions, cache hits, skips and failures use their terminal time. A job
   arriving before the range can finish inside it. Work filters include matching attempts, so a job
   may have a successful final outcome after its selected failed attempt.
   Tokens/provider execution time omitted by the provider are unknown, with reporting
   counts shown; a reported zero is a measured zero. Wait, HTTP request and total times
   are separate averages in milliseconds. Old daily records lack those boundaries and
   useful-result/dispatch information; no latency percentile is derived from sums.
6. **Check attribution and unmeasured work.** Current configured services are separate
   from service names saved with historical attempts. An administrator can set a safe
   service name/type on the compatible-provider card. Renaming/changing its endpoint
   creates a new service identity. Unsaved test calls have a separate opaque identity
   labeled “test endpoint,” even when testing the same address as a saved service.
   Existing ambiguous daily rows stay legacy/unknown;
   a model name does not prove OpenAI. Patch investigations show current source-research
   activity separately, with partial coverage before inference. Model discovery/control
   calls, requests refused before inference, unchanged inventory that creates no job,
   and other clients using the provider are outside the inference totals. A process
   running an older version can contribute daily totals without granular live facts.

No calls in a readable selected period differs from no matching filters; reset filters
or choose a range at/after the first measured date. Granular history begins when the new
recorder first saves data. The 90-day retention applies to metadata, including when AI
is off; the existing scheduled maintenance must be running to prune it. See
[AI Activity](ai-activity.md) for field definitions and coverage.

### Ollama model selection

On the OpenAI-compatible card in Settings → AI, enter the Ollama endpoint ending in /v1. Existing cards use their pinned model. Choose **Prefer a loaded compatible Ollama model**, enter the model tags in preference order, then preview. The installed list comes from /api/tags. The running list comes from /api/ps. LoonInspect checks the completion capability with /api/show and chooses the first compatible preference, then tries remaining loaded names in alphabetical order. Preview shows the model and reason before sending a test. Save the card to apply the same choice to interactive features and background summaries.

If no compatible model is loaded, load a chat-capable model or explicitly set a fallback on the card. A selected fallback may cause Ollama to load that model. If discovery is unavailable, a configured fallback can still be requested on the same endpoint. Check the URL, reverse proxy routing for /api/ps and /api/show, credentials and consent. The usage view records the concrete model requested and the model reported in the reply.

## 29. "Codex or Claude cannot use LoonInspect"

Start in **Settings → AI connections**, with the intended organization selected. The
[MCP runbook](mcp.md) has the Mac and hosted setup. Choose the step matching the refusal:

1. **The page is absent, or AI features/MCP access is off.** Viewers cannot create
   connections. An administrator must enable **AI features** in **Settings → Feature
   Flags** and separately choose **Allow AI connections** for this organization. The
   community-sharing and AI-inference switches do not substitute for MCP consent.
2. **The active organization changed, or creating a token is refused.** Reload the page,
   confirm the organization, and choose an expiry from 1–365 days. Grant only capabilities
   your account currently holds. Create one token per assistant; an ordinary unrestricted
   API token does not become an MCP grant by being pasted into this page.
3. **The token expired, was revoked, or is not an MCP grant.** Check **Your AI connection
   tokens** and the owner's account status. Create a replacement with explicit capabilities
   and an expiry. For the Mac app, repeat the displayed pairing command with the same
   profile and paste the replacement at its hidden prompt. For HTTP clients, replace the
   credential in the environment or credential store that launches the client. Reconnect
   that client. Never paste the token into a support report or chat.
4. **The Mac helper says no usable Keychain credential was found.** Confirm that the
   profile in the client configuration exactly matches the pairing command, such as
   `codex`, `claude-code` or `claude-desktop`. Unlock the login Keychain and pair again.
   If the bundle does not contain the adapter, install a build that includes MCP support;
   changing the profile cannot add the missing executable resources.
5. **LoonInspect is not ready, restarted, or its local identity does not match.** Open
   LoonInspect, wait for its workspace, and reconnect the assistant. If the mismatch remains,
   quit and reopen LoonInspect once, then reconnect. Do not replace the generated runtime
   file or pin an old localhost port: the helper checks the current app's identity before
   sending a credential. If it reports that the runtime directory or file is not private,
   inspect ownership and sharing permissions on this user's LoonInspect Application Support
   directory. It must not be shared with other accounts. Follow §25 if the app itself will
   not become ready.
6. **Test connection succeeds here, but the assistant cannot connect.** This test checks
   the token, not the assistant's network or configuration. Check the configured command
   and profile for the local app, or the exact HTTPS endpoint for a server. Confirm that
   an HTTP client's launch environment contains the credential variable it references.
   Claude's cloud connector cannot reach this Mac's localhost or an ordinary private
   network address. Use local stdio for this Mac's app, or a reachable HTTPS server for a
   cloud connector. The bundled Mac helper does not proxy a separate hosted instance.
7. **Remote HTTPS, Host or Origin is refused.** Check the app/proxy TLS configuration and
   whether forwarded scheme headers are trusted only from the intended proxy. Configure
   `MCP_ALLOWED_HOSTS` and `MCP_ALLOWED_ORIGINS` as JSON arrays naming the actual address,
   including a nondefault port when sent by the client, then recreate the app container.
   Defaults accept loopback. An HTTP 421 indicates a refused Host; an Origin refusal is
   HTTP 403. A proxy sign-in page, redirect or HTML response is not an MCP response: route
   the authenticated `/mcp` request to the app. LoonInspect has no MCP OAuth sign-in flow.
8. **A tool is missing, unavailable, or its arguments are invalid.** Recheck the token's
   selected capabilities and its owner's current role. Discovery hides tools outside
   that grant. Reconnect after changing access. For argument errors, use the tool's
   published schema: integer IDs and page sizes, dates with timezones, and returned app
   hashes or job IDs. Inventory sweep results use `jobID`; polling tools accept `job_id`.
   An MCP-only credential used against a normal REST URL is deliberately refused.
9. **The connection is busy or reached its per-minute limit.** Let current work finish;
   after a rate refusal, wait a minute before another call. Each backend process allows
   eight tools in progress, sixty tool calls per minute per token and at most six refresh
   calls. A patch-catalog refresh through MCP already in progress also blocks a second
   such refresh in that process. Repeated immediate retries do not make progress.
10. **A sync or refresh timed out.** Its outcome may be unknown. For inventory sweeps,
    inspect the connection's runs or use `list_runs`, `get_run` and `get_run_log` before
    another request. A running sweep is reused and returns `started=false`. Patch-catalog
    refresh is synchronous and has no job ID: inspect the Jamf/Fleet catalog status and
    its existing logs (§6 or §27). Its first read can take minutes; allow a 330-second
    client timeout if using it. Neither client cancellation nor timeout proves that an
    already-started write was rolled back. Do not configure automatic retries.
11. **The result is too large, or report pages seem inconsistent.** Reduce the query's
    page size or time window. Some full REST results are built before MCP slices a page,
    so a small page cannot bypass the source-response limit. For a large evidence report,
    narrow the window or use the existing UI's HTML export. Keep the first answer's
    reporting window on subsequent pages; these are live reads, not a frozen export.
    Read the pagination scope: fleet totals cover the full report, while device details
    can describe only the returned interval page. Missing assessment remains unknown,
    not zero findings.
12. **The operation still cannot complete, or the helper reports an unsupported response.**
    Update the app and helper together and reconnect the client. Read the local backend
    log (**LoonInspect → Show Logs in Finder**) or `docker compose logs app`, using the
    request ID from the failure. If it persists, report it through §8 with the build,
    client name, tool name, time and request ID. Leave out tokens, raw tool results and
    fleet-identifying records. A disclosure entry records categories delivered to the
    client; it cannot identify which downstream model processed them.

## 30. Installed application patch plans

- **No applications match a device filter:** open **Devices → Applications → Installed
  Apps**, check the connection and All/Any condition choice, and remove conditions one
  at a time. Group IDs belong to a specific Jamf connection. Missing EA values, contact
  dates or group observations are unknown; a negative filter does not treat them as a
  confirmed non-match. Collect fresh inventory if the values are missing or stale.
- **An application disappeared while building:** the selected app no longer has devices
  in the applied scope. Refresh the list and select the current application identities.
  Existing saved plans retain the inventory snapshot from when they were built.
- **A plan says “requires investigation” or has conditional matches:** inspect each
  source, its read date and the open review items. A public Jamf title or Fleet package
  does not prove that a deployment policy exists in this Jamf instance. Validate the
  bundle, version and installer before filling in the operator review notes. A review item
  *Fleet catalog is unread or incomplete; absence cannot establish lack of coverage.* is
  §27 step 6.
- **Installomator is unavailable or no label was found:** check outbound HTTPS to
  `api.github.com` and `raw.githubusercontent.com`, including GitHub rate limits. A missing
  name-derived label can be an alias; search the upstream project and review its script.
  The investigation records a pinned source revision and never executes that script.
- **AI is unavailable or returns an unusable result:** open **Settings → AI**, check the
  enabled provider and loaded model, then send a test prompt. Check the AI feature flag
  and inference consent in **Settings → Data Sharing**. For Ollama, use its endpoint
  ending in `/v1`. Retry the investigation after fixing the provider. The plan retains
  its source evidence when AI cannot select valid review priorities.
- **Investigation is interrupted, fails or cannot start:** the application permits two
  concurrent investigations per organization and bounds each to five minutes. Wait for
  a running job to finish. After a restart, reload the plan; after six minutes it marks
  the old job interrupted and allows a retry. Check the server log and connectivity to
  the named source or AI service before retrying a failed job.
- **PDF export or review save reports a changed revision:** reload the saved plan and
  review the newer findings or notes before saving or exporting. Unsaved operator notes
  disable export. The PDF represents the displayed saved revision and includes its
  data checksum. It documents a proposed plan; approvals and deployment results must
  be recorded separately. Analyst or Admin access is needed to build, investigate and
  update a plan; Viewer and Auditor roles can read and export one.

- **Risk filters show an unavailable-source error.** Check the vulnerability source and
  data-sharing settings. Until a corpus is available, clear severity/KEV filters to browse
  inventory. Unknown or stale builds show a dash, not zero. Partial averages use only
  assessed devices; inspect the coverage denominator and source date beside the table.
- **Selected apps no longer match the application filters.** Inventory or vulnerability
  evidence changed after selection. Refresh the list, reselect the apps, and build again.
- **Apply device filter is disabled.** Complete each value, remove empty inner brackets,
  and keep within 20 conditions, ten groups and four group levels. The JSON importer uses
  the same vocabulary; unsupported fields are rejected without replacing the draft.
- **Smart group style cannot apply existing Managed rules.** Smart group style already
  includes only managed Macs, outside the brackets. Remove each Managed condition,
  including nested ones, or switch to Advanced search. The mode switch keeps your rules
  for review. Supervised is independent and remains available in both modes.
- **The EA regular expression is invalid.** Check unmatched brackets, parentheses and
  escaping; these filters use PostgreSQL regex syntax. Use `like` for a literal substring.
  Try the corrected filter again. A failed expression never counts as a negative match.
- **The regex device filter exceeded the database time limit.** Simplify the expression
  or narrow the Jamf connection and retry. Each database statement is limited to five
  seconds (or the database's stricter configured limit). No partial plan was saved.
- **Before/After date differs from an expected device count.** Check the UTC boundary:
  both exclude the selected calendar day. Missing dates and future timestamps count as
  unknown. Confirm whether you meant Last contact or Last inventory; these are distinct.
- **AI cannot propose the group.** Open Settings > AI, verify the selected provider/model
  and inference consent, then use **Check again**. The error names an unavailable service,
  unfinished response, invalid JSON, or unavailable group/EA reference. Try a shorter
  request using the observed group or EA name, or build the conditions manually.
- **AI says the request is unsupported.** No filter changed. Criteria such as installed
  software or FileVault are not device-scope fields in this builder. Unsupported portions
  are not silently dropped. A bounded metadata notice means only some group/EA names fit;
  select the Jamf connection and name the intended group, or enter its IDs manually.
- **The proposal did not change the app list.** Review its JSON and matched-device count,
  choose **Load proposal into builder**, then **Apply device filter**. Imported and saved
  filters follow the same draft/apply flow. Editing the scope discards an earlier proposal.

See [Application patch plans](application-patch-plans.md) for the complete workflow.


## 31. Change filters do not find an OS version or time window

1. **An OS version typed into search finds nothing.** Device search finds a device's name,
   serial, ID or UDID; Named-entry search finds applications, groups, accounts and profiles.
   Use **Section: Operating system → Changed field: OS version → Changed to exactly: 27.2.1**,
   or the example button. Set the observation window, then press **Apply field, time and
   device filters**. AI is not required. The old/new values in each row are the evidence.
2. **“Choose a section and field” or an unusable field in a shared URL.** Select a section,
   then a scalar field from its list. A field from Applications, group criteria or another
   section cannot be used as a scalar target. If field choices failed to load, use
   **Retry field choices**; if this continues, report the visible error and app version.
   A section change clears the previous field/target together. Clear also removes every
   applied filter, including filters carried only by a shared link. Browser Back/Forward
   restores the URL's applied filters and discards unapplied drafts, including when Back
   cancels a filter change before its results render.
3. **The time window is refused or selects the wrong day.** Check the timezone printed
   below the inputs. Start is inclusive and end is exclusive; end must be later. A clock
   time skipped at the start of daylight saving is not valid. Use absolute ISO instants
   with `Z` or an offset when editing API/shared links; an offset also disambiguates a
   repeated local hour. The window uses **Observed**, not collection or installation time.
4. **The total differs from the page's row count or the number of users.** Totals cover all
   matching pages. Multiple transitions on one Mac count as multiple changes and one
   device. Equal IDs in different source connections count separately; groups count as
   changes but not devices. Assigned user does not establish unique-person identity.
5. **Adding a historical device filter removes an expected row.** These filters use the
   attributes stamped on that observation, not Devices' current state. Missing stamps
   remain unknown; narrower collection scopes and older observations may lack a field.
   Remove that dimension filter and inspect the recorded change. A first observation is
   a baseline, not evidence of a prior upgrade. Check **Settings → Change tracking** and
   [retention (§24)](#24-the-change-log-keeps-growing-with-change_log_retention_days-set-or-the-changes-page-lost-history)
   if the expected period has no retained change rows. “Changed to” includes downgrades.
6. **A query fails to load.** Its error replaces the result counts, so an unavailable query
   does not read as zero changes. Correct the field/time message or retry loading the page.
   If valid filters still fail, report the visible error, app version and a synthetic example;
   remove personal values from the shared query before posting it publicly.


## Patch Plans navigation and unsaved review notes

Open **Patch Plans** from the main navigation, or use **Plan application** in Installed
Apps or Catalog. Existing saved `?plan=` links redirect to `/patch-plans?plan=...`.
An account needs both application and device read access to open the page. Creating,
investigating and saving still require patch-plan write access; read-only accounts can
open saved plans and export the saved revision.

If **Browser storage is unavailable** appears, the draft remains in this tab's memory
through navigation, but closing the tab loses it. Save the review notes before closing,
or copy them somewhere appropriate if saving fails. Do not clear browser storage to
resolve a save failure. A draft from an older revision is shown as a conflict: compare
it with the saved report, copy any notes you need, then choose **Discard draft** and edit
the latest revision. Export stays disabled while notes are unsaved, so the PDF cannot
silently omit the visible review. **View current installed apps in this scope** opens
current inventory with the saved report's scope, without changing that report.

Changing organization asks for confirmation before changing the session when this tab
has unsaved review notes. Cancel keeps the current organization. Browser-stored drafts
remain attached to their original organization, account and plan; copy or save any
memory-only notes before confirming, because the switch reloads the page. A failed
switch keeps the current page and its warning before closing or reloading.

If unsaved review notes are gone after signing back in, check whether the account used
**Sign out**: it discards every unsaved review note in the tab without asking, so the next
person on a shared browser cannot read them or meet their prompts. Save review notes before
signing out. A session that expired on its own keeps the draft for the same account.

If **device scope is invalid** appears when building from a planning link, return to
**Choose installed apps**, apply valid device filters and select the apps again. No plan
is created from the invalid scope.


## macOS clean uninstall and reinstall

**Reinstall still asks for the old account:** ordinary app replacement preserves the local
instance. Use the existing account, restore its backup, or choose a deliberate full reset with
**LoonInspect-Uninstall** on the disk image. Reset permanently removes local accounts and
inventory; it is not password recovery. See [Backup](macos-app.md#backup) before proceeding.

1. Run the helper with `--dry-run` in Terminal. Review the exact current-user paths, Keychain
   services and retained files. No services or files change during preview.
2. Save a stopped database copy and its matching three Keychain secrets if recovery matters.
   Move needed backups and exports outside all listed removal directories. The helper never
   creates a backup or exports a secret. Run `--uninstall`, choose the backup acknowledgement,
   and type the user-specific deletion confirmation. Cancel or a mismatched response changes
   nothing. Do not use `sudo`, pipe confirmations or remove refusal checks.
3. **Login Keychain locked/unavailable:** unlock it in Keychain Access and retry. The preflight
   fails before services or data change. An access refusal during deletion can leave a partial
   removal; allow the appropriate item deletion, preview again and retry.
4. **Services did not stop / database live / instance locked:** quit LoonInspect and MCP clients,
   wait for shutdown, then retry. If an orphan remains, restart this Mac or open and quit the
   app cleanly. The helper never force-kills a PID from a database file.
5. **Symbolic link / ownership / changed path / app signature:** inspect the exact reported path.
   A corrupt or unrecognized app bundle is refused before data/key deletion; verify its origin
   before removing it separately. An ad-hoc but valid development signature is accepted. Move the link
   aside without deleting its destination, or resolve ownership through the responsible Mac
   administrator. Generate a fresh preview. Shared app bundles are retained for their owner;
   do not broaden deletion to another user's directory.
6. **Removal may be partial:** read the last completed path, correct the reported access issue,
   then preview and retry. Missing already-removed items are allowed. Unknown sibling files,
   backups, exports outside the listed directories, other Keychain services and remote Jamf
   data remain. A retained custom app copy may be removed separately after checking its identity.
7. Open the newly installed signed app. It should show first-time setup, where you create a new
   local account. Recreate connections and MCP tokens as needed. If old data reappears, verify
   which macOS user and app installation you opened; do not delete a different user's data.

## 32. "LoonSec's patch-policy data has not arrived, is old, or was refused"

LoonSec's patch-policy data (#614) is one reference document for every app LoonSec references:
NVD-derived affected ranges over each app's version list, a first-detectable day per CVE where
LoonSec knows it, and the public release records each app's dates come from. It arrives the way
the vulnerability corpus does (§5): a signed link riding the daily data-sharing exchange,
downloaded only when the document changed, checked whole, and held on this instance. An
air-gapped instance reads it from a file instead (step 8). It answers only for an organization
whose data sharing is on, as the corpus does: it rides the exchange that organization already
makes, and receiving it adds nothing to what that exchange sends.

Where to read its state: Settings › Support › **LoonSec patch-policy data**, one sentence, for
every account that holds **app:read**; `GET /api/patch-policy/apps`, whose `feed.state` and
`feed.sentence` are the same words, with `feed.outcome`, `feed.host`, `feed.httpStatus` and
`feed.detail` from the last attempt; and the container log, where every line about it begins
`patch-policy data` (`docker compose logs app --since 48h | grep -i "patch-policy data"`). A
copy that is held keeps answering through every failure below: a refused document is never
stored, and nothing is deleted to make room for one.

1. ***This organization does not share data with LoonSec, so it does not receive LoonSec's
   patch-policy data.*** The tier is the gate, whichever way the document arrived. Settings ›
   Data Sharing: choose **keys** or **reveal**. A copy the container already holds answers on the
   next page load; if none is held, one arrives with the next exchange, and an administrator can
   press **Send now** to run it at once. On an instance with more than one tenant, check the
   tenant you are looking at. With `COMMUNITY_SHARING=false` nothing is sent whatever the tier
   says, and the tier can still be chosen: that is how an air-gapped instance using step 8 opens
   the gate.
2. ***LoonSec's patch-policy data has not arrived on this instance yet.*** No exchange has
   answered since this build was installed. Settings › Data Sharing shows the last exchange:
   - none yet → the daily exchange is jittered per organization; **Send now** runs it at once.
   - *failed* → the exchange itself did not get an answer, and §5 step 6 walks why. The document
     rides the same request, so it waits for the same fix.
   - *sent*, and the sentence has not moved after a reload → read the container log for
     `patch-policy data could not be stored`: the database refused the write. Check
     `docker compose logs db` and free volume space, then **Send now**.
     `patch-policy data not read from PATCH_POLICY_FEED_FILE: the database session failed` is
     the same check on an instance that reads the file.

   *…has not been read from PATCH_POLICY_FEED_FILE yet* is the same state on an instance that
   reads the file (step 8): the file is read at startup and again within five minutes of any
   change, so this lasts only until the container has started; if it stays, the container log
   names what was found, and `patch-policy data from PATCH_POLICY_FEED_FILE could not be stored`
   is the database, as in the bullet above.
3. ***LoonSec's last exchange carried no patch-policy data.*** The exchange answered and named
   no document. Nothing on this instance is wrong, and a copy already held keeps answering
   (the sentence then ends *Showing the copy dated …*). If it reads the same after the next
   day's exchange, that is reportable state **AA**, below.
4. ***This build reads patch_walk/1; LoonSec's last exchange named only …*** The exchange named
   the document only for a newer way of reading it. Once, it is usually a passing gap at
   LoonSec: while LoonSec publishes two ways at once, after a move, an exchange that could not
   read one of them leaves it out for a few minutes, and the next exchange (or **Send now**)
   names it again; nothing needs updating. If the next exchange names the same, LoonSec has moved
   on: it keeps publishing the older way for at least 90 days after a move, so the instance has
   stayed behind longer than that. Update LoonInspect (§10); the held copy keeps answering until
   then.
5. ***The patch-policy file could not be downloaded from …*** The host it names is the object
   store the exchange's link pointed at, **not** the exchange's own host
   (`api.next.loonsec.io`), so an egress rule that lets the exchange through can still stop
   this. The reason after the colon says which:
   - *…did not complete (ConnectError)* or *(ConnectTimeout)*, *(ReadTimeout)* → the container
     could not reach that host. Allow outbound HTTPS to it, then check from the container
     itself: `docker compose exec app curl -sSI https://<host>/` (any HTTP status is a reach).
   - *…did not complete (HTTP 403)* or *(HTTP 404)* → the host answered and refused the link.
     A link lives fifteen minutes and the download starts seconds after the exchange, so a
     clock far from the right time can expire it on arrival; compare `date -u` in the container
     with the real time. If the clock is right and the same refusal follows the next exchange,
     that is reportable state **AC**.
   - *…redirected somewhere this container refuses* or *the exchange named a link this container
     refuses* → something between the container and the internet answered in the store's place
     (a proxy or a captive portal), or the link named an address the container will not dial.
     Fix the proxy; a refused link with no proxy in the way is reportable state **AC**.
   - *…passed the …-byte ceiling* → far more came back than the document is; something other
     than the store answered. Same as the line above.
   - *…from the exchange's link: the exchange's patch_policy field is …*, *…entry is not an
     object*, *…entry carries no sha256 signature* or *…entry carries no link* → LoonSec's
     exchange answered with something under `patch_policy` that is not a link, so nothing was
     dialled. Nothing on this instance is wrong; the same sentence after the next exchange is
     reportable state **AC**.
6. ***LoonSec's patch-policy data failed its check (…), so it was not stored.*** The document
   arrived and was refused whole; the copy it would have replaced is still used (the sentence
   says which). The words in brackets are the check that failed:
   - *it is not JSON* or *it is not a gzip file* or *its gzip stream is cut short* → the bytes
     did not survive the trip, usually a proxy that rewrote or truncated them.
   - *its kind is …*, *its schema is …*, *its algorithm is …* → the document is not one this
     build reads. Update LoonInspect (§10).
   - *its doc_id … is not what its contents hash to*, *it is not the document the exchange
     named* → the content changed after LoonSec built it, or the link served another
     document.
   - *it lacks …* or *its own counts disagree (…)* → the document does not add up in its own
     key names. That is LoonSec's to fix. An app's `other_channels` (§33 step 4) is held to its
     spelling as well as its shape (*…other_channels[N].versions spelled as an instance reads
     them…*, *…names …, a channel a track of … walks*, *…source as the https URL its versions were
     read from*), because a version spelled otherwise would match nothing a Jamf or Fleet timeline
     names and be counted as unmatched without a word.
   - *its structure could not be checked (…)*, or *an unexpected failure (…) that the container
     log reports* → the check met a shape it has no words for, or failed for a reason that is not
     a refusal. That it reaches you without a sentence is a gap on our side: reportable state
     **AB**, with the log line that begins `patch-policy data` and the error type and stack
     locations logged beneath it.

   The next exchange tries again. The same sentence after the next day's exchange, with no
   proxy in the way, is reportable state **AB**.
7. ***Showing patch-policy data dated …, more than three days old…*** The copy held is more than
   three days old by its own date (`feed.asOf`, the NVD state LoonSec built it from), and that
   date alone decides it. LoonSec's publisher builds the document every night and says when it
   last finished a build, changed or not, and the exchange passes that on (`feed.builtAt`). A
   recent build never makes an old copy current: a publisher that runs every night while
   LoonSec's NVD data stands still makes the same document each night, and that is what this
   state is for. What `feed.builtAt` says is the cause, judged by this instance's clock
   (`feed.publisherRunning`: `true` when that build is under three days old, `false` when it is
   older), and the page names the same cause from it. The sentence goes on with it:
   - ***…: LoonSec's publisher last ran on …, but its NVD data has not advanced since …*** → the
     publisher is running (its last build is under three days old) and LoonSec's NVD data has
     not moved since the copy's date, so each night's build is the copy you hold. Nothing on
     this instance is wrong, and neither the next exchange nor **Send now** changes it. If it
     reads the same after the next day's exchange, that is reportable state **AA**.
   - ***…: LoonSec's publisher last ran on …, more than three days ago, …*** → no build LoonSec
     finished since has reached this instance. Read the last exchange on Settings › Data
     Sharing: *failed* is §5 step 6. *Sent* means LoonSec's publisher has finished no build
     since, which is reportable state **AA** once it has lasted past the next exchange.
   - ***…, more than three days old; the walk ends …*** → LoonSec's last build is not known
     (`feed.builtAt` is null: an exchange from an older LoonSec, or the file of step 8), so the
     sentence names only the copy's date. Read the last exchange the same way. On an instance
     that reads the file (step 8), put a newer file in its place.
8. **An instance with no network: `PATCH_POLICY_FEED_FILE`.** Put the document (the
   `.json.gz` file LoonSec provides) on the data volume and name it in `.env`:
   `docker compose cp patch-policy.json.gz app:/app/data/patch-policy.json.gz`, then
   `PATCH_POLICY_FEED_FILE=/app/data/patch-policy.json.gz` in the `.env` beside
   `docker-compose.yml`, then `docker compose up -d`. The container reads it at startup and
   again within five minutes of any change to it, checks it exactly as it checks a download,
   and from then on the exchange downloads no patch-policy data. The organization's tier still
   has to be on (step 1). If the sentence reads *…could not be read from /app/data/… (Permission
   denied)*, the file is not readable by the container's user:
   `docker compose exec --user root app chmod a+r /app/data/patch-policy.json.gz`. *(No such file
   or directory)* is a path that is not inside the container: the path is the container's, not
   the host's. *…the file is larger than the …-byte ceiling this container accepts* → the path
   names something other than the document, which is a few hundred kilobytes: check that it is
   the `.json.gz` LoonSec provided.

A container log line `patch-policy data not updated: an unexpected failure, not a refusal` (after
an exchange) or `patch-policy data not read from PATCH_POLICY_FEED_FILE: an unexpected failure`
(at startup or a tick) is a defect in this build, not a fault on yours. The container keeps
running, the held copy keeps answering, and the next exchange or change to the file tries again.
Report it as state **AB**, with that line, the error type and stack locations logged with it, and
the build (§8).

**AA.** The exchange answers and LoonSec names no patch-policy document, or names one dated more
than three days ago (step 7), on two consecutive days. The sentence's cause is the part that
matters:
- *…LoonSec's publisher last ran on …, but its NVD data has not advanced since …* → LoonSec's
  publisher is running and its NVD data has stood still: LoonSec's to fix, and nothing an
  instance can change.
- *…LoonSec's publisher last ran on …, more than three days ago…*, or no `feed.builtAt` at all →
  LoonSec's publisher has finished no build that reached this instance since that day.

Report the sentence as worded, `feed.attemptedAt`, `feed.docId`, `feed.asOf`, `feed.builtAt` and
`feed.publisherRunning` from `GET /api/patch-policy/apps`, and the build from Settings › Support
(§8).

**AB.** A downloaded document is refused by its check on two consecutive exchanges, with no
proxy between the container and the store; or the check, or the file read, fails with an
unexpected failure rather than a refusal (step 6, step 8). Report the sentence as worded (the
bracketed check is the part that matters), `feed.host`, any `patch-policy data` log line naming
an unexpected failure with the stack locations beneath it, and the build (§8). Nothing is wrong
with the copy held, which keeps answering.

**AC.** The store refuses the link (`HTTP 403` or `404`), the exchange names a link this
container refuses, or the exchange's `patch_policy` entry is not a link at all (step 5), on two
consecutive exchanges, with the container's clock right and no proxy in the way. Report the sentence as worded, `feed.host` and `feed.httpStatus`, and the build (§8).
The link itself is a credential that expires: do not paste it anywhere, and nothing here stores
or logs it.

## 33. "A patch-policy walk is refused, or Jamf or Fleet cannot date it"

A patch-policy walk (#614) takes one app's track from LoonSec's patch-policy data (§32) and one
timeline of release dates, and replays a Mac that installs each release a set number of days
after it is dated, under every stop of the slider, for a window of two or three years. It is a
reference analysis: it reads no device, and its result is neither stored nor sent anywhere. The
timeline is one of three, the **source**:

- **Public**: the release dates LoonSec publishes with its data, from the public release records
  each timeline names (`sources.timelines`): a vendor's own feed (Google's VersionHistory,
  Mozilla's product-details, Wireshark's tags), or Homebrew's cask history where no vendor feed
  is read.
- **Jamf**: this instance's copy of Jamf's public patch catalog, synced hourly with no Jamf Pro
  connection (§6). Every title whose bundle id is the app's is read.
- **Fleet**: this instance's copy of Fleet's history, the day Fleet's catalog first carried each
  version, read while this organization's **Fleet catalog (maintained apps)** flag is on (§27).
  Every Fleet view says it: these are Fleet's dates, not the vendor's, some hours after Homebrew.

Where to read it: **Posture › Patch policy**, once LoonSec's data is held for this organization
(until then the page draws the reference replays, §22 step 11). The page lists the apps the data
references first (*In LoonSec's data*) and every other Jamf Patch title after them (*No reference
yet*, never a count of zero), then a track, the source toggle (**Public**, **Jamf**, **Fleet**;
Public by default), the window (2 or 3 years) and *Compare sources on the days they all cover*
(`align=common`). A source that cannot date the track is drawn disabled, and its sentence is printed
under the toggle in the page's language, with the instance's own English sentence beneath it as
*This instance's words: …*: that second sentence is the one to report. A walk the instance refuses is
printed the same way where the walk would be, and Evidence marks each sentence it prints from the
instance (the timeline's note, each cut of the window, a source left out, the check's detail) the
same way. Under the slider the day graph draws the CVEs open
on each day at the selected stop, with the days CVEs opened and the days an install resolved them
marked in a strip beneath; *The days the count moved, as a table* lists every one of those days.

The same answers, read directly: `GET /api/patch-policy/apps` (**app:read**) lists, for each app, each source and
each track, `available`, a `state` word and, when it is not available, the sentence that says why;
`GET /api/patch-policy/walk?app=…&track=…&source=public|jamf|fleet&years=2|3` answers the walk,
or a `409` whose `detail` is the sentence, `reason` the word, `source` the timeline it concerns
and `facts` what belongs beside it (the unmatched versions, the versions set aside as a channel
LoonSec's data does not walk, the totals that disagreed). The words
below are those reasons. Nothing a walk reads is written, so no container log line accompanies a
refusal: the sentence is the whole report.

1. **A sentence from §32** (*…does not share data with LoonSec…*, *…has not arrived…*, a refused
   copy with none held). The walk needs the copy §32 is about; follow that path first.
2. ***No reference yet for …*** (`app_unknown`) or ***… has no … track in LoonSec's patch-policy
   data yet; it has …*** (`track_unknown`). Not a fault and not a count of zero: LoonSec's data
   does not reference that app, or that track of it, yet. The tracks it does have are named.
3. **The Public source.** `no_public_dates`: ***LoonSec holds no public release dates for … yet…***
   LoonSec lists the track's versions without dates. It reads two ways:
   - ***…, so it has none of its own to walk.*** Only this track is undated; another track or
     window of the app matched LoonSec's totals, so Jamf and Fleet can still date this one, and
     their view says it is shown because that other walk matched (step 7). Choose Jamf or Fleet.
   - ***…, so no walk of … can be checked against the totals LoonSec publishes, and no view of it
     is shown from any source, Jamf and Fleet included…*** No track of the app has public dates,
     so nothing of it can be held to LoonSec's totals (step 7), and every source of the app reads
     this sentence, here and in `GET /api/patch-policy/apps`. Nothing on this instance is wrong
     and nothing here changes it; the app is shown once LoonSec publishes dates for it.
4. **The Jamf source.**
   - `never_synced`: ***This instance has not finished a sync of Jamf's public patch catalog
     yet…*** The catalog is empty: §6 (**Sync now** on Devices › Applications › Jamf Patch runs the
     sync at once).
   - `no_title`: ***This instance's copy of Jamf's public patch catalog has no title for …*** No
     title names the app's bundle id (the sentence gives it). Search Devices › Applications ›
     Jamf Patch for the bundle id; a title Jamf does not publish cannot be walked. Choose another
     source.
   - `no_versions`: ***This instance's copy of Jamf's public patch catalog names no … version …***
     The titles found list no versions at all. Sync now (§6); if it reads the same, choose another
     source.
   - `channel_empty`: ***… lists no … release on the … channel …: none of the versions it names is
     this track's alone. It names …*** The titles carry another track or channel of the app and
     nothing only this track lists. The sentence names each kind it found: versions on another
     track's list, numbers this track shares with another list (named), versions LoonSec's data
     does not list, and builds of a channel LoonSec's data does not walk yet. Only Jamf's "Mozilla
     Firefox ESR" title is held for the release track, say, which names the numbers both channels
     share (140.0, 153.0), ESR builds, and ESR builds older than the channel's list. Choose that
     track, or another source.
   - Not a refusal: versions set aside as a channel LoonSec's data does not walk yet. Beside an
     app's tracks, LoonSec's data names channels it does not walk yet (`other_channels`: Firefox
     ESR beside Firefox's release track, Thunderbird ESR beside Thunderbird's). Jamf's "Mozilla
     Firefox ESR" title shares Firefox's bundle id, and Thunderbird's one title lists both
     channels, so the release track's Jamf view names ESR builds; a version on a channel's list
     and on no track's is set aside before the walk, neither walked nor counted as unmatched. The
     walk's `inputs.timeline.other_channel` counts them, `other_channels` lists them per channel
     (its label, the public record LoonSec read the versions from, and the versions),
     `definitions.other_channel` states the rule beside the walk's own `join`,
     `GET /api/patch-policy/apps` gives each track's `otherChannel`, and a `409`'s
     `facts.other_channels` says the same beside the refusal. The instance counts them and leaves
     the words to the page, so the view's `note` stays the source's own: the page says it once per
     channel in the reader's language, under Evidence › Versions joined, and beside a refusal's
     unmatched versions. A version a track lists is that track's even when a channel lists it too:
     ESR 153.0 shares its number with release 153.0 and is walked as the release. LoonSec's data
     lists a channel's versions without Mozilla's `esr` suffix; a source that spells one with it
     (`128.5.1esr`) is matched by its spelling as given, then without the suffix, and a track that
     lists either spelling still takes it first (`153.0esr` is the release's 153.0). Nothing to do:
     the view walks the track's own channel.
   - `too_many_unmatched` (the walk's own refusal): ***N of the M versions the timeline from …
     dates from … to …, the days a device in this view could install them, match no version
     LoonSec's patch-policy data lists…*** A version LoonSec's data does not list is never
     installed, so above 5% of those in reach the walk would mislead and is refused; the versions
     are in `facts.in_reach.unmatched`. The channels LoonSec's data names are set aside before this
     count (the bullet above; `facts.other_channels` lists them), so what is left is a build of a
     channel it names nowhere, or a spelling it does not list. Choose Public. If they are plainly
     releases of the track, that is reportable state **AE**; if they are plainly builds of a
     channel LoonSec's data names under `other_channels` (Firefox ESR, say), that is **AD**.
   - `no_matched_versions` (the walk's): ***None of the N versions in the timeline from … is a
     version LoonSec's patch-policy data lists for …*** The titles read are not this track's.
     Choose another source; if the titles named are plainly the app's own, reportable state **AE**.
5. **The Fleet source.**
   - `flag_off`: ***Fleet's catalog is not read while the Fleet catalog flag is off for this
     organization…*** An administrator turns the flag on (§27 step 1).
   - `catalog_unread`: ***Fleet's catalog has not been read on this instance yet…*** No check has
     stored titles; when the sentence goes on to say the last check did not get an answer, that
     is §27 step 3. Otherwise **Check now** on the Fleet catalog tab reads it (§27 step 2).
   - `not_held`: ***Fleet's catalog, as this instance last read it, holds no Mac title for …***
     The last check read Fleet's whole catalog, and no Mac title carries the app's bundle id:
     Fleet does not maintain the app. Choose another source.
   - `catalog_partial`: ***Fleet's catalog, as this instance holds it, has no Mac title for …, but
     this instance has read that catalog only in part…*** (the page's own words: *Fleet's catalog
     has been read only in part on this instance, and the part read holds no Mac title for …*).
     The titles held are partial or unread
     ([`fleet-catalog.md`](fleet-catalog.md#complete-or-partial)). A title missing from a catalog
     read only in part is not proof that Fleet has none, so the source does not say `not_held`.
     The sentence goes on with the cause, as the Fleet catalog tab's status line has it:
     - *The last check did not get an answer: …* → a check was cut short after it had read or
       changed some titles. The rest is that check's own sentence, walked in §27 step 3; the
       next check that gets an answer reads the rest.
     - *The last check said: …* → the last check skipped titles this build could not read (§27
       step 6). They stay unread until Fleet next changes its catalog, and *unrecognized Mac
       manifest path* or *unrecognized Mac index entry* among them means updating LoonInspect.
     - *The last check left no words for it…* → the 1.3.0 upgrade marked a catalog already read
       as partial, once, and left its status line as it was (§27 step 6, last case). The next
       check, within the hour, or **Check now** clears it.

     Once a check reads the whole catalog the source dates the track or reads `not_held`. Until
     then, choose another source.
   - `history_unread`: ***Fleet's version history for … has not been read on this instance
     yet.*** The background reads the titles installed on this organization's Macs, two minutes
     apart (§27 step 8). An administrator holding **patch:catalog-sync** reads it at once with the
     title's **Read history**; a title no Mac here has is read only that way. Fleet can hold more
     than one title under an app's bundle id (`firefox` and `firefox@esr`). While one is unread,
     a view walks the titles that are read and its `note` names the one left out; when what was
     read cannot date the track at all (the ESR track with only `firefox` read), the sentence goes
     on ***…, and the history read so far (…) dates nothing this track can walk*** and names the
     unread title instead.
   - `history_failed`: ***Fleet's version history for … has not been read on this instance, and the
     last history read did not get an answer…*** §27 step 9; the sentence after the colon is that
     read's own.
   - `no_versions`: ***This instance's Fleet history names no … version …*** The history read
     dated no version of the title. The title's history on the Fleet catalog tab says why a version
     is left out (§27 step 10); if **Read again** reads the same, choose another source.
   - `esr_missing`: ***This instance's Fleet history (…) names no … ESR release…*** Only a track on
     the ESR channel reads this, and only when every Fleet title read for the app names another
     track's or channel's builds and no ESR build of the track's own: `firefox` read alone, say.
     Fleet's catalog does hold Firefox's ESR title, `firefox@esr` ("Mozilla Firefox ESR", under
     Firefox's bundle id): while its history is unread the sentence is `history_unread` instead,
     naming it, and once **Read history** has read it (§27) its builds date the ESR track. If the
     sentence still reads this with `firefox@esr` among the titles it names, none of the versions
     Fleet's history gives that title is on the ESR track's list; choose another source.
   - Versions the release track's view sets aside (`other_channel`): as for Jamf above. Once
     `firefox@esr`'s history is read, Firefox's release-track view names its ESR builds, and they
     are set aside because LoonSec's data names the ESR channel under `other_channels`.
   - `line_not_followed`: ***This instance's Fleet history (…) dates no … release, so the …
     device has no line to hold…*** Fleet's catalog carries only an app's newest line (Wireshark's,
     for one), so a track held on an older line has nothing to install, whichever lines LoonSec's
     data lists on that track: which line a version is on is LoonSec's `line`, read, not compared.
     Choose the newest-line track or another source. Jamf reads the same way when no title held
     here dates a release on the held line. The walk's own `ceiling_line_undated` (***The timeline
     from … dates no … release, so the … device has no line to hold…***) is the same finding where
     no source above caught it first: on Public it means LoonSec's data names a held line it does
     not date, reportable state **AD**.
   - `channel_empty`: as for Jamf above.
   - `too_many_unmatched` and `no_matched_versions` (the walk's own): as for Jamf above, with the
     versions Fleet's history dates (`facts.in_reach.unmatched`). Every Fleet title with the app's
     bundle id is read, and the builds of the channels LoonSec's data names under
     `other_channels` are set aside first (`facts.other_channels`): Fleet's `firefox@esr` shares
     Firefox's bundle id, and once its history is read its ESR builds are set aside for the
     release track, not counted here. What is left is a channel the data names nowhere. Choose
     Public. If the versions named are plainly releases of the track, reportable state **AE**; if
     they are plainly builds of a channel the data names under `other_channels`, **AD**.
   - Not a refusal: a Fleet view's `note` says *Fleet's catalog was read only in part…*, or
     carries *Fleet's version history for …:* and a title's own history sentence. While the
     catalog is partial, no daily check confirms a title's history past the day it was read, so
     the view ends the day before that read (`window.shortened_by`: `timeline_as_of`), and with
     `align=common` every aligned view ends there too; a check that reads the whole catalog
     carries it to that check's day. The note says so only when a complete check would have
     carried the view further. A title's history sentence (§27 step 10) names what its read left
     undated: those versions are not in the view, and a fix one of them carried is dated by the
     next version the history dates (step 12), so that CVE counts open longer than Fleet's
     catalog alone would show. A state concluded from the titles that were read (`esr_missing`,
     `channel_empty`, `no_versions`, `line_not_followed`) ends, while the catalog is partial, with
     ***This instance has read Fleet's catalog only in part, so another Fleet title under this
     bundle id may be among those not read…***: the title that would date the track may be one of
     them. Read the status line as in `catalog_partial` above.
6. **The window.** A window that was shortened is not a refusal: `window.shortened_by` names each
   reason, with its sentence (the first detectable day LoonSec records, the timeline's first
   release, a held line's first release, a channel's start, the data's date, the day the
   timeline was read, a promotion table that is behind, and with `align=common` the days the
   sources share). `window_empty`: ***You asked for N years ending …; nothing is left to walk,
   because the view would start … and end …: …*** Those reasons left no day; a Fleet history that
   began recently is the usual one. Choose a longer window or another source.
   `nothing_to_install`: ***The timeline from … dates no … release the … device could install…***
   Every version it dates is undated, above the held line, or above the promotion table.
7. **The totals do not hold up.** Every view of an app is held to the totals LoonSec published
   with its data: the walk of LoonSec's own dates for a window must match them before any source
   of that app is shown.
   - `parity`: ***The walk of LoonSec's published dates for … over N years does not match the
     totals LoonSec published with the data (…), so no view of … is shown.*** One window of the
     app disagrees, and every source and window of that app is refused with it, so a definition
     that moved on one side can never be read as a finding. `facts` holds the stop, the total and
     both values; `GET /api/patch-policy/apps` gives every source of the app the same state and
     sentence. Nothing on this instance can fix it: reportable state **AD** if it reads the same
     after the next day's exchange.
   - `unchecked`: ***LoonSec has published no totals this build could match for any window of …***
     No window of the app has published totals, or none walked (`facts.windows` gives each
     window's reason). An app with no public dates at all reads as `no_public_dates` instead
     (step 3). Reportable state **AD** if it reads the same after the next day's exchange.
   - Not a refusal: `check.state: unchecked_window` with ***LoonSec has no check for a N-year
     window of …; it is shown because the M-year walk matched.*** The window asked for has no
     published totals, and another window of the app matched them.
   - Which view was checked: LoonSec publishes totals only for its own dates over a whole window,
     so the check is the Public walk of the window asked for, without `align=common`, and every
     source and aligned window of the track is shown under that one check. Evidence › Check on
     that Public view says *Matches the totals LoonSec published for this window*. On a Jamf,
     Fleet or aligned view it says *Not checked itself: …*, and the instance's `check.detail`
     (***The walk of LoonSec's published dates for … over N years matches the totals LoonSec
     published with the data.***) names the walk that was. Not a fault: no published total
     exists for a Jamf, Fleet or aligned view to be held to. On an unchecked window (above), a
     Jamf, Fleet or aligned view's `check.detail` ends ***…, and its own numbers are not
     checked.*** for the same reason.
   - `document_invalid`: ***LoonSec's patch-policy data for … failed this build's check (…)…***
     The data does not hold together for this app in a way the copy's own check (§32 step 6)
     does not test. Reportable state **AD**.
8. **A defect on our side.** `invariant` (***…was refused because its own totals disagree…***),
   `timeline_invalid` (***The release timeline given to the walk cannot be read…***) and
   `request_invalid` (***A window is 2 or 3 years…*** or ***The stops asked for are…***, for a
   request the page built) are LoonInspect's own and say so. Reportable state **AE**.
9. **Two sources give different numbers.** They should: their dates differ, and so do the days
   each covers. Compare them only with `align=common`, which cuts every view to the days all the
   sources that can date the track share (`window.aligned` names them, and any left out with its
   sentence), and read each view's own counts. `input_id` names a walk's inputs and `run_id` its
   result; the same pair is the same numbers.
10. **The page says the walk could not be read, or cannot be drawn.**
    - *The walk could not be read from this instance (…)* → the request failed, which is not a
      refusal: a refusal always prints its own sentence. The bracket gives what answered. *no answer*
      is a container that did not answer (§4); `HTTP 403` is an account without **app:read**;
      `HTTP 422` is a request the page built and the route did not accept, as is any other status with
      the container up: reportable state **AE**.
    - *This instance answered with a walk this page cannot draw (…)* → the answer arrived and is not
      the shape this page reads; the bracket names the part. A page left open across an update of the
      instance does this: reload. If it reads the same after a reload, it is reportable state **AE**.
    - *Nothing is walked over … for this track: the reason is under the toggle above* → the address
      names a source the instance reported it cannot date for this track (a link from another
      organization, say). The sentence under the toggle is that source's step above; choose another.
    - *LoonSec's patch-policy data does not walk … ESR yet; it walks …* → Jamf's catalog has an ESR
      title that shares the app's bundle ID, so the list shows it under the app's row; the walk is of
      the release channel only. Whether the ESR builds a Jamf or Fleet view reads are set aside
      depends on the copy held: one that names the ESR channel under `other_channels` sets them
      aside (step 4); one that does not counts them as unmatched, and the view can be refused as
      `too_many_unmatched` (step 4, step 5 on Fleet; choose Public). `feed.docId` from
      `GET /api/patch-policy/apps` names the copy. Not a fault.
    - *Page P is past the end of this list: it holds N CVEs on M pages…* → the address names a page
      of the CVE list (`page=`) that the walk does not have, because the list is shorter now than
      when the link was saved: each new copy of LoonSec's data can change how many CVEs a window
      lists. The route answers such a page with no rows and `cves_page.page` above
      `cves_page.pages`. **Show page M** opens the last page. Not a fault.
11. **The never stop's never-seen count, and what it does not show.** A device kept to the never
    stop never leaves the first version the window starts it on (the walk's
    `policies.never.initial_version`), so under that stop's count the page splits it by why, in
    place of the other stops' *… never seen were never in range…*: *A device that never updates
    stays on … Of the N never seen, F were already fixed in …, so the device never ran a version
    they affect. The other O fall outside every range NVD names…* The two kinds read differently:
    - **Already fixed** (`fix_installed_first`; the stop's `never_seen` less
      `never_seen_outside_affected_range`): the version the device keeps carries the CVE's fix on
      its line, so it never ran a version the CVE affects. An old CVE whose clock day falls in the
      window, years after its fix shipped, reads this way. These are a real never seen.
    - **Outside every range NVD names** (`never_seen_outside_affected_range`): no affected range NVD
      gives the CVE holds that version. Either the CVE affects only other versions, or NVD names no
      range for that version's line: NVD's ranges often stop naming a line once it reaches end of
      life, so a device left on an old line reads never seen for CVEs that may well affect it.
      These do not show the device was safe.

    How the count splits depends on the version the never device keeps, so it differs by app,
    track and window, and it moves whenever a new copy of LoonSec's data moves the window: the
    page prints both numbers for the view on screen. That version is the newest release available
    by the window's first day (`definitions.steady_state`): the never stop is a device that stops
    updating that day, not one already behind, so for the window's first 59 days it can run a
    newer release than the 60-day stop, which opens the window on the newest release it would
    already have installed. Where most were already fixed, the never stop can count fewer never
    seen than the 30-day stop, because the CVEs fixed before the version the device keeps are ones
    it never ran. Read the second kind as "NVD names no range here", not as "this device was never
    exposed"; the stops that install are the comparison that means something. The reference
    replays that ship with the build (§22 step 11) split their never stop the same way, in the
    same words, from the replay file's own `policies.never`. Not a fault.

12. **A CVE's fix is dated by a later version, or by none.** Not a refusal. A timeline often does
    not date the exact build LoonSec's data names as a CVE's fix: Fleet's history holds only the
    builds Fleet's catalog carried, from the day it began. Such a CVE is not left out. As ruled on
    2026-11-25, the walk counts the next dated version at or above the fix on the
    fix's line that the CVE's affected range does not cover (a version the CVE still affects never
    stands in for its fix; one held affected only by rule 5 can), and that version's day is the
    fix's day for every rule, the one that keeps an older-dated build of another release train
    affected included (a build of the fix's own train, or of the train of the version that dated
    it, is spared). Each CVE row says which version dated each fix in `fix_dated_by`: one entry for
    each fix LoonSec's data lists for the CVE on a line the path visits (the line of any version a
    device under any stop runs during the window), in the data's order. LoonSec's data can list
    several fixes at one version (the fix itself, then each of NVD's bounds that lands there), and
    each is its own entry, counted on its own:
    - `fix` is the fix LoonSec's data names, and `named` is NVD's own fix version where the version
      LoonSec points at is not that exact one (null otherwise): the next listed version above it,
      or, where that one is still in the CVE's range, the first listed version above the range.
      NVD can name a build the Mac never got: for Chrome's Linux and Windows build 142.0.7444.59,
      LoonSec points at the Mac's 142.0.7444.60 of the same day, and `named` reads 142.0.7444.59;
    - for Chrome, NVD's build can be another platform's that Google numbered above the Mac's build
      of the same release. LoonSec keeps NVD's bound, and the fix counts from the first Mac build
      at or above it, which is a release late where NVD named such a build. As ruled on
      2026-11-25, three releases are corrected, and only for the CVEs that release's own Chrome
      Releases post names as fixed by it: a CVE on the post whose range NVD ends at the release's
      build counts from the Mac's own build read from that post, and `named` keeps NVD's build
      (106.0.5249.61 for NVD's 106.0.5249.62, 135.0.7049.41/.42 for 135.0.7049.52, and
      136.0.7103.48/.49 for 136.0.7103.59). Any other CVE NVD ends at one of those builds keeps
      NVD's range. One does: CVE-2025-3066, which NVD ends at 135.0.7049.52, is not on the
      2025-04-01 post that 135.0.7049.41/.42 shipped with; Google's 2025-04-08 post names it fixed
      in 135.0.7049.84/.85, and NVD's own description says "prior to 135.0.7049.84". Its `fix`
      135.0.7049.84 beside `named` 135.0.7049.52 is the build that fixed it, not a fault. NVD's
      114.0.5735.110 and 144.0.7559.99 keep NVD's bound too: LoonSec has not read which Mac build
      carries those fixes, so they can count a release late. A copy built before the ruling counts
      all three releases from the first Mac build at or above NVD's. That is LoonSec's data, the
      same on every source, not a fault;
    - `dated_as` and `on` are the version whose date the walk used, and that date. Dating a fix is
      not clearing it: a device clears the CVE when it installs a version outside the CVE's
      affected range that rule 5 does not keep affected. A fix the timeline dates itself is its own
      `dated_as`, since LoonSec's data is the authority on its own fixes, and a later version
      standing in for an undated fix is always outside the range. LoonSec's data never points a
      fix inside its own CVE's affected range: an entry whose `fix` the row's `affected_text`
      covers is walked as given, though installing that fix clears nothing, and is reportable
      state **AD**, with the CVE row;
    - `how` is `fix` when the timeline dates the fix itself, `next_dated` when it dates a later
      version outside the range instead, and `undated` when it dates nothing at or above the fix on
      that line outside the range, or LoonSec's data names no fix version there. An `undated` line
      has no fix a device could install, so the CVE stays open on it until the device moves past
      its affected range.

    `counts.fix_dating` totals the entries over the rows the walk lists. A Jamf or Fleet view reads
    `next_dated` far more often than Public. Open the same CVE on the Public view and compare `on`
    with the fix's day there:
    - `on` weeks or months later is the timeline's gap, not a defect: Public shows the vendor's own
      dates, and a fix older than the first version a timeline dates is dated by that version.
    - `on` earlier means the next dated version is a build of a later release train that the vendor
      shipped before the fix, which a line holding several trains allows. It stands in for the fix,
      so rule 5 spares it, where Public, dating the fix itself, keeps that build affected. The two
      views differ there; neither is a defect.

    On Public, `next_dated` appears only where LoonSec lists a version without a date.
    `how: next_dated` or `fix` with no `dated_as`, or a `next_dated` entry whose `dated_as` the
    CVE's affected range covers, is reportable state **AE**.

    On the page, the list of CVEs gives each row's `fix_dated_by` on a line beneath the row, *Fixes
    of CVE-…, as this source dates them:*, one list item per entry (two entries at one version are
    two items: the fix, then NVD's bound that lands there, with `named`): a `fix` entry is the fix
    and the date the source gives it, with nothing more; a `next_dated` entry reads *…: not dated by this source, so counted from …,
    the first version at or above the fix that it dates outside the CVE's affected range, on …*
    (a version the source dates inside the range is passed over, so this can be later than the
    next version the source dates); an `undated` one reads *…: this source dates no version at or
    above it on the … line outside the CVE's affected range, so this CVE is walked by its affected
    ranges there* (*No fix version on the … line in LoonSec's data…* where the data names none). NVD's own
    version follows in brackets where `named` differs. Where the version that dated a fix is dated on
    the timeline's first day (`inputs.timeline.first`), the line goes on *Fleet's history begins
    here* (or Jamf's): the fix is older than anything the source holds, and its `on` is where that
    history starts, not a day the fix shipped. Evidence › *Fixes dated* gives `counts.fix_dating`,
    over the lines a device under any stop runs in the window.
    A copy of LoonSec's data from before 2026-11-25 still lists `fixed_version_not_in_timeline`
    among the exclusion reasons; the walk counts it 0, and the page's exclusion table says it is no
    longer a reason. Since the same day LoonSec's data no longer excludes a CVE as
    `fixed_version_not_in_catalog` either: it lists a fix the track's version list does not hold
    at the next version at or above it, with `named`. A copy built since counts that reason 0, and
    the table says it is no longer a reason; an older copy can still count some. Not a fault.

**AD.** A patch-policy walk is refused because LoonSec's data does not hold up — the walk of
LoonSec's own dates disagrees with the totals published with it (`parity`), no window of the app
has totals this build matched (`unchecked`), the data fails the walk's check
(`document_invalid`), it names a held line it does not date (`ceiling_line_undated` on
Public), or a Jamf or Fleet timeline is refused over builds of a channel the data names under
`other_channels` and does not list in full (`too_many_unmatched`, with Firefox ESR builds among
`facts.in_reach.unmatched`, say) — and reads the same after the next day's exchange. Report the
sentence as worded, the app, track, source and window asked for, `feed.docId` and `feed.asOf`
from `GET /api/patch-policy/apps`, and the build from Settings › Support (§8). A walk that was
shown is reportable state **AD** too when a CVE row's `fix_dated_by` names a `fix` the row's own
`affected_text` covers (§33 step 12): report that CVE row with the same.

**AE.** A patch-policy walk is refused as a defect in LoonInspect: its own totals disagree
(`invariant`), the timeline or the request it built is refused (`timeline_invalid`,
`request_invalid`), or a Jamf or Fleet timeline is refused over versions that are plainly the
track's own (`too_many_unmatched`, `no_matched_versions`); or, with the container up and the
account holding **app:read**, the page cannot read LoonSec's data's state or a walk (§22 step 11,
step 10), or cannot draw a walk it read, after a reload; or a walk that was shown says it dated a
fix by a version it does not name (`fix_dated_by` with `how: fix` or `next_dated` and no
`dated_as`, step 12), or dated an undated fix by a version the CVE's `affected_text` still covers
(`how: next_dated`, step 12). Report the sentence as worded (or the CVE row), the refusal's
`facts`, the app, track, source and window asked for (the page's address carries all four), and
the build (§8).
