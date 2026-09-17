# Troubleshooting: the step-throughs

Status: **ruled**, 2026-09-10 ([#290](https://github.com/LoonSecIO/LoonInspect/issues/290)) ·
The language these paths are written in is [`diagnosability.md`](diagnosability.md) ·
Every step below uses only what a fresh operator has: the app, its API,
`docker compose logs`, and the run log. A step that needed source code was not written;
it was filed.

Each path is ordered — *check this; if X, then that* — and ends in a fix or in a **named,
reportable state**. When you reach a reportable state, §8 says what to include.

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
3. **Test it.** The Test button, or `POST /api/destinations/<id>/test`. Read
   `statusCode` and the error:
   - connection refused, timeout, name not resolved → the URL, the port, a firewall, or a
     TLS certificate the container does not trust. `https://` with a private CA needs the
     CA in the container ([`splunk-setup.md`](splunk-setup.md) §5); plain `http://` needs
     `ALLOW_INSECURE_DESTINATION_URL=true` and is for a lab. Fix, test again.
   - **401 / 403** → the token or auth header is wrong. Edit the destination, re-enter the
     secret, test again.
   - **400 from HEC** → usually the token's index (step 5) or the URL's path
     (`/services/collector/event`, [`splunk-setup.md`](splunk-setup.md) §3).
   - **200** → step 4.
4. **Delivery health.** The destination row: `pendingCount`, `failedCount`, `lastError`.
   - `failedCount` above zero → those deliveries gave up after ten attempts; `lastError`
     is why. Fix the cause (step 3), then **Redrive** returns them to the queue. Events
     that arrived after the fix flow on their own.
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
     and the next tick drains the queue. The second is the next bullet. Still rising with
     line → reportable **D**. `deadLettered.oldestExpiresAt` is the instant the oldest
     dead letter stops being redrivable, and `retention.nextPurgeAt` is when the purge
     that takes it runs.
   - **More than one app process, and the queue is not draining.** The second reason a
     tick attempts nothing, and usually not a fault at all.
     `docker compose logs app --since 10m | grep "outbox tick skipped"`. That line means
     the process printing it found another one already delivering for that organization
     and did nothing, which is correct: one process delivers at a time and the rest say
     so every tick ([`operations.md` §7](operations.md)). It is only a problem when
     *every* process prints it and the queue is still not moving — `pendingCount`
     climbing and `pending.oldestAgeSeconds` rising with it. Then the process holding the
     lock is wedged rather than working. Restart the stack: the lock goes with its
     connection, and the next tick takes it.
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
   answer beside the build and re-judges when a new corpus arrives, so in the minutes after
   a new corpus lands — before that pass runs — apps read **outside the corpus** rather than
   keeping yesterday's numbers under today's date. That is deliberate: a count from one
   corpus shown under another's date is a wrong answer that looks right, and this one
   corrects itself. It clears on its own within the hour (the patch-catalog job re-judges
   every organization hourly), and sooner for a Mac that checks in — that Mac. A build one
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
   answer is not the collector.
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
   latest**, not for the build you are looking at, and it means the corpus holds no row
   for that release — nobody assessed it. It is deliberately not rendered as *closes all
   of them*: an update whose target nobody looked at buys an unknown, not a clean bill,
   and a missing row is never upgraded into one. Nothing is broken and there is nothing
   to fix in the container. Two things tell the ordinary reading from a fault:
   - the release named is the one the **Latest** column names, and is usually newer than
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
   next time that catalog moves. A release nobody looked up is never dressed as one the
   corpus has no row for, so the absence is the honest state and not a silent failure. To
   stop waiting, use Devices › Applications › **Catalog** › *Refresh* (step 3) — it
   re-matches every row, and the lines appear on the next page load.

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
   department 5*, *Not managed by Jamf*, *Assigned user matching “dana”* — and a press clears it.
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
   corrections), and a click on a row's model, which is how the rest are discovered.

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
   again, which puts it straight back. If yours is not in the count, read the census line's last
   clause. *…; matched by Jamf id, and by serial with UDID* → both keys were there, so compare them
   on its page against Jamf Pro's: one differs, and a **new UDID under the same serial is a
   logic-board repair**, a lineage event rather than a return. *…; matched by Jamf id only: this
   sweep's sections carry no hardware, so no serial to match on* → the collection carries neither
   **hardware** nor **extension attributes** (which force it back in); add either. A serial is
   Apple's and an instance's view of it is not, so a Mac moved to a *different* Jamf Pro departs
   here and enrols as a new Mac.
4. **Your SIEM saw nothing either way.** A Mac's departure and return are not on the wire
   yet. `subject.departure` / `subject.returned` ship today for **objects** — a smart group or
   an extension-attribute definition (path 15) — under the sourcetype `loon:departure`; the
   Mac's own seven-day tail and its closing `state: removed` are built on this census and are
   the follow-up to #179. Until then the run log above and
   `GET /api/devices?includeDeparted=true` are where a departed Mac is visible, and a saved
   search on `loon:departure` will correctly find no `subjectKind=computer` events. That is
   not a delivery fault and not reportable.
5. **An alert closed itself, or the nightly numbers moved, and nobody touched anything.** A
   Mac leaving takes its open latches with it — the sweep is what closes a latch, and a Mac
   that left is never swept again, so one left open would read as *true of the fleet* for ever.
   The census line says so: *…N open alert latches closed on Macs that left the fleet; nothing
   was deleted*. **Nothing was** — `GET /api/alerts?open=false` lists the row with
   `closedReason: "device_departed"`, which is what tells it from an ordinary `app_gone` close,
   and the Mac's apps, observations and changes are all still there (closed rows then age out
   at 30 days, like run history). No `closedReason` at all means the row closed before
   2026-09-16, when the reason started being recorded; not a fault. The same day is the answer
   to the numbers: the posture tape counts the fleet without its departed Macs — device counts,
   alert counts, and every app, catalog, patch and vulnerability key that counts what a Mac
   carries ([posture-snapshot.md](posture-snapshot.md), *Departed Macs*) — so a Mac's numbers
   leave on **day seven of its tail**, not the day you deleted it in Jamf, `devices.departed_24h`
   says how many left that night, and captures written before 2026-09-16 counted deleted Macs
   and cannot be corrected. An open latch still sitting on a Mac that left *is* a fault: the
   census has not run since it crossed day seven (step 1), and if a clean one has, state **T**.
6. **You want it gone for good.** Nothing removes a Mac's history today — not this, not
   deleting the connection. Honouring a Jamf deletion as an erasure is a stated, deliberate
   deferral (v5); [`jamf-observations.md`](jamf-observations.md) §8 says what is held.

**T.** A finished, unselected, failure-free device sweep whose log has no *device census* line;
a Mac Jamf returns on the sweep's own endpoint that still departs or stays departed; or an open
alert latch still on a Mac that left the fleet after a clean census has run since. Report the
run's `jobID` and its log, the census line if there is one, the Mac's Jamf id, the collection's
**Selector** field, and `docker compose logs app --since 30m`.

## 17. "The evidence report is empty, or every row says it was not reported"

The report is a document a person files, so it never leaves a reader to infer why it is thin: every
state below prints its own sentence in a **Read this first** box at the top of the page, above the sum.
Read the box first, then the step here. **Settings › Connections → Evidence report** on the connection's
row downloads it (`GET /api/evidence/report.html`, the same answer as `…/report` in JSON, which is also
inside the page); both need the **Auditor** role's `audit:read`.

1. **The download is refused outright.** Three refusals, each carrying its sentence in the red line
   above the table:
   - *This connection has no observations…* → the observation ledger is written by a **device sweep**
     and nothing else, so a connection that has only run catalog refreshes or webhook runs has none.
     §2 step 5 has the rest.
   - *The report window is empty: `start` must be earlier than `asOf`.* → only reachable by calling the
     endpoint with your own dates. The button asks for neither and gets the ninety days before the
     ledger's last collection.
   - *The evidence report cannot be rendered: the baseline rule catalogue could not be read…* → the
     report refuses rather than printing part of a catalogue, because a rule that failed to load reads
     exactly like a passing fleet. The sentence names the file it looked for. This is reportable state
     **U** — nothing about the fleet is wrong.
2. **The page downloads, and says *No observation in this window*.** The window closes before this
   connection's first observation, or opens after its last. The connection is not broken and no Mac is
   named because none had been seen yet. Open the connection's run panel for the newest device sweep and
   read its finish time; ask again for a window that reaches it.
3. **It says *Part of this window was not collected*.** A stretch inside the window where nothing
   reported — the collector not running, not a fleet in a good state. Those days are counted as *no
   observation* by Mac in the sum rather than folded into met or unmet. Find the stretch's dates in the
   **Every interval** table, then read the runs for them. If the stretch is a scheduled sweep that did
   not fire, that is §1 or §12; if it is a sweep that ran and failed, its run row says why.
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
7. **It printed badly.** Print from a browser to A4 portrait with headers and footers off; the page
   carries its own margins and repeats both the refusal line and each table's heading on every sheet.
   Nothing is fetched while it renders, so a machine with no network prints the same page. A digest that
   wraps across two lines is wrapped, never shortened — every character is there.

**U.** The catalogue refusal, or a contract version this build has no rules for. Report the sentence
from the box, the build from Settings › Support, and `docker compose logs app --since 30m`.
