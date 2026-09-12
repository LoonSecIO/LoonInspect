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
destination with what is queued, what gave up, and the last error. The Overview's status
strip is the first line to read: it says which of those is unwell.

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
```

**The container log.** `docker compose logs app --since 30m` (add `db` for the
database). This is where the app speaks before there is a run to write to.

**The run log.** One line per milestone: `run started`, `devices processed`,
`group definitions observed`, `run finished`, and warnings such as `throttled by Jamf;
backed off and continued` or `extension attribute definitions not readable; census
skipped`. It is the panel under the connection's row, or `GET /api/runs/{jobId}/log`.

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

**C.** Webhook runs for inventory events process zero devices. Report the `jobID`, the
event type Jamf sent (the webhook's own configuration), and the run log.

## 3. "Events are not arriving in Splunk" (or any destination)

Work from the app outward: was anything produced, was it queued, was it delivered, and
did Splunk keep it.

1. **Was anything produced?** `GET /api/runs?pageSize=5`: a `device_sweep` run with
   `status: succeeded` and `deviceCount` above zero. None → this is §1 or §2, not a
   delivery problem.
2. **Is there an enabled destination?** Settings › Destinations, or
   `GET /api/destinations` → `enabled: true`. A stack with no enabled destination holds
   its events and delivers nothing — the setup stepper calls the destination step
   optional, and holding is the ruled behaviour ([`splunk-setup.md`](splunk-setup.md)).
   Add or enable one; the held events fan out on the next tick.
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
   - `pendingCount` climbing and nothing delivered → the destination is accepting slowly
     or the tick is behind; wait two ticks (a minute). Still climbing → reportable **D**.
   - Both zero and the runs in step 1 succeeded → step 5.
5. **Subscriptions.** `subscribedEvents` on the destination: `null` means every event
   type; a list means only those. A list without `device.inventory` gets no snapshots,
   without `device.change` no change events, and a list of none gets nothing at all,
   silently. Set it to what you expect, or clear it.
6. **The index.** LoonInspect never sends an `index` field. The HEC token must have exactly
   one allowed index and it must be the default ([`splunk-setup.md`](splunk-setup.md)
   §2); a token with no default index does not put the events where you are looking.
   Then search the cheapest event first: `index=<yours> sourcetype=loon:run` finds every
   `run.completed`; `sourcetype=loon:jamf:mac:app` finds the app sub-events.
7. Runs succeed, the test is 200, nothing failed or pending, the subscription includes
   the type, the index is right, and the search is empty → reportable **E**.

**D.** Deliveries stay pending across several ticks with no failures. Report the
destination `id`, `pendingCount`, and `docker compose logs app --since 10m`.
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
   If the original key is gone, the stored credentials are gone with it: delete each
   connection and destination and create it again with its secret. Account passwords
   survive; they are hashed, not encrypted. Only if the original key is back and the 500
   persists → reportable **G**.
4. Healthy and signed in, and something else is unreadable → reportable **G**.

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
   if none is, one arrives at the next day's exchange (the schedule is jittered per
   tenant, so it is not immediate). If this instance has more than one tenant, check the
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
     and a run of `failed` rows there is an exchange problem rather than a corpus one,
     with its own error on the row — or the exchanges are succeeding and naming no corpus
     at all, which is the paragraph below.

   **Succeeding exchanges, no library, and nothing wrong.** An exchange that answers
   without naming a corpus is silent by design, so this state is grey with no log line to
   explain it. There is nothing to fix in the container. One state looks exactly like this
   and is not it — an epoch this container holds and cannot read — so search the whole log
   for `the stored vulnerability library could not be read` before you read this paragraph
   as your answer. The published corpus reaches staging first, and **a customer's first
   epoch arrives with the production cutover**; until then an instance pointed at
   production reads *not assessed* for every app with the tier on, and that is the expected
   reading rather than reportable state **H**. Settings › Data Sharing is what separates
   this from a broken exchange: rows reading `sent`, day after day, with no library line
   beside them.
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

## 6. "The Jamf Patch table is empty, or it stopped refreshing"

The patch catalog is the list of titles every Applications surface is matched against. It
is one list for the whole container — not per connection and not per organization — and
it refreshes hourly on its own. **Devices › Applications › Jamf Patch** shows it, with a
**Sync now** button that performs the same refresh immediately. The refresh dials a public
Jamf server; no credential of yours is involved, so nothing here is a permissions problem.

1. **Press Sync now and watch the table's *Synced* column.** If the row dates move, the
   refresh works and the catalog is current; a table that is still empty after a refresh
   that reported no error is reportable state **J**. The first press on a freshly started
   container is the slow one — the whole catalog is fetched title by title and takes
   minutes, not seconds, and nothing on the page cancels it. Let it finish.
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
     the page still shows nothing, that is reportable state **J**.
   - nothing for `/api/jamf-patch/sync` at all — only the page's own `titles` reads, or no
     output whatever → the press never reached this container, and no hourly refresh has
     completed since it started either. The job runs at the top of each hour and not at
     startup, so an empty table is expected for up to an hour after a restart — but a
     press that leaves no line is not. Check that the app is reachable from the browser's
     own machine (`curl -si $BASE/api/health`) and what sits in between; a press that
     still writes nothing while health answers is reportable state **J**.
3. **The table has rows and one title you expect is missing.** A title whose definition
   the server refused is skipped for that refresh and fetched again at the next one, so a
   gap that closes by itself is working as designed. A title that is published by Jamf and
   still missing a day later is reportable state **J**.

**J.** A refresh that reports no error leaves the table empty, a title Jamf publishes
stays missing for more than a day, or a press of **Sync now** writes nothing to the
container log while `/api/health` answers. Report what the *Synced* column shows, the
output of `docker compose logs app --since 1h`, and the build from Settings › Support.

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
