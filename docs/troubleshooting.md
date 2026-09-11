# Troubleshooting: the step-throughs

Status: **ruled**, 2026-09-10 ([#290](https://github.com/LoonSecIO/LoonInspect/issues/290)) ·
The language these paths are written in is [`diagnosability.md`](diagnosability.md) ·
Every step below uses only what a fresh operator has: the app, its API,
`docker compose logs`, and the run log. A step that needed source code was not written;
it was filed.

Each path is ordered — *check this; if X, then that* — and ends in a fix or in a **named,
reportable state**. When you reach a reportable state, §6 says what to include.

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
page) and *is a library installed* (step 2, a log line), in that order — the tier is the
cheaper question and the more common answer.

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
2. **The tier is on and it is still grey — is a library installed?** Read the app's log
   for the one line the loader writes:
   `docker compose logs app --since 48h | grep -i "vulnerability library"`.
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
   - **no line at all** → no exchange has completed since the container started. Settings
     › Data Sharing shows the last exchange and its outcome; a run of `failed` rows there
     is an exchange problem rather than a corpus one, and its own error is on the row.
3. **A date is on the banner, and every app under it says *outside the corpus*.** Not the
   same fault as grey, and usually not a fault at all. The container stores each build's
   answer beside the build and re-judges when a new corpus arrives, so in the minutes after
   a new corpus lands — before that pass runs — apps read **outside the corpus** rather than
   keeping yesterday's numbers under today's date. That is deliberate: a count from one
   corpus shown under another's date is a wrong answer that looks right, and this one
   corrects itself. It clears on its own within the hour (the patch-catalog job re-judges
   every organization hourly), and sooner for any Mac that checks in. Two ways to stop
   waiting:
   - `docker compose logs app --since 2h | grep "vulnerability answers refreshed"` — the
     line the pass writes, with how many builds it re-judged and how many app rows it
     updated. A line since the corpus line in step 2 means the pass has already run, and
     amber on a build is then that build's real answer: the corpus did not assess it;
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

**H.** A corpus is loaded, this organization's tier is not `off`, and the pages still do
not answer from it — either they say nothing is answering (grey), or a *Refresh* leaves
builds the corpus should know reading **outside the corpus** (amber). Report the library
log line, any `vulnerability answers refreshed` or `stored vulnerability answer … could
not be read` lines, the tier shown on Settings › Data Sharing, the build (Settings ›
Support), and `GET /api/catalog` — the response carries `corpusAsOf` beside the rows it
describes, and a `null` there with the tier on is the defect. A `null` with the tier
**off** is step 1, not a defect.
**I.** The published corpus is refused, unreachable, or unchanging. Report the exact log
line (it names the epoch and the state), the build, and roughly when it started.

## 6. When a path ends in "report"

Include: which path and which step you reached; the run's `jobID` and the panel's lines
(or `GET /api/runs/{jobId}/log`); `docker compose logs app --since 30m`; the build,
from Settings › Support; and, for a delivery problem, the destination's `id`, `lastError`
and counts. An issue with those four things is answerable; one without them starts with a
request for them.

## 7. What this document deliberately does not contain

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
