# 🦅 LoonInspect

**The software-change feed for Jamf Pro fleets — what changed on every Mac, in your own SIEM, without installing anything on the Mac.**

Computers only — mobile devices are not collected. See [docs/mobile-devices.md](docs/mobile-devices.md).

LoonInspect reads inventory from Jamf Pro, works out what actually changed since the last read, and streams those changes as structured events into Splunk, Elastic, RunReveal, or any webhook endpoint. It is agentless: nothing is installed on managed devices.

---

Site and Field Notes: [loonsec.io](https://staging.loonsec.io) (staging until launch). The notes hold the setup guides, including [Apple's on-device model with Docker Desktop](https://staging.loonsec.io/notes/apple-foundation-models-with-docker-desktop/).

## 🚀 Features

* **Built for Jamf Pro:** Native Pro API integration and webhook ingestion. LoonInspect is Jamf-only by design (#79) — `app/mdm/factory.py` builds a Jamf client directly rather than dispatching through an abstraction. A second MDM would be a sibling vertical in this repo, not a provider this one plugs into.
* **Delta Streaming Engine:** Diffs inventory against the last observation and streams structured JSON events (`device.inventory.changed`, `device.change`) directly to your SIEM, beside one `device.inventory` snapshot per device per pass so the SIEM always holds the current state. A sweep where nothing changed emits no deltas. The wire vocabulary is frozen and amended only additively — [docs/splunk-wire-vocabulary.md](docs/splunk-wire-vocabulary.md).
* **Small on the wire, by subscription:** Deltas measure 509 bytes per event plus roughly 330 bytes per changed app (both from the real payload builder; [docs/splunk-setup.md](docs/splunk-setup.md) has the sizing) — a quiet day is roughly 4 MB. The per-device snapshot is the expensive one. It is *stored* as about 28 KB for a Mac with 83 apps where every app reads `assessment: off` (see "Vulnerabilities" below), and *delivered* fanned out into 107 records — one per app, extension attribute, certificate, profile, group, local account, plus seven per-device anchors — which measures about 79 KB to a webhook or RunReveal, 84 KB to Splunk HEC, and 90 KB as an Elastic `_bulk` body. That is one request per device per pass either way, so a 40,000-device sweep is roughly 3.2–3.6 GB today (up to about 6.8 GB once every app is fully assessed). The split is what makes `app.name=X app.version=Y` mean one app rather than two independent multivalue fields; [docs/runs.md](docs/runs.md) §4 has both fan-outs. Destinations subscribe per event type, so a delta-only feed stays small.
* **Hybrid Sync Architecture:** Real-time webhooks for active devices and scheduled off-peak sweeps for the rest. Each pull is a *collection* — what to read (Jamf sections, a device filter pushed into Jamf's query, the smart-group catalog) and when (time of day, timezone, cadence) — configured per connection in the app rather than as one global cron.
* **Tenant isolation in the database:** Row-level security is enforced by Postgres rather than by application filters, and CI asserts that the application role cannot bypass it.
* **Self-hosted:** One container and a Postgres database. No vendor account required to run it.

### Vulnerabilities

Each installed app is answered at the build that is actually on the Mac, in one of three
states. A build that was checked reads **No findings**, or the findings themselves — a
count, what is on CISA's KEV list, and the ids. A build that was not checked reads
**Outside the corpus**. **Not assessed** means nothing is answering for your organization
at all. A checked build and one outside the corpus both carry the date the corpus was
generated. *Not assessed* carries no date, because it has none.

The three never collapse into each other. *Outside the corpus* is amber rather than
green, because "we did not look at this" is a different fact from "we looked and found
nothing", and a gap coloured green is a wrong answer that looks right. Nothing
unassessed is ever rendered as a zero, on the page or on the wire
([docs/vulnerabilities.md](docs/vulnerabilities.md) §4a, §4g).

**What the corpus does not know is part of the answer.** It is compiled from public
sources against the list of software titles Jamf publishes in Jamf Pro's Patch
Management catalog, and Jamf's identifiers enter it only as content hashes. It covers
what it covers: the first epoch compiled, on 2026-09-11, answered for 28,872 distinct
builds across 623 of the 1,553 titles that catalog held that day. An app outside that
map reads `unknown_app`, *Outside the corpus* on the page, dated, and it keeps reading
that until a corpus knows it. That is the design and not an embarrassment. A corpus
whose edge is countable is one whose coverage you can check.

**How it arrives.** Once a day, over the data-sharing exchange described below, to
consenting instances only. The response names the published corpus and its signature.
The container downloads it only when that signature moves, verifies the bundle whole or
refuses it whole, and joins it locally against the content keys the app catalog already
carries. Receiving it adds nothing to what leaves: the corpus rides the response to the
exchange the instance already makes, and the request body is unchanged by it. No lookup
leaves the container when a page or an event is answered. Consent earns it in both
directions — an organization with data sharing off reads *Not assessed* even where the
container holds a corpus ([docs/vulnerabilities.md](docs/vulnerabilities.md) §8).

**A customer's first epoch arrives with the production cutover.** Until then the
published corpus is delivered on staging only, so an instance pointed at production
reads *Not assessed* for every app. When a page says that and you expected otherwise,
[docs/troubleshooting.md](docs/troubleshooting.md) §5 is the step-through.

*This product uses the NVD API but is not endorsed or certified by the NVD.*

### What it does not do

No EPSS, no CVSS, and no scanner. Nothing is installed on a Mac, and LoonInspect scores
nothing of its own: it reports what the published corpus carries for the build Jamf
reported. No SCIM, no MFA. The vulnerability answer is the summary block described above
and nothing else — no per-finding lifecycle events, no fleet-wide coverage tile, and
nothing at all against a Jamf Patch title's version row, which carries no build to answer
at. The corpus is compiled outside this repository and delivered over the data-sharing
exchange, to consenting instances only ([docs/vulnerabilities.md](docs/vulnerabilities.md)
§1, §2); an instance pointed at production reads `assessment: off` for every app until the
production cutover, and a customer's first epoch arrives with that cutover. If what you
need is a scanner and a CVE score, this is not that tool.

---

## 🏗 Architecture Overview

LoonInspect is designed around a **"Diff, Stream, Commit"** pipeline:

1. **Ingest:** Receives a Jamf webhook, or runs a scheduled sweep.
2. **Fingerprint:** Hashes each app's identity and version, so a repeat read is recognisable without comparing strings.
3. **Analyze:** Diffs against the stored observation to determine what actually changed.
4. **Stream:** Emits the delta to your SIEM for logging, compliance, and alerting.

Beneath the delta, every Jamf observation is also kept as a versioned, content-addressed
record — what each device looked like each time it was read, and through what collector
configuration — so history can be diffed without phantom changes when the shape evolves.
The contract is in [docs/jamf-observations.md](docs/jamf-observations.md).

**Nothing here is deleted.** Devices, installed apps, extension attributes, the
observation ledger, and the change log (`device_changes`) have no retention setting and
no purge job — a Mac removed from Jamf keeps its full history. The only three things this
project ever prunes are the delivery outbox (7 days), finished runs (30 days), and the
audit log (30 days, by file rotation). See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for what
that means at scale.

---

### Cache, don't calculate, on the device's path

The question behind the design is how fast a device gets from Jamf Pro to your SIEM: wait for as
little as possible, have as much as possible cached. Jamf patch state, vulnerability data and the
other enrichments are **lookups** keyed by the hashes every installed app carries — computed once
per distinct app in the tenant's app catalog, refreshed in the background when the upstream
catalog moves — never calculated per device. Touching hundreds of MB of catalog for each device
is what stops 40k devices fitting in ten minutes. See [docs/app-catalog.md](docs/app-catalog.md).

## 🛠 Quick Start (Docker Compose)

LoonInspect is deployed as two containers: the application — one image carrying both the
React frontend and the FastAPI backend — and a Postgres alongside it. `docker compose up
--build` builds natively for your machine, Apple Silicon included. The images CI builds are
multi-arch (`linux/amd64` + `linux/arm64`) for the hosted pods, but there is no public image
registry yet — build from source, as below.
Both are in the bundle; nothing external is required, and the database port is never
published to the host.

```text
LoonInspect/
├── backend/
│   └── pyproject.toml
├── frontend/
│   └── package.json
├── ops/
│   └── postgres/initdb/     # creates the non-superuser role the app connects as
├── .gitignore
├── docker-compose.yml
└── Dockerfile
```

### 1. Clone the repository

```bash
git clone https://github.com/LoonSecIO/LoonInspect.git
cd LoonInspect
```

### 2. Configure environment variables

```bash
cp backend/.env.example .env
```

Generate an `ENCRYPTION_KEY` and add it to `.env` (used to encrypt MDM connection secrets at rest — required, the app won't start without it):

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Then set the two database passwords, which are also required. Hex rather than base64:
these end up inside a connection URL, where a `@` or `/` truncates the string instead of
failing.

```bash
printf 'POSTGRES_PASSWORD=%s\nPOSTGRES_APP_PASSWORD=%s\n' "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" >> .env
```

Two of them because the application deliberately does not connect as a superuser: a
superuser bypasses row-level security silently, which would leave every tenant isolation
policy attached and enforcing nothing. `POSTGRES_PASSWORD` creates the database;
`POSTGRES_APP_PASSWORD` belongs to `looninspect_app`, which the app actually uses. Both
are read once, when the database volume is first created.

A SIEM webhook URL is optional for a first run. Jamf Pro connections aren't configured via `.env` — add them from the app itself once it's running, at `/api/mdm/connections` or the Settings page.

### 3. Create the Jamf Pro API Role and client

Do this in Jamf Pro before adding the connection, at **Settings → System → API roles and
clients**. Create an **API Role** holding the privileges below, then an **API Client**
assigned to that role; the client's Client ID and Client Secret are the two values
LoonInspect asks for. Everything LoonInspect does to Jamf Pro is a read — no privilege
below writes anything, and none is a CRUD privilege.

| Jamf Pro privilege | What it buys | Without it |
| --- | --- | --- |
| `Read Computers` | Computer inventory, and the per-device fetch a webhook triggers | **Nothing works.** Every sweep and every webhook fetch fails |
| `Read Smart Computer Groups` | Smart-group definitions and their criteria | Devices still sync; group definitions are not observed, and the run log says so |
| `Read Computer Extension Attributes` | Extension-attribute definitions — the census a deleted attribute is absent from | Devices still sync and their attribute values are still read; the definitions are not observed, and the run log says so |
| `Read Computer Inventory Collection Settings` | What Jamf was configured to collect — the "aperture" recorded beside every reading | Readings are kept with `available: false`, so a later collection change can't be told apart from a real device change |
| `Read Departments` | Department names | `departmentId` is stored and filterable, but shows as a bare number |
| `Read Buildings` | Building names | `buildingId` is stored and filterable, but shows as a bare number |

Type the names exactly as spelled above — they are Jamf's own strings, and the API Role
editor searches on them.

> **The "Test connection" button does not check any of this.** It performs the OAuth
> client-credentials exchange and nothing else, because that is the only call to Jamf
> Pro that needs no privilege. An API Role with every box unticked passes the test and
> then sweeps zero devices. If a connection tests green and the first run comes back
> empty, the role is where to look.

**Jamf Pro version.** This is verified against **Jamf Pro 11.31.1**. The client calls
the newest generation of each endpoint family — `v4` computer inventory, `v3` smart
groups, `v2` inventory collection settings — and Jamf's API reference does not state
which release first served them, so we don't publish a minimum: 11.31.1 is the version
we can stand behind, not the earliest that works. Two consequences worth knowing on an
older server: the inventory reads have no fallback to an older endpoint version, so a
Jamf Pro that doesn't serve `v4` fails outright rather than degrading; and
`cfBundleVersion` arrived in Jamf Pro 11.31, so before that a build-only bump under an
unchanged marketing version is not visible to anyone, including Jamf.

### 4. Build and run

```bash
GIT_SHA=$(git rev-parse --short HEAD) docker compose up --build
```

This builds the frontend, bundles it into the FastAPI image, and starts the app at <http://localhost:8001>. API docs are at <http://localhost:8001/docs>.

> **Note:** the container logs and `docker ps` will show the address as `0.0.0.0:8001` — that's the server listening on all interfaces, not a URL you can open. Use `http://localhost:8001` (or `127.0.0.1:8001`) in your browser instead; some browsers will refuse to navigate to `0.0.0.0` directly.

The static assets that ship inside the image have a deliberate caching policy: a
content-hashed file under `/assets/` (Vite's fingerprinted JS, CSS and imported assets)
is served `Cache-Control: public, max-age=31536000, immutable` and gzip-compressed when
your browser accepts it, since the filename changes on every rebuild. The page shell
(`index.html`) and anything else — favicons included — is served `no-cache` instead, so
a returning browser always revalidates and a new build is picked up immediately; a
matching `ETag`/`If-None-Match` earns a real `304` rather than re-sending the body. A
request for a bundle that no longer exists under `/assets/` gets a `404`, not the SPA
shell as a misleading `200`.

### 5. Point it at Splunk

Destination URLs must be `https` — every delivery carries the destination's own
credential. `ALLOW_INSECURE_DESTINATION_URL=true` accepts plain `http` for a lab SIEM
without TLS; nothing accepts a loopback or link-local address, or a hostname that
resolves to one, which are refused when saved and again at delivery
(`docs/splunk-setup.md`).

The onboarding stepper's third step is "Send it to Splunk", and there is more to it than
a URL: HEC ships disabled, the "Secret" field means the HEC token, the index comes from
the token rather than from anything LoonInspect sends, and Splunk's stock self-signed
certificate is refused by default. **[docs/splunk-setup.md](docs/splunk-setup.md)** walks
through all of it, including a `props.conf` stanza to hand your Splunk team and what to
do about that certificate without turning verification off.

### 6. Back it up before you need to

**[docs/troubleshooting.md](docs/troubleshooting.md)** is where to start when something is not working: six ordered paths — a green test and an empty sweep, a run with zero devices, events not reaching Splunk, a stack that will not start, applications reading *not assessed*, a Jamf Patch table that is empty or has stopped refreshing — each ending in a fix or a named state to report. **[docs/operations.md](docs/operations.md)** is the operator runbook: what to back up
(the database *and* `ENCRYPTION_KEY` — a dump without the key restores an instance whose
every MDM connection is permanently unreadable), the `pg_dump` and `psql` commands to do
it, what a restore does to in-flight outbox rows and the run mutex, how upgrades and
rollbacks actually behave, and how to read the one failure that crash-loops. Every
command in it was run against a throwaway stack and the real output is printed beside it.

**[KNOWN_ISSUES.md](KNOWN_ISSUES.md)** is the measured limits list — what grows without
bound, at what rate, at what fleet size it bites, and the workaround for each. Read it
before sizing the database volume.

### Upgrading an existing install

Migrations run unattended at startup, so `docker compose up -d --build` on a newer
checkout *is* the upgrade. Take a dump first, and read
[docs/operations.md §4–5](docs/operations.md) before rolling one back: the downgrade has
to be run from the newer image, and swapping the image back first crash-loops.

The container now runs as a non-root user (`looninspect`, uid 10001) rather than
as root. A data volume created by an earlier version is owned by root, and the
new container cannot write to it — it will exit at startup with
`PermissionError: [Errno 13] Permission denied: 'data/audit'`.

Fix it once, with the stack stopped:

```bash
docker run --rm -v looninspect_looninspect-data:/data alpine chown -R 10001:10001 /data
```

Substitute your own volume name if it differs; `docker volume ls` will show it.
Volumes created from this version onward inherit the right ownership and need
nothing.

For day-to-day development with hot-reloading instead, see [backend/README.md](backend/README.md) and run the frontend separately with `npm run dev` inside `frontend/` (proxies `/api` to the backend on port 8001).


---

## 🔐 Is everything encrypted?

A fair question, and one that comes up in every security review. The honest answer has
two halves.

**At rest.** MDM credentials, webhook secrets, and license keys are encrypted with
Fernet (AES-128-CBC + HMAC) using the `ENCRYPTION_KEY` you generate at install. The
database itself is an unencrypted Postgres on its own volume — encrypt the volume if
your threat model needs that.

**In transit.** Configurable, because deployments differ:

| `TLS_MODE` | Behaviour | Use when |
| --- | --- | --- |
| `off` (default) | Plain HTTP on 8001 | Local use, or something in front already terminates TLS and you're content with a plaintext hop inside your own network |
| `self-signed` | Generates a certificate on first boot, persists it on the data volume, serves HTTPS | You need TLS all the way to the application process — typically to satisfy a review that asks about the load-balancer-to-container hop |
| `provided` | Serves HTTPS from a certificate and key you mount in | You have a real certificate for the hostname, or an internal CA |

```bash
TLS_MODE=self-signed docker compose up -d
```

The self-signed certificate is **not trusted by browsers** — that's inherent, not a
defect. It exists so the hop between your load balancer and this container is encrypted
and you can say so plainly. Browsers, and anything else that validates chains, need
`TLS_MODE=provided` with a real certificate.

**Behind a reverse proxy**, set `FORWARDED_ALLOW_IPS` to the proxy's address. Otherwise
the audit log records the proxy's IP for every event instead of the real client's, and
`X-Forwarded-For` is left untrusted by default because anything that can reach the port
could otherwise forge it.

**One thing to watch:** session cookies are marked `Secure` by default, and browsers
discard `Secure` cookies over plain HTTP on any hostname other than `localhost`. If you
serve plain HTTP on a real hostname, sign-in will fail silently — the login succeeds,
the cookie is dropped, and everything afterwards looks logged out. The startup logs
warn about this. Either terminate TLS in front, use `TLS_MODE=self-signed`, or set
`SECURE_COOKIES=false` if you genuinely intend to run without TLS.

**Response headers.** Every response carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, and a `Permissions-Policy` that
denies what a Jamf console never asks for. `SECURITY_HEADERS=false` turns off every
header described here at once — there is deliberately no way to keep some and drop
others. `Strict-Transport-Security` is not one of the four defaults: the app can judge
its own bundle, but only you know whether this hostname will still terminate valid
HTTPS in six months, so HSTS is relayed verbatim from `HSTS_MAX_AGE` (seconds; `0`, the
default, means never send it) and is never `includeSubDomains` or `preload`. Set it only
once you're sure — a `max-age` a browser has already seen can only be withdrawn over a
still-validating HTTPS connection on the same hostname, which is unavailable in exactly
the situation that makes you want to withdraw it.

**Content-Security-Policy.** Every response also carries a CSP. The app's pages get a
strict one — `script-src 'self'` with no inline script, hash or nonce (the pre-paint
theme script lives in its own file), `connect-src 'self'`, no framing, no objects — with
one accepted weakness: `style-src 'unsafe-inline'`, because a dozen React style
attributes compute severity and status colours at runtime. `/docs` and `/redoc` get a
second, weaker policy that names `cdn.jsdelivr.net`, where Swagger UI and ReDoc load
from, and `cdn.redoc.ly` for the one image ReDoc fetches on its own, its footer logo;
both pages sit behind sign-in, so it is never served to an anonymous visitor.
`CONTENT_SECURITY_POLICY` is a value, not a toggle: leave it unset for the built-in
policies, set it to `off` to send no CSP while keeping the other headers, or set it to a
policy string, which is sent verbatim on every response — it **replaces** the built-in
policy rather than extending it, so start from the one in `backend/app/core/middleware.py`.
The one case that needs it: a frontend you rebuilt with `VITE_API_BASE_URL` pointing at
another origin, which the backend cannot know about and whose `connect-src` must then
name that origin. The startup log says whether a custom policy is in force, never what
it contains.

Self-signed certificates (`TLS_MODE=self-signed`) now renew themselves: at boot, a
certificate past the midpoint of its own validity window (capped at 183 days) is
regenerated in place and the previous one stops being served, so a self-signed pair
generated once is no longer served indefinitely past its own expiry. A `TLS_MODE=provided`
certificate is never touched — the app logs a warning as it nears that same point and an
error once it has actually expired, but only ever regenerates a certificate it minted
itself.

---

## 🏷️ Which build am I running?

Builds are named `YYYY.MM.DD+<sha>` — the date answers "how old is this?", the sha
answers "exactly what code?". A local build following the command above gets the short
sha; images built by CI carry the full 40-character one. Three ways to read it, in the
order you'll reach for them:

**In the app.** The sidebar footer carries it on every page — but the sidebar is hidden
below 768px and can be switched off, so **Settings → My Account** shows the same value
and is always reachable. Either way, any signed-in account can see it.

**Over the API.** Any session or API token can ask — no permission required, so even a
narrowly scoped token works:

```bash
curl -s -H "Authorization: Bearer $LOONINSPECT_TOKEN" https://your-host/api/system/version
```

**From the host, without signing in.** The image carries the same answer, so a locked
-out operator — or one whose container won't start — can still find out:

```bash
docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}} built {{.Created}}' looninspect-app-1
```

The sign-in page deliberately shows nothing. A build identifier is a precise statement
about which published fixes an instance has *not* taken, so it is for people who
already have an account here, not for anyone who can reach the port. The one exception
is a fresh instance that nobody has claimed yet: the first-run setup page shows the
build, because at that moment it is already offering the next caller an admin account
and has nothing left to protect.

This withholds the version *string*. It does not make the build unknowable to someone
determined, and two accepted exposures are worth stating plainly rather than leaving
for a reader to discover (issues #130 and #170):

- **Static assets carry a `Last-Modified` of the image build time**, so the date half
  is one anonymous request away. Accepted deliberately (#170): `FileResponse` stamps
  it from the file's mtime, and the caching policy above (#172) leans on revalidation
  rather than on that header — the shell is `no-cache` and hashed assets `immutable`
  whatever the mtime says. Freezing the mtime to a constant would be the naive fix, and
  it is worse than the leak: browsers fall back to heuristic caching and serve a stale
  app shell for years. If you revisit this, remove the header; never fake it.
- **The shipped SPA bundle names the frontend commit.** The Vite build is
  bit-reproducible, so `/assets/index-<hash>.js` in the page source is a lookup key
  into public history for anyone willing to rebuild it once. Inherent to serving a
  client bundle built from a public repo.

So the accurate claim is that the build is no longer *stated*, not that it is secret.
What the version rule still buys is real: naming it required no rebuild table, and
the bundle hash only moves when the frontend does — most changes here are backend-only,
which is where the API's own security fixes live.

---

## 🔔 Update notifications

Once a day, the backend asks GitHub for the newest commit on `main`
(`api.github.com/repos/LoonSecIO/LoonInspect/commits/main`) and compares it with the
sha this build was stamped with. Nothing is sent beyond the request itself — no
instance ID, no telemetry, no inventory. When a newer build exists, signed-in
operators see a banner with the update command; the sign-in page deliberately shows
nothing, so an outdated instance never advertises that fact to strangers.

The check never performs the update. Updating stays a host-side decision:

```
git pull && GIT_SHA=$(git rev-parse --short HEAD) docker compose up -d --build
```

Set `UPDATE_CHECK=false` in `.env` to disable the outbound call entirely. Air-gapped
deployments can also simply leave it on — an unreachable check fails silently and is
indistinguishable from being up to date.

---

## 🤝 Community data sharing

The community patching and vulnerability feeds LoonInspect is building are made from
anonymous community inventory, and participating instances are what will keep them
accurate. One half of that now runs in both directions: the daily exchange's response
names the published vulnerability corpus, which a sharing instance downloads, verifies
and joins locally — on staging today, and for a customer with the production cutover (see
"Vulnerabilities" above). The community half — per-key verdicts made from what other
instances have seen — is reserved on that response and not yet parsed, and the patching
feed is not built. The two are separate channels on one
exchange. Once a day, a sharing instance sends per-tenant **content-hash keys** of installed
applications with aggregated install counts (plus OS tuples; the hardware tuple is
reserved and ships empty) — never per-device rows, and
never device identifiers, serials, hostnames, user names, file paths, or anything from
the accounts and credential tables. App *names* cross the wire only when the instance
answers an explicit request for a title already seen at 5+ independent contributors —
the server's published policy — and only in the default tier; internal, company-specific
apps are never revealed. The stronger guarantee isn't the count, which a client cannot
verify: it's that a request can only *name* an app whose plaintext the requester already
holds, so a genuinely private title is unaddressable regardless of how many contributors
share it. The full design — including exactly what the k-threshold does and doesn't
guarantee — is in [docs/data-sharing.md](docs/data-sharing.md).

The choice is presented during first-run setup and lives under **Settings → Data
Sharing** afterwards, alongside a button that renders the literal next payload from
live data. **An install that was never asked does not share:** bootstrapping
non-interactively with `INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD` (below) skips
the wizard, so sharing stays off until an administrator turns it on. `COMMUNITY_SHARING=false`
in `.env` hard-disables it regardless of the UI. Air-gapped instances can leave it on —
a failed exchange is silent and logged locally only.

---

## 🧪 AI test box (off by default)

Settings › AI is a test box, not a feature: one prompt to a model endpoint you name, the
reply shown as it came back. It exists so the first real AI feature arrives into plumbing
that already refuses correctly. Two switches gate it, both off out of the box: the
`ai_features` flag (Settings › Feature Flags) and the AI-inference consent (toggled on the
page itself). Every send writes one share-log row naming the destination and the single
field that left, the prompt. Three endpoints are offered: Apple Foundation Models through Apple's own
`fm serve` on the Mac host (macOS 27; the card is labelled "via Docker Desktop", the one
runtime this cut implements), any OpenAI-compatible endpoint (Ollama on the host by
default), and Anthropic's Messages API. Bring your own URL and key; the key is used for that
one request and never stored. Every model call is made by the backend, never by your
browser. Design record: `docs/ai-layer.md`; issue #319.

## 👥 Accounts and roles

The first administrator is created either through the first-run wizard (a claim token
is printed to `docker compose logs` on first boot) or non-interactively:

```bash
INITIAL_ADMIN_EMAIL=you@corp.com INITIAL_ADMIN_PASSWORD=a-long-passphrase docker compose up -d
```

After that, **Settings → Accounts** manages everyone else. Four roles:

| Role | Sees | Can change |
| --- | --- | --- |
| **Viewer** | Devices and applications, including each build's vulnerability answer | Nothing |
| **Analyst** | The above, plus connection and destination config, runs, and audit history | Can trigger a device sweep and a patch-catalog sync; can mint API tokens for their own account |
| **Auditor** | The above, plus accounts and roles | Nothing in the product — read-only by design; can mint API tokens for their own account |
| **Admin** | Everything, including credential values | Everything |

Auditor is a strict subset of Admin with no write permission and no access to secret
values, which is what makes it safe to hand to someone outside the team for a review.

Accounts are never deleted, only disabled — past audit records stay attributable to a
real account. Disabling revokes that account's sessions and API tokens immediately
rather than waiting for them to expire. There is no email delivery, so new accounts get
an initial password set by an administrator, and an administrator can reset a forgotten
one from the same page.

## 🆘 Support

Two places to ask, and one thing that goes to neither of them.

- **Bugs, questions and feature requests** go to
  [the issue tracker](https://github.com/LoonSecIO/LoonInspect/issues). Search what is
  already open first — a documented issue often has the workaround attached — then
  [open one](https://github.com/LoonSecIO/LoonInspect/issues/new/choose) if yours isn't
  there. A useful report starts with the build string (**Settings → Support** in the app,
  or the `docker inspect` line under *Which build am I running?*), then what you expected,
  what happened instead, and how to get back to it.
- **Conversation** happens in `#loonsecio` on [MacAdmins Slack](https://macadmins.org/):
  how other people have set something up, whether a behaviour is expected, the questions
  that are not a bug report yet. It is a conversation, not a queue — nobody is on call.
- **Security findings never go in a public issue.** Report privately through GitHub —
  **Security → Report a vulnerability** on this repository — or email
  **security@loonsec.io**. [SECURITY.md](SECURITY.md) has the details and the scope.

Leave out device names, serial numbers, hostnames and email addresses. A screenshot of
LoonInspect is largely made of those — the Devices table is hostnames and serials, and
your own name sits in the top bar — so crop or black them out before attaching one.
Nothing in the product files a report for you: LoonInspect is self-hosted and phones
home to nobody.

## 📄 License

Apache-2.0 — the full text is in [LICENSE](LICENSE). Contributions are accepted under
the same terms; see [CONTRIBUTING.md](CONTRIBUTING.md#license).
