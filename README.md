# 🦅 LoonInspect

**The software-change feed for Jamf Pro fleets — what changed on every Mac, in your own SIEM, without installing anything on the Mac.**

Computers only — mobile devices are not collected. See [docs/mobile-devices.md](docs/mobile-devices.md).

LoonInspect reads inventory from Jamf Pro, works out what actually changed since the last read, and streams those changes as structured events into Splunk, Elastic, RunReveal, or any webhook endpoint. It is agentless: nothing is installed on managed devices.

---

## 🚀 Features

* **Built for Jamf Pro:** Native Pro API integration and webhook ingestion, unapologetically Jamf-first (SimpleMDM and Addigy are on the roadmap).
* **Delta Streaming Engine:** Diffs inventory against the last observation and streams structured JSON events (`device.inventory.changed`, `device.change`) directly to your SIEM. A sweep where nothing changed emits nothing at all.
* **Small on the wire:** Measured at 509 bytes per event plus 311 bytes per changed app. A 40,000-device baseline sweep is roughly 1.06 GB, once; a quiet day afterwards is roughly 4 MB.
* **Hybrid Sync Architecture:** Real-time webhooks for active devices and scheduled off-peak sweeps for the rest. Each pull is a *collection* — what to read (Jamf sections, a device filter pushed into Jamf's query, the smart-group catalog) and when (time of day, timezone, cadence) — configured per connection in the app rather than as one global cron.
* **Tenant isolation in the database:** Row-level security is enforced by Postgres rather than by application filters, and CI asserts that the application role cannot bypass it.
* **Self-hosted:** One container and a Postgres database. No vendor account required to run it.

### What it does not do

No CVE or EPSS enrichment. No vulnerability scoring. No SCIM, no MFA. Jamf Patch title compliance is implemented; nothing else vulnerability-shaped is. If you need those today, this is not that tool.

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
--build` builds natively for your machine, Apple Silicon included, and the images CI
publishes are multi-arch (`linux/amd64` + `linux/arm64`), so pulling one directly is native
too.
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

### 5. Point it at Splunk

The onboarding stepper's third step is "Send it to Splunk", and there is more to it than
a URL: HEC ships disabled, the "Secret" field means the HEC token, the index comes from
the token rather than from anything LoonInspect sends, and Splunk's stock self-signed
certificate is refused by default. **[docs/splunk-setup.md](docs/splunk-setup.md)** walks
through all of it, including a `props.conf` stanza to hand your Splunk team and what to
do about that certificate without turning verification off.

### 5. Back it up before you need to

**[docs/operations.md](docs/operations.md)** is the operator runbook: what to back up
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
denies what a Jamf console never asks for. `SECURITY_HEADERS=false` turns off all five
headers described here at once — there is deliberately no way to keep some and drop
others. `Strict-Transport-Security` is not one of the four defaults: the app can judge
its own bundle, but only you know whether this hostname will still terminate valid
HTTPS in six months, so HSTS is relayed verbatim from `HSTS_MAX_AGE` (seconds; `0`, the
default, means never send it) and is never `includeSubDomains` or `preload`. Set it only
once you're sure — a `max-age` a browser has already seen can only be withdrawn over a
still-validating HTTPS connection on the same hostname, which is unavailable in exactly
the situation that makes you want to withdraw it. Content-Security-Policy is not in this
list yet; it enforces nothing today (tracked for a later release).

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
  is one anonymous request away. Accepted deliberately: removing it correctly means
  also giving the static path an explicit caching policy it does not have today, and
  the naive version of the fix is worse than the leak. The mtime is currently what
  keeps browser heuristic caching honest — freeze it to a constant and browsers will
  serve a stale app shell for years. If you revisit this, remove the headers; never
  fake them.
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

LoonInspect's patching and vulnerability feeds are built from anonymous community
inventory, and participating instances are what keep them accurate. Once a day, a
sharing instance sends per-tenant **content-hash keys** of installed applications with
aggregated install counts (plus OS and hardware tuples) — never per-device rows, and
never device identifiers, serials, hostnames, user names, file paths, or anything from
the accounts and credential tables. App *names* cross the wire only when the instance
answers an explicit request for a title already seen at 5+ independent contributors,
and only in the default tier; internal, company-specific apps are never revealed. The
full design — including exactly what the k-threshold does and doesn't guarantee — is
in [docs/data-sharing.md](docs/data-sharing.md).

The choice is presented during first-run setup and lives under **Settings → Data
Sharing** afterwards, alongside a button that renders the literal next payload from
live data. **An install that was never asked does not share:** bootstrapping
non-interactively with `INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD` (below) skips
the wizard, so sharing stays off until an administrator turns it on. `COMMUNITY_SHARING=false`
in `.env` hard-disables it regardless of the UI. Air-gapped instances can leave it on —
a failed exchange is silent and logged locally only.

---

## 👥 Accounts and roles

The first administrator is created either through the first-run wizard (a claim token
is printed to `docker compose logs` on first boot) or non-interactively:

```bash
INITIAL_ADMIN_EMAIL=you@corp.com INITIAL_ADMIN_PASSWORD=a-long-passphrase docker compose up -d
```

After that, **Settings → Accounts** manages everyone else. Four roles:

| Role | Sees | Can change |
| --- | --- | --- |
| **Viewer** | Devices, applications, vulnerabilities | Nothing |
| **Analyst** | The above, plus connection config and audit history | Can trigger a patch-catalog sync |
| **Auditor** | The above, plus accounts and roles | Nothing — read-only by design |
| **Admin** | Everything, including credential values | Everything |

Auditor is a strict subset of Admin with no write permission and no access to secret
values, which is what makes it safe to hand to someone outside the team for a review.

Accounts are never deleted, only disabled — past audit records stay attributable to a
real account. Disabling revokes that account's sessions and API tokens immediately
rather than waiting for them to expire. There is no email delivery, so new accounts get
an initial password set by an administrator, and an administrator can reset a forgotten
one from the same page.

## 📄 License

Apache-2.0 — the full text is in [LICENSE](LICENSE). Contributions are accepted under
the same terms; see [CONTRIBUTING.md](CONTRIBUTING.md#license).
