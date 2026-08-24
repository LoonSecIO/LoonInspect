# 🦅 LoonInspect

**A self-hosted, open-source vulnerability scanner and MDM inventory engine for enterprise Apple environments.**

LoonInspect bridges the gap between your Apple Mobile Device Management (MDM) platforms and your security operations. It pulls raw app inventory from MDMs like Jamf Pro, generates O(1) hashed fingerprints, maps them against real-time CVE intelligence, and streams the delta events directly into your SIEM (Splunk, RunReveal, Datadog). 

All without bloating your local database or grinding your MDM APIs to a halt.

---

## 🚀 Features

* **Multi-MDM Support:** Native API integration and Webhook ingestion for Jamf Pro (Addigy and SimpleMDM coming soon).
* **O(1) Vulnerability Hashing:** Translates raw app metadata into MD5 `FullHashes`, allowing lightning-fast lookups against the LoonVD vulnerability engine.
* **Delta Streaming Engine:** Calculates inventory diffs in-memory and streams structured JSON events (`device.inventory.changed`) directly to your SIEM.
* **Hybrid Sync Architecture:** Supports real-time webhooks for active devices and scheduled off-peak bulk sweeps to catch devices that were offline. Each pull is a *collection* — what to read (Jamf sections, a device filter pushed into Jamf's query, the smart-group catalog) and when (time of day, timezone, cadence) — configured per connection in the app rather than as one global cron.
* **Secure by Default:** Built-in SCIM provisioning (Okta/Azure AD) and WebAuthn (Touch ID/YubiKey) MFA on the free tier.
* **Lightweight Container:** Multi-architecture (AMD64/ARM64) Docker image built on hardened base images.

---

## 🏗 Architecture Overview

LoonInspect is designed around a **"Diff, Stream, Commit"** pipeline to keep local storage requirements microscopic while delivering enterprise-grade telemetry:

1. **Ingest:** Receives a webhook, chron, or event system.
2. **Fingerprint:** Deduplicates raw app strings into cryptographic `FullHashes`.
3. **Analyze:** Checks hashes against the local Postgres database to determine what changed.
4. **Enrich (Optional):** Sends unseen hashes to the LoonVD AWS Gateway to retrieve real-time EPSS scores, CVE mappings, and patch manifests. Whether you use Munki, Jamf's App Installers, or other patching service.
5. **Stream:** Emits the calculated delta directly to your SIEM for logging, compliance, and eventing.

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

LoonInspect is deployed as two containers: the application — one multi-architecture image
carrying both the React frontend and the FastAPI backend — and a Postgres alongside it.
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
git clone https://github.com/your-org/LoonInspect.git
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

A SIEM webhook URL is optional for a first run. MDM connections (Jamf, SimpleMDM, etc.) aren't configured via `.env` — add them from the app itself once it's running, at `/api/mdm/connections` or the Settings page.

### 3. Build and run

```bash
GIT_SHA=$(git rev-parse --short HEAD) docker compose up --build
```

This builds the frontend, bundles it into the FastAPI image, and starts the app at <http://localhost:8001>. API docs are at <http://localhost:8001/docs>.

> **Note:** the container logs and `docker ps` will show the address as `0.0.0.0:8001` — that's the server listening on all interfaces, not a URL you can open. Use `http://localhost:8001` (or `127.0.0.1:8001`) in your browser instead; some browsers will refuse to navigate to `0.0.0.0` directly.

### Upgrading an existing install

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
live data. `COMMUNITY_SHARING=false` in `.env` hard-disables sharing regardless of the
UI. Air-gapped instances can leave it on — a failed exchange is silent and logged
locally only.

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
