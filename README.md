# 🦅 LoonInspect

**A self-hosted, open-source vulnerability scanner and MDM inventory engine for enterprise Apple environments.**

LoonInspect bridges the gap between your Apple Mobile Device Management (MDM) platforms and your security operations. It pulls raw app inventory from MDMs like Jamf Pro, generates O(1) hashed fingerprints, maps them against real-time CVE intelligence, and streams the delta events directly into your SIEM (Splunk, RunReveal, Datadog). 

All without bloating your local database or grinding your MDM APIs to a halt.

---

## 🚀 Features

* **Multi-MDM Support:** Native API integration and Webhook ingestion for Jamf Pro (Addigy and SimpleMDM coming soon).
* **O(1) Vulnerability Hashing:** Translates raw app metadata into MD5 `FullHashes`, allowing lightning-fast lookups against the LoonVD vulnerability engine.
* **Delta Streaming Engine:** Calculates inventory diffs in-memory and streams structured JSON events (`device.inventory.changed`) directly to your SIEM.
* **Hybrid Sync Architecture:** Supports real-time webhooks for active devices and scheduled off-peak bulk sweeps to catch devices that were offline.
* **Secure by Default:** Built-in SCIM provisioning (Okta/Azure AD) and WebAuthn (Touch ID/YubiKey) MFA on the free tier.
* **Lightweight Container:** Multi-architecture (AMD64/ARM64) Docker image built on hardened base images.

---

## 🏗 Architecture Overview

LoonInspect is designed around a **"Diff, Stream, Commit"** pipeline to keep local storage requirements microscopic while delivering enterprise-grade telemetry:

1. **Ingest:** Receives a webhook, chron, or event system.
2. **Fingerprint:** Deduplicates raw app strings into cryptographic `FullHashes`.
3. **Analyze:** Checks hashes against the local SQLite database to determine what changed.
4. **Enrich (Optional):** Sends unseen hashes to the LoonVD AWS Gateway to retrieve real-time EPSS scores, CVE mappings, and patch manifests. Whether you use Munki, Jamf's App Installers, or other patching service.
5. **Stream:** Emits the calculated delta directly to your SIEM for logging, compliance, and eventing.

---

## 🛠 Quick Start (Docker Compose)

LoonInspect is deployed as a single, multi-architecture container containing both the React frontend and the FastAPI backend.

```text
LoonInspect/
├── backend/
│   └── pyproject.toml
├── frontend/
│   └── package.json
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

A SIEM webhook URL is optional for a first run. MDM connections (Jamf, SimpleMDM, etc.) aren't configured via `.env` — add them from the app itself once it's running, at `/api/mdm/connections` or the Settings page.

### 3. Build and run

```bash
docker compose up --build
```

This builds the frontend, bundles it into the FastAPI image, and starts the app at <http://localhost:8000>. API docs are at <http://localhost:8000/docs>.

> **Note:** the container logs and `docker ps` will show the address as `0.0.0.0:8000` — that's the server listening on all interfaces, not a URL you can open. Use `http://localhost:8000` (or `127.0.0.1:8000`) in your browser instead; some browsers will refuse to navigate to `0.0.0.0` directly.

For day-to-day development with hot-reloading instead, see [backend/README.md](backend/README.md) and run the frontend separately with `npm run dev` inside `frontend/` (proxies `/api` to the backend on port 8000).


---

## 🔐 Is everything encrypted?

A fair question, and one that comes up in every security review. The honest answer has
two halves.

**At rest.** MDM credentials, webhook secrets, and license keys are encrypted with
Fernet (AES-128-CBC + HMAC) using the `ENCRYPTION_KEY` you generate at install. The
database itself is plain SQLite on the data volume — encrypt the volume if your threat
model needs that.

**In transit.** Configurable, because deployments differ:

| `TLS_MODE` | Behaviour | Use when |
| --- | --- | --- |
| `off` (default) | Plain HTTP on 8000 | Local use, or something in front already terminates TLS and you're content with a plaintext hop inside your own network |
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
