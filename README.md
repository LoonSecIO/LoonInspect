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

Edit `.env` to add MDM credentials (Jamf/SimpleMDM) and a SIEM webhook URL if you have them — everything is optional for a first run.

### 3. Build and run

```bash
docker compose up --build
```

This builds the frontend, bundles it into the FastAPI image, and starts the app at <http://localhost:8000>. API docs are at <http://localhost:8000/docs>.

> **Note:** the container logs and `docker ps` will show the address as `0.0.0.0:8000` — that's the server listening on all interfaces, not a URL you can open. Use `http://localhost:8000` (or `127.0.0.1:8000`) in your browser instead; some browsers will refuse to navigate to `0.0.0.0` directly.

For day-to-day development with hot-reloading instead, see [backend/README.md](backend/README.md) and run the frontend separately with `npm run dev` inside `frontend/` (proxies `/api` to the backend on port 8000).

