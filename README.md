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

### 1. Clone the repository
```bash
git clone [https://github.com/your-org/LoonInspect.git](https://github.com/your-org/LoonInspect.git)
cd LoonInspect
```

