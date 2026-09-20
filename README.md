# LoonInspect

**Inventory and software-change tracking for Jamf Pro fleets, in your own SIEM.**

LoonInspect reads Jamf Pro computer inventory, keeps observations and change history,
and sends structured events to Splunk, Elastic, RunReveal, or a webhook. Nothing is
installed on managed Macs. Mobile devices are not collected.

## What it does

- Collects inventory through scheduled sweeps and Jamf webhooks, with schedules and
  filters configured per connection.
- Sends inventory snapshots and change events; destinations choose which event types
  to receive. See the [wire vocabulary](docs/splunk-wire-vocabulary.md).
- Shows devices, applications, Jamf Patch matches, change history, posture, and
  [baseline evidence](docs/compliance-evidence.md).
- Reports vulnerability findings when a downloaded corpus is available and community
  sharing is enabled. **Not assessed**, **Outside the corpus**, and **No findings**
  are distinct answers; unavailable coverage is never a zero. See
  [vulnerability coverage and consent](docs/vulnerabilities.md).
- Offers optional AI-assisted queries and [inventory summaries](docs/inventory-summaries.md),
  gated by the AI feature flag, consent, and provider configuration. See
  [AI setup and behavior](docs/ai-layer.md).
- Runs a React frontend and FastAPI backend in one application container, with
  Postgres and database-enforced tenant isolation.

*This product uses the NVD API but is not endorsed or certified by the NVD.*

### What it does not do

LoonInspect is Jamf-only and reads inventory; it does not manage devices, install an
endpoint agent, or scan Macs for vulnerabilities. Its answers depend on what Jamf
reported and what the vulnerability corpus covers. See [scope decisions](docs/v-never.md)
and [measured limits](KNOWN_ISSUES.md) before planning a deployment.

## Run on Docker Desktop

Start Docker Desktop with Docker Compose available. You also need Git and OpenSSL.
The Compose bundle builds from source, including natively on Apple Silicon, and runs
both the app and Postgres. The database port is not published to the host.

### 1. Clone and configure

```bash
git clone https://github.com/LoonSecIO/LoonInspect.git
cd LoonInspect
cp backend/.env.example .env
chmod 600 .env
```

Generate three values, then paste each into its existing entry in `.env`:

```bash
# ENCRYPTION_KEY: a URL-safe base64 encoding of 32 random bytes
openssl rand -base64 32 | tr '+/' '-_'

# POSTGRES_PASSWORD
openssl rand -hex 32

# POSTGRES_APP_PASSWORD
openssl rand -hex 32
```

Keep `ENCRYPTION_KEY` safe: it encrypts connection secrets and must be restored with
any database backup. The two database passwords are separate because the app uses
`looninspect_app`, a non-superuser role that cannot bypass tenant isolation. They are
applied when the database volume is first created; editing `.env` later does not
rotate them.

### 2. Build, start, and claim the instance

```bash
GIT_SHA=$(git rev-parse --short HEAD) docker compose up -d --build
docker compose logs -f app
```

Open [http://localhost:8001](http://localhost:8001), enter the claim token printed in
the app logs, and create the first administrator. API documentation is available at
[/docs](http://localhost:8001/docs) after sign-in. To bootstrap non-interactively,
set `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD` (at least 12 characters) in
`.env` before starting; this skips the wizard and leaves community sharing off.

```bash
curl --fail http://localhost:8001/api/health
docker compose ps
```

The named volumes preserve the database and `/app/data` across container restarts.
`docker compose down` stops the stack; **adding `--volumes` deletes its stored data**.
A local `docker-compose.override.yml`, if present, can change ports and settings.

### 3. Connect Jamf Pro

In Jamf Pro, open **Settings → System → API roles and clients**. Create an API Role
with these read privileges, assign it to an API Client, and use that client's ID and
secret in LoonInspect under **Settings → Connections**.

| Jamf Pro privilege | Purpose |
| --- | --- |
| `Read Computers` | Required for inventory sweeps and webhook-triggered reads |
| `Read Smart Computer Groups` | Smart-group definitions and criteria |
| `Read Computer Extension Attributes` | Extension-attribute definitions |
| `Read Computer Inventory Collection Settings` | Records what Jamf was configured to collect |
| `Read Departments` | Resolves department IDs to names |
| `Read Buildings` | Resolves building IDs to names |

**Test connection checks authentication, not these privileges.** A successful test
does not prove inventory access. Configure the connection's collections and run a
sweep to verify it. Missing optional privileges reduce the information collected.

The recorded compatibility check is against **Jamf Pro 11.31.1**, not a minimum-version
claim. The client requires the v4 computer inventory endpoints and has no fallback
to older inventory APIs.

### 4. Send events and enable webhooks

Add a destination and select its event subscriptions. The
[Splunk setup guide](docs/splunk-setup.md) covers HEC enablement, tokens, indexes,
certificates, and event shaping. Destination URLs default to HTTPS; the destination
form supports explicitly allowing HTTP for a lab destination.

For timely per-device updates, follow the [Jamf webhook guide](docs/jamf-webhooks.md)
to connect `ComputerInventoryCompleted` and `ComputerAdded`. Jamf must be able to
reach the app over HTTPS; `localhost` on your laptop is not reachable from Jamf Cloud.
Scheduled sweeps work without inbound webhooks.

## Run on AWS

The repository includes an AWS deployment walkthrough in
[ops/aws/README.md](ops/aws/README.md). It runs the app and Postgres together in one
ECS Fargate task, using private ECR images and SSM SecureString parameters.

Follow that guide in order:

1. Configure an AWS CLI profile and `AWS_REGION`, then deploy
   [images.template.yml](ops/aws/images.template.yml) for ECR and the GitHub OIDC push role.
2. Set the repository variables `AWS_ECR_PUSH_ROLE_ARN` and `AWS_REGION`. Run
   **Publish images** on `main` (also triggered by relevant source changes) and use
   that workflow's commit SHA for both image tags.
3. Create the pod's SSM parameters for database credentials, `ENCRYPTION_KEY`, and
   the initial administrator password.
4. Deploy [pod.template.yml](ops/aws/pod.template.yml) with the image URIs, VPC,
   public subnets, administrator email, and your ingress IP range.
5. Retrieve the task's public IP and open `https://<ip>:8001`. This stack uses a
   self-signed certificate. Verify `/api/health`, sign in, and inspect CloudWatch
   logs as described in the guide.

**This is a disposable verification stack. A task replacement loses its database
and local app data.** It has no load balancer or persistent storage. The repository
also contains separate [ingress](ops/aws/pods-ingress.template.yml) and
[persistent-data](ops/aws/pod-data.template.yml) templates, but the walkthrough's
`pod.template.yml` does not use them. Do not use the disposable stack for data you
need to retain.

## Is everything encrypted?

Connection secrets are encrypted with `ENCRYPTION_KEY`; the bundled Postgres volume
is not encrypted by the app. For a remote deployment, configure HTTPS:

| `TLS_MODE` | Behavior |
| --- | --- |
| `off` (default) | HTTP on port 8001; suitable for localhost or behind a TLS proxy |
| `self-signed` | Generates and persists a certificate; browsers do not trust it automatically |
| `provided` | Uses certificate and key files you mount at `TLS_CERT_PATH` and `TLS_KEY_PATH` |

Behind a proxy, set `FORWARDED_ALLOW_IPS` to the trusted proxy address and
`KEEP_ALIVE_TIMEOUT_SECONDS` above its idle timeout. Session cookies are `Secure`
by default: plain HTTP on a non-localhost hostname breaks sign-in unless you
explicitly set `SECURE_COOKIES=false`.

**Response headers:** the app supplies security headers and a Content Security
Policy. `CONTENT_SECURITY_POLICY` can replace the policy, or `off` disables CSP.
See [configuration defaults](backend/app/core/config.py) and
[proxy troubleshooting](docs/troubleshooting.md#a-proxy-in-front-answers-for-itself).

## Community data sharing

Sharing is a choice during setup and under **Settings → Data Sharing**, where you
can inspect the outgoing payload. The exchange sends content-hash keys and aggregate
inventory counts, not per-device rows; title disclosure has additional rules described
in the [sharing contract](docs/data-sharing.md). `COMMUNITY_SHARING=false` in `.env`
hard-disables it. Vulnerability corpus access depends on consent and provider availability.

Separately, a daily GitHub release check notifies signed-in users about updates; it
never installs them. Set `UPDATE_CHECK=false` to disable it. Optional AI features send
their disclosed inputs to the configured model provider when enabled.

## Operations and development

- **Back up before upgrading:** preserve the database, `ENCRYPTION_KEY`, and app data.
  Follow the [backup, restore, upgrade, and rollback runbook](docs/operations.md).
  Migrations run at startup; rolling an image back can require a schema downgrade first.
- **Diagnose problems:** start with [troubleshooting](docs/troubleshooting.md) and
  [known limits](KNOWN_ISSUES.md). Include the build shown in **Settings → Support**
  when reporting a problem.
- **Manage access:** **Settings → Accounts** provides Viewer, Analyst, Auditor, and
  Admin roles. See the [account and permission design](docs/auth-design.md).
- **Develop locally:** follow [backend setup](backend/README.md), then run
  `npm ci` and `npm run dev` in `frontend/` for the development UI.
- **Understand or contribute:** read the [architecture](docs/ARCHITECTURE.md),
  [documentation index](docs/README.md), and [contribution rules](CONTRIBUTING.md).

## Support and license

Use [GitHub Issues](https://github.com/LoonSecIO/LoonInspect/issues) for bugs and
questions, or `#loonsecio` on [MacAdmins Slack](https://macadmins.org/) for discussion.
Remove device names, serials, hostnames, and email addresses from reports and screenshots.
Report security findings privately as described in [SECURITY.md](SECURITY.md).

Licensed under [Apache-2.0](LICENSE).
