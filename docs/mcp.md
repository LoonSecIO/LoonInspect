# Connect Codex and Claude to LoonInspect

Status: **implemented in development, default-off, 2026-11-22**. This describes the
current implementation, intended for v1.3 rather than a published release. Official
Developer ID signing and notarization remain in the existing GitHub `macOS release`
workflow and run when v1.3 is cut. Integration does not change that signing setup or
require another certificate. Development checks below use only synthetic fleet data.

LoonInspect exposes an authenticated `/mcp` endpoint for inspecting fleet devices,
applications, vulnerability evidence, runs and reports, and requesting inventory or
catalog refreshes. It uses the existing API's permissions, tenant binding and run locks.
The Mac app includes a stdio adapter that attaches to its running local backend. Both
paths serve the same tools and the same organization's data.

## 1. Enable access and create a connection

1. Sign in to the organization whose data the assistant should receive. An administrator
   enables **AI features** in **Settings → Feature Flags**. This master flag defaults off.
2. Open **Settings → AI connections**, read the disclosure, and choose **Allow AI
   connections**. This organization's separate `mcp_access` consent also defaults off.
   Enabling it does not change the master flag. Community data sharing and the
   `ai_inference` consent for LoonInspect's own model calls are separate controls.
3. Create a named connection for each assistant. Select explicit read capabilities and
   an expiry of 1–365 days. Add refresh capabilities only if the assistant should request
   work from Jamf or a public catalog. Copy the token when shown; it cannot be recovered
   later. The setup configuration contains a credential reference, never the token itself.
4. Use the Mac or server setup below. **Test connection** checks the supplied token's
   organization, account, consent and available tools. It does not check connectivity
   from the assistant's network or the assistant's installed configuration.

Administrators control consent. Administrators, Analysts and Auditors can create their
own tokens within their existing permissions; Auditors cannot grant refresh actions.
Viewers cannot mint connections. Every grant includes explicit `mcp:connect`, a finite
expiry and only the supported fleet scopes. Its permissions remain the intersection of
the grant and its owner's current permissions. It belongs to the organization in which
it was created; switching the browser's active organization does not move it.

These credentials work only through MCP. Using one directly against an ordinary REST
endpoint is refused. Revoking it or disabling its account stops access. Turning off
either MCP consent or the master AI flag refuses existing connections too. A request
already performing a write may finish; neither revocation nor cancellation rolls it back.

## 2. Connect the Mac app

Open LoonInspect and wait for the workspace. For Codex, run this in Terminal and paste
the new token at the hidden prompt:

```sh
/Applications/LoonInspect.app/Contents/MacOS/LoonInspect --mcp-pair --profile codex
```

Pairing stores the token in this Mac's login Keychain. The adapter receives it through
a private pipe, not command arguments, environment variables or a temporary file.
If the app is installed elsewhere, use its actual bundle path.

Merge the following into the Codex MCP configuration:

```toml
[mcp_servers.looninspect]
command = "/Applications/LoonInspect.app/Contents/MacOS/LoonInspect"
args = ["--mcp", "--profile", "codex"]
tool_timeout_sec = 330
```

For Claude Code or Claude Desktop, pair separately with profile `claude-code` or
`claude-desktop`. Merge this entry into that client's local MCP configuration, using the
matching profile:

```json
{
  "mcpServers": {
    "looninspect": {
      "command": "/Applications/LoonInspect.app/Contents/MacOS/LoonInspect",
      "args": ["--mcp", "--profile", "claude-desktop"]
    }
  }
}
```

Reconnect the server in Codex, use `/mcp` in Claude Code, or restart Claude Desktop.
Settings generates the configuration for the selected client. Repeating pairing replaces
the saved Keychain credential for that profile; revoke the previous token in LoonInspect.

The adapter attaches to the existing app and never starts another database. It discovers
the current port from the private `~/Library/Application Support/LoonInspect/run/mcp.json`
file and checks the backend's instance identity before sending a credential. A fixed
localhost URL can become stale when the app chooses a different free port.

Closing the window leaves MCP available. Quitting stops it; sleep interrupts requests.
After quitting and reopening LoonInspect, reconnect the MCP client. The bundled helper
serves this Mac's local app only; it does not proxy a separate Docker or hosted instance.

## 3. Connect a server or Docker deployment

Use `https://inspect.example.com/mcp`, replacing the example hostname with the deployment's
actual address. Remote MCP connections require HTTPS. Configure the app's TLS or its
reverse proxy, including `FORWARDED_ALLOW_IPS` for the trusted proxy addresses when TLS
terminates there. The app must see the correct scheme and Host header.

The Host and Origin allowlists default to loopback. Explicitly name the hosted address
in the Compose `.env` file; the values are JSON arrays:

```dotenv
MCP_ALLOWED_HOSTS=["inspect.example.com"]
MCP_ALLOWED_ORIGINS=["https://inspect.example.com"]
```

Include a port in a Host or Origin entry when the client sends a nondefault port. Add
other trusted browser origins only when a client needs them. Host validation applies
to every connection; Origin validation applies when that header is present. Recreate
the app container after changing deployment settings. Keep the endpoint on the existing
app listener and route `/mcp` through the proxy without redirecting it to a sign-in page.

For Codex, populate `LOONINSPECT_MCP_TOKEN` through your credential manager in the
environment that launches the client, then use:

```toml
[mcp_servers.looninspect]
url = "https://inspect.example.com/mcp"
bearer_token_env_var = "LOONINSPECT_MCP_TOKEN"
tool_timeout_sec = 330
```

Claude Code's HTTP configuration uses the same environment reference:

```json
{
  "mcpServers": {
    "looninspect": {
      "type": "http",
      "url": "https://inspect.example.com/mcp",
      "headers": {"Authorization": "Bearer ${LOONINSPECT_MCP_TOKEN}"}
    }
  }
}
```

A Claude cloud custom connector connects from Anthropic's infrastructure. It cannot reach
this Mac's localhost or a private address without a separate supported network path; use
publicly reachable HTTPS on port 443 and the client's Authorization-header configuration.
For a local Mac instance, use the bundled stdio setup instead. LoonInspect currently uses
bearer credentials and provides no OAuth authorization server or browser sign-in flow for
MCP. A client that requires OAuth cannot complete that flow against this implementation.

## 4. Available tools

The registry currently contains **25 tools: 22 reads and 3 refresh actions**. Discovery
lists only those the token can call; naming a hidden tool does not grant access.

| Area | Tools | What the answer means |
| --- | --- | --- |
| Instance and connections | `get_instance_status`, `list_connections` | Build/update facts and connection IDs, names, provider and active state. Connection credentials and URLs are omitted. |
| Devices | `list_devices`, `list_vulnerable_devices`, `get_device`, `get_device_history`, `get_device_history_point` | Current or recorded inventory with timestamps and evidence states. A history point is not a fresh collection. |
| Applications | `list_applications`, `get_application`, `list_application_devices`, `search_catalog` | Installed applications, builds, affected Macs and patch/vulnerability evidence. Do not sum overlapping build cohorts as distinct Macs. |
| Vulnerabilities | `get_vulnerability_status`, `get_vulnerability` | The served corpus date and installed builds associated with a finding. Missing or disabled assessment is not a clean result. |
| Changes and alerts | `list_changes`, `list_alerts` | Recorded changes and alert state. Reading alerts does not dismiss them. |
| Runs | `list_runs`, `get_run`, `get_run_log` | Inventory job state and bounded log batches. A completed run may still have unread log lines. |
| Delivery | `get_delivery_status` | Queue, dead-letter and retention facts. It does not retry deliveries. |
| Reports | `get_posture_registry`, `get_posture`, `get_evidence_report` | Metric definitions, retained posture and observation-ledger evidence, preserving caveats and missing values. |
| Refresh actions | `refresh_device`, `start_inventory_sync`, `refresh_patch_catalog` | Read from existing Jamf connections or public catalogs and update LoonInspect's records. These do not deploy software or send a command to a managed Mac. |

`start_inventory_sync` returns the existing API's `jobId` promptly. If a sweep is already
running, it returns that job with `started=false` instead of starting another. Poll
`get_run` and `get_run_log` using the tool argument `job_id`; a returned job ID is not a
completion receipt.

`refresh_patch_catalog` is synchronous. It can take minutes, returns no job ID, and has
a 300-second server deadline; the Mac helper allows 330 seconds. Fleet's catalog source
still requires its existing feature flag. A timeout does not establish that a refresh
failed: inspect the catalog's status before another attempt. No write is retried
automatically. `refresh_device` is also synchronous and uses the ordinary tool deadline.

## 5. Data, protocol and operating limits

The assistant receives the fleet values permitted by its grant. Device names, serials,
users, application details, diagnostic text and evidence reports can identify a fleet.
The selected client may send results to its model provider. LoonInspect does not choose
that provider, and cannot verify the downstream provider or model or control retention
after delivery. Fleet text is untrusted data, including text that resembles instructions.

Before a successful tool result is returned, LoonInspect rechecks access and commits a
share-log row under tier `ai`. It records the tool, connection, field categories and
`mcp-client:<token-id>` recipient, with the model unknown. It does not copy raw fleet
values or credentials into that disclosure row. Tool attempts also write an audit event
with their outcome. Share-log retention is 90 days. These rows describe disclosure to the
client, not proof that a particular downstream model received or retained it.

The endpoint uses stateless Streamable HTTP with JSON responses. The bundled adapter
supports the 2025-11-25 initialization flow and the 2026-07-28 per-request envelope flow,
including their different cancellation transports. There is no persistent MCP session
to resume and no automatic write replay.

| Limit | Current behavior |
| --- | --- |
| Request / response | 256 KiB request limit; results are bounded to fit a 512 KiB response. Oversize results are refused with a request to narrow the query. |
| Tool concurrency | 8 active tool calls per backend process; one active patch-catalog tool call at a time per process. |
| Call rate | 60 tool calls per minute per token, including at most 6 refresh calls. Limits are held per process, not across replicas. |
| Pages | Usually 50 records by default, at most 200; the device-history timeline uses its existing 12-point pages. Follow each returned pagination field. |
| Deadlines | 30 seconds per ordinary server tool; 300 seconds for patch catalog. The helper allows 45 and 330 seconds respectively; local discovery allows 10 seconds. |

Background syncs and writes retained after a timeout or cancellation can continue after
their tool call releases its slot. A retained catalog refresh blocks another refresh
of the same source until it ends; a different catalog source can still run.

Some source REST answers are assembled before the adapter slices a page. The internal
REST response has a 4 MiB limit, so a large device or evidence report can be refused even
when a small MCP page was requested. Narrow the report window or use the existing UI's
HTML evidence export. Report pages are live reads, not a frozen export: keep the returned
window's `start` and `as_of` on later pages, and account for inventory arriving between
calls. Evidence fleet totals cover the full window; device details and interval rows
identify the current page's scope.

For failures, follow [Troubleshooting §29](troubleshooting.md#29-codex-or-claude-cannot-use-looninspect).
The implementation registry is [tools.py](../backend/app/mcp/tools.py); client setup is
generated by [configuration.ts](../frontend/src/features/mcp/configuration.ts). These
sources and the actual running build take precedence over an older copy of this runbook.

## 6. Integration validation

The implementation was integrated on top of main `5c7dda76`. Live checks used an
isolated database with one synthetic Mac, expiring scoped credentials, temporary
client configuration, and a separate Mac runtime descriptor. Production fleet data,
installed client configuration and the release workflow were not changed.

| Client or path | Observed result |
| --- | --- |
| Codex CLI 0.169.1, HTTP | Completed `get_instance_status`, `list_devices` and `get_device`; returned the synthetic tenant and its one Mac. The client blocked a refresh under its approval policy. |
| Codex CLI 0.169.1, Mac stdio | Launched the native `--mcp` entrypoint, read the synthetic Keychain profile and completed the same three reads. |
| Claude Code 2.1.330, HTTP and Mac stdio | On 2026-11-23, model-driven calls against merged commit `0ab7d7cc` completed `get_instance_status`, `list_devices` and `get_device` over each transport. All six results matched the synthetic organization and device. |
| Claude Code 2.1.330, fleet reads over HTTP | Seven additional model-driven calls completed: `list_connections`, `get_vulnerability_status`, `list_runs`, `get_run`, `get_run_log`, `get_posture` and `get_evidence_report`. Returned connection/run IDs, the seeded log, device total and report caveats matched the fixture. |
| Official SDK through the Mac entrypoint | Both 2025-11-25 and 2026-07-28 flows listed the 24 granted tools and completed the same three reads. The catalog-refresh permission was deliberately omitted from this test credential. |
| Revocation | Revoking the synthetic credential through the token API changed Claude's stdio check from Connected to an explicit expired-or-revoked error; HTTP MCP initialization returned 401. |

The Claude follow-up used a fresh isolated database, a one-day credential granting
22 read tools, and a temporary Keychain profile. All 13 model-driven reads returned
the expected organization. The completed run and posture capture were seeded records,
not an executed Jamf sync. With no vulnerability corpus loaded, Claude reported the
fleet as unassessed; the evidence answer preserved missing coverage, pagination and
the report's refusal to judge compliance. No refresh actions were granted or invoked.

Disclosure and audit records matched all 13 Claude reads plus nine fixture smoke reads.
Disclosure rows contained field categories, not the synthetic hostname, serial or
credential. Revocation was repeated after the model calls: the token API returned 204,
Claude's HTTP connection check rejected the credential with 401, and its Mac stdio
check reported expired or revoked. The temporary database, backend, credentials,
Keychain profile and runtime descriptor were removed and their absence verified.

This completes live Claude Code validation on both transports. Claude Desktop's UI
and model interaction, production-fleet behavior and actual Jamf refreshes were not
exercised. The Mac check reused the existing development bundle; its native MCP
entrypoint and Python bridge matched the tested commit, with no new signing run.

Automated checks in the integrated checkout:

| Check | Command and result |
| --- | --- |
| Backend, Python 3.12 with isolated Postgres 17 | `RUN_DB_TESTS=1 .venv/bin/pytest -q --tb=short`: 4,570 passed, 71 skipped, 3 expected failures. `DATABASE_URL` used a role without superuser or BYPASSRLS; `ADMIN_DATABASE_URL` was provided only for disposable migration round-trip databases. |
| Backend lint and formatting | `.venv/bin/ruff check .` and `.venv/bin/ruff format --check .` passed from `backend/`. |
| Frontend, Node 22.23.5 | `npx tsc -b --noEmit`, `npx eslint .`, `npm test -- --run --maxWorkers=1` and `npm run build` passed; 812 tests passed. The first parallel run hit resource-related timeouts; no assertion or timeout limit was relaxed. |
| Container and documentation | The multi-stage `docker build` passed, as did `.github/scripts/check-readme-claims.sh` with all 11 active claims backed. |
| Mac regression checks | 12 shell/MCP/watchdog tests, native export checks, and 4 notarization-script unit tests passed. The unit tests do not submit an app to Apple. |

The first full backend run exposed an existing alert-test fixture reusing a connection
object expired by a bookkeeping rollback. The fixture now reloads that row as the
next real request would; the existing reinstall test exercises the rollback explicitly.
Production ingestion logic was unchanged, and the clean full rerun above passed.

The Mac runtime check used an already built local Developer ID-signed development
bundle with hardened runtime. It was not a release or notarization run. Official
release signing, notarization and release acceptance remain deferred to the v1.3 cut.
