# The posture snapshot

Status: **implemented (#102, 2026-08-29)** · Target: V0

The nightly tape of fleet posture. One table, `posture_snapshot(tenant_id, metric_key,
value, captured_at, full_sweep_run_id)` — one row per metric per capture, never a wide
row, never a JSON blob. The recorder (`app.core.posture`) fires as the last act of every
closed full sweep (`app.core.runs.finish`, lock class `device_sweep`), success **and**
failure: a failed night's database state is real, and the failed run id stamped on the
rows is what makes staleness visible. The failure itself gets loud elsewhere (run log +
`run.completed`); a run whose process died and was later reclaimed writes no capture at
all, and that gap in the tape is itself the signal.

This is the one piece of the 2026-08-29 design record that had to be code before the
freeze: history not recorded can never be backfilled, so this is the only decision in
the whole design that destroys data if taken late. Recording buys zero pixels — no
chart, no endpoint, no surface ships with it. The tape starts at launch; what reads it
comes later.

Three mechanical facts about the rows:

* **`full_sweep_run_id` outlives its run.** Runs are purged after 30 days
  (`app.core.runs.purge_runs`) while audit periods run 12 months; the FK is
  `ON DELETE SET NULL`, so the snapshot is the only durable run history.
* **Absent means "did not apply", never zero.** `outbox.oldest_pending_age_s` writes no
  row when nothing was pending; zero is always written as `0`.
* **A capture can fail; the sweep cannot fail with it.** The recorder commits its own
  rows after the run's terminal status is committed, and every recorder error is logged
  and swallowed by the caller.

## Guardrails

Written here so a future key argues against a rule rather than against silence:

* fleet-level scalars only (no per-entity key families)
* definitions immutable per key (a change mints a new key and retires the old)
* ratios never stored (numerator and denominator as separate keys)
* recorder reads the DB never the API
* recording buys zero pixels
* no zero-priming
* no operator-behavior keys ever

"No zero-priming" is why the reserved keys below have no writer: a key that records
before its feature's table exists writes a run of zeros that lies about when
measurement began. "No operator-behavior keys ever" means the tape measures the fleet
and the pipeline, never the humans operating them — page views, click paths, and login
cadences are not posture and will not become keys.

## Definitions v1

Every key is one bounded SQL query inside the capture (`app.core.posture._compute`).
Windows are exact hours from the capture instant (`7d` = 168h, `24h` = trailing 24h),
never calendar boundaries. `capture` below is `captured_at`.

### Devices

The population for every `devices.*` key is device rows on **active** connections.
NULLs count as stale in both staleness keys — a device that has never checked in is the
worst staleness there is.

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `devices.total` | ACTIVE | Device rows across active connections. | `devices` ⋈ `mdm_connections.is_active` |
| `devices.stale_checkin_7d` | ACTIVE | `last_check_in` older than capture − 168h, NULLs included. | `devices` |
| `devices.unmanaged` | ACTIVE | `managed = false`. | `devices` |
| `devices.stale_inventory_7d` | ACTIVE | `last_inventory_at` older than capture − 168h, NULLs included. | `devices` |

### App catalog and applications

Same semantics as `CatalogSummaryOut` (`/api/catalog`), computed recorder-side.
"Installed" = at least one installed app carries the entry's `version_hash`.

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `catalog.entries` | ACTIVE | All `app_catalog` rows. | `app_catalog` |
| `catalog.installed` | ACTIVE | Entries with at least one install. | `app_catalog` ⋈ `installed_apps` |
| `catalog.matched` | ACTIVE | Entries with `jamf_title_ids` not null. | `app_catalog` |
| `catalog.unmatched` | ACTIVE | Entries with `jamf_title_ids` null. | `app_catalog` |
| `catalog.installed_not_latest` | ACTIVE | Installed entries where `is_latest = false` and `latest_version` is present. Grain frozen: catalog **entries**, not device pairs. | `app_catalog` ⋈ `installed_apps` |
| `apps.distinct` | ACTIVE | Distinct `app_hash` groups in the fleet. | `installed_apps` |

### Patch posture

The pair grain: a *pair* is one distinct (device, matched Jamf Patch title), reached
through the `AppCatalogTitleMatch` → catalog row → `InstalledApp` join — the same join
`/api/jamf-patch` counts devices through. `on_latest` carries the standing "latest =
any title says so" semantics the matcher stamped on the row. Coverage % derives at
render from the two pair keys; it is never stored.

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `patch.pairs_total` | ACTIVE | Distinct (device, matched title) install pairs. | title matches ⋈ `app_catalog` ⋈ `installed_apps` |
| `patch.pairs_on_latest` | ACTIVE | Pairs where the installed version equals the title's latest (`on_latest`). | same join |
| `patch.titles_with_laggards` | ACTIVE | Matched titles where `devices_on_latest < device_count` and `device_count > 0`. | same join, per title |
| `patch.pairs_laggard_over_14d` | RESERVED | Pairs behind a latest that has been available longer than 14 days. Gated on #68 (`patch_available_since`); activates when that contract closes. | — |

### Changes

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `changes.notable_24h` | ACTIVE | `device_changes` rows at level ≥ notable (the closed LEVELS ordering at `normal` or above — one SQL predicate, no API parameter) with `observed_at` in the trailing 24h. | `device_changes` |

### Runs

30-day run retention against 12-month audit periods: these captures are the only
durable run history.

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `runs.sweeps_succeeded_24h` | ACTIVE | Runs with `trigger = sweep`, `status = succeeded`, finished in the window. | `runs` |
| `runs.failed_24h` | ACTIVE | Runs with `status = failed` (any trigger), finished in the window. | `runs` |
| `runs.full_sweep_duration_s` | ACTIVE | `finished_at − started_at` of the very run this capture stamps. | `runs` |

### Outbox

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `outbox.pending` | ACTIVE | `event_outbox` rows awaiting delivery (not yet fanned out, or holding a pending delivery). **A nightly point-sample** of a queue that drains continuously — the number says "this much was in flight at capture", never "this much accumulated today". | `event_outbox`, `outbox_deliveries` |
| `outbox.failed_24h` | ACTIVE | `outbox_deliveries` rows entering `failed` (dead-lettered) in the window, timed by the last attempt. | `outbox_deliveries` |
| `outbox.oldest_pending_age_s` | ACTIVE | Max age of undelivered `event_outbox` rows at capture. **If zero rows are pending, no row is written** — absent means no pending existed; it is never coerced to 0. | `event_outbox` |

### Operator surface

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `accounts.total` | ACTIVE | Non-revoked accounts (`status = active`). | `accounts` |
| `accounts.admins` | ACTIVE | Active accounts holding the admin role — the same cut the accounts API's last-admin guard counts. | `accounts` ⋈ `account_roles` |
| `tokens.active` | ACTIVE | API tokens with `revoked_at` null. | `api_tokens` |

### Reserved: alerts and vulnerabilities

Frozen definitions, no writer yet. Each activates with its feature's table — no
zero-priming: no key records before the thing it measures exists.

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `alerts.open` | RESERVED | Open rows in #101's alerts table at capture. Activates with that table. | — |
| `alerts.opened_24h` | RESERVED | Alerts opened in the trailing 24h. Activates with #101's alerts table. | — |
| `vuln.apps_affected` | RESERVED | Distinct apps with at least one LoonVD-known vulnerability. Gated on the LoonVD wire. | — |
| `vuln.apps_kev_affected` | RESERVED | Distinct apps carrying a KEV-listed vulnerability. Gated on the LoonVD wire. | — |
| `vuln.apps_unknown` | RESERVED | Apps LoonVD cannot assess (`unknown_app`). Gated on the LoonVD wire. | — |
| `vuln.devices_affected` | RESERVED | Distinct devices carrying at least one affected app. Gated on the LoonVD wire. | — |

## The process line

Every feature issue or PR that creates or reshapes a data area answers one line:

```
posture_snapshot: <keys | none>
```

`none` is a first-class answer — it means the question was asked and the change moves
no fleet-level number worth a nightly row. A missing line means the question was never
asked. The gate lives in CONTRIBUTING.md; the registry
(`app.core.posture.ACTIVE_KEYS` / `RESERVED_KEYS`) and this document are kept in step
by `tests/test_posture_registry.py`.
