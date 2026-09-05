# The posture snapshot

Status: **implemented (#102, 2026-08-29)** · Target: V0

The nightly tape of fleet posture. One table, `posture_snapshot(tenant_id, metric_key,
platform, value, captured_at, full_sweep_run_id)` — one row per metric per capture per
population, never a wide row, never a JSON blob. The recorder (`app.core.posture`) fires
as the last act of every closed full sweep (`app.core.runs.finish`, lock class
`device_sweep`), success **and** failure: a failed night's database state is real, and
the failed run id stamped on the rows is what makes staleness visible. The failure
itself gets loud elsewhere (run log + `run.completed`); a run whose process died and was
later reclaimed writes no capture at all, and that gap in the tape is itself the signal.

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
* **Every row says which population it counted.** `platform` is on the row, and
  `uq_posture_snapshot_capture` makes `(tenant_id, metric_key, platform, captured_at)`
  unique — see [Population](#population) below.

## Guardrails

Written here so a future key argues against a rule rather than against silence:

* fleet-level scalars only (no per-entity key families)
* definitions immutable per key (a change mints a new key and retires the old)
* every row names its population (see [Population](#population))
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

## Population

Ruled 2026-09-02 (#230). **A capture's rows are scoped to the population the run that
wrote them observed, and the row says so.** `platform` is stamped by
`app.core.posture.CAPTURE_PLATFORM`; today it is `macos` on every row, because v0 reads
computers only ([mobile-devices.md](mobile-devices.md)) and every device the recorder
counts is a Mac by construction.

The column exists because the guardrails above leave no way to add it later. Thirteen of
the 29 active keys count a *different population* the first night a sweep observes more
than Macs — the four `devices.*`, the five `catalog.*`, `apps.distinct`,
`changes.notable_24h` and the two `alerts.*` — and at that point both available moves
destroy something.
Redefining `devices.total` in place to mean "Macs and iPads" is forbidden by
*definitions immutable per key*, and silent besides: no error, no migration, just a
series that stops meaning what its own history means. Minting `devices.macos.total` and
retiring `devices.total` obeys that rule and collides with *no zero-priming* — the new
key starts with no history behind it and can never be backfilled. The peer aggregate is
worse than the local read: a size band derived from a population-less `devices.total`
files a 3,000-Mac tenant and a 1,500-Mac/1,500-iPad tenant in the same bucket.

`catalog.matched` is the sharpest of the catalog keys. Jamf Patch carries macOS titles only,
so an iOS app can never enter that numerator and lands in `catalog.unmatched`
permanently — patch coverage collapses on the graph while nothing about the fleet got
worse. The `patch.*` keys are safe for that same reason: they count pairs reached
through a matched title, and there are no mobile titles to reach through.

The rules the column carries:

* **The vocabulary is one value per Apple OS**: `macos`, `ios`, `ipados`, `tvos`,
  `visionos`. This is the content-key OS spelling (`os_key("macos", …)`), **not** the
  sourcetype segment's `mac` — the two namespaces spell Mac differently and both
  spellings are already minted, so neither is renamed to match the other (Kyle,
  2026-09-02).
* **A platform value is never reused for a different population.** It is as immutable
  as a key name, and for the same reason: a value's meaning is what its history means.
* **`all` is reserved for a cross-platform roll-up and is never written by a
  single-platform run.** A roll-up is a different number, not a synonym for the only
  population that happened to exist that night. Writing `all` for a Mac-only capture
  would make the roll-up's own history start as a lie about its coverage.
* **Every read filters on platform.** A query that groups by `metric_key` alone sums
  across populations, and no constraint can save it — a `macos` row and an `all` row
  for one key are legitimately two rows. What `uq_posture_snapshot_capture` guarantees
  is the other half: *within* one population there is exactly one row per key per
  capture, so a read that does filter can never double-count. Unique on `(tenant_id,
  metric_key, platform, captured_at)`, its backing index is also the series read shape,
  which is why `ix_posture_snapshot_series` was dropped into it rather than widened
  beside it — that would have been the same four columns twice.
* **Reserved keys are stamped by the run that activates them**, on the same rule: the
  four names below carry no population today because they carry no rows, and each starts
  its tape under the platform its first capture observed.

## Definitions v1

Every key is one bounded SQL query inside the capture (`app.core.posture._compute`).
Windows are exact hours from the capture instant (`7d` = 168h, `24h` = trailing 24h),
never calendar boundaries. `capture` below is `captured_at`.

### Devices

The population for every `devices.*` key is device rows on **active** connections, of
the capture's own platform — the recorder counts what the sweep observed and the row
records which that was ([Population](#population)). NULLs count as stale in both
staleness keys — a device that has never checked in is the worst staleness there is.

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
| `catalog.installed_not_latest` | ACTIVE | Installed entries where `is_latest = false` and `latest_version` is present. Grain frozen: catalog **entries**, not device pairs. **Includes AHEAD entries** — `is_latest` is false for a build newer than the catalog's current one, which is the matcher's own answer — so this is *not* a count of builds needing an update; `patch.pairs_laggard_over_14d` is that. Kept as-is on 2026-09-04 ([#314](https://github.com/LoonSecIO/LoonInspect/issues/314)) because, unlike "laggards", the name claims nothing the data does not support. | `app_catalog` ⋈ `installed_apps` |
| `apps.distinct` | ACTIVE | Distinct `app_hash` groups in the fleet. | `installed_apps` |

### Patch posture

The pair grain: a *pair* is one distinct (device, matched Jamf Patch title), reached
through the `AppCatalogTitleMatch` → catalog row → `InstalledApp` join — the same join
`/api/jamf-patch` counts devices through. `on_latest` carries the standing "latest =
any title says so" semantics the matcher stamped on the row. Coverage % derives at
render from the two pair keys; it is never stored. The two dated keys read the pair's
own row — `installed_apps.patch_available_since` is a fold across an app's titles and
is never what the tape counts.

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `patch.pairs_total` | ACTIVE | Distinct (device, matched title) install pairs. | title matches ⋈ `app_catalog` ⋈ `installed_apps` |
| `patch.pairs_on_latest` | ACTIVE | Pairs where the installed version equals the title's latest (`on_latest`). | same join |
| `patch.titles_with_laggards` | ACTIVE | Matched titles carrying at least one pair with `state = behind`. **Ahead and unknown are excluded**, for the reason `pairs_unknown_build` was split out below: a build that is out in front, or that cannot be placed at all, must not take a silent seat in a laggard number. No 14-day cut — this key answers *which titles have someone behind at all*; the dated question is `pairs_laggard_over_14d` one grain down. Corrected 2026-09-04 ([#314](https://github.com/LoonSecIO/LoonInspect/issues/314)) from "any device not on the title's current version", which counted a Mac running a build **newer** than Jamf publishes as a laggard — not a rare state, since Chrome and Safari auto-update ahead of the catalog on essentially every fleet, so the tenant patching fastest scored worst. | same join, distinct `title_id` |
| `patch.pairs_laggard_over_14d` | ACTIVE | Pairs with `state = behind` whose `first_newer_released_at` — Jamf's release date of the earliest listed version newer than the installed one, read from the pair's own title row, never folded across titles — is older than 336h at capture. **Every update, not severity-filtered:** a superset of the Cyber Essentials 14-day number, which scopes to high-risk and critical updates; Jamf's catalog carries no severity. **Under-counts where a title's newer patches carry no release date:** the matcher then falls back to the latest version's date, a later one. Unlisted builds are not here — see the next key. #68's clock, ruled 2026-09-02. | same join, `app_catalog_title_matches.first_newer_released_at` |
| `patch.pairs_behind_under_14d` | ACTIVE | Pairs with `state = behind` that the laggard cut does not reach: `first_newer_released_at` at or after the 336h boundary, **or null**. Null lands here rather than in the laggard key — the matcher leaves the date null when a title publishes none for anything newer, and `< cutoff` excludes null in SQL, so before this key such a pair sat in the total and in no bucket at all. The conservative side, and the same direction the laggard key's documented under-count already errs in. | same join |
| `patch.pairs_unknown_build` | ACTIVE | Pairs with `state = unknown`: the installed build is one Jamf never listed and is not newer than the title's latest. Kept out of the laggard key by design — a build that cannot be placed cannot honestly be called "14 days behind" a specific update — and given its own key so it is visible in the tape at all. | same join |
| `patch.pairs_ahead` | ACTIVE | Pairs with `state = ahead`: installed newer than anything the title lists. Given a key for the reason above it has one ([#314](https://github.com/LoonSecIO/LoonInspect/issues/314)) — before it, `ahead` was counted in `pairs_total` and in nothing else, which made the state invisible and let two other keys absorb it. Chrome and Safari live here on most Mac fleets. | same join |

> **The five state keys partition `pairs_total` exactly.**
> `pairs_on_latest + pairs_behind_under_14d + pairs_laggard_over_14d + pairs_unknown_build + pairs_ahead = pairs_total`, always. `classify()` assigns exactly one of latest / ahead / behind / unknown, `on_latest` is true iff the state is latest, and the behind half is split by a predicate whose two branches cover null. The recorder asserts the identity at capture rather than trusting it, so a drift in any one predicate fails there instead of in a dashboard.
>
> It is written down because it was not true until 2026-09-04: an `ahead` pair, and a `behind` pair inside the cut, sat in none of the buckets, and the tape said nothing — the same hazard `VulnEnrichment` states in its own schema for the severity bands, which genuinely do **not** sum. These do.

### Changes

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `changes.notable_24h` | ACTIVE | `device_changes` rows at level ≥ notable (the closed LEVELS ordering at `normal` or above — one SQL predicate, no API parameter) with `observed_at` in the trailing 24h. | `device_changes` |

### Alerts

Activated 2026-09-04 with the table they measure (#101, [alerts.md](alerts.md)) — in the
same commit, because a key whose definition ships ahead of its writer is a key nobody
can check. The population is the active-connection cut every `devices.*` key counts
over, and `GET /api/alerts` draws the same one, so the tape and the surface can never
disagree about how many things need attention.

An alert is a **derived latch**: it is opened by the sync path when its condition
becomes true and closed by the same path when the condition stops being true, with no
acknowledge, no dismiss and no human state anywhere in the table. That is what licenses
the plain reading of `alerts.open` — *true of the fleet at capture*, never "not yet
dealt with", which is a measurement of the operator and would fall foul of *no
operator-behavior keys ever*.

`alerts.opened_24h` counts rows that have **since closed**, and that is the whole reason
closed rows age out on a retention clock rather than being deleted at close: a
delete-on-close would silently redefine this key as "…opened in the trailing 24h and
still open", which is a different number with the same name.

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `alerts.open` | ACTIVE | `alerts` rows with `closed_at` null at capture, on devices whose connection is active. | `alerts` ⋈ `devices` ⋈ `mdm_connections.is_active` |
| `alerts.opened_24h` | ACTIVE | `alerts` rows with `opened_at` in the trailing 24h, on devices whose connection is active — **including rows that have since closed**. | `alerts` ⋈ `devices` ⋈ `mdm_connections.is_active` |

### Runs

30-day run retention against 12-month audit periods: these captures are the only
durable run history.

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `runs.sweeps_succeeded_24h` | ACTIVE | Runs with `trigger = sweep`, `status = succeeded`, finished in the window. | `runs` |
| `runs.failed_24h` | ACTIVE | Runs with `status = failed` (any trigger), finished in the window. | `runs` |
| `runs.full_sweep_duration_s` | ACTIVE | `finished_at − started_at` of the very run this capture stamps. | `runs` |

### Outbox

The capture observes its own run. The recorder fires inside `finish()` after the run's
own `run.completed` / `run.failed` events are committed to the outbox but before the
worker fans them out, so every capture counts the 1–2 events its own close just
enqueued. On sweep nights `outbox.pending` therefore carries a permanent floor of
~1–2, and `outbox.oldest_pending_age_s` is in practice always written — milliseconds
old — so the "zero rows pending, no row written" case below effectively never occurs
(confirmed by the 2026-08-29 wire-e2e regression). This is the point-sample semantics
working, not a bug: trends read unchanged, and the definitions stand as written.
Readers and renderers should treat `pending ≤ 2` with a millisecond-scale age as an
empty-queue night — **on a pod that has an enabled destination.**

A pod that has none does not have a queue that drains. Since #157 `fan_out_pending`
*holds* events while nothing is enabled rather than consuming them unsent, and
`_outbox_pending_where()` counts un-fanned rows, so a destination-less pod reports
`outbox.pending` as its entire held backlog — one `device.inventory` snapshot per device
per sweep, every sweep since #241, plus the deltas — with `outbox.oldest_pending_age_s`
climbing toward the retention window
(604,800s at the default seven days) until a destination is added or the events age
out. That is the hold working as ruled, not a stalled queue, and it is the normal
reading during onboarding because the setup stepper calls the destination step
optional. Renderers, and anything comparing a pod against the peer aggregate, must not
read it as a backed-up outbox. The `outbox.pending` definition below is unchanged — the
rows really are awaiting delivery — but its *distribution* on this configuration is
accumulation rather than a point-sample of flow, and the "drains continuously" gloss in
that cell is written for the destination-configured case.

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

### Reserved: vulnerabilities

Frozen definitions, no writer yet. Each activates with its feature's table — no
zero-priming: no key records before the thing it measures exists. Their population is
whatever the run that activates them observed, stamped on the row like every other key
([Population](#population)); until then they have no population because they have no
rows.

**The `vuln.*` activation rule, ruled on #113 (2026-09-02).** While a tenant has never
run the corpus join — every app reading `assessment: off` on the wire — the four
`vuln.*` keys write **no rows, not zeros**. This is the guardrail above applied to a
case a naive recorder gets wrong: a zero here is not "no vulnerabilities", it is "never
assessed", and writing it manufactures a clean bill of health for a fleet nobody looked
at. The keys activate the night the join first runs for that tenant, and their tape
starts then. The contract they gate is [`docs/vulnerabilities.md`](vulnerabilities.md).

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `vuln.apps_affected` | RESERVED | Distinct apps with at least one LoonVD-known vulnerability. Gated on the LoonVD wire. | — |
| `vuln.apps_kev_affected` | RESERVED | Distinct apps carrying a KEV-listed vulnerability. Gated on the LoonVD wire. | — |
| `vuln.apps_unknown` | RESERVED | Apps LoonVD cannot assess (`unknown_app` — a ruled wire value, deliberately snake_case). Gated on the LoonVD wire. | — |
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
