# The posture snapshot

Status: **implemented (#102, 2026-08-29)** · 37 keys, last activated 2026-09-19
(`devices.departed_24h`, #476) · 0 reserved · Target: V0

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
came later — `GET /api/posture`, ruled and built 2026-09-16 ([The reader](#the-reader)).

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

"No zero-priming" is why a ruled key waits in `RESERVED_KEYS` for its writer: a key that
records before its feature's table exists writes a run of zeros that lies about when
measurement began. It is also why the four `vuln.*` keys, active since 2026-09-11, still
write **no rows at all** on a tenant nothing has assessed — the same rule one layer in,
applied per tenant rather than per release ([Vulnerabilities](#vulnerabilities) below).
"No operator-behavior keys ever" means the tape measures the fleet and the pipeline,
never the humans operating them — page views, click paths, and login cadences are not
posture and will not become keys.

## Population

Ruled 2026-09-02 (#230). **A capture's rows are scoped to the population the run that
wrote them observed, and the row says so.** `platform` is stamped by
`app.core.posture.CAPTURE_PLATFORM`; today it is `macos` on every row, because v0 reads
computers only ([mobile-devices.md](mobile-devices.md)) and every device the recorder
counts is a Mac by construction.

The column exists because the guardrails above leave no way to add it later. Eighteen of
the 37 active keys count a *different population* the first night a sweep observes more
than Macs — the five `devices.*`, the five `catalog.*`, `apps.distinct`,
`changes.notable_24h`, the two `alerts.*` and the four `vuln.*` — and at that point both
available moves destroy something.
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
* **A key that starts writing later is stamped by the run that activates it**, on the
  same rule: it has no population until it has rows, and its tape starts under the
  platform its first capture observed. The four `vuln.*` keys are the live case — their
  first row for a tenant is written the night the corpus join first judges it, under that
  night's platform.

### Departed Macs

Ruled 2026-09-16 ([#135](https://github.com/LoonSecIO/LoonInspect/issues/135)), ahead of
the [#183](https://github.com/LoonSecIO/LoonInspect/issues/183) build that needs it, and
**built the same day** ([#476](https://github.com/LoonSecIO/LoonInspect/issues/476)). A Mac
Jamf has deleted leaves the counted population at the end of #183's seven-day tail — not
on the first night it is missed, and never on a dirty or scoped sweep, because the
evidence is one clean census. Its `devices` row, its observation spans and its change
history all **stay**; erasing them is
[#180](https://github.com/LoonSecIO/LoonInspect/issues/180) and v5.

**One predicate, twenty keys.** The exclusion is not a `devices.*` rule. It reaches every
key that counts a Mac, and every key that counts what was installed on one. It is
`app.core.posture._in_the_fleet`, written once and read at `captured_at` — never at
`now()`, because a capture is as of its instant and the first key and the twentieth must
answer alike about a Mac whose tail runs out mid-capture:

* `_devices_on_active_connections()` — the four `devices.*` population keys.
* `_alerts_on_active_connections()` — `alerts.open` and `alerts.opened_24h`, which draw
  the device cut through their own helper so the tape and `GET /api/alerts` can never
  disagree.
* the device join inside `_vuln_values` — `vuln.devices_affected`.
* `_installed()`, `_patch_pairs()`, and `apps.distinct`'s own count over
  `installed_apps` — `catalog.installed`, `catalog.installed_not_latest`,
  `apps.distinct`, the three `vuln.apps_*` keys and the seven `patch.*` keys. A departed
  Mac's `installed_apps` rows stay in the database and stop being evidence that anybody
  has the build.

`patch_pair_counts` is shared with `GET /api/jamf-patch/coverage` (#109), so the instant is a
parameter: `captured_at` for the tape, `now()` for the tile.

**`devices.departed_24h` is that same predicate read twice** — in the population 24h before the
capture, gone for good by the capture — so the key counts exactly what the exclusion stopped
counting and cannot drift from it. **Derived, never a column**: an open departure row *is* the
tail (#183). A Jamf id retired by a serial match (#475) lands here on its own day seven: that
row leaves the population while the Mac counts beside it under a new one.

**Why this is not a redefinition.** Until #183 no device row *could* be departed: nothing
removed a device or marked one absent, so every capture written before it counts exactly
the Macs Jamf knew about that night. "Device rows on active connections" and "Macs Jamf
currently knows about" were the same set — the first was only the spelling of the second
that the database could express. #183 introduced rows that are not that: a
Mac Jamf deleted, kept for its history. Excluding them is what keeps `devices.total`
meaning in 2027 what it meant on its first night; *including* them is what would change
every series in the list under itself, silently, with no new key and no error. So this is
*definitions immutable per key* obeyed rather than bent — and it is written down before the
v2026.09.17 tag because after the tag it stops being possible to say at all.

**Explicitly out of scope: an active-connection filter on `_installed()` or
`_patch_pairs()`.** Those two count `installed_apps` rows without asking whether the
device's connection is active, and that is deliberate and already documented — a build
carried only by a Mac on a deactivated connection is counted by `catalog.installed` and by
no device in `vuln.devices_affected` ([Vulnerabilities](#vulnerabilities) says so in the
key rows themselves). Departure and deactivation are different facts: a deactivated
connection is an operator turning a source off, a departure is Jamf saying the Mac is gone.
Narrowing those helpers to active connections is a second, separate redefinition of five
key families, and nothing here rules it.

**Captures taken before 2026-09-16 count deleted Macs** — the gap is closed, and the tape it
left is permanent. The predicate activated with #476 on the day it was ruled; before that
`last_seen_at` was the only evidence of absence and no key read it, so every key above counted
a Mac Jamf had deleted for as long as the container had been running. A fleet with ordinary
churn reads a few percent high per month across that stretch, monotonically — it never corrects
itself and cannot be backfilled out. Read those nights the way `outbox.pending`'s
destination-less accumulation and `patch.pairs_laggard_over_14d`'s dateless under-count are
read: a known direction of error, stated here, not a number to correct later.

## Definitions v1

Every key is one bounded SQL query inside the capture (`app.core.posture._compute`).
Windows are exact hours from the capture instant (`7d` = 168h, `24h` = trailing 24h),
never calendar boundaries. `capture` below is `captured_at`.

### Devices

The population for every `devices.*` key is device rows on **active** connections, of
the capture's own platform, **that the last clean census still observed** — the recorder
counts what the sweep observed and the row records which that was
([Population](#population)). A Mac Jamf has deleted leaves this population at the end of
#183's seven-day tail; its row, its spans and its change history stay
([Departed Macs](#departed-macs), where the same exclusion's other sixteen keys are listed,
and where `devices.departed_24h` — the one key here that counts the Macs the other four
stopped counting — is derived from that same predicate). NULLs count as stale in both
staleness keys — a device that has never checked in is the worst staleness there is.

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `devices.total` | ACTIVE | Device rows across active connections that the last clean census still observed. A Mac Jamf deleted leaves this count at the end of #183's seven-day tail and keeps its row, spans and change history — erasure is #180 (v5). | `devices` ⋈ `mdm_connections.is_active` |
| `devices.stale_checkin_7d` | ACTIVE | `last_check_in` older than capture − 168h, NULLs included, over that same population: active connections, still observed by the last clean census. | `devices` |
| `devices.unmanaged` | ACTIVE | `managed = false`, over that same population: active connections, still observed by the last clean census. | `devices` |
| `devices.stale_inventory_7d` | ACTIVE | `last_inventory_at` older than capture − 168h, NULLs included, over that same population: active connections, still observed by the last clean census. | `devices` |
| `devices.departed_24h` | ACTIVE | Devices that left the counted population in the trailing 24h — in it at capture − 24h, gone for good at capture. The end of #183's seven-day tail, not the day absence was first derived, and derived from the open `subject_departures` row rather than stored. A Mac that returns by Jamf id inside its tail never reaches this key; a Jamf id **retired** by a serial match (#475) does, on its own day seven, because that row leaves the population while the Mac counts beside it under a new one. | `devices` ⋈ `subject_departures` |

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

### Vulnerabilities

Activated 2026-09-11 (#250) on the per-build answers the local join stores (#381,
[`vulnerabilities.md`](vulnerabilities.md) §4f).

**The grain was set on 2026-09-11, at activation, and is immutable from that date like
every other definition here.** What #102 reserved was the four *names*, the activation
rule below, and a one-line gloss written before there was a table to count — "distinct
**apps** with at least one LoonVD-known vulnerability". The rows below are narrower than
that gloss on purpose: the unit is the **installed build** — one `app_catalog` row, one
`version_hash` — which is `catalog.installed`'s unit, so the three app keys have a
denominator on the same tape and at the same grain. Setting a definition at activation is
allowed only while a key is RESERVED, because no row was ever written: there is no series
to orphan and no history that changes meaning under itself. It has happened twice — here,
and `devices.departed_24h` on 2026-09-16, whose retired-id clause (#475) is stated in its
own row. From 2026-09-11 the standing rule applies — a change to any of these four mints a
new key and retires the old.

**"Apps" in these four names is not `apps.distinct`'s grain.** That key counts `app_hash`
groups: one per app across every version of it the fleet carries. These count builds. Two
versions of Wireshark are one `apps.distinct` and two `vuln.apps_affected`, so
`vuln.apps_affected / apps.distinct` is a ratio of two different units and reads high; the
denominator that belongs under these three is `catalog.installed`.

**The activation rule, ruled on #113 (2026-09-02) and enforced by
`app.core.posture._vuln_values`.** While a tenant has never run the corpus join — every
app reading `assessment: off` on the wire — these four keys write **no rows, not
zeros**. This is the guardrail above applied to a case a naive recorder gets wrong: a
zero here is not "no vulnerabilities", it is "never assessed", and writing it
manufactures a clean bill of health for a fleet nobody looked at. The keys start writing
the night the join first judges that tenant, and their tape starts then.

Two database facts open the gate, both read and neither derived: the container holds a
corpus epoch (`vuln_library_epoch`), and at least one of this tenant's `app_catalog` rows
carries a stored answer (`vuln_signature` not null) — **ever judged**, never *judged
against tonight's epoch*. So a pod with no library writes nothing, and a tenant whose
data-sharing tier is `off` writes nothing, because the judge pass clears its stored
answers and the gate closes behind them. **A gap in this family is a statement** —
"nothing has ever been assessed here" — and it is a different statement from four zeros.

**A tenant whose answers are merely behind still writes its night.** Corrected 2026-09-11
before the first row existed: the gate first asked for equality with the answering epoch,
which spelled "one epoch behind" exactly the way it spells "never assessed". That state is
reachable with nothing broken — a new epoch lands, the next sweep fails before it processes
a device (the recorder fires on failed sweeps by design), and the hourly re-judge has not
run yet — so the absence would have been a lie about a fleet assessed for months, in a tape
nobody can re-date. Such a night writes what the wire said that night: every build reads
`unknown_app` under an epoch that is no longer answering, so `apps_unknown` carries the
whole installed population and the other three keys are honest zeros. **`apps_unknown ==
catalog.installed`, with the other three at zero, is what "nothing was answered tonight"
looks like** — distinct from a gap, which means nothing was ever answered.

**What a row cannot say: which epoch answered it.** `posture_snapshot` has no epoch column
— one row is one metric, one capture, one population, never a wide row — and
`vuln_library_epoch` keeps a single row with no history, so a count cannot be traced to the
corpus that produced it years later. The shape above is the substitute, and it is written
here rather than left for a reader to work out.

The population for the three app keys is `catalog.installed`'s exactly: distinct builds
of the capture's platform that at least one device carries. That is the denominator a
reader needs — of N installed builds, A affected, U unassessed, and the rest assessed
clean. `apps_kev_affected` is a subset of `apps_affected` and never its own population;
the two land as separate keys because ratios are never stored. An answer is counted only
under the epoch that produced it (equality on the stored signature, never ordering), so
the tape says what the wire said that night rather than restating one epoch's counts
under another's date.

**The two halves count two populations, on purpose.** The three app keys draw
`catalog.installed`'s cut, which counts a build any device row carries; `devices_affected`
draws the active-connection device population every `devices.*` key counts. So a build
carried only by a Mac on a deactivated connection adds one to the app keys and no device to
`devices_affected`, and the two halves of this family can differ by that much without
either being wrong. They are not aligned because aligning them would give the three app
keys a denominator `catalog.installed` no longer matches.

| Key | Status | Definition | Source |
| --- | --- | --- | --- |
| `vuln.apps_affected` | ACTIVE | Installed builds whose stored answer is `covered` under the answering epoch with `counts.total > 0` — at least one vulnerability the corpus knows. Grain: one `app_catalog` build, `catalog.installed`'s unit, which counts a build any device row carries — including a Mac on a deactivated connection, which `devices_affected` does not count. **No row while the tenant has never been judged.** | `app_catalog` ⋈ `installed_apps` |
| `vuln.apps_kev_affected` | ACTIVE | The same population with `counts.kev > 0` — carrying a KEV-listed vulnerability. A subset of `apps_affected`. Same build grain and same `catalog.installed` cut, so a build only a deactivated connection's Mac carries is counted here and in no device under `devices_affected`. **No row while the tenant has never been judged.** | `app_catalog` ⋈ `installed_apps` |
| `vuln.apps_unknown` | ACTIVE | Installed builds the corpus cannot assess (`unknown_app` — a ruled wire value, deliberately snake_case): no row in the epoch, or an answer from an epoch that is no longer answering. Same build grain and same `catalog.installed` cut, deactivated connections included. Equals `catalog.installed` on a night when nothing answered. **No row while the tenant has never been judged.** | `app_catalog` ⋈ `installed_apps` |
| `vuln.devices_affected` | ACTIVE | Distinct devices on active connections carrying at least one build `apps_affected` counted. Folded through the catalog row, not the device's copy, so a copy lagging its device's sync cannot make the two disagree about a build — the copy-lag axis only. On the population axis they differ by design: this is the active-connection device cut every `devices.*` key draws, while the app keys are `catalog.installed`'s any-device-row cut, so a build only a deactivated connection's Mac carries is counted there and nowhere here. **No row while the tenant has never been judged.** | `installed_apps` ⋈ `app_catalog` ⋈ `devices` |
| `vuln.findings_open` | ACTIVE | Open `device_findings` rows — one per (Mac, carrier title, finding id) still detected as of that Mac's last observation (#590, [`vulnerabilities.md`](vulnerabilities.md) §6), never as of the capture. Findings and not devices or builds: one Mac carrying one id through Safari and through the OS is two. No device cut and no departure cut — `device_departed` has no writer yet, so a Mac deleted in Jamf keeps its open rows here, bounded by its last observation and never read as fixed. **No row while the tenant has never been judged, or while its finding ledger holds no row at all.** | `device_findings` |
| `vuln.findings_new_24h` | ACTIVE | Ledger rows whose `first_observed_at` falls in the trailing 24h — findings this pod saw on a Mac for the first time. Includes rows a backfill reconstructed (`first_seen_basis = backfill`), which date to the change log and not to the night, so the first nights after the ledger lands read low rather than as a spike. A reopened row keeps its original clock and is counted in neither direction. **No row while the tenant has never been judged, or while its finding ledger holds no row at all.** | `device_findings` |
| `vuln.findings_resolved_24h` | ACTIVE | Ledger rows closed in the trailing 24h, by `resolved_at`, whatever the reason — including `corpus_withdrawn`, which is *the epoch stopped listing it* and never *it was fixed* (#589 ruling 4). Not a remediation count: read it beside `findings_open`, and the reason on the row itself. **No row while the tenant has never been judged, or while its finding ledger holds no row at all.** | `device_findings` |

## The reader

`GET /api/posture` (#470, 2026-09-16), after three weeks of tape with nothing but `psql` to read
it — which is where the platform filter gets left off. **The rows, never a grid:** one row per
metric per capture per population (`key`, `value`, `capturedAt`, `platform`, `fullSweepRunId`),
so a key that recorded nothing has no row and no cell for a renderer to fill with a zero —
absent-not-zero held in the shape rather than in a footnote. `fullSweepRunId` is null once the
run is purged out from under its capture, and `value` is a JSON number, so a count arrives as
`12.0`: the column is NUMERIC and the two `…_s` keys carry real fractions of a second.

**The default is the latest capture, chosen by the tape and never by the key filter** — the
newest `captured_at` for the population, then `keys` over that capture's rows. Picking the
newest capture that *carries* the asked-for key would answer "the last time this was
written" to a question that was "what was written last night", which is how an empty queue
comes back as yesterday's `outbox.oldest_pending_age_s`. `days` or `since` reads the series
instead — one or the other, never both — and `platform`, defaulting to `CAPTURE_PLATFORM` with
no value that folds two, is one population per read. An unknown key, a `keys` sent with no key
in it, a `RESERVED_KEYS` name and a platform outside the vocabulary above are each refused in
words: an empty page would read as "never captured", the sentence this tape reserves for a real
gap. **`all` is refused too**, in a sentence of its own — *the reserved cross-platform roll-up,
and nothing writes it: ask for one population* — because its empty page is guaranteed rather
than merely possible, and because it is the English word for the fold this design forbids, so
the reader likeliest to type it is the likeliest to read `total: 0` as "the tape is empty".

**`GET /api/posture/registry`** hands over every active and reserved key with the opening of its
definition and what an absent row means, so a value can be read without this document. The
definitions still live *here*: `app.core.posture.KEY_DEFINITIONS` quotes each row's opening
words and `tests/test_posture_registry.py` refuses a sentence this document does not open with.

**Permission: `AUDIT_READ`**, the one the share-log export uses — fleet-level scalars with no
per-entity grain ([data-access-grain.md](data-access-grain.md) §3), answering the auditor's
question: the durable history of a fleet. `SYSTEM_READ` guards a different subject, this
instance's own status; analyst, auditor and admin hold both, so the choice moves no access,
it names the question.

**Its first consumer, 2026-09-17 (#538).** Posture › Vulnerabilities reads the latest capture's
seven `vuln.*` keys into *By the numbers* at the foot of the page, dated with `capturedAt` and
stamped with `fullSweepRunId`. It is the only reader, and the band is **planned** against
`AUDIT_READ` rather than rendered into a `403` (`features/vulnerabilities/pageBands.ts`, after
`overviewPlan.ts`): no band for an account without it, and a dash — never a zero — for a key with
no row.

## The process line

Every feature issue that creates or reshapes a data area, and every pull request, answers
one line:

```
posture_snapshot: <keys | none>
```

`none` is a first-class answer — it means the question was asked and the change moves
no fleet-level number worth a nightly row. A missing line means the question was never
asked. The gate lives in CONTRIBUTING.md, and the `PR body` check holds the pull request
half; the registry (`app.core.posture.ACTIVE_KEYS` / `RESERVED_KEYS`) and this document
are kept in step by `tests/test_posture_registry.py`.
