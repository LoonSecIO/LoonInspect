# The app catalog: the fleet's distinct apps, first and last seen, and what Jamf says

Status: v0, built under #67 (2026-08-22). Code: `backend/app/catalog/service.py` (the tenant
rows, when they are written and judged), `backend/app/catalog/index.py` (Jamf's side as a local
lookup), `backend/app/api/catalog.py`; migration `b4c7e9d2a1f6`. UI: Devices › Applications ›
**Catalog**. Tests: `tests/test_catalog.py`, `tests/test_catalog_db.py`,
`tests/test_patch_matching_db.py`.

## 0. Why cache tables at all

Kyle (2026-08-22): *"The reason for all these cache tables is to answer the question of how do I
get the device from Jamf Pro to Splunk as fast as possible. That method is to wait for as little
as possible and have as much as possible be cached. Moving Jamf Patching, vulnerability and other
fields to a lookup instead of a calculation means you are not touching hundreds of MB for each
device when you are trying to parse 40k in 10 minutes."*

That is the design principle every table in this document serves: **what a device needs is
looked up, never calculated, on the device's path.** The Jamf answer for an app is computed once
per distinct (name, bundle ID, version) and looked up by hash; the title index is in process
memory and rebuilt only when the catalog changes; the per-device path touches the device's own
rows and nothing else (§3a). Vulnerability data (LoonSecIO) and any later enrichment join the
same way: by the hashes on the catalog row, as a lookup, never as a per-device computation.

## 1. What it is

Kyle's brief (2026-08-22): *"From a tenant perspective for an app lookup: I want when it was
first seen on any device, most recently seen on a device, and you have the AppName, BundleID,
and Version string so Jamf can catalog that. You can run this as a background routine to look at
the local table and keep Jamf's stuff up to date."* And why Jamf's titles bootstrap it: *"it has
the values — when you get an App you can do the local MD5 lookup on it."*

So the catalog is the **tenant's distinct apps** — one row per (name, bundle ID, version[, short
version]) the fleet has shown, keyed by the `version_hash` every installed app already carries
(`app.core.hashing`: `md5(name:bundle_id:version[:short_version])`, plus the v1 content keys of
`app.core.content_keys`) — with **`first_seen_at` / `last_seen_at`** on any device and **Jamf's
answer** on the row: which titles, is it the latest, has Jamf seen this version, when was it
released (`docs/jamf-patch-matching.md` decides the answer; this document decides where it
lives and when it is refreshed).

Devices reach their answer through `installed_apps.version_hash`. The per-device matches table
of #65 is gone; the columns of the same name on `installed_apps` are copies kept current by the
catalog, so device pages and the Applications overview need no join.

## 2. Two tables per tenant, one global

- **`app_catalog`** (RLS): `name`, `bundle_id`, `version`, `short_version`, the four keys
  (`app_hash`, `version_hash`, `key_title`, `key_full`), `first_seen_at`, `last_seen_at`, and the
  answer: `jamf_title_ids`, `patch_state` (latest | behind | ahead | unknown), `is_latest`,
  `patch_available`, `patch_available_since`, `releases_missed`, `this_version_seen`, `latest_version`,
  `latest_released_at`, `released_at` (Jamf's date for the installed version itself),
  `evaluated_at`, `evaluated_signature` (which catalog it was judged against: the title count and
  newest `synced_at`). Unique per tenant on `version_hash`.
- **`app_catalog_title_matches`** (RLS): one row per (catalog row, Jamf title) — `basis`
  (`requirements` | `ea_assumed`), `state`, `version_known`, `on_latest`, `installed_version`,
  `installed_released_at`, `latest_version`, `latest_released_at`, `first_newer_released_at`,
  `releases_missed`.
  Replaced wholesale when the row is judged; the Jamf Patch page's device counts come from here
  through the catalog row and `installed_apps.version_hash`.
- **`app_catalog_versions`** (global, like `jamf_patch_titles`): Jamf's side as a local lookup —
  one row per considered title × bundle ID (the title's column and every `Application Bundle ID
  is` value) × listed version, with `released_at`, `is_latest`, and, where Jamf names the app
  (`appName`: 1,040 of 1,549 titles), the same four keys precomputed Jamf-style (no short
  version). Titles Jamf names no app for — the versioned lines, "Wireshark 4.2" — are reached by
  `(bundle_id, version)`. Rebuilt after every catalog sync.

## 3. When rows are written and judged

1. **At device process** — `record_device_apps` runs inside `process_sync` after the app rows
   are flushed: every app the device reports is *seen now* (`first_seen_at` on creation,
   `last_seen_at` always); rows whose `evaluated_signature` is not the current catalog's are
   judged (`match_app` + `summarize` from #65 on the row's own facts); each app row gets its copy.
   A (name, bundle ID, version) the fleet has not shown before is therefore answered the moment
   it appears, not at the next schedule.
2. **After every Jamf catalog sync** — `hourly_jamf_patch_sync` and `POST /api/jamf-patch/sync`
   rebuild `app_catalog_versions` and call `refresh_tenant` (every operational tenant for the
   hourly job, the caller's tenant for the endpoint): rows judged against an older catalog are
   re-judged and their copies on `installed_apps` refreshed. A sync that changed no title leaves
   the signature alone and costs nothing. `POST /api/catalog/refresh` forces a full re-judge.
3. Rows outlive devices by design — an app nobody carries any more keeps its first/last seen —
   and `last_seen_at` only moves when a device reports the app again.

### 3a. What one device process costs (the hot path)

`record_device_apps`, per device, in order: one SELECT of the device's app rows; one SELECT of
their catalog rows by `version_hash` (indexed); an INSERT per triple the fleet has never shown;
a `last_seen_at` UPDATE only for rows older than `LAST_SEEN_GRANULARITY` (15 minutes) — so a
sweep writes it about once per distinct app, not once per device carrying it (40k devices × 80
apps would otherwise be ~3M row updates for one timestamp); an in-memory rule pass only for rows
the current catalog has not judged (new triples, or a catalog that moved since); and a copy onto
an app row only when that row is new or its catalog row was just judged. A device whose apps the
fleet has already shown, processed after the first device of the sweep, writes nothing for the
catalog. Nothing on this path reads `jamf_patch_titles` or `app_catalog_versions`; the catalog
signature check is one `count / max(synced_at)` query against the in-process index.

Judging at catalog level means no device facts: extension attributes resolve TRUE (Kyle's
practice for them — they are Jamf's scoping device, not a fact about the app) and OS-version
tests are not applicable. A per-device override that reads a carried attribute is a follow-up.

## 4. The API

- `GET /api/catalog` — the tenant's rows with the fleet on them: `deviceCount` (distinct devices
  carrying the exact version now), the Jamf titles by name, state, latest, released; `q`,
  `jamf=all|matched|unmatched`, `installedOnly` (default on), paging; plus a summary (entries,
  installed now, known to Jamf, not in Jamf's catalog) and `corpusAsOf` (#251 — see below).
- **`vuln` on every row** (#251): LoonInspect's own answer for that exact build —
  `covered` | `unknown_app` | `off`, with the summary block of
  [`docs/vulnerabilities.md`](vulnerabilities.md) §4 under `covered`. The join is the
  local hash-join this document is built for: the corpus is asked one question per row, on
  the `key_title` / `key_full` the row already carries, and it reads no table. The response
  also carries **`corpusAsOf`**, the corpus generation those blocks came from — `null` when
  no corpus is loaded, which is why every row reads `off` until #248 lands. The stamp rides
  the same response as the rows so a header can never date a column the server answered
  from a different corpus. `corpusAsOf` is deliberately **not** on the summary: the four
  tiles count every row the tenant has, and counting the three assessments across all of
  them is a scan per request rather than a lookup (§0).
- `GET /api/catalog/lookup?versionHash=…&keyFull=…&appHash=…` and `POST /api/catalog/lookup`
  `{versionHashes, keyFulls, appHashes}` — the local lookup: per key, the tenant's row if the
  fleet has shown the app (with its answer) and what Jamf knows about that exact (appName,
  bundleId, version) from `app_catalog_versions`; `appHash` answers with the newest version the
  tenant has seen. Same vocabulary as the Global API's quick lookup (`jamfTitleIds`, `isLatest`,
  `latest`, `latestReleasedAt`, `thisVersionSeen`, `releasedAt`).
- `POST /api/catalog/refresh` — re-judge every row of the tenant (Analyst and up, like the
  catalog sync).

## 5. The UI

Devices › Applications › **Catalog**: one row per distinct app version — name, bundle ID,
version, devices, first seen, last seen, Jamf title(s) (linking to the title page), state, latest,
released, **vulnerabilities** — with search, the Jamf filter, and "installed now only"; four tiles
(distinct app versions, installed now, known to Jamf, not in Jamf's catalog). en + de.

The **Vulnerabilities** column (#251) is where the corpus's edge is shown, because this tab's
grain — one row per distinct build — is exactly the grain the corpus is keyed on. It renders
three states that never look alike: *no findings* (green, dated by the corpus it was checked
against), *outside the corpus* (amber, dated), and *not assessed · no corpus loaded* (grey, with
no date at all). Sorting on it puts findings first, then the apps the corpus could not look up,
then the clean bills, then the apps nobody looked at. Above the table, the corpus banner carries
`corpusAsOf` and one sentence naming what this container does **not** know — which is the whole
point: a small corpus is only honest if its edge is legible.
See [`docs/vulnerabilities.md`](vulnerabilities.md) §4g.

## 6. Not here (follow-ups)

A second source for the catalog (community / LoonSec corpus, manual entries) and editing;
families across Jamf's versioned lines; icons and descriptions; rows for apps that arrive through
paths other than an MDM inventory (HEC); the per-device attribute override; retention for rows
nobody has carried for a long time.
