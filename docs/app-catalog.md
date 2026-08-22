# The app catalog: the fleet's distinct apps, first and last seen, and what Jamf says

Status: v0, built under #67 (2026-08-22). Code: `backend/app/catalog/service.py` (the tenant
rows, when they are written and judged), `backend/app/catalog/index.py` (Jamf's side as a local
lookup), `backend/app/api/catalog.py`; migration `b4c7e9d2a1f6`. UI: Devices › Applications ›
**Catalog**. Tests: `tests/test_catalog.py`, `tests/test_catalog_db.py`,
`tests/test_patch_matching_db.py`.

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
  `patch_available`, `patch_available_since`, `this_version_seen`, `latest_version`,
  `latest_released_at`, `released_at` (Jamf's date for the installed version itself),
  `evaluated_at`, `evaluated_signature` (which catalog it was judged against: the title count and
  newest `synced_at`). Unique per tenant on `version_hash`.
- **`app_catalog_title_matches`** (RLS): one row per (catalog row, Jamf title) — `basis`
  (`requirements` | `ea_assumed`), `state`, `version_known`, `on_latest`, `installed_version`,
  `installed_released_at`, `latest_version`, `latest_released_at`, `first_newer_released_at`.
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

Judging at catalog level means no device facts: extension attributes resolve TRUE (Kyle's
practice for them — they are Jamf's scoping device, not a fact about the app) and OS-version
tests are not applicable. A per-device override that reads a carried attribute is a follow-up.

## 4. The API

- `GET /api/catalog` — the tenant's rows with the fleet on them: `deviceCount` (distinct devices
  carrying the exact version now), the Jamf titles by name, state, latest, released; `q`,
  `jamf=all|matched|unmatched`, `installedOnly` (default on), paging; plus a summary (entries,
  installed now, known to Jamf, not in Jamf's catalog).
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
released — with search, the Jamf filter, and "installed now only"; four tiles (distinct app
versions, installed now, known to Jamf, not in Jamf's catalog). en + de.

## 6. Not here (follow-ups)

A second source for the catalog (community / LoonSec corpus, manual entries) and editing;
families across Jamf's versioned lines; icons and descriptions; rows for apps that arrive through
paths other than an MDM inventory (HEC); the per-device attribute override; retention for rows
nobody has carried for a long time.
