# Jamf Patch matching: which title, is it the latest, has Jamf seen the version

Status: v0, built under #65 (2026-08-22). Code: `backend/app/mdm/patch/requirements.py` (the
pure evaluator), `backend/app/mdm/patch/matching.py` (the matcher and the write),
`frontend/src/features/jamfPatch/requirementsEvaluator.ts` (the same rule, for the admin's hand
check on a title page). Tests: `tests/test_patch_requirements.py`, `tests/test_patch_matching.py`,
`tests/test_patch_matching_db.py`; fixture `tests/fixtures/jamf/patch_titles_subset.json`.

## 1. What is answered, and when

At device process — `process_sync`, for every device of every connection, after the installed-app
rows are written — each installed app is tested against the Jamf Patch catalog cached in
`jamf_patch_titles` (global, credential-free, refreshed hourly) and three things are recorded:

1. **Which title(s) the app belongs to.** Decided by each title's `requirements`, never by the
   `bundle_id` column alone. In the catalog as synced on 2026-08-22 (1,543 titles) 91 bundle IDs
   are shared by 504 titles — Jamf models major versions as separate titles (Tableau Desktop ×41,
   Wireshark ×16, 1Password 4/5/6 on one bundle ID) — and 201 titles have no `bundleId` at all,
   102 of which still test `Application Bundle ID` in their requirements (Microsoft Word, Jamf
   Self Service). A join on the column over-counts the first group and misses the second.
2. **Whether the installed version is the title's latest** — `currentVersion`, not `patches[0]`
   (seven titles differ, thirty-one patch lists are not date-sorted).
3. **Whether Jamf has seen the installed version** — it appears in `patches[].version`, exact —
   and when Jamf says it was released.

The answer is stored one row per (distinct app, title) in `app_catalog_title_matches` (#67: the
tenant app catalog, `docs/app-catalog.md`) and summarised on the catalog row and on
`installed_apps` (§5). A (name, bundle ID, version) is judged the moment the fleet first shows it
and re-judged after every Jamf catalog sync (`docs/app-catalog.md` §3). Nothing else writes
these columns today; a connection's own patch provider (LoonSecIO, later) overlays them after
the catalog pass.

## 2. The requirements, and the `and` flag

A title's requirements come from Jamf as a flat list — a Smart Group criteria object. Every
criterion carries `and`, which is **always present** and says how the criterion joins to the one
*before it* in the list: `true` AND, `false` OR. The first element's flag is meaningless (GIMP's
is `false`). There are no parentheses in the patch schema, so AND binds tighter than OR:

    A(true) B(true) C(false) D(true)   →   (A AND B) OR (C AND D)

`jamf_catalog._convert_requirements` folds that into OR'd groups of AND'd `tests`, which is the
only shape the evaluator sees. The flat list is the part most tooling misreads.

## 3. The evaluator

`evaluate(groups, facts) → matched | not_matched | inconclusive`, built from small pieces so each
is a unit: `compare_versions`, `compare(operator, actual, expected)`, `evaluate_test`,
`evaluate_group`, `evaluate`.

Facts are one app on one device: title (with `.app`), bundle ID, every version string the source
carries (Jamf: the marketing version; SimpleMDM: build and marketing — "Application Version"
passes if any of them does), OS version, platform (`Mac`), and extension-attribute values by name.

Operators actually in use in the catalog, and their meaning here:

| test · operator | titles | meaning |
|---|---|---|
| Application Bundle ID · is / is not / like | 1,213 / 1 / 27 | case-insensitive equality; `like` is substring |
| Application Version · like / not like / matches regex / does not match regex / is / is not | 350 / 14 / 53 / 9 / 2 / 1 | substring; regex case-insensitive, an invalid pattern fails (and "does not match" then passes) |
| Application Title · is / has | 8 / 1 | `has` is substring |
| Operating System Version · greater than or equal / less than / like | 8 / 8 / 7 | ordered operators compare digit-run tuples: "7.0.5 (81138)" → (7, 0, 5, 81138) |
| Platform · is | 8 | |
| `<extension attribute>` · like / is not / matches regex | 235 / 64 / 4 | the attribute's value on the device |

`like` being substring is load-bearing: 1Password 4's one group reads `Bundle ID is … AND Version
like "4." AND Bundle ID is … AND Version not like "5.4."` because "5.4.3" *is* like "4.".

A test whose fact is unknown — an OS version we were not given, a test name or operator we do
not know — is **not applicable**, never a pass (extension attributes are the exception, §4).
A group with a failure is not matched; a group with no failure but something not applicable is
inconclusive; only a group whose every test passed is matched. A title matches when any group
matches, is inconclusive when none matches but one is inconclusive, otherwise does not match.

**Which titles are considered** (Kyle's rule): only a title with at least one `recon` test on
`Application Bundle ID` or `Application Title` — the tests that can identify an installed app.
That is 1,248 of 1,549. The 301 others — device-level ("Apple macOS …"), attribute-only (the
`jamf-patch-*` set: JDKs, Node, Python, daemons, and a few apps Jamf tells apart only by
attribute, such as PyCharm Professional and Firefox) and version-only titles — are the patching
agent's business and are never matched here.

## 4. The matcher

For each installed app, the candidates are every considered title whose every group pins the
bundle ID with `is` and names the app's bundle ID, plus every title that cannot be narrowed that
way (title-only, `like` on the bundle ID, a group without a bundle test). Each candidate is evaluated:

- `matched` → a match; anything else → no match. Inconclusive never counts.

**Extension attributes inside a considered title** (Kyle, 2026-08-22) are Jamf's *scoping*
device for collisions — PyCharm Community vs Professional, Firefox vs Firefox ESR — not a fact
about the app. So an attribute the device carries is read for real (by the requirement's name,
i.e. the definition's `key`, or by the definition's `displayName`, which is what Jamf Pro calls
the attribute it creates; an attribute present and empty is Jamf's "not installed"); one it does
not carry **resolves TRUE**, and the match is recorded with `basis = ea_assumed` so the
assumption stays visible. Because the attribute is about the device, a group made only of
attribute tests can never identify an app by itself and is ignored ("JetBrains PyCharm
Community" is `[attribute] OR [Bundle ID is com.jetbrains.pycharm.ce]` — the second group
decides).

Per match, the version answers: `version_known` (any of the app's version strings is in
`patches`), `on_latest` (equals `currentVersion`), and `state`:

| state | meaning |
|---|---|
| `latest` | installed version is `currentVersion` |
| `behind` | installed version is in `patches` and is not the latest |
| `ahead` | not in `patches` and newer than `currentVersion` (Safari 27.0 on the macOS 27 beta vs 26.6.2) |
| `unknown` | not in `patches` and not newer — a build Jamf never listed |

plus `installed_released_at` (Jamf's release date of the installed version), `latest_version` /
`latest_released_at`, and `first_newer_released_at` — the release date of the earliest listed
version newer than the installed one: when a patch first became available, by the catalog's clock.

One app can belong to several titles — Jamf keeps versioned titles beside rolling ones. On the
real record, Wireshark 4.2.0 matches "Wireshark 4.2" (latest 4.2.14) and "Wireshark" (4.6.8);
Camtasia 2022.6.10 is on the latest of "TechSmith Camtasia 2022" and four years behind "TechSmith
Camtasia" (2026.2.0). Both answers are kept.

## 5. Storage and the summary

The answer is stored per distinct app, not per device, since #67 — `app_catalog` and
`app_catalog_title_matches` (`docs/app-catalog.md`); a device reaches it through
`installed_apps.version_hash`. Per (catalog row, title): `title_id`, `basis`,
`state`, `version_known`, `on_latest`, `installed_version`, `installed_released_at`,
`latest_version`, `latest_released_at`, `first_newer_released_at`, `evaluated_at`; unique per
(row, title); replaced wholesale each time the row is judged; cascades with the catalog row.

On the catalog row — and copied onto every `installed_apps` row with that `version_hash` — derived from the set. **Latest is Kyle's rule: at least one matched title
says the installed version is its current one** — a Firefox ESR user on the latest ESR is
latest although the rolling "Mozilla Firefox" title says behind; Camtasia 2022 on 2022.6.10 is
latest on its line. The title that says so is the reference; otherwise the **rolling title** (the
highest `currentVersion` among the matches) is, so an app behind everywhere shows what the
vendor ships now:

| column | meaning |
|---|---|
| `jamf_title_ids` | the matched titles, fully-evaluated first, then by name |
| `patch_state` | `latest` when any title says so, else the rolling title's state |
| `is_compliant` | any matched title says latest |
| `patch_available` | no title says latest **and** one says `behind` / `unknown` |
| `patch_available_since` | earliest `first_newer_released_at` across those — Jamf's date, not "when we first noticed" |
| `this_version_seen` | Jamf lists the installed version on any matched title |
| `latest_version`, `latest_released_at` | the reference title's |
| `last_patch_check_at` | when the app was last evaluated (set even when nothing matched) |

All null when nothing matched. `ahead` is its own state: neither compliant nor patch-available.

The real Mac mini (83 apps) resolves 11 apps to 13 rows: Xcode 26.6 on latest; Camtasia 2022 on
the latest of its line (and behind the rolling title — both kept); Slack, Docker, Zoom, Postman,
Codex, Bambu Studio, Self Service, Wireshark behind with the version known to Jamf; Safari ahead.
PyCharm's only title is attribute-only and is not considered. The other 72 apps — 64 of them
under `/System` — match nothing. `tests/test_patch_matching.py` pins exactly that.

## 6. Surfaces

- Devices › Applications › Jamf Patch: "Devices with app" and "Devices on latest" per title
  (distinct devices, tenant-scoped through RLS), sortable; a title page shows devices per listed
  version and how many devices sit on a version Jamf has not listed.
- Applications overview: Compliant / Patch available per build, from the summary.
- `GET /api/devices/{id}`: each app carries `jamfTitleIds`, `patchState`, `thisVersionSeen`,
  `latestVersion`, `latestReleasedAt` beside the older compliance fields.
- The title page's "Test requirements" panel applies the same rule by hand; keep the two
  evaluators in lockstep when either changes.

## 7. Not here (follow-ups)

Re-evaluating matches when the hourly catalog sync changes a title (today the next device process
does it); change-log entries for "fell behind" / "patch available"; device-level titles ("Apple
macOS …" — is the device on the latest macOS); vulnerability columns (LoonSecIO); fleet findings.
