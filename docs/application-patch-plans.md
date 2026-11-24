# Installed application patch plans

**Patch Plans** is a top-level navigation entry at `/patch-plans`. Open a saved report
directly, or start in Devices > Applications > Installed Apps: select up to 50 applications
and choose **Plan for selected apps**, or **Plan application** on one row. The device
scope and application search, severity bands and KEV filter travel with that selection.
Catalog also offers a contextual planning action; neither inventory page loads the full
planning workspace. Installed Fleet catalog titles link to Installed Apps for planning.

Saved plans use `/patch-plans?plan=<id>`. Existing `?plan=` links from Installed Apps
and Catalog redirect to the same report. Refresh and Back/Forward preserve the selected
plan. **View current installed apps in this scope** returns to live inventory using the
report's saved device and application scope; it does not change the saved evidence.

Unsaved operator notes are scoped to organization, account and plan in this browser tab.
They survive navigation and are restored when the plan is reopened. **Sign out** discards
them without asking, so the next person to sign in on this tab cannot read them; save the
notes first. An expired session keeps them for the same account. A draft from an older
revision is marked as a conflict and cannot overwrite newer saved notes; copy the notes
you need, then discard the draft. Browser storage failures retain an in-memory draft and
show a warning to save before closing the tab; closing/reloading asks before losing notes.
Fleet's feature flag controls Fleet evidence only; planning works while Fleet is off.

## Device scope

The shared server predicate selects current Jamf macOS inventory before counting apps,
versions, devices or patch availability. It excludes departed computers and distinguishes
unknown timestamps, EAs and group memberships from negative matches. Up to 20 conditions
combine with **AND** or **OR**, inside the connection selection. Brackets can nest
up to four group levels (including the root), with at most ten groups total. Each
indented bracket has a vertical line and its own AND/OR selector:

- Managed and Supervised independently, each Yes/No or unknown.
- Last contact or inventory within/older than 1–3650 days, before/after a calendar date, or unknown/future dates.
- Observed smart/static group membership, keyed by connection ID and Jamf group ID.
- EA name/definition ID with is, is not, like, not like, matches regex, does not match regex, or unknown.
- Site, department/building IDs and macOS version.

**Advanced search** includes managed and unmanaged Macs unless a Managed rule narrows it.
**Smart group style** (`mode: "smart_group"`) implicitly requires Managed = Yes outside
all AND/OR brackets; Managed conditions are unavailable in this mode. Switching modes
keeps existing rules for review and blocks Apply until Managed conditions are removed.
Supervised is independent in both modes. Old JSON defaults to `advanced_search`.
This is a local inventory scope, not creation or export of a Jamf group.

Before/After uses `YYYY-MM-DD` and UTC calendar boundaries, excluding the selected day:
before 2024-02-29 means earlier than midnight starting that day; after means midnight
starting 2024-03-01 or later. Missing and future timestamps are unknown and excluded
from these comparisons. Day windows remain relative to the query time.

EA comparison labels follow [Jamf's criteria operators](https://learn.jamf.com/r/en-US/jamf-pro-documentation-11.16.0/Criteria_Operators).
`like` / `not_like` use a case-insensitive literal substring (% and _ are ordinary characters).
`matches_regex` / `does_not_match_regex` use case-insensitive PostgreSQL regular-expression
search; add ^ and $ for whole-value matching. Advanced regex syntax can differ from
Jamf's engine. Existing `is` / `is_not` retain exact, case-sensitive matching.
A positive comparison matches any EA value; a negative comparison requires an observed,
nonempty values list with no matching element. Missing/empty EAs match only unknown.
Invalid regex is rejected before querying inventory, even when there are no devices.
Regex-scoped database statements have a five-second limit (or a stricter configured
limit); a timeout returns an explicit error, never a partial plan or empty-success result.

`deviceScope` holds the validated JSON in the URL. Named filters are browser-local and
partitioned by organization and account. Saved filters and imported JSON load into the
draft; **Apply device filter** commits the draft to the URL. Empty inner groups and
invalid conditions block applying. **Save or inspect scope JSON** exposes the exact
recursive JSON for copying or importing. A shared URL applies the recipient's current
organization and permissions. A missing group-membership section cannot establish that
a device is outside a group. Definition lists are suggestions; IDs can be entered directly.

## Application risk scope

Application scope combines name/bundle search with any selected severity (low, medium,
high, critical), then ANDs **Has KEV** if checked. Risk filters run before pagination,
inside the applied device scope. They require an available vulnerability corpus; an
unavailable source produces an explicit error rather than a misleading empty list.

**Known findings** sums the stored uncapped vulnerability counts once per device/build.
Duplicate installation paths do not multiply a build's findings. This is exposure count,
not unique CVEs across builds: a CVE can affect multiple installed builds. **Avg / assessed
device** divides that total by distinct devices with at least one assessed build. Unknown,
stale and malformed assessments do not contribute zeroes; partial coverage shows the
assessed-device denominator. A covered zero is distinct from unknown. Severity and KEV
counts use that same population. The page records the corpus date and release identifier.

The list API accepts repeated `severity=high&severity=critical`, `hasKev=true`, and the
existing `q`, `deviceScope`, `page` and `pageSize`. Old flat device JSON remains valid.
A nested example is `{ "match": "all", "rules": [{ "field": "managed", "value": "true" },
{ "match": "any", "rules": [{ "field": "contact", "operator": "within", "value": "14" },
{ "field": "ea", "key": "Update Ring", "value": "Pilot" }] }] }`.

## AI group proposals

**Propose a group with AI** sends the operator's request, draft scope and bounded observed
connection/group/EA names and IDs through the existing saved-provider, consent, disclosure
and usage-accounting gates. It adds no inventory device names, serial numbers or stored credentials.
Each metadata category is limited to 100 entries and 3,500 serialized characters;
matching names are preferred and truncation is disclosed. Group and EA references must
be present in this supplied context. The selected connection and search mode cannot be changed by the model. Observed EA references are
limited to that connection, so an ID from another Jamf instance cannot be borrowed.

The model returns validated recursive JSON. Unsupported criteria, invented references,
malformed output and partial answers cannot produce an applied filter. A proposal shows
a database-derived matched-device count. **Load proposal into builder** loads a draft;
**Apply device filter** is still a separate operator action. Scope edits discard an
outstanding proposal so a reply cannot overwrite a newer draft. Proposals take up to two
minutes; leaving the builder discards the result. They do not create a Jamf smart group
or save a patch plan. Named drafts remain browser-local.

## Plans and evidence

`application_patch_plans` stores the report under forced PostgreSQL tenant isolation.
Creation reads one database snapshot. App identities, installed version counts, selected
scope, distinct affected Macs, source connections and inventory-date ranges are preserved
even when live inventory changes. The saved `applicationScope`, vulnerability counts,
coverage, corpus date/release and nested device brackets appear in the plan and PDF.
If a selected app no longer matches the application filters, creation refuses the stale
selection and asks for a refresh; it does not silently omit the app. Proposed targets are recommendations for review.

Jamf matches use the installed builds' recorded match IDs; conditional EA matches,
multiple titles and matches missing from some builds require identity review. Public
Jamf title presence does not establish a configured package or deployment policy.
Fleet bundle matches retain manifest blob revisions and read dates. A disabled or
incomplete Fleet cache is not evidence that a product lacks coverage.

Each application has a proposed Jamf rollout covering identity, target verification,
package/policy association, pilot, recovery, phased rollout and fresh-inventory checks.
Operators can record ownership, maintenance window, pilot criteria, recovery, exceptions
and approval references. These notes increment the revision and retain the recorder and
timestamp; optimistic revision checks prevent overwriting another review.

## Background investigation and AI

Investigation reads a pinned Installomator Git commit and a bounded label definition
derived from the application name. It records the URL, commit, exact-source SHA-256,
check time and static signing-team value if present. Scripts are never executed.
A matching label name is a **candidate**, requiring bundle/signing/architecture review.
A 404 at the derived label does not rule out an alias or other Installomator support.

Optional AI uses the saved provider, endpoint validation, inference-consent gate,
disclosure log, loaded-model resolver and usage accounting already used by LoonInspect.
It receives app identities, versions, catalog options, counts and rollout steps, and selects priorities
from the report's seven documented steps. Unrecognized apps, duplicate/out-of-range
steps and malformed output are refused; generated text cannot invent verified coverage.
Requested/reported models, prompt hash and completion time accompany the result.

At most two investigations per organization run concurrently. They have a five-minute
deadline and survive page navigation. They are process-bound: after restart, a job still
marked running is reported interrupted after six minutes and can be retried. This is a
bounded application investigation, not the full loonSupport service or a deployment agent.

## Auditor PDF and API

**Export plan as PDF** renders the saved revision shown on the page. Unsaved review notes
and running investigation disable the button. The server refuses a stale requested
revision with 409. The report identifies its organization, preparer, scope, application
coverage, evidence dates, source URLs/revisions, review notes, gaps, AI provenance, and
SHA-256 of the canonical report data. It states that a plan is not completion evidence.
The checksum is an identifier, not a signature. PDFs use no-store responses.

All routes are under `/api/application-patch-plans` and require `app:read` and `device:read`.
Creation, review updates and investigation additionally require `patch:plan-write`, granted
to Admin and Analyst. Viewer and Auditor may read and export saved plans.

| Method / path | Result |
| --- | --- |
| GET `/scope-options?deviceScope=…` | Observed filter choices and scoped device count |
| POST `/propose-scope` | Propose validated scope JSON from `question`, current `scope`, and optional saved `provider` |
| GET `/ai-status` | Saved provider availability without credentials |
| GET `/` | Most recent 100 saved plans |
| POST `/` | Save a plan for `appHashes` and validated `scope` / `applicationScope` |
| GET `/{id}` | Saved report data and checksum |
| PATCH `/{id}` | Version-checked operator review notes |
| POST `/{id}/research` | Start bounded background investigation |
| GET `/{id}/pdf?revision=N` | PDF of exactly revision N, or 409 |

The installed list and catalog accept the same `deviceScope`; old callers omitting it
retain their existing behavior. Plan create/review/export/investigation actions are audited.

Measurement: `posture_snapshot: none`. Counts belong to each saved report's exact scope;
this change does not add a fleet-wide nightly posture metric.
