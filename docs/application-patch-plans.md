# Installed application patch plans

Devices > Applications > Installed Apps is the primary entry. Select up to 50 applications
or choose **Build a patch plan** on one row. Catalog also offers the same workflow, and
Installed Fleet catalog titles link to Installed Apps for planning.
Fleet's feature flag controls Fleet evidence only; planning works while Fleet is off.

## Device scope

The shared server predicate selects current Jamf macOS inventory before counting apps,
versions, devices or patch availability. It excludes departed computers and distinguishes
unknown timestamps, EAs and group memberships from negative matches. Up to 20 conditions
combine with **all** or **any**, inside the connection selection:

- Managed status, including unknown.
- Last contact or inventory within/older than 1–3650 days, or unknown/future dates.
- Observed smart/static group membership, keyed by connection ID and Jamf group ID.
- EA name/definition ID and exact value (including multi-value EAs), or unknown.
- Site, department/building IDs and macOS version.

`deviceScope` holds the validated JSON in the URL. Named filters are browser-local and
partitioned by organization and account. A shared URL applies the recipient's current
organization and permissions. A missing group-membership section cannot establish that
a device is outside a group. Definition lists are suggestions; IDs can be entered directly.

## Plans and evidence

`application_patch_plans` stores the report under forced PostgreSQL tenant isolation.
Creation reads one database snapshot. App identities, installed version counts, selected
scope, distinct affected Macs, source connections and inventory-date ranges are preserved
even when live inventory changes. Proposed targets are recommendations for review.

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
| GET `/ai-status` | Saved provider availability without credentials |
| GET `/` | Most recent 100 saved plans |
| POST `/` | Save a plan for `appHashes` and validated `scope` |
| GET `/{id}` | Saved report data and checksum |
| PATCH `/{id}` | Version-checked operator review notes |
| POST `/{id}/research` | Start bounded background investigation |
| GET `/{id}/pdf?revision=N` | PDF of exactly revision N, or 409 |

The installed list and catalog accept the same `deviceScope`; old callers omitting it
retain their existing behavior. Plan create/review/export/investigation actions are audited.

Measurement: `posture_snapshot: none`. Counts belong to each saved report's exact scope;
this change does not add a fleet-wide nightly posture metric.
