# Device history (#605)

The card at `/devices/{id}` reads recorded inventory states and comparisons. Its six defaults
are OS version/build, installed applications, open findings, critical findings, FileVault,
and firewall. The date and “What moved” panel sit outside the customizable values.

The “Jamf computer” label opens the source record in a new tab, using this device's
connection URL and Jamf ID. “Update this device” requires `device:sync` and reads just
that computer's latest saved inventory from Jamf. It does not send a command to the Mac.
The card, current inventory, and change log reload after the read; AI summaries follow
the normal asynchronous pipeline. An unchanged read adds no artificial history point.

Targeted reads use the enabled webhook collection's sections and EA quarantine, or the
full contract when no such scope is configured, matching the existing single-device
webhook path. The operation has a 60-second bound and its own `device_refresh` run class.
Only one manual device refresh runs per connection at a time; another request gets a
busy response and can be retried. It neither advances the last full-sweep stamp nor
marks other devices departed. The normal monotonic guard retains newer saved inventory
if Jamf supplies an older observation.

## Selection and policy

“Customize” saves up to 20 ordered values per **acting tenant and account ID**. The layout
follows that user across devices in that tenant. It is never keyed by email or copied into
another tenant. Switching account, tenant, or device remounts the card and cancels obsolete
read callbacks; the API rechecks membership and `device:read` through normal authentication.
Saved preferences are tenant-RLS protected and deleted when their account is deleted.

The picker reads the effective Change Log policy. It includes scalar fields and fields of
entries present in the selected/latest inventory, including a named application's version.
System apps honor the individual-system-app switch; muted groups and EAs are ineligible.
Last check-in is additionally available as observation context. New receipts retain the
clock known at collection; older receipts without it say “Not recorded.” Quiet sweeps do
not rewrite an earlier point's clock or create a point just because a heartbeat moved.
Adding clock retention creates one new point on the next read when an older point lacks it.
The six initial choices remain defaults; users can save up to 20. Search stays active at
the limit so a value can be found before choosing which existing slot to replace.
Extension attributes are keyed by connection and definition ID, display their current
name, and show `values[0]`. A rename changes the label without changing the saved selection.
The main extension-attribute table filters by name, ID, and first value, with optional
source and enabled columns. Customize shows name, immutable ID, and first value together
before adding the selection. “What the ledger holds” is collapsed until opened.
Application counts and finding metrics require both application-addition and removal tracking.
Counts include all installed applications, including system apps; suppressing individual system
app change events does not redefine the inventory count. OS build is included with version
only when build tracking is enabled. A previously selected disabled field stays visibly disabled
until replaced; missing entries on another device say “Not present.” EA/group IDs are scoped to
their connection, while app identity can follow devices across connections in the same tenant.

The policy controls display eligibility, not collection or historical retention. Old retained
inventory remains usable after a field is enabled. The recorded aperture determines missing
versus outside-collection states; today's collection settings do not rewrite old evidence.

## Evidence and clocks

The timeline is paginated at twelve recorded states, ordered by inventory observation time,
collection time, then stable point ID. It does not pretend every sweep is a new inventory state.
Latest means the newest recorded state, not a fresh observation of a silent device. Both clocks
are displayed: each dot is dated by its collection clock, when LoonInspect recorded the state, and
the Mac's own report time (*Observed*) is in the dot's tooltip and, beside *Collected*, in the
selected state's header (#645). The report time does not move when Jamf's record changes without
a new inventory report, so a Latest dot dated today can carry an *Observed* clock days old; that
is the silent device, not a stale page. The line runs oldest to newest, left to right; *← Older*
pages toward earlier states and *Newer →* back toward Latest (#618). Existing inventory tables
below the card are labeled latest inventory. The page's *Last recorded change* line and its Recent
changes table are dated by the collection clock the same way, each row's tooltip carrying the
report time; the Changes page's *Observed* column keeps the report time.

Old spans remain readable without new storage. Going forward, ingestion adds a small
`device_history_points` row when the span or compact assessment evidence changes; identical
sweeps add no row. Inventory bodies remain in the existing content-addressed ledger. Each point
retains the exact source outbox ID, device observation time, collection time, assessment totals,
coverage, corpus dates, and a digest of compact evidence (including capped finding identities).
The source ID is not an FK: outbox expiration must not delete history. Counts are the original
uncapped source-event counts; they do not depend on the truncated ID lists.

Finding totals count **distinct app-name/bundle/version × CVE pairs**, not distinct CVEs on the
whole device or the finding ledger's carrier lifecycle. Duplicate inventory paths for the same
build are counted once. A CVE present on two builds counts twice. Critical is the critical subset
of the same original assessment. Coverage and corpus dates are shown beside the slots. No assessed
builds means unavailable, not zero; partial coverage reports counts over covered builds and names
how many builds lack an assessment. No contemporary assessment row means “Not recorded.”

Deterministic before/after values are computed against the preceding timeline state and only
compared when both values were observed. Other logged changes remain accessible by span ID.
A first state is a baseline, never “No updates”; an unchanged selected subset makes no claim that
the whole inventory was unchanged. AI summaries are copied only for the exact source outbox ID
and displayed as advisory. Reads never invoke inference. AI disabled, pending, incomplete, failed,
dropped and unavailable outcomes have separate wording. Repeated quiet observations do not
replace an earlier point's summary with a later observation's “No updates.” “No updates” names
what the AI compares — apps and their findings, OS version and build, FileVault, SIP, Gatekeeper,
the firewall, and the extension attributes the Change Log records — and the card adds the ledger
sections the observation itself recorded changes in, read off the span chain (#644), so a change
outside that scope never reads as nothing having changed.

## Retention and upgrading

Migration `d605a1b2c3d4` adds history points and preferences with FORCE RLS. Device event shapes are unchanged; `run.completed` adds `lockClass` to distinguish targeted refreshes.
Points have the same retention horizon as their referenced inventory spans and cascade with
span/device deletion. Summary text is retained on the point after the eight-day job cache expires;
no extra raw inventory or unbounded AI evidence body is copied. This is deliberate historical
storage and grows with inventory/assessment changes. No large-fleet capacity claim is made.

The optional command below imports **still-retained** source inventory receipts and their exact
saved summary job outcomes. It does not fetch Jamf, invoke AI, or use the current vulnerability
corpus. A source must fall within the device's recorded span collection window and observation
clock range. Uncorrelated sources are skipped. Purged receipts cannot be reconstructed.

```sh
uv run --frozen --no-sync python -m app.observations.history_import
```

Run it after migration with the application's normal database role/environment. It commits in
batches of 100 and is idempotent. Summary-only receipts whose source inventory has expired remain
unavailable; nearest-date matching is not a substitute for correlation. New ingestion records
history automatically, regardless of whether AI is enabled.

Rollback: run the Alembic downgrade to `a9d4e7b2c610` before reverting the image only if deliberately
removing this feature's saved history/preferences. Reverting the application image alone can leave
the additive tables in place. Back up the database before deployment; do not reset its volumes.

posture_snapshot: none

## Tenant-selected assessment evidence (#621 preview)

With `VULN_TENANT_SELECTION=true`, new inventory history points also retain per-build
answers: content keys and reported version, release digest/as-of, evaluation clock,
uncapped counts, the supplied IDs and their truncation flag, and publication-date
aggregates. The device observation clock remains on the history point. Old points are
not rewritten or evaluated against today's corpus; the retained-event importer never
attaches current provenance to a historical receipt.

A release change appends an **assessment** point against the last recorded application
observation. It is not a new inventory observation, an AI summary or a remediation claim.
It has no source event ID. The history view labels its assessment time separately and
exposes the saved evidence. Correction and rollback append new assertions; earlier ones
remain readable. Missing coverage keeps counts absent, and a truncated list stays marked
incomplete. A device with no recorded application observation receives no invented point.

Selection, current answers and their history entries commit together. If evidence cannot
be saved, the new release is not selected. Repeating the selection, refreshing only an
evaluation clock, and unchanged sweeps do not add another receipt. Release transitions
process up to 100 devices per batch in the transaction; this is a memory bound, not a
large-fleet performance claim. Tenant isolation and existing observation/device deletion
policies apply to these same history rows. They retain their evidence independently of
later corpus cleanup; they do not pin whole corpus bytes forever.

Migration `c621f4a8e902` permits a null source ID and changes no existing row. Downgrade
refuses while assessment-only points exist, rather than deleting evidence. Keep the
schema or restore a complete pre-upgrade backup; do not remove history to force a downgrade.
The preview remains disabled by default pending safe pruning and release validation.
