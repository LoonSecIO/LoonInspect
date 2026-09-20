# Device history (#605)

The card at `/devices/{id}` reads recorded inventory states and comparisons. Its six defaults
are OS version/build, installed applications, open findings, critical findings, FileVault,
and firewall. The date and “What moved” panel sit outside the six customizable slots.

## Selection and policy

“Customize” saves up to six ordered values per **acting tenant and account ID**. The layout
follows that user across devices in that tenant. It is never keyed by email or copied into
another tenant. Switching account, tenant, or device remounts the card and cancels obsolete
read callbacks; the API rechecks membership and `device:read` through normal authentication.
Saved preferences are tenant-RLS protected and deleted when their account is deleted.

The picker reads the effective Change Log policy. It includes scalar fields and fields of
entries present in the selected/latest inventory, including a named application's version.
System apps honor the individual-system-app switch; muted groups and EAs are ineligible.
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
are displayed. Existing inventory tables below the card are labeled latest inventory.

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
replace an earlier point's summary with a later observation's “No updates.”

## Retention and upgrading

Migration `d605a1b2c3d4` adds history points and preferences with FORCE RLS. No wire event changes.
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
