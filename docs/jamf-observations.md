# Jamf observations: the ledger beneath the connector

**Status: settled at v0.** This document freezes the parts of Jamf ingestion that are
hard to change once customers have history in them: what an observation *is*, how it is
identified, how it is hashed, and how it is stored. Everything derived from it — change
events, summaries, SIEM shapes, flap detection, lineage across re-enrollment — is
deliberately out of scope and stays soft.

Code: `backend/app/mdm/jamf/contract.py` (normalization, pure), `backend/app/observations/ledger.py`
(storage), migration `4a8c1f2e7b93`. Vectors: `backend/tests/test_jamf_observation_contract.py`.
Issue: #58.

---

## 1. Why this is a stone

LoonInspect's value is diffing stored observations of a device over time. That makes the
normalized shape of an observation the one thing in the codebase that cannot be
refactored casually: a later reshape does not merely break consumers, it manufactures
phantom diffs at the migration boundary — every device "changes" the day the shape
does — and corrupts the change stream that is the product.

So the shape is a **versioned contract** (`v0`), the version is stamped on every record,
and the contract changes only behind a new version string, never in place. The literal
SHA-256 digests in the tests are the contract's signature; a change that breaks a vector
is wrong by definition.

Four things are the stone. Everything else in this document explains them.

| Stone | Where |
| --- | --- |
| Head schema — one row per span of identical observations | `observation_spans` |
| Normalization contract — per-section allowlists; the digest defines what a change is | `contract.py` |
| Group-side capture — smart-group definitions with criteria as their own subject | `canonicalize_smart_group` |
| SHA-256 content addressing — head → sections → entries, entries deduplicated fleet-wide | `observation_sections`, `observation_entries` |

---

## 2. The model

```
head        digest over { subject, aperture, {section: digest} }      one per span
  section   digest over a canonical document (general, hardware, …)   or
            digest over the sorted list of entry digests (applications, …)
    entry   digest over one canonical item (an app, a cert, a group membership)
```

### 2.1 The recipe

Every digest is

```
"v0:" + sha256( "loon.jamf.observation" ␟ "v0" ␟ <kind> ␟ <canonical JSON> )
```

where `␟` is U+001F, `<kind>` is `section:<name>`, `entry:<kind>`, `head`, or
`aperture`, and canonical JSON is `json.dumps(value, sort_keys=True,
separators=(",", ":"), ensure_ascii=False)`. The domain string and the kind are inside
the hash, so an entry digest can never equal a section digest for the same bytes and
neither can collide with `app.core.content_keys`, which hashes under its own domain.

Worked vectors, computed from the recipe alone and asserted against the implementation:

| Kind | Canonical body | Digest |
| --- | --- | --- |
| `entry:application` | `{"bundleId":"com.tinyspeck.slackmacgap","macAppStore":true,"name":"Slack.app","path":"/Applications/Slack.app","version":"4.39.95"}` | `v0:3a9edfeecdef9d7bc6c5f66afcd5b477c324b617a11b4096946e2a85afdb26d5` |
| `entry:extension_attribute` | `{"definitionId":"27","values":["Engineering","Research"]}` | `v0:d2ce67a4398db7f555dbe4d96e48eda412fc1aa9d51c74e1ded5cee9afbd4328` |
| `entry:group_membership` | `{"groupId":"17","smartGroup":true}` | `v0:96594ee6aa8bc4da4a3f1b61d7af4c14eef03fcb287fab4a5b0e760ce279da6d` |
| `section:software_updates` | `["v0:8fca1f74a190fdd9918981bad7b4e5b27ad11e2880aef6e3c758ed73d74f3cda"]` | `v0:44de6270b38e6fe820cd6da26c0ffaa23e2a93068864809ff54b3e7e38154642` |

### 2.2 Three rules decide what reaches a digest

1. **Allowlist, not denylist.** Each section names the fields that are hashed (§5). A
   field Jamf adds in a later release is ignored until a contract version chooses to
   include it, so a Jamf upgrade can never change every device's digest overnight.
   Telemetry — contact times, IPs, battery, disk free, sizes, "update available",
   certificate status — is simply not listed.
2. **Names of Jamf objects are labels, not content.** A smart group, an extension
   attribute, a configuration profile, a site, or a PreStage can be renamed by an admin
   without anything changing on any device. Their ids are hashed; their names ride
   alongside as labels (`observation_entries.label`, or the group's own definition
   observation). The exception is content that *is* a name — an application's name, a
   certificate's common name, a local account's username.
3. **Absence is absence.** `null`, `""`, `[]`, `{}` and a missing key are one thing and
   are dropped. Strings are NFC-normalized and stripped. Timestamps that survive the
   allowlist are reduced to UTC whole seconds (`YYYY-MM-DDTHH:MM:SSZ`); date-only
   strings pass through. Lists that carry no order — EA values, FileVault users, the
   entries of a section — are sorted. Identical entries collapse to one. `false` and `0`
   are values, not absence.

---

## 3. Identity

**The subject is (connection, kind, id).** For computers, the id is Jamf's computer id —
the same value as `devices.external_id` on the same connection, which is how the UI
joins to the ledger. For smart groups, the group id.

The head also carries `udid`, `serial_number`, and `management_id`. None of them is the
subject key in v0; all of them are recorded so that **lineage** — the same Mac
re-enrolled under a new Jamf id, seen by two collectors, or repaired — can be derived
later without a reshape. What would be irrecoverable is not recording them; the chaining
rule is soft as long as the raw keys are kept.

**Lineage is three keys, taken together: the Jamf Pro instance it came from, the UDID,
and the serial number.** Neither hardware key alone is enough, and they fail in
different directions:

- The **serial** is the device's warranty identity. When Apple replaces a logic board
  rather than the whole Mac, the original serial is flashed onto the new board, so the
  serial survives a repair.
- The **UDID** is derived from the logic board and immutable for that board, so it
  *changes* with a board replacement. That is the one common case today where the two
  keys disagree, and it is rare and becoming rarer.

So within one collector: **same serial, new UDID = the same device with a new board** —
a lineage event (`board replaced`), not a new device. Same UDID with a different serial
should not happen and is an anomaly worth surfacing rather than silently merging. Across
collectors (a Jamf-to-Jamf migration, or Jamf beside another MDM), the pair (UDID,
serial) is what says two subjects are one Mac; the collector key is what keeps their
observations apart, since each collector's aperture differs (§6).

`observation_spans` is indexed on `(tenant_id, serial_number)` and `(tenant_id, udid)`
for exactly these walks. The lineage layer itself — which spans belong to one physical
device, and which boundary events that implies — is derived and lives above the ledger.

**Two triples, two jobs.** Lineage answers "is this the same Mac over its life". The
everyday *correlation* key — what the author dedups on in Splunk, and what the SIEM
`device_meta` block should carry verbatim because it is both sufficient and readable —
is **(serial number, Jamf Pro URL, Jamf device id)**: one record, in one instance, with
a human-legible handle. Every head has it: `serial_number`, the connection's URL, and
`subject_id`. The UDID rides alongside for the lineage walk; it is not needed to dedup.

One legacy artifact the correlation key exposes and lineage must not misread: a device
can *join* a Jamf Pro more than once, leaving several computer records for one physical
Mac in one instance. Those are distinct subjects in the ledger (different Jamf ids), and
the lineage layer classifies **same serial, same UDID, different Jamf ids within one
collector** as a duplicate-record artifact — not a board replacement (the UDID did not
change) and not a new device.

---

## 4. Time and spans

Two clocks, never conflated:

| Column | Meaning | Source |
| --- | --- | --- |
| `observed_at` | the device's own inventory time | Jamf `general.reportDate`; our clock for subjects without one (groups) |
| `collected_at` | when we read it | our clock |

A span is a run of consecutive observations with the same head digest. Recording an
observation has exactly five outcomes:

| Outcome | Condition | Effect |
| --- | --- | --- |
| `new` | no current span for the subject | span opened, all content written |
| `changed` | head digest differs | old span closed, new one opened with `previous_id`; only sections whose digest changed have content written |
| `unchanged` | same head, newer `observed_at` | `observation_count`, `last_observed_at`, `last_collected_at` advance |
| `repeat` | same head, same `observed_at` | nothing written — Jamf served the same submission twice (a sweep after a webhook) |
| `stale` | `observed_at` older than the current span's | ignored entirely |

`stale` is the monotonic write guard from `docs/ingest-scheduling.md` §4.4: a sweep
that read a device at 01:10 cannot overwrite the webhook that wrote it at 01:30 when the
sweep reaches that row at 01:40. It gates the current-state tables too — `ingest_computer`
consults the ledger first and skips `process_sync` on stale input.

Storage is therefore proportional to **change rate, not sweep count**: an unchanged
device costs one `UPDATE` per sweep (or nothing, on `repeat`), and "sustained for k
observations" — the debouncer that should gate anything destructive — is
`observation_count`, a column.

---

## 5. The v0 sections

The default device sweep requests exactly these fourteen. A *collection* (#27 — Settings →
Connections → Collections) may narrow the set per pull; the narrowing is recorded in the
aperture (§6), so it reads as a scope change, not as every omitted section disappearing.

### Scalar sections (one canonical document each)

| Section | Hashed | Deliberately not hashed |
| --- | --- | --- |
| `general` | name, platform, barcode1/2, assetTag, remoteManagement.managed, supervised, mdmCapable.capable, lastEnrolledDate, mdmProfileExpiration, initialEntryDate, distributionPoint, enrollmentMethod.{id, objectType}, site.id, itunesStoreAccountActive, enrolledViaAutomatedDeviceEnrollment, userApprovedMdm, declarativeDeviceManagementEnabled, managementId, jamfBinaryVersion | reportDate, lastContactTime / lastContact / lastCheckIn, all IPs, lastCloudBackupDate, lastLoggedInUsername* and timestamps, mdmCapable.capableUsers / userManagementInfo, site.name and enrollmentMethod.objectName (labels), nested extensionAttributes (merged, §7) |
| `hardware` | make, model, modelIdentifier, serialNumber, processor*, busSpeedMhz, cacheSizeKilobytes, networkAdapterType, macAddress, altNetworkAdapterType, altMacAddress, totalRamMegabytes, openRamSlots, smcVersion, opticalDrive, bootRom, bleCapable, supportsIosAppInstalls, appleSilicon, provisioningUdid | batteryCapacityPercent, batteryHealth, nicSpeed |
| `operating_system` | name, version, build, supplementalBuildVersion, rapidSecurityResponse, activeDirectoryStatus, fileVault2Status, softwareUpdateDeviceId | — |
| `user_and_location` | username, realname, email, position, phone, departmentId, buildingId, room | — |
| `purchasing` | purchased, leased, poNumber, vendor, appleCareId, purchasePrice, purchasingAccount, purchasingContact, poDate, warrantyDate, leaseDate, lifeExpectancy | — |
| `security` | sipStatus, gatekeeperStatus, xprotectVersion, autoLoginDisabled, remoteDesktopEnabled, activationLockEnabled, recoveryLockEnabled, firewallEnabled, secureBootLevel, externalBootLevel, bootstrapTokenAllowed, bootstrapTokenEscrowedStatus, attestationStatus | lastAttestationAttempt, lastSuccessfulAttestation |
| `disk_encryption` | bootPartitionEncryptionDetails.{partitionName, partitionFileVault2State}, individualRecoveryKeyValidityStatus, institutionalRecoveryKeyPresent, diskEncryptionConfigurationName, fileVault2Enabled, fileVault2EnabledUserNames (sorted), fileVault2EligibilityMessage | partitionFileVault2Percent |

### List sections (one entry per item; the section digest covers the sorted entry digests)

| Section | Entry kind | Hashed | Label | Not hashed |
| --- | --- | --- | --- | --- |
| `applications` | `application` | name, path, version, cfBundleShortVersionString, cfBundleVersion, bundleId, macAppStore | — | sizeMegabytes, updateAvailable, externalVersionId |
| `extension_attributes` | `extension_attribute` | definitionId, values (sorted) | name | description, dataType, inputType, options, enabled, multiValue |
| `group_memberships` | `group_membership` | groupId, smartGroup | groupName | groupDescription |
| `configuration_profiles` | `configuration_profile` | id, profileIdentifier, uuid, removable, username | displayName | lastInstalled |
| `local_user_accounts` | `local_user_account` | uid, userGuid, username, fullName, admin, homeDirectory, fileVault2Enabled, userAccountType, password* policy, *AzureActiveDirectoryId | — | homeDirectorySizeMb |
| `certificates` | `certificate` | commonName, identity, expirationDate, username, subjectName, serialNumber, sha1Fingerprint, issuedDate | — | lifecycleStatus, certificateStatus (Jamf derives both from the dates and the clock) |
| `software_updates` | `software_update` | name, version, packageName | — | — |

Two things the real record (§11) decided: `cfBundleVersion` / `cfBundleShortVersionString`
are hashed because Jamf Pro 11.31 reports them and a build bump under the same marketing
version is a real change — older servers omit them, and absence is absence, so nothing
shifts until the server upgrades, which is itself an aperture change. And Jamf's own
profiles arrive with `id` and `uuid` null, so the `profileIdentifier` is what identifies
them; that is why it is hashed alongside.

### Not in v0

`storage`, `printers`, `services`, `attachments`, `plugins`, `package_receipts`, `fonts`,
`licensed_software`, `ibeacons`, `content_caching`. Each is either pure telemetry
(`storage` free space, `content_caching`), high volume with low security value
(`services` — 429 rows on one Mac mini, `fonts`), or Jamf-derived rather than observed.
Requesting one is a `ValueError` under v0; adding one is a new contract version.

---

## 6. The aperture

An app list is a function of (device, collector, collector configuration). SimpleMDM
reports roughly a fifth more applications than Jamf for the same Mac because Jamf
inventories over configured paths rather than reading the MDM application list. So
every head carries an **aperture digest** over everything about *how* the observation
was taken that could change what it contains without the device changing:

```json
{
  "contract": "v0",
  "collector": {"provider": "jamf", "host": "acme.jamfcloud.com", "version": "11.31.1-t…"},
  "sections": ["applications", "certificates", "…"],
  "inventoryCollection": {
    "available": true,
    "preferences": {"includeAccounts": true, "includeFonts": false, "…": "…"},
    "applicationPaths": ["/Applications"], "fontPaths": [], "pluginPaths": []
  },
  "quarantinedExtensionAttributes": ["9"]
}
```

`inventoryCollection` is Jamf's own `/v1/computer-inventory-collection-settings`. When
the API client lacks the privilege to read it, that is recorded as `{"available": false}`
rather than by omission, so it can never be confused with settings that were read and
happened to be empty.

An aperture change opens a new span for every subject with **no changed sections** —
one explicit event, rather than fleet-wide phantom churn in whichever sections the
change touched. It is sampled once per run (two reads), never per device; the webhook
path inherits the latest aperture recorded on its connection.

---

## 7. Extension attributes

Jamf reports EAs in four places — a top-level array and one nested under each section
an admin chose as the EA's "inventory display". The contract merges all of them into one
section keyed by `definitionId`, reading nested arrays only from *requested* sections,
so moving an EA between display sections changes nothing and a detail record (every
section) hashes identically to a sweep page (the requested ones).

An EA defined on the server but unanswered by the device is still an entry —
`{"definitionId": "2"}` — so a first value later is a change, not an appearance.

**Quarantine.** EAs that report uptime, battery, or free disk change on every recon and
would open a new span per device per sweep. `canonicalize_computer(…,
quarantined_extension_attributes=ids)` drops them from the section, and the quarantine
list is part of the aperture so the omission is explicit. The mechanism ships in v0; the
knob to set it arrives with ingest profiles (#27), since a quarantine is a property of
how a connection is read.

---

## 8. Smart groups

Group *membership* is device-side: an entry per group in `group_memberships`, hashed on
`{groupId, smartGroup}` with the name as a label — so a rename is not a membership change
on every member. Group *definitions* are their own subject (`computer_group`), observed
once per run from `/v2/computer-groups/smart-groups/{id}`, with a single `definition`
section over `{name, siteId, criteria}` — criteria ordered by priority, conjunction
lower-cased, parentheses preserved. A rename or a criteria edit is one explicit span on
that subject.

That is the two-cause disambiguation: when a device's membership changes between
observations t₁ and t₂, a derived layer checks whether the group's definition span changed
in (t₁, t₂] — *criteria moved* — or not — *device drifted*. Jamf keeps only the current
definition; the ledger keeps both histories.

---

## 9. Storage

| Table | Row | Mutability |
| --- | --- | --- |
| `observation_spans` | one span per subject per head digest | `last_*`, `observation_count`, `label`, `is_current` |
| `observation_sections` | one per (tenant, section digest): scalar body, or the sorted entry-digest array | immutable |
| `observation_entries` | one per (tenant, entry digest): canonical body | `label` only |
| `observation_apertures` | one per (tenant, aperture digest) | `last_seen_at` only |

All four are tenant-scoped under RLS like the rest of the schema. Content rows are never
deleted in v0; a compaction job later must keep anything a span still names.

Indexes worth knowing: a partial unique index makes "at most one current span per
subject" a database fact (the insert is the claim); `observation_spans.section_digests`
is GIN-indexed (`jsonb_path_ops`) and `observation_sections.entry_digests` is GIN-indexed,
so **Discover** — "which devices carry entry X right now" — is two index hops:

```sql
select s.subject_id, s.label
from observation_sections c
join observation_spans s
  on s.section_digests @> jsonb_build_object('applications', c.digest)
where c.entry_digests ? 'v0:06f5843400adb08c…'   -- Slack 4.50.143 (450000143)
  and s.is_current;
```

Cost model for the first customer's shape (40k macOS): an unchanged device is one
`SELECT` and at most one `UPDATE` per sweep; a changed device additionally writes one
section row and only the entries that are new to the tenant. Entries — the bulk of the
bytes — are shared across the fleet.

---

## 10. Versioning rules

- Nothing that alters a digest changes under `v0`: not an allowlist, not the canonical
  form, not the recipe. Bug fixes that would change digests are a new version too.
- A new version (`v1`) is a new `CONTRACT_VERSION`, a new aperture (the version is in
  it), and therefore a new span for every subject on the first `v1` run — one explicit
  boundary, and `v0` rows are never rewritten. Both versions coexist in the tables;
  consumers compare digests within a version only.
- Labels, `observation_count`, `last_*` columns, and anything in §12 may change freely.

---

## 11. Ingest paths

Sweep, manual run, and webhook all go through `ingest_computer` — the ledger first (the
guard), then `process_sync` for `devices` / `installed_apps` and the outbox event,
committing together per device.

The webhook path **fetches**. Jamf's computer webhooks (`ComputerAdded`,
`ComputerCheckIn`, `ComputerInventoryCompleted`) carry an identity — `jssID`, `udid`,
serial, a few general fields — and no inventory; normalizing the payload directly diffed
an empty application list against the stored one and reported every app removed on every
webhook. `ingest_webhook` reads `jssID` and fetches `/v1/computers-inventory-detail/{id}`,
which is exactly #27's inversion: the event path, being one device already known to have
changed, fetches *more* than the sweep.

Jamf privileges the API client needs: Read Computers (inventory), Read Smart Computer
Groups (definitions; absent → groups are not observed, logged), Read Computer Inventory
Collection (aperture; absent → `available: false`), and the Jamf Pro version endpoint
(absent → recorded as missing).

Verified against a real record: `tests/fixtures/jamf/computer_inventory_detail_real.json`
is a Jamf Pro 11.31.1 inventory of an M4 Mac mini on a macOS 27 beta, scrubbed of
identity. It is where `cfBundleVersion` and `lastContact` / `lastCheckIn` surfaced.

---

## 12. Decisions deferred, and one to raise

- **Identity / lineage** (§3): decided — the triple (collector, UDID, serial), with the
  board-replacement rule. Recorded and indexed in v0; chaining is a derived layer.
- **Certificates** are in v0 with status fields excluded; a derived "expiring" signal
  comes from `expirationDate` and the clock at query time, not from the ledger.
- **Quarantine knob** → #27. **Run id on the head** → #31 (`last_trigger` carries the
  vocabulary now). **Retention / compaction** → later; nothing is deleted in v0.
- **Label staleness**: an entry's label refreshes when a section that contains it is
  next written. A rename alone does not write anything — by design — so labels lag
  until the next real change. Group names have their own subject and do not lag.
- **Raised for the author — the `version` vocabulary.** `NormalizedApp.version` and
  `content_keys.app_full_key` treat `version` as the build (the frozen v1 vector hashes
  Chrome as `version="6478.127", short_version="126.0.6478.127"`), while the Jamf
  normalizer has always put Jamf's `version` — the *marketing* version — in that slot
  with `short_version=None`. Jamf 11.31 now reports `cfBundleVersion` too, so the
  mapping *could* become version=`cfBundleVersion`, short_version=`cfBundleShortVersionString`.
  That would be correct and would also change every Jamf-sourced `version_hash` and
  `key_full` on upgrade (one round of phantom inventory deltas, and a prevalence split
  in the community keys). This document does not change it; the observation contract
  is unaffected either way because it hashes all three fields as they arrive.

---

## 13. Related

`docs/ingest-scheduling.md` (§4.4 guard, §6 catalog freshness), `docs/splunk-event-shaping.md`
(the per-device observation id it asks for is `observation_spans.id`), #27 (sections and
quarantine per ingest profile), #31 (run id, trigger vocabulary), #58 (this work).
