# The change log: which changes an admin hears about

**Status: v0 (2026-08-22, #61).** The observation ledger (`docs/jamf-observations.md`)
records every contract field on every observation. This document fixes the layer above
it: which *changes* between two observations become change-log rows and `device.change`
events, at what level, and how an admin overrides or selects. Code:
`backend/app/changes/policy.py` (defaults as data), `backend/app/changes/diff.py` (the
engine), `backend/app/changes/derive.py` (derivation at the write), API under
`/api/changes`, UI at Devices → Changes and Settings → Change tracking.

The policy is **derived and soft** in the sense the ledger doc uses: nothing here
changes what is stored. A field an admin turns on later can be replayed from the spans.
That is what makes opinionated defaults safe.

---

## 1. Reasoning from the record

The defaults were reasoned from a real Jamf Pro 11.31.1 inventory of an M4 Mac mini
(`backend/tests/fixtures/jamf/computer_inventory_detail_real.json`), section by section.
The shape of the record decided four things:

1. **Apple system apps collapse into the OS update.** 64 of the record's 83 applications
   live under `/System/Applications` and bump versions with every macOS update. Logged
   individually, one update is sixty events per device. By default their version bumps
   are counted onto the OS version change (`details.systemAppsUpdated`); an admin who
   wants them individually flips one switch.
2. **Security posture is low-volume and high-signal.** `security.*`,
   `diskEncryption.*`, OS version/build, directory binding, FileVault, and management
   state (managed, supervised, UAMDM, DDM, ADE, enrollment method, management id) change
   rarely and always matter. They are `high`.
3. **Asset and procurement metadata is admin-driven, not device state.** Purchasing,
   asset tag, barcodes, distribution point, position/phone/room. They are `low` — off
   by default, one click away.
4. **Some real fields change fleet-wide for reasons unrelated to the device.** XProtect
   version (weekly, from Apple), Jamf binary version (every Jamf release), boot ROM (every
   OS update), the alternate MAC (docks), pending software updates (appear when Apple
   releases). `low`; most are better served by a fleet-level finding than by per-device
   events.

Entries (the list sections) follow the same logic with identities: an application is
(name, bundleId, path) so a version bump is one `updated`, not a removal and an
addition; a local account is (uid, username) so an admin flag flip is an `updated`
naming the field; a group membership is the group id (its name is a label); a profile is
its identifier; a certificate is its fingerprint; an extension attribute is its
definition id.

---

## 2. The level decides the default

| Level | Meaning | Default |
| --- | --- | --- |
| `high` | Security posture, privileged accounts, management state, hardware identity, smart-group criteria | on |
| `normal` | Inventory: applications, profiles, groups, EAs, user assignment, OS details | on |
| `low` | Cosmetic, asset metadata, fleet-wide noise | off |

The **preset** is a minimum level: *High only*, *High + normal* (default), *Everything*.
Every field and entry kind can then be flipped individually. Overrides are stored
**sparse** — a diff from the defaults, per tenant (`change_policies.overrides`) — so a
row the admin never touched follows future defaults when the policy version moves, and
an explicit choice persists. The UI shows the level, the reason, whether the row is at
its default, and lets an admin reset to defaults.

Two more knobs: **muted smart groups** (joining/leaving is not logged — for groups that
churn by design, like "out of check-in compliance") and **muted extension attributes**
(value changes not logged; the collection-level quarantine goes further and keeps them
out of the ledger entirely).

---

## 3. What the engine does

For each span boundary the ledger reports (`changed`), the derivation loads the previous
span's section contents by digest, diffs:

- scalar sections leaf by leaf on the canonical documents (dotted paths; lists such as
  FileVault users or group criteria are compared whole), producing `changed` rows with
  `old`/`new`;
- list sections as entry sets, then pairs removed/added entries by the kind's identity so
  a change within an entry is one `updated` naming `changedFields`;

then applies the policy and writes one `device_changes` row and one `device.change`
outbox event per kept change, in the same transaction as the device's state tables.

Two judgements need more than one section and live in the derivation rather than the
engine: the system-app collapse above, and **two-cause membership** — a group joined or
left carries `criteriaChanged`: whether the group's own definition span moved since this
device was last observed (criteria moved) or not (device drifted). Jamf cannot say; the
ledger keeps both histories.

Every row and event carries the correlation triple (serial, Jamf URL, Jamf id), the
UDID, both span ids, the device's own `observed_at`, the trigger, and the policy
version. The legacy `device.inventory.changed` event is unchanged.

**On the wire** the event also carries `deviceMeta` — #189's block, the same names and
values the inventory event from the same pull carries, including the `eventID` that names
that pull — and a Splunk HEC delivery stamps it with the entity's own sourcetype,
`loon:jamf:mac:<entity>:change`. Both landed in
[#223](https://github.com/LoonSecIO/LoonInspect/issues/223) on the family ruled in
[#243](https://github.com/LoonSecIO/LoonInspect/issues/243); the shape is
[`runs.md`](runs.md) §4 and the strings are
[`splunk-wire-vocabulary.md`](splunk-wire-vocabulary.md) §2.

---

## 4. The defaults

### Fields

| Section | Field | Level | Default | Why |
| --- | --- | --- | --- | --- |
| `general` | `name` — Computer name | normal | on | A rename is worth a line; it is not a security signal. |
| `general` | `platform` — Platform | low | off | Never changes on a real device. |
| `general` | `barcode1` — Barcode 1 | low | off | Asset metadata edited in Jamf, not device state. |
| `general` | `barcode2` — Barcode 2 | low | off | Asset metadata edited in Jamf, not device state. |
| `general` | `assetTag` — Asset tag | low | off | Asset metadata edited in Jamf, not device state. |
| `general` | `remoteManagement.managed` — Managed | high | on | A device leaving management is the first thing to know. |
| `general` | `supervised` — Supervised | high | on | Supervision governs which MDM commands are possible. |
| `general` | `mdmCapable.capable` — MDM capable | high | on | Losing MDM capability means losing control. |
| `general` | `lastEnrolledDate` — Last enrolled | high | on | A new enrollment date is a re-enrollment event. |
| `general` | `mdmProfileExpiration` — MDM profile expiration | low | off | Moves on renewal; informational. |
| `general` | `initialEntryDate` — Initial entry | low | off | Set once; a change would be a duplicate record. |
| `general` | `distributionPoint` — Distribution point | low | off | Jamf infrastructure assignment, not device state. |
| `general` | `enrollmentMethod.id` — Enrollment method | high | on | How the device was enrolled changes only on re-enrollment. |
| `general` | `enrollmentMethod.objectType` — Enrollment method type | high | on | PreStage vs user-initiated is a posture fact. |
| `general` | `site.id` — Site | normal | on | Moving sites changes who administers the device. |
| `general` | `itunesStoreAccountActive` — App Store account active | low | off | User sign-in state; privacy-adjacent, low value. |
| `general` | `enrolledViaAutomatedDeviceEnrollment` — Automated Device Enrollment | high | on | ADE status is the strongest enrollment guarantee. |
| `general` | `userApprovedMdm` — User-approved MDM | high | on | Without UAMDM, kernel and system extensions cannot be managed. |
| `general` | `declarativeDeviceManagementEnabled` — Declarative management | high | on | DDM on/off changes how configuration is enforced. |
| `general` | `managementId` — Management id | high | on | A new management id is a new enrollment. |
| `general` | `jamfBinaryVersion` — Jamf binary version | low | off | Changes fleet-wide on every Jamf release; better as a fleet finding. |
| `hardware` | `make` — Make | high | on | Hardware identity; a change means a different machine. |
| `hardware` | `model` — Model | high | on | Hardware identity. |
| `hardware` | `modelIdentifier` — Model identifier | high | on | Hardware identity. |
| `hardware` | `serialNumber` — Serial number | high | on | Lineage key; a change under one Jamf id is an anomaly or a re-flash. |
| `hardware` | `processorSpeedMhz` — Processor speed | normal | on | Hardware identity detail; rare. |
| `hardware` | `processorCount` — Processor count | normal | on | Hardware identity detail; rare. |
| `hardware` | `coreCount` — Core count | normal | on | Hardware identity detail; rare. |
| `hardware` | `processorType` — Processor | normal | on | Hardware identity detail; rare. |
| `hardware` | `processorArchitecture` — Architecture | normal | on | Hardware identity detail; rare. |
| `hardware` | `busSpeedMhz` — Bus speed | low | off | Reported as 0 on Apple silicon; noise. |
| `hardware` | `cacheSizeKilobytes` — Cache size | low | off | Reported as 0 on Apple silicon; noise. |
| `hardware` | `networkAdapterType` — Primary network adapter | normal | on | Which interface is primary. |
| `hardware` | `macAddress` — MAC address | high | on | Primary hardware MAC; a change is a board or identity event. |
| `hardware` | `altNetworkAdapterType` — Alternate adapter | low | off | Docks and adapters come and go. |
| `hardware` | `altMacAddress` — Alternate MAC | low | off | Docks and adapters come and go. |
| `hardware` | `totalRamMegabytes` — RAM | normal | on | A hardware change; rare and worth knowing. |
| `hardware` | `openRamSlots` — Open RAM slots | low | off | Static. |
| `hardware` | `smcVersion` — SMC version | low | off | Firmware detail that moves with OS updates. |
| `hardware` | `bootRom` — Boot ROM | low | off | Moves with every OS update; the OS version already says so. |
| `hardware` | `opticalDrive` — Optical drive | low | off | Static. |
| `hardware` | `bleCapable` — Bluetooth LE capable | low | off | Static. |
| `hardware` | `supportsIosAppInstalls` — Supports iOS apps | low | off | Static. |
| `hardware` | `appleSilicon` — Apple silicon | low | off | Static. |
| `hardware` | `provisioningUdid` — Provisioning UDID | high | on | Lineage key; board-derived and immutable for the board. |
| `operating_system` | `name` — OS name | normal | on | macOS; a change would be notable. |
| `operating_system` | `version` — OS version | high | on | Patch state. The single most-asked change. |
| `operating_system` | `build` — OS build | high | on | Distinguishes builds within a version, including betas. |
| `operating_system` | `supplementalBuildVersion` — Supplemental build | high | on | Rapid/supplemental patch state. |
| `operating_system` | `rapidSecurityResponse` — Rapid Security Response | high | on | Security patch state. |
| `operating_system` | `activeDirectoryStatus` — Directory binding | high | on | Bound or unbound changes who can sign in. |
| `operating_system` | `fileVault2Status` — FileVault status | high | on | Disk encryption posture. |
| `operating_system` | `softwareUpdateDeviceId` — Software update device id | low | off | Static model code. |
| `user_and_location` | `username` — Assigned user | normal | on | Reassignment is an operational event. |
| `user_and_location` | `realname` — Assigned user name | normal | on | Reassignment is an operational event. |
| `user_and_location` | `email` — Assigned email | normal | on | Reassignment is an operational event. |
| `user_and_location` | `position` — Position | low | off | HR detail; churns with directory syncs. |
| `user_and_location` | `phone` — Phone | low | off | HR detail; churns with directory syncs. |
| `user_and_location` | `departmentId` — Department | normal | on | Organisational move. |
| `user_and_location` | `buildingId` — Building | normal | on | Location move. |
| `user_and_location` | `room` — Room | low | off | Location detail. |
| `purchasing` | `purchased` — Purchased | low | off | Procurement metadata. |
| `purchasing` | `leased` — Leased | low | off | Procurement metadata. |
| `purchasing` | `poNumber` — PO number | low | off | Procurement metadata. |
| `purchasing` | `vendor` — Vendor | low | off | Procurement metadata. |
| `purchasing` | `appleCareId` — AppleCare id | low | off | Procurement metadata. |
| `purchasing` | `purchasePrice` — Purchase price | low | off | Procurement metadata. |
| `purchasing` | `purchasingAccount` — Purchasing account | low | off | Procurement metadata. |
| `purchasing` | `purchasingContact` — Purchasing contact | low | off | Procurement metadata. |
| `purchasing` | `poDate` — PO date | low | off | Procurement metadata. |
| `purchasing` | `warrantyDate` — Warranty date | low | off | Procurement metadata. |
| `purchasing` | `leaseDate` — Lease date | low | off | Procurement metadata. |
| `purchasing` | `lifeExpectancy` — Life expectancy | low | off | Procurement metadata. |
| `security` | `sipStatus` — System Integrity Protection | high | on | Core OS protection. |
| `security` | `gatekeeperStatus` — Gatekeeper | high | on | What may launch. |
| `security` | `xprotectVersion` — XProtect version | low | off | Updates fleet-wide weekly; an out-of-date finding is the useful signal. |
| `security` | `autoLoginDisabled` — Auto-login disabled | high | on | Auto-login bypasses authentication at boot. |
| `security` | `remoteDesktopEnabled` — Remote Desktop | high | on | Remote access surface. |
| `security` | `activationLockEnabled` — Activation Lock | high | on | Theft protection. |
| `security` | `recoveryLockEnabled` — Recovery Lock | high | on | Recovery-mode protection. |
| `security` | `firewallEnabled` — Firewall | high | on | Network exposure. |
| `security` | `secureBootLevel` — Secure boot | high | on | Boot chain integrity. |
| `security` | `externalBootLevel` — External boot | high | on | Whether external media can boot the Mac. |
| `security` | `bootstrapTokenAllowed` — Bootstrap token allowed | high | on | Secure-token escrow. |
| `security` | `bootstrapTokenEscrowedStatus` — Bootstrap token escrowed | high | on | Secure-token escrow. |
| `security` | `attestationStatus` — Attestation | high | on | A failed attestation is a tamper signal. |
| `disk_encryption` | `bootPartitionEncryptionDetails.partitionName` — Boot partition | normal | on | Which volume is the boot partition. |
| `disk_encryption` | `bootPartitionEncryptionDetails.partitionFileVault2State` — Boot partition encryption | high | on | Encryption state of the boot volume. |
| `disk_encryption` | `individualRecoveryKeyValidityStatus` — Recovery key validity | high | on | Whether the escrowed key still works. |
| `disk_encryption` | `institutionalRecoveryKeyPresent` — Institutional recovery key | high | on | Escrow posture. |
| `disk_encryption` | `diskEncryptionConfigurationName` — Disk encryption configuration | normal | on | Which policy applies. |
| `disk_encryption` | `fileVault2Enabled` — FileVault enabled | high | on | Disk encryption posture. |
| `disk_encryption` | `fileVault2EnabledUserNames` — FileVault-enabled users | high | on | Who can unlock the disk. |
| `disk_encryption` | `fileVault2EligibilityMessage` — FileVault eligibility | low | off | Informational. |
| `definition` | `name` — Group name | normal | on | A rename, on the group rather than on every member. |
| `definition` | `siteId` — Group site | normal | on | Scope of the group. |
| `definition` | `criteria` — Group criteria | high | on | Criteria moving re-scopes every policy the group drives. |

### Entries

| Entry kind | Identity | Added / removed | Within-entry fields | Why |
| --- | --- | --- | --- | --- |
| `application` — Applications | name, bundleId, path | normal (on) | version (normal), cfBundleShortVersionString (normal), cfBundleVersion (normal), macAppStore (low) | Installs, removals and version changes are the inventory's core; Apple system apps collapse into the OS update unless logged individually. |
| `extension_attribute` — Extension attributes | definitionId | normal (on) | values (normal) | Admins wrote these for exactly the facts they care about; the quarantine already removes the churny ones. |
| `group_membership` — Smart group memberships | groupId | normal (on) | smartGroup (low) | Joining and leaving drives policy scoping; each event says whether the criteria moved or the device drifted. |
| `configuration_profile` — Configuration profiles | profileIdentifier | high (on) | uuid (high), id (low), removable (normal), username (low) | A removed profile is configuration drift; a new one is new configuration. |
| `local_user_account` — Local accounts | uid, username | high (on) | admin (high), fileVault2Enabled (high), passwordMinLength (high), passwordMaxAge (high), passwordMinComplexCharacters (high), passwordHistoryDepth (high), passwordRequireAlphanumeric (high), userAccountType (normal), computerAzureActiveDirectoryId (normal), userAzureActiveDirectoryId (normal), azureActiveDirectoryId (normal), fullName (low), homeDirectory (low), userGuid (low) | New or removed accounts, and admin or FileVault flips, are privilege changes. |
| `certificate` — Certificates | sha1Fingerprint | normal (on) | identity (low), username (low) | New identities and CAs on a device matter; expiry is a query-time finding, not a change. |
| `software_update` — Pending software updates | name | low (off) | version (low), packageName (low) | Appears fleet-wide when Apple releases; the OS version change says when it landed. |


---

## 5. Versioning

- Changing a default level, adding a field, or changing an identity is a new
  `CHANGE_POLICY_VERSION`; overrides stay keyed by `section.field` / `kind.field` and
  carry over.
- A contract field the policy does not name yet is treated as `normal`, so a new
  contract version cannot silently drop changes.
- Rows record the policy version they were derived under.
