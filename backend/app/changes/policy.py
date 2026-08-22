# ruff: noqa: E501 — the rule tables below read best as one rule per line.
"""The change-log policy: which observed changes become events, and at what level.

The ledger (docs/jamf-observations.md) records every contract field on every
observation. This module decides which *changes* an admin hears about. Two ideas:

* Every field and entry kind the contract can observe carries a **level** — `high`
  (security posture, privileged accounts, management state, hardware identity),
  `normal` (inventory: applications, profiles, groups, EAs, user assignment, OS
  details), or `low` (cosmetic, asset metadata, and fields that change fleet-wide for
  reasons unrelated to the device). The level decides the default: high and normal are
  on, low is off.
* Admins override sparsely: a minimum level (the preset — "high only", the default
  "high + normal", or "everything"), per-field and per-entry flips, a mute list for
  smart groups and extension attributes, and whether Apple system applications under
  /System are logged individually or collapsed into the OS update. Overrides are stored
  as a diff from the defaults, so a field an admin never touched follows future
  defaults and an explicit choice persists.

The policy can only name contract fields — telemetry never reaches the ledger, so it
cannot be change-logged by mistake. Defaults were reasoned from a real Jamf Pro 11.31
record (tests/fixtures/jamf/computer_inventory_detail_real.json); docs/change-log.md
carries the table and the reasoning.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

CHANGE_POLICY_VERSION = "v0"

HIGH = "high"
NORMAL = "normal"
LOW = "low"
LEVELS: tuple[str, ...] = (HIGH, NORMAL, LOW)
_RANK = {HIGH: 0, NORMAL: 1, LOW: 2}
DEFAULT_MINIMUM_LEVEL = NORMAL  # high + normal on, low off

# Apple system applications live here and bump versions with every macOS update; 64 of
# the 83 apps on the reference Mac mini. Logged individually they turn one OS update
# into sixty events per device, so by default they collapse into the OS change.
SYSTEM_APP_PREFIXES: tuple[str, ...] = ("/System/",)


@dataclass(frozen=True, slots=True)
class FieldRule:
    section: str
    field: str  # dotted path inside the canonical section document
    level: str
    label: str
    why: str

    @property
    def key(self) -> str:
        return f"{self.section}.{self.field}"


@dataclass(frozen=True, slots=True)
class EntryFieldRule:
    name: str
    level: str
    label: str
    why: str = ""


@dataclass(frozen=True, slots=True)
class EntryRule:
    kind: str  # the contract's entry kind
    section: str
    identity: tuple[str, ...]  # body fields that name one entry across observations
    level: str  # for added / removed
    label: str
    why: str
    fields: tuple[EntryFieldRule, ...] = ()  # within-entry changes that count as "updated"


def _f(section: str, name: str, level: str, label: str, why: str) -> FieldRule:
    return FieldRule(section, name, level, label, why)


# --- scalar sections ------------------------------------------------------------------

FIELD_RULES: tuple[FieldRule, ...] = (
    # general — management state is posture; names and tags are admin metadata
    _f("general", "name", NORMAL, "Computer name", "A rename is worth a line; it is not a security signal."),
    _f("general", "platform", LOW, "Platform", "Never changes on a real device."),
    _f("general", "barcode1", LOW, "Barcode 1", "Asset metadata edited in Jamf, not device state."),
    _f("general", "barcode2", LOW, "Barcode 2", "Asset metadata edited in Jamf, not device state."),
    _f("general", "assetTag", LOW, "Asset tag", "Asset metadata edited in Jamf, not device state."),
    _f("general", "remoteManagement.managed", HIGH, "Managed", "A device leaving management is the first thing to know."),
    _f("general", "supervised", HIGH, "Supervised", "Supervision governs which MDM commands are possible."),
    _f("general", "mdmCapable.capable", HIGH, "MDM capable", "Losing MDM capability means losing control."),
    _f("general", "lastEnrolledDate", HIGH, "Last enrolled", "A new enrollment date is a re-enrollment event."),
    _f("general", "mdmProfileExpiration", LOW, "MDM profile expiration", "Moves on renewal; informational."),
    _f("general", "initialEntryDate", LOW, "Initial entry", "Set once; a change would be a duplicate record."),
    _f("general", "distributionPoint", LOW, "Distribution point", "Jamf infrastructure assignment, not device state."),
    _f("general", "enrollmentMethod.id", HIGH, "Enrollment method", "How the device was enrolled changes only on re-enrollment."),
    _f("general", "enrollmentMethod.objectType", HIGH, "Enrollment method type", "PreStage vs user-initiated is a posture fact."),
    _f("general", "site.id", NORMAL, "Site", "Moving sites changes who administers the device."),
    _f("general", "itunesStoreAccountActive", LOW, "App Store account active", "User sign-in state; privacy-adjacent, low value."),
    _f("general", "enrolledViaAutomatedDeviceEnrollment", HIGH, "Automated Device Enrollment", "ADE status is the strongest enrollment guarantee."),
    _f("general", "userApprovedMdm", HIGH, "User-approved MDM", "Without UAMDM, kernel and system extensions cannot be managed."),
    _f("general", "declarativeDeviceManagementEnabled", HIGH, "Declarative management", "DDM on/off changes how configuration is enforced."),
    _f("general", "managementId", HIGH, "Management id", "A new management id is a new enrollment."),
    _f("general", "jamfBinaryVersion", LOW, "Jamf binary version", "Changes fleet-wide on every Jamf release; better as a fleet finding."),
    # hardware — identity is high, capacities are normal, static capability flags low
    _f("hardware", "make", HIGH, "Make", "Hardware identity; a change means a different machine."),
    _f("hardware", "model", HIGH, "Model", "Hardware identity."),
    _f("hardware", "modelIdentifier", HIGH, "Model identifier", "Hardware identity."),
    _f("hardware", "serialNumber", HIGH, "Serial number", "Lineage key; a change under one Jamf id is an anomaly or a re-flash."),
    _f("hardware", "processorSpeedMhz", NORMAL, "Processor speed", "Hardware identity detail; rare."),
    _f("hardware", "processorCount", NORMAL, "Processor count", "Hardware identity detail; rare."),
    _f("hardware", "coreCount", NORMAL, "Core count", "Hardware identity detail; rare."),
    _f("hardware", "processorType", NORMAL, "Processor", "Hardware identity detail; rare."),
    _f("hardware", "processorArchitecture", NORMAL, "Architecture", "Hardware identity detail; rare."),
    _f("hardware", "busSpeedMhz", LOW, "Bus speed", "Reported as 0 on Apple silicon; noise."),
    _f("hardware", "cacheSizeKilobytes", LOW, "Cache size", "Reported as 0 on Apple silicon; noise."),
    _f("hardware", "networkAdapterType", NORMAL, "Primary network adapter", "Which interface is primary."),
    _f("hardware", "macAddress", HIGH, "MAC address", "Primary hardware MAC; a change is a board or identity event."),
    _f("hardware", "altNetworkAdapterType", LOW, "Alternate adapter", "Docks and adapters come and go."),
    _f("hardware", "altMacAddress", LOW, "Alternate MAC", "Docks and adapters come and go."),
    _f("hardware", "totalRamMegabytes", NORMAL, "RAM", "A hardware change; rare and worth knowing."),
    _f("hardware", "openRamSlots", LOW, "Open RAM slots", "Static."),
    _f("hardware", "smcVersion", LOW, "SMC version", "Firmware detail that moves with OS updates."),
    _f("hardware", "bootRom", LOW, "Boot ROM", "Moves with every OS update; the OS version already says so."),
    _f("hardware", "opticalDrive", LOW, "Optical drive", "Static."),
    _f("hardware", "bleCapable", LOW, "Bluetooth LE capable", "Static."),
    _f("hardware", "supportsIosAppInstalls", LOW, "Supports iOS apps", "Static."),
    _f("hardware", "appleSilicon", LOW, "Apple silicon", "Static."),
    _f("hardware", "provisioningUdid", HIGH, "Provisioning UDID", "Lineage key; board-derived and immutable for the board."),
    # operating_system
    _f("operating_system", "name", NORMAL, "OS name", "macOS; a change would be notable."),
    _f("operating_system", "version", HIGH, "OS version", "Patch state. The single most-asked change."),
    _f("operating_system", "build", HIGH, "OS build", "Distinguishes builds within a version, including betas."),
    _f("operating_system", "supplementalBuildVersion", HIGH, "Supplemental build", "Rapid/supplemental patch state."),
    _f("operating_system", "rapidSecurityResponse", HIGH, "Rapid Security Response", "Security patch state."),
    _f("operating_system", "activeDirectoryStatus", HIGH, "Directory binding", "Bound or unbound changes who can sign in."),
    _f("operating_system", "fileVault2Status", HIGH, "FileVault status", "Disk encryption posture."),
    _f("operating_system", "softwareUpdateDeviceId", LOW, "Software update device id", "Static model code."),
    # user_and_location
    _f("user_and_location", "username", NORMAL, "Assigned user", "Reassignment is an operational event."),
    _f("user_and_location", "realname", NORMAL, "Assigned user name", "Reassignment is an operational event."),
    _f("user_and_location", "email", NORMAL, "Assigned email", "Reassignment is an operational event."),
    _f("user_and_location", "position", LOW, "Position", "HR detail; churns with directory syncs."),
    _f("user_and_location", "phone", LOW, "Phone", "HR detail; churns with directory syncs."),
    _f("user_and_location", "departmentId", NORMAL, "Department", "Organisational move."),
    _f("user_and_location", "buildingId", NORMAL, "Building", "Location move."),
    _f("user_and_location", "room", LOW, "Room", "Location detail."),
    # purchasing — all low: warranty and procurement metadata
    _f("purchasing", "purchased", LOW, "Purchased", "Procurement metadata."),
    _f("purchasing", "leased", LOW, "Leased", "Procurement metadata."),
    _f("purchasing", "poNumber", LOW, "PO number", "Procurement metadata."),
    _f("purchasing", "vendor", LOW, "Vendor", "Procurement metadata."),
    _f("purchasing", "appleCareId", LOW, "AppleCare id", "Procurement metadata."),
    _f("purchasing", "purchasePrice", LOW, "Purchase price", "Procurement metadata."),
    _f("purchasing", "purchasingAccount", LOW, "Purchasing account", "Procurement metadata."),
    _f("purchasing", "purchasingContact", LOW, "Purchasing contact", "Procurement metadata."),
    _f("purchasing", "poDate", LOW, "PO date", "Procurement metadata."),
    _f("purchasing", "warrantyDate", LOW, "Warranty date", "Procurement metadata."),
    _f("purchasing", "leaseDate", LOW, "Lease date", "Procurement metadata."),
    _f("purchasing", "lifeExpectancy", LOW, "Life expectancy", "Procurement metadata."),
    # security — posture, all high except the fleet-wide XProtect version
    _f("security", "sipStatus", HIGH, "System Integrity Protection", "Core OS protection."),
    _f("security", "gatekeeperStatus", HIGH, "Gatekeeper", "What may launch."),
    _f("security", "xprotectVersion", LOW, "XProtect version", "Updates fleet-wide weekly; an out-of-date finding is the useful signal."),
    _f("security", "autoLoginDisabled", HIGH, "Auto-login disabled", "Auto-login bypasses authentication at boot."),
    _f("security", "remoteDesktopEnabled", HIGH, "Remote Desktop", "Remote access surface."),
    _f("security", "activationLockEnabled", HIGH, "Activation Lock", "Theft protection."),
    _f("security", "recoveryLockEnabled", HIGH, "Recovery Lock", "Recovery-mode protection."),
    _f("security", "firewallEnabled", HIGH, "Firewall", "Network exposure."),
    _f("security", "secureBootLevel", HIGH, "Secure boot", "Boot chain integrity."),
    _f("security", "externalBootLevel", HIGH, "External boot", "Whether external media can boot the Mac."),
    _f("security", "bootstrapTokenAllowed", HIGH, "Bootstrap token allowed", "Secure-token escrow."),
    _f("security", "bootstrapTokenEscrowedStatus", HIGH, "Bootstrap token escrowed", "Secure-token escrow."),
    _f("security", "attestationStatus", HIGH, "Attestation", "A failed attestation is a tamper signal."),
    # disk_encryption — all high
    _f("disk_encryption", "bootPartitionEncryptionDetails.partitionName", NORMAL, "Boot partition", "Which volume is the boot partition."),
    _f("disk_encryption", "bootPartitionEncryptionDetails.partitionFileVault2State", HIGH, "Boot partition encryption", "Encryption state of the boot volume."),
    _f("disk_encryption", "individualRecoveryKeyValidityStatus", HIGH, "Recovery key validity", "Whether the escrowed key still works."),
    _f("disk_encryption", "institutionalRecoveryKeyPresent", HIGH, "Institutional recovery key", "Escrow posture."),
    _f("disk_encryption", "diskEncryptionConfigurationName", NORMAL, "Disk encryption configuration", "Which policy applies."),
    _f("disk_encryption", "fileVault2Enabled", HIGH, "FileVault enabled", "Disk encryption posture."),
    _f("disk_encryption", "fileVault2EnabledUserNames", HIGH, "FileVault-enabled users", "Who can unlock the disk."),
    _f("disk_encryption", "fileVault2EligibilityMessage", LOW, "FileVault eligibility", "Informational."),
    # smart-group definitions (subject computer_group)
    _f("definition", "name", NORMAL, "Group name", "A rename, on the group rather than on every member."),
    _f("definition", "siteId", NORMAL, "Group site", "Scope of the group."),
    _f("definition", "criteria", HIGH, "Group criteria", "Criteria moving re-scopes every policy the group drives."),
)

# --- list sections ----------------------------------------------------------------------

ENTRY_RULES: tuple[EntryRule, ...] = (
    EntryRule(
        kind="application", section="applications", identity=("name", "bundleId", "path"), level=NORMAL,
        label="Applications",
        why="Installs, removals and version changes are the inventory's core; Apple system apps collapse into the OS update unless logged individually.",
        fields=(
            EntryFieldRule("version", NORMAL, "Version"),
            EntryFieldRule("cfBundleShortVersionString", NORMAL, "Short version"),
            EntryFieldRule("cfBundleVersion", NORMAL, "Bundle version"),
            EntryFieldRule("macAppStore", LOW, "App Store flag"),
        ),
    ),
    EntryRule(
        kind="extension_attribute", section="extension_attributes", identity=("definitionId",), level=NORMAL,
        label="Extension attributes",
        why="Admins wrote these for exactly the facts they care about; the quarantine already removes the churny ones.",
        fields=(EntryFieldRule("values", NORMAL, "Value"),),
    ),
    EntryRule(
        kind="group_membership", section="group_memberships", identity=("groupId",), level=NORMAL,
        label="Smart group memberships",
        why="Joining and leaving drives policy scoping; each event says whether the criteria moved or the device drifted.",
        fields=(EntryFieldRule("smartGroup", LOW, "Smart flag"),),
    ),
    EntryRule(
        kind="configuration_profile", section="configuration_profiles", identity=("profileIdentifier",), level=HIGH,
        label="Configuration profiles",
        why="A removed profile is configuration drift; a new one is new configuration.",
        fields=(
            EntryFieldRule("uuid", HIGH, "Payload UUID", "A new payload UUID is a redeployed profile."),
            EntryFieldRule("id", LOW, "Jamf id"),
            EntryFieldRule("removable", NORMAL, "Removable"),
            EntryFieldRule("username", LOW, "Username"),
        ),
    ),
    EntryRule(
        kind="local_user_account", section="local_user_accounts", identity=("uid", "username"), level=HIGH,
        label="Local accounts",
        why="New or removed accounts, and admin or FileVault flips, are privilege changes.",
        fields=(
            EntryFieldRule("admin", HIGH, "Administrator", "Privilege escalation or de-escalation."),
            EntryFieldRule("fileVault2Enabled", HIGH, "FileVault enabled", "Who can unlock the disk."),
            EntryFieldRule("passwordMinLength", HIGH, "Password minimum length"),
            EntryFieldRule("passwordMaxAge", HIGH, "Password max age"),
            EntryFieldRule("passwordMinComplexCharacters", HIGH, "Password complexity"),
            EntryFieldRule("passwordHistoryDepth", HIGH, "Password history"),
            EntryFieldRule("passwordRequireAlphanumeric", HIGH, "Password alphanumeric"),
            EntryFieldRule("userAccountType", NORMAL, "Account type"),
            EntryFieldRule("computerAzureActiveDirectoryId", NORMAL, "Computer Entra id"),
            EntryFieldRule("userAzureActiveDirectoryId", NORMAL, "User Entra id"),
            EntryFieldRule("azureActiveDirectoryId", NORMAL, "Entra registration"),
            EntryFieldRule("fullName", LOW, "Full name"),
            EntryFieldRule("homeDirectory", LOW, "Home directory"),
            EntryFieldRule("userGuid", LOW, "GUID"),
        ),
    ),
    EntryRule(
        kind="certificate", section="certificates", identity=("sha1Fingerprint",), level=NORMAL,
        label="Certificates",
        why="New identities and CAs on a device matter; expiry is a query-time finding, not a change.",
        fields=(
            EntryFieldRule("identity", LOW, "Identity flag"),
            EntryFieldRule("username", LOW, "Username"),
        ),
    ),
    EntryRule(
        kind="software_update", section="software_updates", identity=("name",), level=LOW,
        label="Pending software updates",
        why="Appears fleet-wide when Apple releases; the OS version change says when it landed.",
        fields=(EntryFieldRule("version", LOW, "Version"), EntryFieldRule("packageName", LOW, "Package")),
    ),
)

FIELD_RULES_BY_KEY: dict[str, FieldRule] = {rule.key: rule for rule in FIELD_RULES}
ENTRY_RULES_BY_KIND: dict[str, EntryRule] = {rule.kind: rule for rule in ENTRY_RULES}


# --- overrides and the effective policy ---------------------------------------------------


@dataclass(frozen=True, slots=True)
class Overrides:
    """What an admin changed, and nothing else."""

    minimum_level: str = DEFAULT_MINIMUM_LEVEL
    fields: Mapping[str, bool] = field(default_factory=dict)  # "section.field" -> on/off
    entries: Mapping[str, bool] = field(default_factory=dict)  # "kind", "kind.added", "kind.removed", "kind.field" -> on/off
    system_apps_individually: bool = False
    muted_groups: tuple[str, ...] = ()
    muted_extension_attributes: tuple[str, ...] = ()

    @classmethod
    def from_document(cls, document: Mapping | None) -> Overrides:
        document = document or {}
        level = document.get("minimumLevel") or DEFAULT_MINIMUM_LEVEL
        if level not in LEVELS:
            level = DEFAULT_MINIMUM_LEVEL
        return cls(
            minimum_level=level,
            fields={str(k): bool(v) for k, v in (document.get("fields") or {}).items()},
            entries={str(k): bool(v) for k, v in (document.get("entries") or {}).items()},
            system_apps_individually=bool(document.get("systemAppsIndividually", False)),
            muted_groups=tuple(str(g) for g in document.get("mutedGroups") or ()),
            muted_extension_attributes=tuple(str(e) for e in document.get("mutedExtensionAttributes") or ()),
        )

    def to_document(self) -> dict:
        return {
            "minimumLevel": self.minimum_level,
            "fields": dict(self.fields),
            "entries": dict(self.entries),
            "systemAppsIndividually": self.system_apps_individually,
            "mutedGroups": list(self.muted_groups),
            "mutedExtensionAttributes": list(self.muted_extension_attributes),
        }


def default_on(level: str, minimum_level: str = DEFAULT_MINIMUM_LEVEL) -> bool:
    return _RANK[level] <= _RANK[minimum_level]


class EffectivePolicy:
    """Defaults ⊕ overrides, answering "is this change logged?" and "at what level?"."""

    def __init__(self, overrides: Overrides | None = None) -> None:
        self.overrides = overrides or Overrides()
        self.version = CHANGE_POLICY_VERSION

    # scalar fields
    def field_rule(self, section: str, name: str) -> FieldRule | None:
        return FIELD_RULES_BY_KEY.get(f"{section}.{name}")

    def field_enabled(self, section: str, name: str) -> bool:
        rule = self.field_rule(section, name)
        if rule is None:
            # A contract field the policy has no opinion on yet: treat as normal, so a
            # new contract version does not silently drop changes on the floor.
            return default_on(NORMAL, self.overrides.minimum_level)
        override = self.overrides.fields.get(rule.key)
        if override is not None:
            return override
        return default_on(rule.level, self.overrides.minimum_level)

    def field_level(self, section: str, name: str) -> str:
        rule = self.field_rule(section, name)
        return rule.level if rule else NORMAL

    # entries
    def entry_rule(self, kind: str) -> EntryRule | None:
        return ENTRY_RULES_BY_KIND.get(kind)

    def entry_enabled(self, kind: str, change: str, changed_field: str | None = None) -> bool:
        """`change` is added | removed | updated. For updated, `changed_field` names one
        within-entry field; the update is logged if any changed field is enabled."""
        rule = self.entry_rule(kind)
        whole = self.overrides.entries.get(kind)
        if whole is False:
            return False
        if change in ("added", "removed"):
            specific = self.overrides.entries.get(f"{kind}.{change}")
            if specific is not None:
                return specific
            if whole is True:
                return True
            return default_on(rule.level if rule else NORMAL, self.overrides.minimum_level)
        # updated
        if changed_field is None:
            return False
        specific = self.overrides.entries.get(f"{kind}.{changed_field}")
        if specific is not None:
            return specific
        if whole is True:
            return True
        level = NORMAL
        if rule is not None:
            for entry_field in rule.fields:
                if entry_field.name == changed_field:
                    level = entry_field.level
                    break
        return default_on(level, self.overrides.minimum_level)

    def entry_level(self, kind: str, change: str, changed_fields: Iterable[str] = ()) -> str:
        rule = self.entry_rule(kind)
        if rule is None:
            return NORMAL
        if change in ("added", "removed"):
            return rule.level
        levels = [f.level for f in rule.fields if f.name in set(changed_fields)]
        if not levels:
            return NORMAL
        return min(levels, key=lambda level: _RANK[level])

    def group_muted(self, group_id: str) -> bool:
        return str(group_id) in self.overrides.muted_groups

    def extension_attribute_muted(self, definition_id: str) -> bool:
        return str(definition_id) in self.overrides.muted_extension_attributes

    @property
    def system_apps_individually(self) -> bool:
        return self.overrides.system_apps_individually

    # description for the API / UI
    def describe(self) -> dict:
        sections: dict[str, list[dict]] = {}
        for rule in FIELD_RULES:
            sections.setdefault(rule.section, []).append(
                {
                    "key": rule.key,
                    "field": rule.field,
                    "label": rule.label,
                    "level": rule.level,
                    "why": rule.why,
                    "default": default_on(rule.level, self.overrides.minimum_level),
                    "enabled": self.field_enabled(rule.section, rule.field),
                    "overridden": rule.key in self.overrides.fields,
                }
            )
        entries = []
        for rule in ENTRY_RULES:
            entries.append(
                {
                    "kind": rule.kind,
                    "section": rule.section,
                    "label": rule.label,
                    "level": rule.level,
                    "why": rule.why,
                    "identity": list(rule.identity),
                    "added": self.entry_enabled(rule.kind, "added"),
                    "removed": self.entry_enabled(rule.kind, "removed"),
                    "overridden": any(
                        key == rule.kind or key.startswith(f"{rule.kind}.") for key in self.overrides.entries
                    ),
                    "fields": [
                        {
                            "name": f.name,
                            "label": f.label,
                            "level": f.level,
                            "why": f.why,
                            "enabled": self.entry_enabled(rule.kind, "updated", f.name),
                            "overridden": f"{rule.kind}.{f.name}" in self.overrides.entries,
                        }
                        for f in rule.fields
                    ],
                }
            )
        return {
            "version": self.version,
            "minimumLevel": self.overrides.minimum_level,
            "systemAppsIndividually": self.overrides.system_apps_individually,
            "mutedGroups": list(self.overrides.muted_groups),
            "mutedExtensionAttributes": list(self.overrides.muted_extension_attributes),
            "sections": [{"section": name, "fields": fields} for name, fields in sections.items()],
            "entries": entries,
        }


def is_system_app(body: Mapping) -> bool:
    path = body.get("path")
    return isinstance(path, str) and path.startswith(SYSTEM_APP_PREFIXES)
