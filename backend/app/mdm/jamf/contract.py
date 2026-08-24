"""The Jamf observation contract, v0 — what a change *is*.

LoonInspect's value is diffing stored observations of a device over time. That makes
the normalized shape of an observation the one thing in this codebase that is genuinely
hard to change: a later reshape does not merely break consumers, it manufactures phantom
diffs at the migration boundary and corrupts the change stream itself. So the shape is
a versioned contract, frozen in docs/jamf-observations.md and asserted as literal digests
in tests/test_jamf_observation_contract.py, and it changes only behind a new version
string — never in place.

Everything here is pure: raw Jamf Pro API JSON in, canonical documents and SHA-256
digests out. No I/O, no session, no clock.

The model, top to bottom:

  head      one digest per (subject, aperture) over the map {section: digest}
  section   one digest per Jamf inventory section — a scalar document (general,
            hardware, …) or the sorted set of entry digests (applications, …)
  entry     one digest per content-addressed item (an application, a certificate, …)
            deduplicated across the whole fleet

Three rules decide what reaches a digest:

1. **Allowlist, not denylist.** Every section names the fields that are hashed. A field
   Jamf adds in a later release is ignored until a contract version chooses to include
   it, so a Jamf upgrade can never change every device's digest overnight. Telemetry
   (contact times, IPs, battery, disk free, sizes, "update available", certificate
   status) is simply not listed.
2. **Names of Jamf objects are labels, not content.** A smart group, an extension
   attribute, a configuration profile, a site, or a PreStage can be renamed by an admin
   without anything changing on any device. Their ids are hashed; their names ride
   alongside as labels (entry labels, or the group's own definition observation). The
   exception is content that *is* a name — an application's name, a certificate's
   common name, a local account's username.
3. **Absence is absence.** null, "", [], {} and a missing key are the same thing.
   Strings are NFC-normalized and stripped. Timestamps that survive the allowlist are
   reduced to UTC whole seconds. Lists that carry no order (EA values, FileVault users,
   entry sets) are sorted.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

CONTRACT_VERSION = "v0"

# Hash-domain separation: the payload hashed is DOMAIN ␟ version ␟ kind ␟ canonical JSON,
# so an entry digest can never equal a section digest for the same bytes, and neither
# can collide with app.core.content_keys, which hashes under its own domain. U+001F is
# the same joiner content_keys uses and is stripped from every string for the same
# reason: a delimiter that can occur in data is two digests for one thing.
_DOMAIN = "loon.jamf.observation"
_SEPARATOR = "\x1f"
_PREFIX = f"{CONTRACT_VERSION}:"

# Allowlist markers. `True` keeps the field as-is; TS reduces a timestamp to UTC whole
# seconds (date-only strings pass through); SORTED sorts a list of strings; a nested
# mapping recurses.
TS = "timestamp"
SORTED = "sorted-strings"

Allow = Mapping[str, Any]


# --- canonical values ---------------------------------------------------------------


def canonical_string(value: str) -> str:
    return unicodedata.normalize("NFC", value).strip().replace(_SEPARATOR, "")


_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$")


def canonical_timestamp(value: str) -> str:
    """UTC whole seconds, `YYYY-MM-DDTHH:MM:SSZ`. Jamf emits millisecond precision on
    some fields and none on others, and sub-second precision on an enrollment date
    carries no information — normalizing it means the format Jamf happens to use is
    not part of the digest. Anything that is not an ISO-8601 datetime (a date-only
    string, or garbage) is returned verbatim rather than guessed at."""
    text = value.strip()
    if not _TS_RE.match(text):
        return text
    try:
        parsed = datetime.fromisoformat(re.sub(r"\.\d+", "", text).replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_jamf_datetime(value: str | None) -> datetime | None:
    """A real datetime for fields the ledger needs as time (reportDate), not as
    content. Same parse as canonical_timestamp, without the formatting."""
    if not value or not _TS_RE.match(value.strip()):
        return None
    try:
        parsed = datetime.fromisoformat(re.sub(r"\.\d+", "", value.strip()).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _prune(value: Any) -> Any:
    """Canonicalize strings and drop every spelling of absence, recursively.

    Returns None for anything that reduces to nothing, so a caller can drop the key.
    Booleans and numbers are kept as-is — `False` and `0` are values, not absence.
    """
    if value is None:
        return None
    if isinstance(value, str):
        text = canonical_string(value)
        return text or None
    if isinstance(value, bool | int | float):
        return value
    if isinstance(value, Mapping):
        out = {}
        for key in sorted(value):
            pruned = _prune(value[key])
            if pruned is not None:
                out[str(key)] = pruned
        return out or None
    if isinstance(value, list | tuple):
        items = [item for item in (_prune(v) for v in value) if item is not None]
        return items or None
    # Anything exotic is stringified rather than rejected; the allowlist should have
    # kept it out, and failing a sweep over one odd value is the wrong trade.
    text = canonical_string(str(value))
    return text or None


def canonical_json(value: Any) -> str:
    """Sorted keys, no whitespace, UTF-8 as-is. The bytes that are hashed."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(kind: str, canonical: str) -> str:
    payload = _SEPARATOR.join([_DOMAIN, CONTRACT_VERSION, kind, canonical])
    return _PREFIX + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _select(value: Any, allow: Allow) -> dict:
    """Apply an allowlist to a raw object. Keys not named are dropped; named keys are
    kept, reduced, or recursed into per their marker. Absent keys stay absent."""
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, Any] = {}
    for key, rule in allow.items():
        if key not in value:
            continue
        raw = value[key]
        if rule is True:
            out[key] = raw
        elif rule == TS:
            out[key] = canonical_timestamp(raw) if isinstance(raw, str) else raw
        elif rule == SORTED:
            if isinstance(raw, list | tuple):
                out[key] = sorted(canonical_string(str(item)) for item in raw if item is not None)
            else:
                out[key] = raw
        elif isinstance(rule, Mapping):
            out[key] = _select(raw, rule)
    return out


def canonical_document(value: Any, allow: Allow) -> dict:
    return _prune(_select(value, allow)) or {}


# --- the v0 section registry --------------------------------------------------------


@dataclass(frozen=True)
class SectionSpec:
    name: str  # the contract's name, and the key in every head's section map
    jamf_section: str  # the value for computers-inventory's `section` parameter
    response_key: str  # where it lives in the API object
    fields: Allow | None = None  # scalar sections
    entry_kind: str | None = None  # list sections
    entry_fields: Allow | None = None
    entry_label: str | None = None  # the raw field carried as a label, never hashed

    @property
    def is_list(self) -> bool:
        return self.entry_kind is not None


_GENERAL: Allow = {
    "name": True,
    "platform": True,
    "barcode1": True,
    "barcode2": True,
    "assetTag": True,
    "remoteManagement": {"managed": True},
    "supervised": True,
    "mdmCapable": {"capable": True},
    "lastEnrolledDate": TS,
    "mdmProfileExpiration": TS,
    "initialEntryDate": TS,
    "distributionPoint": True,
    # objectName is the PreStage's display name — a label (rule 2).
    "enrollmentMethod": {"id": True, "objectType": True},
    # site.name likewise; the id is the site.
    "site": {"id": True},
    "itunesStoreAccountActive": True,
    "enrolledViaAutomatedDeviceEnrollment": True,
    "userApprovedMdm": True,
    "declarativeDeviceManagementEnabled": True,
    "managementId": True,
    "jamfBinaryVersion": True,
    # Not listed, deliberately: lastIpAddress, lastReportedIp*, reportDate,
    # lastContactTime, lastCloudBackupDate, lastLoggedInUsername* and their timestamps,
    # mdmCapable.capableUsers/userManagementInfo, extensionAttributes (merged into the
    # extension_attributes section).
}

_HARDWARE: Allow = {
    "make": True,
    "model": True,
    "modelIdentifier": True,
    "serialNumber": True,
    "processorSpeedMhz": True,
    "processorCount": True,
    "coreCount": True,
    "processorType": True,
    "processorArchitecture": True,
    "busSpeedMhz": True,
    "cacheSizeKilobytes": True,
    "networkAdapterType": True,
    "macAddress": True,
    "altNetworkAdapterType": True,
    "altMacAddress": True,
    "totalRamMegabytes": True,
    "openRamSlots": True,
    "smcVersion": True,
    "opticalDrive": True,
    "bootRom": True,
    "bleCapable": True,
    "supportsIosAppInstalls": True,
    "appleSilicon": True,
    "provisioningUdid": True,
    # Not listed: batteryCapacityPercent, batteryHealth, nicSpeed (link speed varies
    # per connection), extensionAttributes.
}

_OPERATING_SYSTEM: Allow = {
    "name": True,
    "version": True,
    "build": True,
    "supplementalBuildVersion": True,
    "rapidSecurityResponse": True,
    "activeDirectoryStatus": True,
    "fileVault2Status": True,
    "softwareUpdateDeviceId": True,
}

_USER_AND_LOCATION: Allow = {
    "username": True,
    "realname": True,
    "email": True,
    "position": True,
    "phone": True,
    "departmentId": True,
    "buildingId": True,
    "room": True,
}

_PURCHASING: Allow = {
    "purchased": True,
    "leased": True,
    "poNumber": True,
    "vendor": True,
    "appleCareId": True,
    "purchasePrice": True,
    "purchasingAccount": True,
    "purchasingContact": True,
    "poDate": TS,
    "warrantyDate": TS,
    "leaseDate": TS,
    "lifeExpectancy": True,
}

_SECURITY: Allow = {
    "sipStatus": True,
    "gatekeeperStatus": True,
    "xprotectVersion": True,
    "autoLoginDisabled": True,
    "remoteDesktopEnabled": True,
    "activationLockEnabled": True,
    "recoveryLockEnabled": True,
    "firewallEnabled": True,
    "secureBootLevel": True,
    "externalBootLevel": True,
    "bootstrapTokenAllowed": True,
    "bootstrapTokenEscrowedStatus": True,
    "attestationStatus": True,
    # Not listed: lastAttestationAttempt, lastSuccessfulAttestation.
}

_DISK_ENCRYPTION: Allow = {
    # partitionFileVault2Percent is progress, not state.
    "bootPartitionEncryptionDetails": {"partitionName": True, "partitionFileVault2State": True},
    "individualRecoveryKeyValidityStatus": True,
    "institutionalRecoveryKeyPresent": True,
    "diskEncryptionConfigurationName": True,
    "fileVault2Enabled": True,
    "fileVault2EnabledUserNames": SORTED,
    "fileVault2EligibilityMessage": True,
}

_APPLICATION: Allow = {
    "name": True,
    "path": True,
    "version": True,
    # Jamf Pro 11.31 started reporting both bundle version fields alongside `version`
    # (which equals cfBundleShortVersionString). Both are content: a build bump under
    # the same marketing version is a real change. Older servers omit them, and
    # absence is absence, so their digests are unaffected until the server upgrades —
    # which is an aperture change, because the Jamf version is in the aperture.
    "cfBundleShortVersionString": True,
    "cfBundleVersion": True,
    "bundleId": True,
    "macAppStore": True,
    # Not listed: sizeMegabytes, updateAvailable, externalVersionId.
}

_EXTENSION_ATTRIBUTE: Allow = {
    "definitionId": True,
    "values": SORTED,
    # name is the label; dataType/inputType/options/description/enabled describe the
    # definition, not the device.
}

_GROUP_MEMBERSHIP: Allow = {
    "groupId": True,
    "smartGroup": True,
    # groupName is the label; groupDescription describes the definition.
}

_CONFIGURATION_PROFILE: Allow = {
    "id": True,
    "profileIdentifier": True,
    "uuid": True,
    "removable": True,
    "username": True,
    # displayName is the label; lastInstalled is a timestamp of delivery, not state.
}

_LOCAL_USER_ACCOUNT: Allow = {
    "uid": True,
    "userGuid": True,
    "username": True,
    "fullName": True,
    "admin": True,
    "homeDirectory": True,
    "fileVault2Enabled": True,
    "userAccountType": True,
    "passwordMinLength": True,
    "passwordMaxAge": True,
    "passwordMinComplexCharacters": True,
    "passwordHistoryDepth": True,
    "passwordRequireAlphanumeric": True,
    "computerAzureActiveDirectoryId": True,
    "userAzureActiveDirectoryId": True,
    "azureActiveDirectoryId": True,
    # Not listed: homeDirectorySizeMb.
}

_CERTIFICATE: Allow = {
    "commonName": True,
    "identity": True,
    "expirationDate": TS,
    "username": True,
    "subjectName": True,
    "serialNumber": True,
    "sha1Fingerprint": True,
    "issuedDate": TS,
    # Not listed: lifecycleStatus and certificateStatus — Jamf derives both from the
    # dates above and the clock, so they flip with no change on the device.
}

_SOFTWARE_UPDATE: Allow = {
    "name": True,
    "version": True,
    "packageName": True,
}

SECTIONS: dict[str, SectionSpec] = {
    spec.name: spec
    for spec in (
        SectionSpec("general", "GENERAL", "general", fields=_GENERAL),
        SectionSpec("hardware", "HARDWARE", "hardware", fields=_HARDWARE),
        SectionSpec("operating_system", "OPERATING_SYSTEM", "operatingSystem", fields=_OPERATING_SYSTEM),
        SectionSpec("user_and_location", "USER_AND_LOCATION", "userAndLocation", fields=_USER_AND_LOCATION),
        SectionSpec("purchasing", "PURCHASING", "purchasing", fields=_PURCHASING),
        SectionSpec("security", "SECURITY", "security", fields=_SECURITY),
        SectionSpec("disk_encryption", "DISK_ENCRYPTION", "diskEncryption", fields=_DISK_ENCRYPTION),
        SectionSpec(
            "applications", "APPLICATIONS", "applications",
            entry_kind="application", entry_fields=_APPLICATION,
        ),
        SectionSpec(
            "extension_attributes", "EXTENSION_ATTRIBUTES", "extensionAttributes",
            entry_kind="extension_attribute", entry_fields=_EXTENSION_ATTRIBUTE, entry_label="name",
        ),
        SectionSpec(
            "group_memberships", "GROUP_MEMBERSHIPS", "groupMemberships",
            entry_kind="group_membership", entry_fields=_GROUP_MEMBERSHIP, entry_label="groupName",
        ),
        SectionSpec(
            "configuration_profiles", "CONFIGURATION_PROFILES", "configurationProfiles",
            entry_kind="configuration_profile", entry_fields=_CONFIGURATION_PROFILE, entry_label="displayName",
        ),
        SectionSpec(
            "local_user_accounts", "LOCAL_USER_ACCOUNTS", "localUserAccounts",
            entry_kind="local_user_account", entry_fields=_LOCAL_USER_ACCOUNT,
        ),
        SectionSpec(
            "certificates", "CERTIFICATES", "certificates",
            entry_kind="certificate", entry_fields=_CERTIFICATE,
        ),
        SectionSpec(
            "software_updates", "SOFTWARE_UPDATES", "softwareUpdates",
            entry_kind="software_update", entry_fields=_SOFTWARE_UPDATE,
        ),
    )
}

# The whole of v0. A sweep requests exactly these; an ingest profile (#27) may narrow
# the set, and the narrowing is recorded in the aperture so it reads as a scope change
# rather than as every omitted section "disappearing".
V0_SECTIONS: tuple[str, ...] = tuple(SECTIONS)

# Extension attributes are reported in four places — a top-level array, and one nested
# under each section an admin chose as the EA's "inventory display". The contract merges
# all of them into one section keyed by definition id, so moving an EA between display
# sections in Jamf changes nothing here.
_NESTED_EA_SECTIONS = ("general", "hardware", "operating_system", "user_and_location", "purchasing")

# Jamf's group membership scope is computers; definitions come from a different endpoint
# and are observed as their own subject kind.
SUBJECT_COMPUTER = "computer"
SUBJECT_COMPUTER_GROUP = "computer_group"
GROUP_DEFINITION_SECTION = "definition"


def jamf_section_param(sections: Iterable[str]) -> str:
    """The `section` query parameter for computers-inventory, in registry order."""
    wanted = set(sections)
    return ",".join(spec.jamf_section for spec in SECTIONS.values() if spec.name in wanted)


# --- results ------------------------------------------------------------------------


@dataclass(frozen=True)
class Entry:
    kind: str
    digest: str
    body: dict
    label: str | None = None


@dataclass(frozen=True)
class SectionContent:
    name: str
    digest: str
    body: dict | None = None  # scalar sections
    entries: tuple[Entry, ...] = ()  # list sections, sorted by digest, unique

    @property
    def is_list(self) -> bool:
        return self.body is None

    @property
    def entry_digests(self) -> list[str]:
        return [entry.digest for entry in self.entries]


@dataclass(frozen=True)
class Observation:
    subject_kind: str
    subject_id: str
    sections: dict[str, SectionContent]
    observed_at: datetime | None = None  # device time where the source has one
    udid: str | None = None
    serial_number: str | None = None
    management_id: str | None = None
    label: str | None = None  # a display name for the subject, never hashed
    warnings: tuple[str, ...] = field(default=())

    @property
    def section_digests(self) -> dict[str, str]:
        return {name: content.digest for name, content in sorted(self.sections.items())}


# --- computers ----------------------------------------------------------------------


def _scalar_section(spec: SectionSpec, raw: Mapping) -> SectionContent:
    body = canonical_document(raw.get(spec.response_key), spec.fields or {})
    return SectionContent(name=spec.name, digest=digest(f"section:{spec.name}", canonical_json(body)), body=body)


def _entries(spec: SectionSpec, items: Iterable[Any]) -> tuple[Entry, ...]:
    by_digest: dict[str, Entry] = {}
    for item in items:
        if not isinstance(item, Mapping):
            continue
        body = canonical_document(item, spec.entry_fields or {})
        if not body:
            continue
        entry_digest = digest(f"entry:{spec.entry_kind}", canonical_json(body))
        if entry_digest in by_digest:
            continue
        label = None
        if spec.entry_label:
            raw_label = item.get(spec.entry_label)
            label = canonical_string(raw_label) or None if isinstance(raw_label, str) else None
        by_digest[entry_digest] = Entry(kind=spec.entry_kind or "", digest=entry_digest, body=body, label=label)
    return tuple(by_digest[key] for key in sorted(by_digest))


def _list_section(spec: SectionSpec, items: Iterable[Any]) -> SectionContent:
    entries = _entries(spec, items)
    # The section digest covers the sorted set of entry digests, not the entries'
    # bodies, so it is order-independent and cheap to recompute from the stored map.
    canonical = canonical_json([entry.digest for entry in entries])
    return SectionContent(name=spec.name, digest=digest(f"section:{spec.name}", canonical), entries=entries)


def _collect_extension_attributes(
    raw: Mapping, requested: set[str], quarantined: frozenset[str]
) -> list[Mapping]:
    items: list[Mapping] = []
    sources: list[Any] = [raw.get("extensionAttributes")]
    for name in _NESTED_EA_SECTIONS:
        if name in requested:
            section = raw.get(SECTIONS[name].response_key)
            if isinstance(section, Mapping):
                sources.append(section.get("extensionAttributes"))
    for source in sources:
        if not isinstance(source, list):
            continue
        for item in source:
            if not isinstance(item, Mapping):
                continue
            definition_id = item.get("definitionId")
            if definition_id is not None and str(definition_id) in quarantined:
                continue
            items.append(item)
    return items


def canonicalize_computer(
    raw: Mapping,
    sections: Sequence[str] = V0_SECTIONS,
    *,
    quarantined_extension_attributes: Iterable[str] = (),
) -> Observation:
    """One computers-inventory (or computers-inventory-detail) object → an Observation.

    Only `sections` are read. A detail record carries every section Jamf knows; a sweep
    page carries the ones it asked for; both must hash identically for the same device
    state, so anything outside the requested set is ignored even when present.

    Quarantined extension attributes (by definition id) are dropped from the
    extension_attributes section entirely. The aperture records the quarantine list, so
    the omission is explicit. This is the churn valve for EAs that report uptime,
    battery, or free disk on every recon.
    """
    unknown = [name for name in sections if name not in SECTIONS]
    if unknown:
        raise ValueError(f"sections outside contract {CONTRACT_VERSION}: {unknown}")
    requested = set(sections)
    quarantined = frozenset(str(item) for item in quarantined_extension_attributes)

    contents: dict[str, SectionContent] = {}
    for name in sections:
        spec = SECTIONS[name]
        if name == "extension_attributes":
            contents[name] = _list_section(spec, _collect_extension_attributes(raw, requested, quarantined))
        elif spec.is_list:
            items = raw.get(spec.response_key)
            contents[name] = _list_section(spec, items if isinstance(items, list) else [])
        else:
            contents[name] = _scalar_section(spec, raw)

    general = raw.get("general") if isinstance(raw.get("general"), Mapping) else {}
    hardware = raw.get("hardware") if isinstance(raw.get("hardware"), Mapping) else {}

    subject_id = raw.get("id")
    if subject_id is None:
        subject_id = general.get("id")
    if subject_id is None:
        raise ValueError("computer record has no id")

    return Observation(
        subject_kind=SUBJECT_COMPUTER,
        subject_id=str(subject_id),
        sections=contents,
        observed_at=parse_jamf_datetime(general.get("reportDate")),
        udid=_optional_string(raw.get("udid")),
        serial_number=_optional_string(hardware.get("serialNumber")),
        management_id=_optional_string(general.get("managementId")),
        label=_optional_string(general.get("name")),
    )


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = canonical_string(str(value))
    return text or None


# --- smart groups -------------------------------------------------------------------

_CRITERION: Allow = {
    "name": True,
    "priority": True,
    "andOr": True,
    "searchType": True,
    "value": True,
    "openingParen": True,
    "closingParen": True,
}

_GROUP_DEFINITION: Allow = {
    # The group's name *is* its definition here — renaming a group is a catalog event on
    # this one subject, not a membership change on every member.
    "name": True,
    "siteId": True,
    "criteria": True,  # replaced below with the ordered, allowlisted criteria
}


def canonicalize_smart_group(raw: Mapping) -> Observation:
    """One /v3/computer-groups/smart-groups/{id} object → an Observation with a single
    `definition` section. Criteria are ordered by priority and their conjunction is
    lower-cased (Jamf accepts "AND" and "and" as the same thing)."""
    group_id = raw.get("id")
    if group_id is None:
        raise ValueError("smart group record has no id")

    criteria_raw = raw.get("criteria")
    criteria: list[dict] = []
    if isinstance(criteria_raw, list):
        for item in criteria_raw:
            if not isinstance(item, Mapping):
                continue
            selected = _select(item, _CRITERION)
            if isinstance(selected.get("andOr"), str):
                selected["andOr"] = selected["andOr"].lower()
            criteria.append(selected)
        criteria.sort(key=lambda c: (c.get("priority") if isinstance(c.get("priority"), int) else 0))

    body = canonical_document({**raw, "criteria": criteria}, _GROUP_DEFINITION)
    content = SectionContent(
        name=GROUP_DEFINITION_SECTION,
        digest=digest(f"section:{GROUP_DEFINITION_SECTION}", canonical_json(body)),
        body=body,
    )
    return Observation(
        subject_kind=SUBJECT_COMPUTER_GROUP,
        subject_id=str(group_id),
        sections={GROUP_DEFINITION_SECTION: content},
        label=_optional_string(raw.get("name")),
    )


# --- head and aperture --------------------------------------------------------------


def compute_head_digest(
    subject_kind: str, subject_id: str, aperture_digest: str, section_digests: Mapping[str, str]
) -> str:
    """The span boundary. Includes the subject so a head names *whose* state it is, and
    the aperture so a change in what was asked of Jamf starts a new span explicitly
    instead of leaking in as per-section noise."""
    return digest(
        "head",
        canonical_json(
            {
                "subject": {"kind": subject_kind, "id": subject_id},
                "aperture": aperture_digest,
                "sections": dict(sorted(section_digests.items())),
            }
        ),
    )


_COLLECTION_PREFERENCES: Allow = {
    "monitorApplicationUsage": True,
    "includeFonts": True,
    "includePlugins": True,
    "includePackages": True,
    "includeSoftwareUpdates": True,
    "includeSoftwareId": True,
    "includeAccounts": True,
    "calculateSizes": True,
    "includeHiddenAccounts": True,
    "includePrinters": True,
    "includeServices": True,
    "collectSyncedMobileDeviceInfo": True,
    "updateLdapInfoOnComputerInventorySubmissions": True,
    "monitorBeacons": True,
    "allowChangingUserAndLocation": True,
    "useUnixUserPaths": True,
    "collectUnmanagedCertificates": True,
}


def _paths(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    paths = []
    for item in value:
        if isinstance(item, Mapping) and isinstance(item.get("path"), str):
            path = canonical_string(item["path"])
            if path:
                paths.append(path)
    return sorted(paths)


@dataclass(frozen=True)
class Aperture:
    document: dict
    digest: str


def build_aperture(
    *,
    host: str,
    jamf_version: str | None,
    sections: Iterable[str],
    inventory_collection: Mapping | None,
    quarantined_extension_attributes: Iterable[str] = (),
) -> Aperture:
    """Everything about *how* the observation was taken that could change what it
    contains without the device changing: the collector and its version, the sections
    requested, Jamf's own inventory-collection settings (the paths it scans, whether it
    reads home directories, accounts, printers…), and the EA quarantine.

    SimpleMDM reports roughly a fifth more applications than Jamf for the same Mac,
    because Jamf inventories over configured paths rather than reading the MDM
    application list. An app list is a function of (device, collector, collector
    config); this digest names the last two so their changes are ledger events rather
    than fleet-wide phantom churn.

    `inventory_collection` is None when the API client lacks the privilege to read it.
    That is recorded explicitly as `{"available": false}` rather than by omission, so it
    can never be confused with settings that were read and happened to be empty — and
    so granting the privilege later reads as an aperture change, honestly, once.
    """
    collection: dict = {"available": inventory_collection is not None}
    if inventory_collection is not None:
        collection.update(
            {
                "preferences": canonical_document(
                    inventory_collection.get("computerInventoryCollectionPreferences"), _COLLECTION_PREFERENCES
                ),
                "applicationPaths": _paths(inventory_collection.get("applicationPaths")),
                "fontPaths": _paths(inventory_collection.get("fontPaths")),
                "pluginPaths": _paths(inventory_collection.get("pluginPaths")),
            }
        )
    document = {
        "contract": CONTRACT_VERSION,
        "collector": {
            "provider": "jamf",
            "host": canonical_string(host),
            "version": canonical_string(jamf_version) if jamf_version else None,
        },
        "sections": sorted(set(sections)),
        "inventoryCollection": collection,
        "quarantinedExtensionAttributes": sorted({str(item) for item in quarantined_extension_attributes}),
    }
    pruned = _prune(document) or {}
    return Aperture(document=pruned, digest=digest("aperture", canonical_json(pruned)))
