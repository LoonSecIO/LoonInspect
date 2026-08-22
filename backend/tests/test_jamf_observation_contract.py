"""`app.mdm.jamf.contract` is the observation contract, frozen in docs/jamf-observations.md.

Every digest here is a literal, not a recomputation. The contract's job is to make "the
same device state" hash to the same bytes forever — across sweeps, webhooks, and every
future release — so a test that follows the implementation proves only self-consistency,
which is the one property that does not matter. If a change breaks a vector, the change
is wrong; the contract evolves only behind a new version string.

Two kinds of vector:

* **Recipe vectors** — digests computed in this file from the documented recipe alone
  (hashlib + json.dumps), checked against the implementation. These prove the doc and
  the code describe the same bytes.
* **Fixture vectors** — digests of the documented-schema record in
  tests/fixtures/jamf/computer_inventory_detail.json, frozen from the first run. These
  catch any drift in selection, pruning, merging, or ordering.

The semantic tests below the vectors pin the rules the vectors alone cannot: what is
excluded, what merges, what is a label, what is absence.
"""

from __future__ import annotations

import copy
import hashlib
import json
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.mdm.jamf import contract as c

FIXTURE = Path(__file__).parent / "fixtures" / "jamf" / "computer_inventory_detail.json"


@pytest.fixture
def raw() -> dict:
    return json.loads(FIXTURE.read_text())


def _digests(record: dict, sections=c.V0_SECTIONS, **kwargs) -> dict[str, str]:
    return c.canonicalize_computer(record, sections, **kwargs).section_digests


def _recipe(kind: str, body) -> str:
    """The documented recipe, independent of the implementation."""
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    payload = "\x1f".join(["loon.jamf.observation", "v0", kind, canonical])
    return "v0:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --- recipe vectors ---------------------------------------------------------------


def test_application_entry_recipe_vector(raw: dict) -> None:
    expected = "v0:3a9edfeecdef9d7bc6c5f66afcd5b477c324b617a11b4096946e2a85afdb26d5"
    assert (
        _recipe(
            "entry:application",
            {
                "bundleId": "com.tinyspeck.slackmacgap",
                "macAppStore": True,
                "name": "Slack.app",
                "path": "/Applications/Slack.app",
                "version": "4.39.95",
            },
        )
        == expected
    )
    observation = c.canonicalize_computer(raw)
    slack = [e for e in observation.sections["applications"].entries if e.body["bundleId"] == "com.tinyspeck.slackmacgap"]
    assert [e.digest for e in slack] == [expected]


def test_extension_attribute_entry_recipe_vector(raw: dict) -> None:
    """Values sorted, name absent: the EA is its definition id plus its values."""
    expected = "v0:d2ce67a4398db7f555dbe4d96e48eda412fc1aa9d51c74e1ded5cee9afbd4328"
    assert _recipe("entry:extension_attribute", {"definitionId": "27", "values": ["Engineering", "Research"]}) == expected
    entries = c.canonicalize_computer(raw).sections["extension_attributes"].entries
    match = [e for e in entries if e.body["definitionId"] == "27"]
    assert [e.digest for e in match] == [expected]
    assert match[0].label == "Departments Served"


def test_group_membership_entry_recipe_vector(raw: dict) -> None:
    expected = "v0:96594ee6aa8bc4da4a3f1b61d7af4c14eef03fcb287fab4a5b0e760ce279da6d"
    assert _recipe("entry:group_membership", {"groupId": "17", "smartGroup": True}) == expected
    entries = c.canonicalize_computer(raw).sections["group_memberships"].entries
    assert any(e.digest == expected and e.label == "Falcon Installed" for e in entries)


def test_list_section_recipe_vector(raw: dict) -> None:
    """A list section's digest is the digest of the sorted array of its entry digests."""
    entry = _recipe("entry:software_update", {"name": "macOS Sonoma 14.6.1", "version": "14.6.1"})
    assert entry == "v0:8fca1f74a190fdd9918981bad7b4e5b27ad11e2880aef6e3c758ed73d74f3cda"
    section = _recipe("section:software_updates", [entry])
    assert section == "v0:44de6270b38e6fe820cd6da26c0ffaa23e2a93068864809ff54b3e7e38154642"
    assert _digests(raw)["software_updates"] == section


def test_head_recipe_vector() -> None:
    aperture = "v0:" + "a" * 64
    sections = {"general": "v0:" + "b" * 64, "applications": "v0:" + "c" * 64}
    expected = _recipe(
        "head",
        {"subject": {"kind": "computer", "id": "42"}, "aperture": aperture, "sections": sections},
    )
    assert c.compute_head_digest("computer", "42", aperture, sections) == expected
    assert expected == "v0:ae21644bd019cdc6c6876e7b77d70fe0582e992eb40423484ca0df5f7756d8fe"


# --- fixture vectors --------------------------------------------------------------

FIXTURE_SECTION_DIGESTS = {
    "general": "v0:ac3c9f5b6d4767661ac5280caaba292ce8d0f60490d52dbe7d8cad29248219cd",
    "hardware": "v0:5e4a14724cd33d645722175ca9fdf02a2cdb46d437bad17ca7a419255f6fdce3",
    "operating_system": "v0:b7dcf6ea95b54a4fe05a1f990ad9ac9452d84627dad9afcce683d9ca758512bb",
    "user_and_location": "v0:56e5f59b46cdb1d2a9f9515ab91409db77192c600440af69b770cc567df223f6",
    "purchasing": "v0:f358a0de87ba1fe99c02172141b0cb263ee8be675dfc4a13c43b654454499948",
    "security": "v0:270f56e709e0474180e1e30b5b452c2d34878fa387c0fb29019a206b91981e39",
    "disk_encryption": "v0:cad8c41a0c2376973c5ef0f1cc61bf260c63722fd6d13aabdd1270e038854045",
    "applications": "v0:4d6178315ccc044f763aa61ffb0864a42f4417087b24f180950ed5a3a4567583",
    "extension_attributes": "v0:f497130e7d0dfb9739fbfacb0fd1f4609b8da19d7faeecd39e90dc9cf36be942",
    "group_memberships": "v0:10f3e7bef805088e1f27bccc99fe8137453747a4641d58a7aeb89c5234802502",
    "configuration_profiles": "v0:f9344e19d484f21304102f0af80e4a0f16bcb94d1d1d3cc9caac18289dd59c25",
    "local_user_accounts": "v0:9c6bad2b75fabc1bd16e5a351ffbcf17e90d117c8d47f32e3d92fed591931fcc",
    "certificates": "v0:17f9dca9446d6b96cdc5c308fe63ad0165a1e05e62a2637ec6c97ad2e8036f0c",
    "software_updates": "v0:44de6270b38e6fe820cd6da26c0ffaa23e2a93068864809ff54b3e7e38154642",
}

FIXTURE_APERTURE_DIGEST = "v0:febc57ec36d9d77d0f608ecf47b035095d9d8d6c55c3c01db570beb74ea0746c"
FIXTURE_HEAD_DIGEST = "v0:48c684149c4ed2071cf6dcfa96a98d320973b4355fc0afb30a5d472bf89b727b"
FIXTURE_GROUP_DIGEST = "v0:1b7e5d55fff05e4e8d5faa6bf62f6c7ec3139ac421832733538704dbe939e01f"


def _fixture_aperture() -> c.Aperture:
    return c.build_aperture(
        host="loon.jamfcloud.com",
        jamf_version="11.16.0",
        sections=c.V0_SECTIONS,
        inventory_collection={
            "computerInventoryCollectionPreferences": {"includeFonts": False, "includeAccounts": True},
            "applicationPaths": [{"id": "1", "path": "/Applications"}],
        },
    )


def test_fixture_section_vectors(raw: dict) -> None:
    assert _digests(raw) == FIXTURE_SECTION_DIGESTS


def test_fixture_identity(raw: dict) -> None:
    observation = c.canonicalize_computer(raw)
    assert observation.subject_kind == "computer"
    assert observation.subject_id == "42"
    assert observation.udid == "00008112-000A1D2E3F4G5H6I"
    assert observation.serial_number == "C02ZL0ONSEC1"
    assert observation.management_id == "5f6a0c1e-9d2b-4c3a-8e7f-1a2b3c4d5e6f"
    assert observation.label == "mbp-ada"
    assert observation.observed_at == datetime(2026, 8, 21, 7, 15, 42, tzinfo=timezone.utc)


def test_fixture_aperture_and_head_vectors(raw: dict) -> None:
    aperture = _fixture_aperture()
    assert aperture.digest == FIXTURE_APERTURE_DIGEST
    observation = c.canonicalize_computer(raw)
    assert (
        c.compute_head_digest("computer", "42", aperture.digest, observation.section_digests)
        == FIXTURE_HEAD_DIGEST
    )


def test_fixture_group_vector() -> None:
    group = c.canonicalize_smart_group(
        {
            "id": "17",
            "name": "Falcon Installed",
            "siteId": "-1",
            "criteria": [
                {
                    "name": "Application Title", "priority": 1, "andOr": "AND", "searchType": "is",
                    "value": "Falcon.app", "openingParen": False, "closingParen": False,
                },
                {
                    "name": "Computer Group", "priority": 0, "andOr": "and", "searchType": "member of",
                    "value": "All Managed Clients",
                },
            ],
        }
    )
    assert group.subject_kind == "computer_group"
    assert group.subject_id == "17"
    assert group.label == "Falcon Installed"
    assert group.sections["definition"].digest == FIXTURE_GROUP_DIGEST
    assert [criterion["name"] for criterion in group.sections["definition"].body["criteria"]] == [
        "Computer Group",
        "Application Title",
    ]


# --- rule 1: allowlist, telemetry excluded ---------------------------------------


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("general", "lastContactTime"), "2030-01-01T00:00:00Z"),
        (("general", "reportDate"), "2030-01-01T00:00:00Z"),
        (("general", "lastIpAddress"), "192.0.2.1"),
        (("general", "lastReportedIpV4"), "192.0.2.1"),
        (("general", "lastLoggedInUsernameBinary"), "someone-else"),
        (("general", "mdmCapable", "capableUsers"), ["x", "y"]),
        (("hardware", "batteryCapacityPercent"), 3),
        (("hardware", "batteryHealth"), "SERVICE_RECOMMENDED"),
        (("hardware", "nicSpeed"), "100"),
        (("security", "lastAttestationAttempt"), "2030-01-01T00:00:00Z"),
        (("diskEncryption", "bootPartitionEncryptionDetails", "partitionFileVault2Percent"), 12),
    ],
)
def test_telemetry_never_reaches_a_digest(raw: dict, path, value) -> None:
    before = _digests(raw)
    target = raw
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert _digests(raw) == before


def test_application_telemetry_is_excluded_but_version_is_not(raw: dict) -> None:
    before = _digests(raw)["applications"]
    raw["applications"][1]["sizeMegabytes"] = 9999
    raw["applications"][1]["updateAvailable"] = not raw["applications"][1]["updateAvailable"]
    raw["applications"][1]["externalVersionId"] = "777"
    assert _digests(raw)["applications"] == before

    raw["applications"][1]["version"] = "128.0.0.1"
    assert _digests(raw)["applications"] != before


def test_certificate_status_is_excluded_but_expiry_is_not(raw: dict) -> None:
    """Jamf derives lifecycleStatus/certificateStatus from the dates and the clock, so
    they flip with no change on the device; the dates themselves are content."""
    before = _digests(raw)["certificates"]
    raw["certificates"][2]["certificateStatus"] = "EXPIRED"
    raw["certificates"][2]["lifecycleStatus"] = "INACTIVE"
    assert _digests(raw)["certificates"] == before
    raw["certificates"][2]["expirationDate"] = "2027-09-15T00:00:00Z"
    assert _digests(raw)["certificates"] != before


def test_unknown_fields_are_ignored(raw: dict) -> None:
    """A field Jamf adds in a later release must not change every device's digest."""
    before = _digests(raw)
    raw["general"]["someFutureField"] = "x"
    raw["hardware"]["neuralEngineCores"] = 16
    raw["applications"][0]["notarized"] = True
    raw["certificates"][0]["keyUsage"] = ["digitalSignature"]
    assert _digests(raw) == before


def test_sections_outside_the_contract_raise() -> None:
    with pytest.raises(ValueError):
        c.canonicalize_computer({"id": "1"}, ("general", "fonts"))


def test_only_requested_sections_are_read(raw: dict) -> None:
    """A detail record (every section) and a sweep page (the requested ones) must hash
    identically for the same device state, so unrequested sections are ignored even
    when present."""
    subset = ("general", "applications")
    full_record = c.canonicalize_computer(raw, subset)
    trimmed = {"id": raw["id"], "general": raw["general"], "applications": raw["applications"]}
    assert full_record.section_digests == c.canonicalize_computer(trimmed, subset).section_digests
    assert set(full_record.sections) == set(subset)


# --- rule 2: names of Jamf objects are labels ------------------------------------


def test_renaming_a_group_changes_no_membership_digest(raw: dict) -> None:
    before = c.canonicalize_computer(raw).sections["group_memberships"]
    raw["groupMemberships"][1]["groupName"] = "Falcon Installed (renamed)"
    raw["groupMemberships"][1]["groupDescription"] = "edited"
    after = c.canonicalize_computer(raw).sections["group_memberships"]
    assert after.digest == before.digest
    assert {e.label for e in after.entries} != {e.label for e in before.entries}


def test_renaming_an_extension_attribute_changes_no_digest(raw: dict) -> None:
    before = _digests(raw)["extension_attributes"]
    raw["extensionAttributes"][0]["name"] = "Battery Cycles (renamed)"
    raw["extensionAttributes"][0]["description"] = "edited"
    raw["extensionAttributes"][0]["inputType"] = "TEXT"
    assert _digests(raw)["extension_attributes"] == before


def test_renaming_a_profile_changes_no_digest_but_redeploying_does(raw: dict) -> None:
    before = _digests(raw)["configuration_profiles"]
    raw["configurationProfiles"][0]["displayName"] = "FileVault Escrow v2"
    raw["configurationProfiles"][0]["lastInstalled"] = "2030-01-01T00:00:00Z"
    assert _digests(raw)["configuration_profiles"] == before
    raw["configurationProfiles"][0]["uuid"] = "00000000-0000-4000-8000-000000000000"
    assert _digests(raw)["configuration_profiles"] != before


def test_site_and_prestage_names_are_not_content(raw: dict) -> None:
    before = _digests(raw)["general"]
    raw["general"]["site"]["name"] = "Renamed Site"
    raw["general"]["enrollmentMethod"]["objectName"] = "Renamed PreStage"
    assert _digests(raw)["general"] == before
    raw["general"]["site"]["id"] = "7"
    assert _digests(raw)["general"] != before


def test_group_rename_is_a_definition_change() -> None:
    """The other half of rule 2: the name lives on the group's own subject, where a
    rename is one explicit event instead of one per member."""
    base = {"id": "17", "name": "Falcon Installed", "criteria": []}
    renamed = {**base, "name": "Falcon Present"}
    assert c.canonicalize_smart_group(base).section_digests != c.canonicalize_smart_group(renamed).section_digests


# --- rule 3: absence, order, normalization ----------------------------------------


def test_null_empty_and_missing_are_one_thing(raw: dict) -> None:
    before = _digests(raw)
    raw["general"]["barcode1"] = None  # was ""
    raw["general"]["distributionPoint"] = "   "
    del raw["general"]["barcode2"]  # was ""
    raw["diskEncryption"]["fileVault2EligibilityMessage"] = None
    raw["softwareUpdates"][0]["packageName"] = None  # was ""
    raw["purchasing"]["appleCareId"] = None
    assert _digests(raw) == before


def test_list_order_does_not_matter(raw: dict) -> None:
    before = _digests(raw)
    raw["applications"].reverse()
    raw["certificates"].reverse()
    raw["groupMemberships"].reverse()
    raw["extensionAttributes"][1]["values"] = ["Research", "Engineering"]
    raw["diskEncryption"]["fileVault2EnabledUserNames"] = ["localadmin", "ada"]
    assert _digests(raw) == before


def test_identical_entries_collapse(raw: dict) -> None:
    before = _digests(raw)["applications"]
    raw["applications"].append(copy.deepcopy(raw["applications"][0]))
    assert _digests(raw)["applications"] == before
    # A second copy at a different path is a different install.
    other = copy.deepcopy(raw["applications"][0])
    other["path"] = "/Users/ada/Applications/Safari.app"
    raw["applications"].append(other)
    assert _digests(raw)["applications"] != before


def test_timestamp_precision_and_zone_are_not_content(raw: dict) -> None:
    before = _digests(raw)
    raw["general"]["lastEnrolledDate"] = "2025-11-03T16:20:07Z"  # was .000Z
    raw["general"]["mdmProfileExpiration"] = "2027-11-03T18:20:07.500+02:00"  # same instant
    raw["certificates"][0]["expirationDate"] = "2034-11-01T00:00:00.000Z"
    assert _digests(raw) == before


def test_canonical_timestamp_rules() -> None:
    assert c.canonical_timestamp("2025-11-03T16:20:07.123Z") == "2025-11-03T16:20:07Z"
    assert c.canonical_timestamp("2025-11-03T18:20:07+02:00") == "2025-11-03T16:20:07Z"
    assert c.canonical_timestamp("2025-11-03") == "2025-11-03"  # date-only passes through
    assert c.canonical_timestamp("not a date") == "not a date"
    assert c.parse_jamf_datetime("2025-11-03T16:20:07.391Z") == datetime(2025, 11, 3, 16, 20, 7, tzinfo=timezone.utc)
    assert c.parse_jamf_datetime("2025-11-03") is None
    assert c.parse_jamf_datetime(None) is None


def test_nfc_and_nfd_spellings_are_one_entry(raw: dict) -> None:
    nfc_name = unicodedata.normalize("NFC", "Café Tool.app")
    nfd_name = unicodedata.normalize("NFD", "Café Tool.app")
    assert nfc_name != nfd_name
    before = _digests(raw)["applications"]
    target = next(app for app in raw["applications"] if app["bundleId"] == "io.example.cafetool")
    assert target["name"] == nfc_name
    target["name"] = nfd_name
    assert _digests(raw)["applications"] == before


def test_false_and_zero_are_values(raw: dict) -> None:
    before = _digests(raw)
    raw["security"]["firewallEnabled"] = False
    assert _digests(raw)["security"] != before["security"]
    raw["hardware"]["openRamSlots"] = 2  # was 0, and 0 was hashed
    assert _digests(raw)["hardware"] != before["hardware"]


# --- extension attributes: merge and quarantine ------------------------------------


def test_extension_attributes_merge_from_every_display_section(raw: dict) -> None:
    labels = {e.label for e in c.canonicalize_computer(raw).sections["extension_attributes"].entries}
    assert labels == {
        "Battery Cycle Count",
        "Departments Served",
        "Crowdstrike Sensor Version",
        "Uptime Days",
        "Last OS Update Check",
        "Manager",
        "Cost Center",
    }


def test_moving_an_extension_attribute_between_display_sections_changes_nothing(raw: dict) -> None:
    before = _digests(raw)
    moved = raw["hardware"]["extensionAttributes"].pop()
    raw["extensionAttributes"].append(moved)
    assert _digests(raw) == before


def test_extension_attributes_in_an_unrequested_section_are_not_merged(raw: dict) -> None:
    """Sweep and webhook must agree: the merge reads only requested sections, so the
    purchasing EA is absent when purchasing is not requested, whether or not the raw
    record happens to carry it."""
    without_purchasing = tuple(s for s in c.V0_SECTIONS if s != "purchasing")
    labels = {
        e.label
        for e in c.canonicalize_computer(raw, without_purchasing).sections["extension_attributes"].entries
    }
    assert "Cost Center" not in labels
    del raw["purchasing"]
    labels_trimmed = {
        e.label
        for e in c.canonicalize_computer(raw, without_purchasing).sections["extension_attributes"].entries
    }
    assert labels == labels_trimmed


def test_quarantined_extension_attributes_are_dropped(raw: dict) -> None:
    before = c.canonicalize_computer(raw).sections["extension_attributes"]
    quarantined = c.canonicalize_computer(raw, quarantined_extension_attributes=["9"]).sections["extension_attributes"]
    assert quarantined.digest != before.digest
    assert "Uptime Days" not in {e.label for e in quarantined.entries}
    raw["hardware"]["extensionAttributes"][0]["values"] = ["14"]  # the churn the quarantine exists for
    still = c.canonicalize_computer(raw, quarantined_extension_attributes=["9"]).sections["extension_attributes"]
    assert still.digest == quarantined.digest


# --- aperture ---------------------------------------------------------------------


def _aperture(**overrides) -> c.Aperture:
    base = {"host": "x.jamfcloud.com", "jamf_version": "11.16.0", "sections": c.V0_SECTIONS, "inventory_collection": {}}
    return c.build_aperture(**(base | overrides))


def test_aperture_is_order_insensitive_and_records_absence() -> None:
    a = _aperture(sections=("general", "applications"))
    b = _aperture(sections=("applications", "general"))
    assert a.digest == b.digest
    unavailable = _aperture(sections=("general", "applications"), inventory_collection=None)
    assert unavailable.digest != a.digest
    assert unavailable.document["inventoryCollection"] == {"available": False}
    assert a.document["inventoryCollection"] == {"available": True}


def test_aperture_changes_with_collector_version_scope_and_quarantine() -> None:
    base = {"host": "x.jamfcloud.com", "jamf_version": "11.16.0", "sections": c.V0_SECTIONS, "inventory_collection": {}}
    reference = c.build_aperture(**base).digest
    assert c.build_aperture(**{**base, "jamf_version": "11.17.0"}).digest != reference
    assert c.build_aperture(**{**base, "sections": c.V0_SECTIONS[:-1]}).digest != reference
    assert c.build_aperture(**base, quarantined_extension_attributes=["9"]).digest != reference
    assert c.build_aperture(**{**base, "host": "y.jamfcloud.com"}).digest != reference


def test_aperture_reads_only_collection_settings_that_matter() -> None:
    settings = {
        "computerInventoryCollectionPreferences": {"includeAccounts": True, "somethingNew": True},
        "applicationPaths": [{"id": "2", "path": "/Users/Shared/Apps"}, {"id": "1", "path": "/Applications"}],
        "fontPaths": [],
    }
    aperture = c.build_aperture(host="x", jamf_version=None, sections=("general",), inventory_collection=settings)
    assert aperture.document["inventoryCollection"] == {
        "available": True,
        "applicationPaths": ["/Applications", "/Users/Shared/Apps"],
        "preferences": {"includeAccounts": True},
    }
    assert "version" not in aperture.document["collector"]


# --- the real record ----------------------------------------------------------------
#
# tests/fixtures/jamf/computer_inventory_detail_real.json is a Jamf Pro 11.31.1 record
# of an M4 Mac mini on a macOS 27 beta, scrubbed of identity (name, usernames, serials,
# UDIDs, MACs, public IP, per-device certificate identities and fingerprints — each
# replacement listed in the scrub script that produced it). It is what turned "built
# to spec" into "verified against a record": two fields the documentation did not
# mention (cfBundleVersion / cfBundleShortVersionString on applications, and
# lastContact / lastCheckIn replacing lastContactTime) surfaced here first.

REAL_FIXTURE = Path(__file__).parent / "fixtures" / "jamf" / "computer_inventory_detail_real.json"

REAL_SECTION_DIGESTS = {
    "general": "v0:dbaebf915f7a745be565808c5c421bed111dc9087e5970ca47a9fd25f24ac2ee",
    "hardware": "v0:2e7c05b6a00ada281f9e41ad861795a92b769be78eb46eeca8f73c4d5dac899b",
    "operating_system": "v0:d73f6910e85ddcfe3eb05953c93d8a5aaa5a349f9c4239059cf258d865601a70",
    "user_and_location": "v0:41adab295b8374b138c3c8d6125284e61a972cc8a522131a624aa19dadd98dd2",
    "purchasing": "v0:cbf8953200929929b6c855bfea5bfdeedb86e3659ae17624ce75fe6dfb28a77d",
    "security": "v0:e7fa6f0c71a2bea4d6482517f9d43ffc0fcaef8161ef98bc31bd901b8d9cf78f",
    "disk_encryption": "v0:f54faad660f9d8bedcdd1db55722c057cf58e19f9b536dcd5c274e4ed28f36e4",
    "applications": "v0:c96c3981508db8cbdb623bba2fbeb71ef86a4e5841937a8a55964f079611e98f",
    "extension_attributes": "v0:78202e32f4d2227500193b57763d7bd6c46942b59e31aa97c6f426ed2490df05",
    "group_memberships": "v0:4359e3372e7fe7d00213f1b99c1974c2604b1f3a4956b3732ac05f227aaf4460",
    "configuration_profiles": "v0:1197e8469b47eacdc3d7e8814a0026e1a1d803dd0dd2ab6c33e6a49a6bc760e4",
    "local_user_accounts": "v0:3a1e75ddb1e4b879ca49e17d3a14da0facaa0bf5bdac1c672f3bf2c8fa4a8809",
    "certificates": "v0:499fb23222dbeba8414a84f3fe36ab004e616b56ae86394edb885a0c78e71a54",
    "software_updates": "v0:fa821f1ce81fc441eac5a2ce53128337c56918873edc127c706bdd6022133e6c",
}
REAL_APERTURE_DIGEST = "v0:697cb22fbd69eb2e9476edca8941722ff204d3c0a2e02b72dff227d98b113b27"
REAL_HEAD_DIGEST = "v0:9737a8846151e343e730f8a1efbbe065abe1bd5c9749b3b1a41d2b09a4659ef8"
REAL_SLACK_DIGEST = "v0:06f5843400adb08cf5c65fee6a0f2cc7d57d1a42bd0a6d9f880fd8c7e45b949a"


@pytest.fixture
def real() -> dict:
    return json.loads(REAL_FIXTURE.read_text())


def test_real_record_section_vectors(real: dict) -> None:
    assert _digests(real) == REAL_SECTION_DIGESTS


def test_real_record_identity_and_head(real: dict) -> None:
    observation = c.canonicalize_computer(real)
    assert observation.subject_id == "3"
    assert observation.udid == "A1B2C3D4-0000-4000-8000-0000000000A3"
    assert observation.serial_number == "LOONMINI0M4"
    assert observation.management_id == "11111111-2222-4333-8444-555555555555"
    assert observation.label == "Loon\u2019s Mac mini"  # the curly apostrophe survives NFC intact
    assert observation.observed_at == datetime(2026, 8, 21, 21, 44, 27, tzinfo=timezone.utc)
    aperture = c.build_aperture(
        host="loon.jamfcloud.com", jamf_version="11.31.1", sections=c.V0_SECTIONS, inventory_collection=None
    )
    assert aperture.digest == REAL_APERTURE_DIGEST
    assert c.compute_head_digest("computer", "3", aperture.digest, observation.section_digests) == REAL_HEAD_DIGEST


def test_real_record_bundle_versions_are_content(real: dict) -> None:
    """Jamf 11.31 reports cfBundleVersion and cfBundleShortVersionString; a build bump
    under the same marketing version is a real change and must move the digest."""
    entries = c.canonicalize_computer(real).sections["applications"].entries
    slack = next(e for e in entries if e.body["bundleId"] == "com.tinyspeck.slackmacgap")
    assert slack.digest == REAL_SLACK_DIGEST
    assert slack.body["cfBundleVersion"] == "450000143" and slack.body["version"] == "4.50.143"
    assert _recipe("entry:application", slack.body) == REAL_SLACK_DIGEST

    before = _digests(real)["applications"]
    target = next(app for app in real["applications"] if app["bundleId"] == "com.tinyspeck.slackmacgap")
    target["cfBundleVersion"] = "450000144"
    assert _digests(real)["applications"] != before


def test_real_record_jamf_managed_profiles_are_keyed_by_identifier(real: dict) -> None:
    """Jamf's own profiles arrive with id and uuid null; the profileIdentifier is what
    is left, and five distinct ones must stay five entries."""
    profiles = c.canonicalize_computer(real).sections["configuration_profiles"].entries
    assert len(profiles) == 5
    assert {e.label for e in profiles} >= {"MDM Profile", "Jamf Notifications"}
    assert all("profileIdentifier" in e.body for e in profiles)


def test_real_record_empty_extension_attributes_are_still_entries(real: dict) -> None:
    """An EA defined on the server but unanswered by the device is the definition id
    alone — present, so a first value later is a change rather than an appearance."""
    entries = c.canonicalize_computer(real).sections["extension_attributes"].entries
    assert sorted(e.body["definitionId"] for e in entries) == ["1", "2", "3"]
    assert all(set(e.body) == {"definitionId"} for e in entries)


def test_real_record_current_state_normalizer(real: dict) -> None:
    from app.mdm.jamf.client import normalize_computer

    device = normalize_computer(real)
    assert device.external_id == "3" and device.serial_number == "LOONMINI0M4"
    assert device.os_version == "27.0" and len(device.apps) == 83
    # lastContact (11.31) rather than the documented lastContactTime.
    assert device.last_check_in == datetime(2026, 8, 22, 13, 47, 30, tzinfo=timezone.utc)
    assert device.last_inventory_at == datetime(2026, 8, 21, 21, 44, 27, tzinfo=timezone.utc)


# --- smart groups -----------------------------------------------------------------


def _criterion(name: str, priority: int, and_or: str, value: str) -> dict:
    return {"name": name, "priority": priority, "andOr": and_or, "searchType": "is", "value": value}


def test_smart_group_conjunction_is_case_insensitive_and_priority_ordered() -> None:
    upper = {"id": "1", "name": "g", "criteria": [_criterion("A", 1, "AND", "1"), _criterion("B", 0, "OR", "2")]}
    lower = {"id": "1", "name": "g", "criteria": [_criterion("B", 0, "or", "2"), _criterion("A", 1, "and", "1")]}
    assert c.canonicalize_smart_group(upper).section_digests == c.canonicalize_smart_group(lower).section_digests


def test_smart_group_criteria_changes_are_definition_changes() -> None:
    base = {"id": "1", "name": "g", "criteria": [{"name": "A", "priority": 0, "andOr": "and", "searchType": "is", "value": "1"}]}
    changed = copy.deepcopy(base)
    changed["criteria"][0]["value"] = "2"
    parens = copy.deepcopy(base)
    parens["criteria"][0]["openingParen"] = True
    assert c.canonicalize_smart_group(base).section_digests != c.canonicalize_smart_group(changed).section_digests
    assert c.canonicalize_smart_group(base).section_digests != c.canonicalize_smart_group(parens).section_digests


def test_jamf_section_param_is_registry_ordered() -> None:
    assert c.jamf_section_param(("applications", "general")) == "GENERAL,APPLICATIONS"
    assert c.jamf_section_param(c.V0_SECTIONS).split(",")[0] == "GENERAL"
