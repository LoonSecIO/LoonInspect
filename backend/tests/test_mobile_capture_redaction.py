"""The scrub behind the mobile capture (#238), over a sample shaped like a record.

The capture runs once, against the maintainer's own tenant, and what it writes is committed to a
public repository — there is no second chance to notice that a key held an identifier. Every
identifier below is a *different* shape on purpose: an e-mail under an unread key would pass on the
sweep alone and prove nothing about the key rule meant to catch it. Two keys no rule names are here
because a first capture of an unread endpoint is exactly where one turns up.

Two of the shapes are not identifiers at all. A password and an activation-lock bypass code match no
sweep — a secret looks like nothing — so only a key rule can catch one, and `airPlayPassword` reached a
written fixture in full before this test existed. The rest is the `held` list: what the scrub wrote out
as the tenant wrote it, which is the only list "read it before committing it" can be read against.
"""

from __future__ import annotations

import json
import re

from scripts.capture_jamf_mobile_device import redact

SAMPLE = json.loads("""
{
  "id": "12", "name": "Kyle's iPad", "udid": "8A0F1C2D-1111-4222-8333-444455556666",
  "general": {"enrollmentMethodPrestage": {"id": "3", "profileName": "Kyle's iPad Prestage"},
              "enrollmentMethod": {"id": "3", "objectName": "Kyle's iPad Prestage"}},
  "ebooks": [{"title": "Loon Handbook", "author": "Kyle Pazandak", "version": "1.2", "kind": "IBOOK"}],
  "serviceSubscriptions": [{"label": "Kyle Personal", "phoneNumber": "612-555-0123",
                            "carrierSettingsVersion": "54.0"}],
  "serialNumber": "DMPX1234ABCD", "wifiMacAddress": "AC:DE:48:00:11:22", "ipAddress": "198.51.100.7",
  "supervised": true, "enforceName": false, "batteryLevel": 88, "osVersion": "26.1.2",
  "airPlayPassword": "Loon1nspect!2026",
  "location": {"username": "kpazandak", "realName": "Kyle Pazandak", "emailAddress": "kyle@loonsec.io",
               "phoneNumber": "+1-612-555-0123", "room": "Studio", "department": null,
               "latitude": 44.9778, "longitude": -93.265},
  "network": {"imei": "351234567890123", "iccid": "89012601234567890123", "homeCarrierNetwork": "Verizon"},
  "security": {"lostModeEnabled": true, "lostModePhone": "612-555-0100",
               "activationLockBypassCode": "3CJH-XNMA-9K2P-LL41-QQ1Z-TT9W",
               "passcodePresent": true, "passcodeLockGracePeriodEnforced": 300,
               "lostModeMessage": "Call Kyle Pazandak on 612-555-0100", "lostModeFootnote": "Property of Kyle Pazandak",
               "lostModeLocation": {"lostModeLocationLatitude": 44.9778, "lostModeLocationLongitude": -93.265}},
  "applications": [{"name": "Wireshark.app", "shortVersion": "2.6.6", "bundleId": "org.wireshark.Wireshark"}],
  "certificates": [{"commonName": "LoonSecIO JSS Built-in Certificate Authority", "identity": true}],
  "sharedUsers": [{"username": "kpazandak"}],
  "extensionAttributes": [{"name": "Device Owner", "type": "STRING", "value": ["kpazandak"]}],
  "enrollmentNote": "enrolled by 8A0F1C2D-1111-4222-8333-444455556666",
  "purchasingNote": "warranty desk (612) 555-0177"
}
""")
IDENTIFIERS = (
    "Kyle's iPad|8A0F1C2D-1111-4222-8333-444455556666|DMPX1234ABCD|AC:DE:48:00:11:22|198.51.100.7|kpazandak|"
    "Kyle Pazandak|kyle@loonsec.io|612-555-0123|612-555-0100|555-0177|Studio|351234567890123|"
    "89012601234567890123|44.9778|93.265|Loon1nspect!2026|3CJH-XNMA-9K2P-LL41-QQ1Z-TT9W|"
    # Tenant-chosen names under keys that are not `name`: Jamf spells the PreStage `profileName` and
    # `objectName`, an e-book carries the author and title the tenant loaded, and a cellular line's
    # `label` is what the device's own user typed on the iPhone.
    "Kyle's iPad Prestage|Loon Handbook|Kyle Personal"
)
# The smart-group read is one of the three the capture makes, and the likeliest to be a Classic body:
# its criteria hold whatever the tenant searched on, under a key that says only `value`.
GROUP = json.loads("""
{"mobile_device_group": {"id": 12, "name": "Kyle's iPads", "is_smart": true,
  "criteria": [{"criterion": {"name": "Serial Number", "priority": 0, "search_type": "is",
                              "value": "DMPX1234ABCD"}},
               {"criterion": {"name": "Username", "priority": 1, "search_type": "is", "value": "kpazandak"}}],
  "mobile_devices": [{"id": 3, "name": "Kyle's iPad", "serial_number": "DMPX1234ABCD",
                      "udid": "8A0F1C2D-1111-4222-8333-444455556666", "username": "kpazandak"}]}}
""")


def test_no_identifier_survives() -> None:
    redacted, _ = redact(SAMPLE)
    written = json.dumps(redacted)
    for identifier in IDENTIFIERS.split("|"):
        assert identifier not in written, f"{identifier} reached the fixture"


def test_the_shapes_the_contract_reads_survive() -> None:
    redacted, scrub = redact(SAMPLE)
    assert redacted["supervised"] is True and redacted["enforceName"] is False
    assert redacted["batteryLevel"] == 88 and redacted["osVersion"] == "26.1.2"
    assert redacted["applications"][0] == SAMPLE["applications"][0]  # an app name is not an identifier
    assert redacted["extensionAttributes"][0]["name"] == "Device Owner" and redacted["network"]["homeCarrierNetwork"] == "Verizon"
    # absent stays absent rather than becoming a placeholder, and the Jamf id is the subject, not an identity
    assert redacted["location"]["department"] is None and redacted["id"] == "12"
    assert re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", redacted["wifiMacAddress"])
    assert len(redacted["network"]["imei"]) == len(SAMPLE["network"]["imei"])
    # a coordinate is replaced in its own type, and the flag beside it is a shape, not an identity
    assert redacted["location"]["latitude"] == 0.0 and redacted["security"]["lostModeEnabled"] is True
    assert scrub.counts["uuid"] == 1  # the same UDID twice is one replacement


def test_no_secret_reaches_the_fixture() -> None:
    """A secret matches no sweep, so the key rule is the whole defence — and a flag beside it is a shape."""
    redacted, _ = redact(SAMPLE)
    assert redacted["airPlayPassword"] == "redacted-secret-1"
    assert redacted["security"]["activationLockBypassCode"] == "redacted-secret-2"
    assert redacted["security"]["passcodePresent"] is True
    assert redacted["security"]["passcodeLockGracePeriodEnforced"] == 300


def test_every_key_no_rule_names_is_held_for_a_human_to_read() -> None:
    """`held` is the list the fixture is read against: every string written as the tenant wrote it,
    under a key no rule named. A version, an enum and a Jamf id are not on it — nobody re-reads those."""
    _, scrub = redact(SAMPLE)
    assert scrub.held == {
        "applications.name",
        "applications.bundleId",
        "extensionAttributes.name",
        "network.homeCarrierNetwork",
        "enrollmentNote",
        "purchasingNote",
    }


def test_an_identifier_shape_under_an_unread_key_is_held() -> None:
    """The shapes no sweep can see. A bare serial, a bare phone number, an ICCID and an IMEI match none of
    the four sweep patterns, so if `_TRIVIAL` calls them trivial they are written out whole and never named
    — the held list is the only thing left that can say so. Beside them, what nobody re-reads stays off it."""
    sample = {
        "aKeyNoRuleNames": "DMPX1234ABCD",
        "anotherKeyNoRuleNames": "6125550123",
        "aThirdKeyNoRuleNames": "89012601234567890123",
        "aFourthKeyNoRuleNames": "351234567890123",
        "ownership": "INSTITUTIONAL",
        "release": "26.1.2",
        "lastInventoryUpdate": "2026-09-16T14:03:11.000+0000",
        "managed": "true",
        "gracePeriod": "300",
    }
    redacted, scrub = redact(sample)
    assert redacted == sample  # no rule names these keys and no sweep matches: it is all written as it came
    assert scrub.swept == set()
    assert scrub.held == {"aKeyNoRuleNames", "anotherKeyNoRuleNames", "aThirdKeyNoRuleNames", "aFourthKeyNoRuleNames"}


def test_a_group_body_is_scrubbed_and_still_joins_to_the_device() -> None:
    """One scrub for the whole trip, as the capture runs it: what the group searched on has to survive
    as a join to the device record, or the fixture cannot show what a smart group actually selects."""
    device, scrub = redact(SAMPLE)
    group, _ = redact(GROUP, scrub)
    written = json.dumps(group)
    for identifier in ("Kyle's iPad", "Kyle's iPads", "DMPX1234ABCD", "kpazandak"):
        assert identifier not in written, f"{identifier} reached the fixture"
    inner = group["mobile_device_group"]
    assert [criterion["criterion"]["name"] for criterion in inner["criteria"]] == ["Serial Number", "Username"]
    assert inner["criteria"][0]["criterion"]["value"] == device["serialNumber"]
    assert inner["criteria"][1]["criterion"]["value"] == device["location"]["username"]
    assert inner["mobile_devices"][0]["udid"] == device["udid"]
    assert inner["mobile_devices"][0]["name"] == device["name"]  # the same iPad, the same placeholder


def test_joins_survive_and_unknown_keys_are_swept() -> None:
    redacted, scrub = redact(SAMPLE)
    assert redacted["location"]["username"] == redacted["sharedUsers"][0]["username"]
    assert redacted["udid"] in redacted["enrollmentNote"]  # swept by shape, same placeholder
    assert scrub.swept == {"enrollmentNote", "purchasingNote"}  # the only two keys no rule named
    assert redact(redacted)[0] == redacted  # and a re-capture does not churn the fixture
