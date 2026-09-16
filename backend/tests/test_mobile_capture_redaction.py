"""The scrub behind the mobile capture (#238), over a sample shaped like a record.

The capture runs once, against the maintainer's own tenant, and what it writes is committed
to a public repository — there is no second chance to notice that a key held an identifier.
The sample carries a key the table has never heard of, because a first capture of an unread
endpoint is exactly where one turns up.
"""

from __future__ import annotations

import json
import re

from scripts.capture_jamf_mobile_device import redact

SAMPLE = json.loads("""
{
  "id": "12", "name": "Kyle's iPad", "udid": "8A0F1C2D-1111-4222-8333-444455556666",
  "serialNumber": "DMPX1234ABCD", "wifiMacAddress": "AC:DE:48:00:11:22", "ipAddress": "198.51.100.7",
  "supervised": true, "enforceName": false, "batteryLevel": 88, "osVersion": "26.1.2",
  "location": {"username": "kpazandak", "realName": "Kyle Pazandak", "emailAddress": "kyle@loonsec.io",
               "phoneNumber": "+1-612-555-0123", "room": "Studio", "department": null},
  "network": {"imei": "351234567890123", "iccid": "89012601234567890123", "homeCarrierNetwork": "Verizon"},
  "applications": [{"name": "Wireshark.app", "shortVersion": "2.6.6", "bundleId": "org.wireshark.Wireshark"}],
  "certificates": [{"commonName": "LoonSecIO JSS Built-in Certificate Authority", "identity": true}],
  "sharedUsers": [{"username": "kpazandak"}],
  "extensionAttributes": [{"name": "Device Owner", "value": ["kyle@loonsec.io"]}],
  "enrollmentNote": "enrolled by 8A0F1C2D-1111-4222-8333-444455556666"
}
""")
IDENTIFIERS = (
    "Kyle's iPad|8A0F1C2D-1111-4222-8333-444455556666|DMPX1234ABCD|AC:DE:48:00:11:22|198.51.100.7|kpazandak|"
    "Kyle Pazandak|kyle@loonsec.io|+1-612-555-0123|Studio|351234567890123|89012601234567890123"
)


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
    assert scrub.counts["uuid"] == 1  # the same UDID twice is one replacement


def test_joins_survive_and_unknown_keys_are_swept() -> None:
    redacted, scrub = redact(SAMPLE)
    assert redacted["location"]["username"] == redacted["sharedUsers"][0]["username"]
    assert redacted["udid"] in redacted["enrollmentNote"]  # swept by shape, same placeholder
    assert scrub.swept == {"enrollmentNote", "extensionAttributes.value"}
    assert redact(redacted)[0] == redacted  # and a re-capture does not churn the fixture
