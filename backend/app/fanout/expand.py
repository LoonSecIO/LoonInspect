"""The section walk — one stored `device.inventory` snapshot in, one sub-event descriptor
out per section item, in the order the wire has always emitted them (#306).

This is the Splunk fan-out's traversal (`app.core.hec_fanout.fan_out`) lifted into a
service of its own, so a record-oriented destination can reach the same expansion without
going through HEC. It is a deliberate **copy** rather than a refactor of the original, and
the reason is worth keeping: the Splunk wire is frozen (#188) and pinned item-for-item by
tests/test_hec_fanout.py against a captured Jamf Pro 11.31 record, and #306 is a change
for the OTHER three destination types. A fix for `runreveal` must not be able to move a
byte on the one wire that already has a customer, and a shared helper threaded through
`hec_fanout` could.

The cost of a copy is drift. tests/test_record_fanout.py pays it down directly: it asserts
that this walk and `hec_fanout.fan_out` select the same items, in the same order, under
the same strings, over the real fixture. The day the two diverge, that test names which
one moved.

What is walked is the contract, not a table here:

* the seven one-per-device sections — `general`, `hardware`, `operatingSystem`,
  `userAndLocation`, `purchasing`, `security`, `diskEncryption` — are one sub-event each,
  what #81 called the *device anchor*;
* the seven list sections — `app`, `ea`, `group`, `profile`, `localUserAccount`, `cert`,
  `update` — fan one sub-event per item, in the payload's order.

Cardinality comes from `SectionSpec.is_list`, wrapper keys and strings from
`registry_rows()` — never spelled by hand, so a section added to the contract is walked
here without an edit (#222's acceptance).

A wrapper the registry does not name — a section a newer producer added, arriving on an
older worker or replayed from the retention window — is emitted rather than dropped or
raised, with no sourcetype. A raise here would burn ten retries and dead-letter the
device's whole pass; the enqueue-side model refuses unknown wrappers, so this path is
version skew, not a producer bug.

Order is fixed — registry order, which puts the seven anchors first in the contract's
declaration order, then the list sections, items in payload order — so expanding twice
over one stored row yields the same sequence and a partial acceptance can be reasoned
about by position (#242, D2).

Pure: the stored payload dict in, descriptors out. No session, no clock, no I/O, and the
input is never mutated — delivery is retried against the same row up to ten times, and
the second attempt must expand exactly what the first did.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import NamedTuple

from app.core.wire_vocabulary import registry_rows
from app.mdm.jamf.contract import SECTIONS
from app.schemas.payload import SNAPSHOT_HEAD_KEYS

logger = logging.getLogger(__name__)


class SubEvent(NamedTuple):
    """One item the snapshot expands into, and the string that routes it.

    `item` is the section item exactly as the payload holds it — already
    `{wrapper: Jamf's object}` or, for an app, `{"app": …, "patch": …, "vuln": …}` (#241
    property 2). Nothing inside a Jamf object is touched here (Kyle, 2026-09-02: "Use
    Jamf's v4 Names Verbatim in the sections I am copying them").

    `sourcetype` is the registry string for the item's wrapper, or None for a wrapper the
    registry does not name.
    """

    item: Mapping[str, object]
    sourcetype: str | None


def expand(payload: Mapping[str, object]) -> list[SubEvent]:
    """Every sub-event one stored `device.inventory` payload becomes, in order.

    `payload` is the stored row minus the envelope key and minus nothing else: the head
    keys are skipped by name (`SNAPSHOT_HEAD_KEYS`) and every other key is a section.
    """
    sub_events: list[SubEvent] = []
    emitted: set[str] = set()

    for section, _response_key, wrapper, sourcetype in registry_rows():
        if wrapper not in payload:
            # Outside this read's aperture: nothing is asserted about it (the 2026-08-29
            # ruling, per section).
            continue
        emitted.add(wrapper)
        value = payload[wrapper]
        if SECTIONS[section].is_list:
            sub_events.extend(SubEvent(item, sourcetype) for item in value)  # type: ignore[union-attr]
        else:
            sub_events.append(SubEvent({wrapper: value}, sourcetype))

    for key, value in payload.items():
        if key in SNAPSHOT_HEAD_KEYS or key in emitted:
            continue
        logger.warning(
            "snapshot carries a section the registry does not name; delivering it unstamped",
            extra={"wrapper": key},
        )
        if isinstance(value, list):
            sub_events.extend(SubEvent(item if isinstance(item, Mapping) else {key: item}, None) for item in value)
        else:
            sub_events.append(SubEvent({key: value}, None))

    return sub_events
