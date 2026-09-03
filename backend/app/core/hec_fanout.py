"""The Splunk HEC fan-out — one `device.inventory` snapshot in, N sub-events out, each
under its ruled sourcetype (#242, absorbing #222).

The snapshot (#241) is one outbox row per device per pass: the head — `event`, `jobID`,
`occurredAt`, `deviceMeta` — and one key per section inside the read's aperture, spelled
by `SECTION_WRAPPERS`. On every destination but Splunk it travels whole. On a `splunk_hec`
destination it is expanded HERE, at delivery, into one HEC event object per section item:

* the seven one-per-device sections — `general`, `hardware`, `operatingSystem`,
  `userAndLocation`, `purchasing`, `security`, `diskEncryption` — are one sub-event each,
  what #81 called the *device anchor*;
* the seven list sections — `app`, `ea`, `group`, `profile`, `localUserAccount`, `cert`,
  `update` — fan one sub-event per item, in the payload's order.

The cardinality comes from the contract's `SectionSpec.is_list`, never from a table here
(`localUserAccount` is a list whatever the registry's naming comment says), and the
wrapper keys and strings come from `registry_rows()`, never spelled by hand.

Why one event per item rather than one nested document: Splunk's automatic JSON
extraction turns a nested `app[]` into independent multivalue fields with no pairing
between them, so `app.name=Chrome app.version=4.0.1` asks two independent questions and
can be true of two different apps (docs/splunk-event-shaping.md). One sub-event per item
makes `app.name` / `app.version` scalar on every event, and the plain search is simply
correct.

The sub-event body is the list item — already `{wrapper: Jamf's object}` or, for an app,
`{"app": …, "patch": …, "vuln": …}` (#241 property 2: the item is the sub-event body
minus the sub-event keys) — plus the three keys every sub-event carries, `SUB_EVENT_KEYS`
(#220, PR #247): `event`, the snapshot's own type verbatim (D1 — nothing mints
`device.inventory.app`; `sourcetype` is what says an event is an app rather than a
certificate); `jobID`, at the sub-event root, so the bare `jobID=$id$` join reaches the
fan-out; and `deviceMeta`, #189's block copied whole — minting nothing into it and
dropping nothing from it (#81 ruling 3). Nothing inside a Jamf object is touched (Kyle,
2026-09-02: "Use Jamf's v4 Names Verbatim in the sections I am copying them"), and the
four minted identity fields do not ride because the snapshot does not carry them (Kyle,
2026-09-02: "leave them out for now"). `occurredAt` does not ride: the three keys are the
ruled complete answer to what survives the split, and the same instant travels beside
every sub-event as the envelope's `time`.

`sourcetype` is the registry string for the item's wrapper — `sourcetype(wrapper)` in
`app.core.wire_vocabulary`, read through `registry_rows()` and nowhere else (#222's
acceptance; #81 ruling 7: the sourcetype tree is the routing dimension). The enrichment
strings (`loon:jamf:mac:app:patch`, `:vuln`, `:alert`) stay minted with no writer: an
enrichment rides inline on the app sub-event, under its own key beside Jamf's object
(#242 item 6; docs/vulnerabilities.md §3). A populated `vuln{}` does not change that —
#249 ruled the summary rides `loon:jamf:mac:app`, because taking `:vuln` for it would
force `loon:jamf:mac:app:patch:vuln` on an app carrying both blocks, and a sourcetype is
a permanent hand-written `props.conf` stanza. `:vuln` stays reserved for the post-v0
lifecycle records.

The ONE thing this seam mints is `-1`. `daysOldestPublished` is always present and always
int on the wire, with `-1` for "no finding in this band" (docs/vulnerabilities.md §4c) —
and the canonical payload keeps `None`, so the stored row, a generic webhook and an
Elastic document can all render it natively as SQL `NULL`. That conversion belongs to the
HEC shaping and to nothing upstream, which is `mint_hec_sentinels` on the item below: a
no-op returning the same object for every item that carries no populated `vuln{}`, which
today is all of them.

Order is fixed — registry order, which puts the seven anchors first in the contract's
declaration order, then the list sections, items in payload order — so building twice
over one stored row is byte-identical and a partial acceptance can be reasoned about by
position (#242, D2).

What the wire loses, on purpose and on the record: a section outside the read's aperture
is absent from the snapshot and fans out nothing, and a LIST section read and genuinely
empty fans out nothing too. On the wire the two look the same — `loon:jamf:mac:general`
with no `loon:jamf:mac:cert` for the same `deviceMeta.eventID` means either zero
certificates or certificates not read. The payload keeps the distinction (absent versus
`[]`); a key saying "unread" on the most-multiplied event is #189's decision, not taken
here (docs/splunk-setup.md §7). A SCALAR section read and genuinely empty is not lost: it
still emits its anchor, as `{}` (`userAndLocation` on the real fixture), so for the seven
anchors absent means unread and `{}` means read-and-empty, and a full read always
produces all seven. Built this way and ruled by default — Kyle confirms or overrules.

Pure: the stored payload dict and the envelope hints in, HEC event objects out. No
session, no clock, no I/O, and the input is never mutated — delivery is retried against
the same row up to ten times, and the second attempt must expand exactly what the first
did.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from app.core.vuln import mint_hec_sentinels
from app.core.wire import hec_event
from app.core.wire_vocabulary import SUB_EVENT_KEYS, registry_rows
from app.mdm.jamf.contract import SECTIONS
from app.schemas.payload import SNAPSHOT_HEAD_KEYS

logger = logging.getLogger(__name__)

_DEVICE_META = "deviceMeta"


def fan_out(payload: Mapping[str, object], hints: Mapping[str, object]) -> list[dict[str, object]]:
    """Every HEC event object one stored `device.inventory` payload becomes, in order.

    `payload` is the stored row minus the envelope key; `hints` is that envelope
    (`time` / `host` / `source`, whichever are present), copied onto every sub-event so a
    sweep's sub-events share the run's window and a webhook's the device's `reportDate`.

    A wrapper the registry does not name — a section a newer producer added, arriving on
    an older worker or replayed from the retention window — is delivered rather than
    dropped or raised: one sub-event per item (or one for an object), with no
    `sourcetype`, so it lands under the HEC input's own default exactly as every event did
    before any string was stamped. A raise here would burn ten retries and dead-letter the
    device's whole pass; the enqueue-side model refuses unknown wrappers, so this path is
    version skew, not a producer bug.
    """
    # The sub-event's own keys, in the snapshot's own layout: the head first, the item,
    # `deviceMeta` last. `jobID` is copied iff the snapshot carries it — absent rather than
    # null outside a run, the rule the block itself follows.
    head = {key: payload[key] for key in SUB_EVENT_KEYS if key != _DEVICE_META and key in payload}
    meta = payload.get(_DEVICE_META)

    def sub_event(item: Mapping[str, object], sourcetype: str | None) -> dict[str, object]:
        body: dict[str, object] = {**head, **mint_hec_sentinels(item)}
        if isinstance(meta, Mapping):
            body[_DEVICE_META] = dict(meta)
        return hec_event(body, hints, sourcetype=sourcetype)

    events: list[dict[str, object]] = []
    emitted: set[str] = set()
    for section, _response_key, wrapper, sourcetype in registry_rows():
        if wrapper not in payload:
            # Outside this read's aperture: nothing is asserted about it (the 2026-08-29
            # ruling, per section).
            continue
        emitted.add(wrapper)
        value = payload[wrapper]
        if SECTIONS[section].is_list:
            events.extend(sub_event(item, sourcetype) for item in value)  # type: ignore[union-attr]
        else:
            events.append(sub_event({wrapper: value}, sourcetype))

    for key, value in payload.items():
        if key in SNAPSHOT_HEAD_KEYS or key in emitted:
            continue
        logger.warning(
            "snapshot carries a section the registry does not name; delivering it unstamped",
            extra={"wrapper": key},
        )
        if isinstance(value, list):
            events.extend(sub_event(item if isinstance(item, Mapping) else {key: item}, None) for item in value)
        else:
            events.append(sub_event({key: value}, None))
    return events
