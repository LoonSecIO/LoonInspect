"""Turn a span boundary into change-log rows and events, under the tenant's policy.

Called right after the ledger reports `changed` for a subject. Loads the previous
span's section contents (by digest — they are content-addressed and still there),
diffs them against the new observation, applies the policy, writes `device_changes`
rows, and enqueues one `device.change` outbox event per row in the same transaction.

Two derived judgements live here because they need more than one section:

* **System-app collapse.** When the OS version (or build) changed in the same boundary,
  the version bumps of applications under /System are folded into the OS change as a
  count rather than logged one by one — unless the policy says otherwise.
* **Two-cause membership.** A group joined or left carries `criteriaChanged`: whether
  the group's own definition span moved since this device was last observed. Jamf
  cannot say; the ledger keeps both histories.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.changes.diff import Entry, EntryChange, FieldChange, diff_entries, diff_scalar
from app.changes.policy import (
    CHANGE_POLICY_VERSION,
    ENTRY_RULES_BY_KIND,
    EffectivePolicy,
    Overrides,
    is_system_app,
)
from app.core.context import get_request_id
from app.core.outbox import enqueue_event
from app.core.runs import event_time, get_run, run_meta
from app.core.wire import ENVELOPE, envelope, instance_label
from app.core.wire_vocabulary import CHANGE_EVENT_TYPE
from app.mdm.jamf.contract import SECTIONS, SUBJECT_COMPUTER, Observation, SectionContent
from app.models.schema import (
    ChangePolicy,
    DeviceChange,
    MdmConnection,
    ObservationEntry,
    ObservationSection,
    ObservationSpan,
)
from app.observations.ledger import RecordResult
from app.schemas.payload import WIRE_SCHEMA_VERSION

logger = logging.getLogger(__name__)

# The family's single subscribable type, taken from the vocabulary rather than spelled
# again here: `app.core.outbox._build_body` stamps the `:change` sourcetype on exactly this
# type, and a second literal is how a producer and its stamp drift apart.
EVENT_TYPE = CHANGE_EVENT_TYPE
_OS_VERSION_FIELDS = ("version", "build", "supplementalBuildVersion", "rapidSecurityResponse")
# The one section the `deviceMeta` block reads a value out of: `managed` lives in
# GENERAL's canonical body, where the current-state normalizer also reads it. The block's
# other device-half keys come off the observation itself (`_change_device_meta`).
_GENERAL_SECTION = "general"


async def load_policy(db: AsyncSession) -> EffectivePolicy:
    row = (await db.execute(select(ChangePolicy))).scalars().first()
    return EffectivePolicy(Overrides.from_document(row.overrides if row else None))


async def _load_section(db: AsyncSession, digest: str | None) -> tuple[dict | None, list[Entry]]:
    """The content behind a stored section digest: a scalar body, or the entries."""
    if not digest:
        return None, []
    row = (await db.execute(select(ObservationSection).where(ObservationSection.digest == digest))).scalars().first()
    if row is None:
        return None, []
    if row.entry_digests is None:
        return row.body or {}, []
    digests = list(row.entry_digests)
    if not digests:
        return None, []
    entries = (
        await db.execute(select(ObservationEntry).where(ObservationEntry.digest.in_(digests)))
    ).scalars().all()
    return None, [Entry(digest=e.digest, body=e.body, label=e.label) for e in entries]


def _entries_of(content: SectionContent) -> list[Entry]:
    return [Entry(digest=e.digest, body=e.body, label=e.label) for e in content.entries]


async def derive_and_record(
    db: AsyncSession,
    *,
    connection: MdmConnection,
    observation: Observation,
    result: RecordResult,
    trigger: str,
    collected_at: datetime | None = None,
) -> list[DeviceChange]:
    """Diff the previous span against this observation and record what the policy keeps.
    Returns the rows written (not yet committed — the caller owns the transaction)."""
    if result.outcome != "changed" or result.previous_span_id is None or not result.changed_sections:
        return []

    previous = await db.get(ObservationSpan, result.previous_span_id)
    if previous is None:
        return []
    policy = await load_policy(db)
    collected_at = collected_at or datetime.now(timezone.utc)
    observed_at = observation.observed_at or collected_at

    field_changes: list[FieldChange] = []
    entry_changes: list[EntryChange] = []
    for name in result.changed_sections:
        content = observation.sections.get(name)
        if content is None:
            continue
        previous_digest = (previous.section_digests or {}).get(name)
        if previous_digest is None:
            # The previous span's aperture never read this section — an absent digest
            # is absence of observation, not an empty section (read-and-empty still
            # digests). Diffing against nothing would mint the whole section as
            # "added" on the first sweep after a narrower scope (#93); a section's
            # first read is a baseline, exactly as a device's first span is.
            continue
        old_body, old_entries = await _load_section(db, previous_digest)
        if content.is_list:
            spec = SECTIONS.get(name)
            kind = spec.entry_kind if spec and spec.entry_kind else name
            rule = ENTRY_RULES_BY_KIND.get(kind)
            identity = rule.identity if rule else ("name",)
            entry_changes.extend(diff_entries(name, kind, identity, old_entries, _entries_of(content)))
        else:
            field_changes.extend(diff_scalar(name, old_body, content.body))

    rows: list[DeviceChange] = []

    def _row(**kwargs) -> DeviceChange:
        return DeviceChange(
            mdm_connection_id=connection.id,
            subject_kind=observation.subject_kind,
            subject_id=observation.subject_id,
            subject_label=observation.label,
            serial_number=observation.serial_number,
            udid=observation.udid,
            span_id=result.span_id,
            previous_span_id=result.previous_span_id,
            observed_at=observed_at,
            collected_at=collected_at,
            trigger=trigger,
            policy_version=CHANGE_POLICY_VERSION,
            **kwargs,
        )

    os_row: DeviceChange | None = None
    os_changed = any(c.section == "operating_system" and c.field in _OS_VERSION_FIELDS for c in field_changes)
    for change in field_changes:
        if not policy.field_enabled(change.section, change.field):
            continue
        row = _row(
            section=change.section,
            field=change.field,
            change="changed",
            old_value=_wrap(change.old),
            new_value=_wrap(change.new),
            level=policy.field_level(change.section, change.field),
        )
        rows.append(row)
        if change.section == "operating_system" and change.field == "version":
            os_row = row

    collapsed_system_apps = 0
    for change in entry_changes:
        if change.kind == "group_membership" and policy.group_muted(str(change.identity.get("groupId"))):
            continue
        if change.kind == "extension_attribute" and policy.extension_attribute_muted(
            str(change.identity.get("definitionId"))
        ):
            continue
        if change.change == "updated":
            enabled_fields = [f for f in change.changed_fields if policy.entry_enabled(change.kind, "updated", f)]
            if not enabled_fields:
                continue
            if (
                change.kind == "application"
                and os_changed
                and not policy.system_apps_individually
                and is_system_app(change.new or {})
            ):
                collapsed_system_apps += 1
                continue
            level = policy.entry_level(change.kind, "updated", enabled_fields)
            details: dict = {"changedFields": enabled_fields}
        else:
            if not policy.entry_enabled(change.kind, change.change):
                continue
            level = policy.entry_level(change.kind, change.change)
            details = {}
            if change.kind == "group_membership":
                details.update(await _membership_cause(db, connection, change, previous))
        rows.append(
            _row(
                section=change.section,
                entry_kind=change.kind,
                entry_identity=change.identity,
                entry_label=change.label,
                change=change.change,
                old_value=dict(change.old) if change.old is not None else None,
                new_value=dict(change.new) if change.new is not None else None,
                level=level,
                details=details or None,
            )
        )

    if collapsed_system_apps:
        if os_row is not None:
            os_row.details = {**(os_row.details or {}), "systemAppsUpdated": collapsed_system_apps}
        else:
            rows.append(
                _row(
                    section="applications",
                    entry_kind="application",
                    change="updated",
                    level="normal",
                    details={"collapsedSystemApps": collapsed_system_apps},
                )
            )

    for row in rows:
        db.add(row)
    await db.flush()
    # Built once per subject, not once per row: every change derived from one observation
    # describes the same device on the same pull, so the block is the same object for all
    # of them and re-deriving it per row would only invite the copies to disagree.
    device_meta = _change_device_meta(observation)
    for row in rows:
        await enqueue_event(db, EVENT_TYPE, _event_payload(row, connection, device_meta), request_id=get_request_id())
    if rows:
        logger.info(
            "changes recorded",
            extra={
                "connection_id": connection.id,
                "subject_id": observation.subject_id,
                "count": len(rows),
                "sections": sorted({r.section for r in rows}),
            },
        )
    return rows


async def _membership_cause(
    db: AsyncSession, connection: MdmConnection, change: EntryChange, previous: ObservationSpan
) -> dict:
    """Did the group's criteria move since this device was last observed? If the group's
    current definition span opened after the device's previous span was last observed,
    the criteria changed in between; otherwise the device drifted."""
    group_id = str(change.identity.get("groupId"))
    definition = (
        await db.execute(
            select(ObservationSpan).where(
                ObservationSpan.mdm_connection_id == connection.id,
                ObservationSpan.subject_kind == "computer_group",
                ObservationSpan.subject_id == group_id,
                ObservationSpan.is_current.is_(True),
            )
        )
    ).scalars().first()
    if definition is None:
        return {"criteriaChanged": None}
    moved = definition.previous_id is not None and definition.first_observed_at > previous.last_observed_at
    return {"criteriaChanged": bool(moved), "groupDefinitionSpanId": str(definition.id)}


def _wrap(value) -> dict | None:
    """Scalars and lists wrapped so old/new are always JSON objects in the row."""
    if value is None:
        return None
    return {"value": value}


def _change_device_meta(observation: Observation) -> dict[str, object]:
    """#189's `deviceMeta` block for one subject's changes — built from the observation
    and the run, never from the `Device` row.

    #223 filed the absence: a `device.change` carried no block at all, so a change joined
    to its own inventory pass through `jobID` + `jamfProID`, the two-term join #189
    rejected for the inventory family because a two-term join "can be half-used, returning
    a plausible superset with no error". #243 ruled the fix and named the constraint this
    function is written around: `mdm.service._device_meta` reads the `Device` row, and in
    `ingest_computer` the derivation runs BEFORE `process_sync` updates that row — so
    reading it here would ship the *previous* pull's hostname, report date and managed
    flag beside this pull's change, and the two device families would disagree about the
    device on the very pull the fold exists to correlate. The observation is this pull, by
    construction.

    Names are #189's and no others (`tests/test_device_meta.py::RULED_TWELVE`): nothing is
    added, nothing is renamed, and the null-drop rule the block already lives under is what
    covers a value this producer cannot know. A section outside the aperture is absence of
    observation, not absence of the fact (#98's discipline), so `managed`, `hostName` and
    `lastReportDate` — all three from GENERAL — drop together when GENERAL was not read,
    and `serialNumber` drops with HARDWARE.

    A `computer_group` subject keeps the run half and `jamfProID`, and nothing else:

    * **no `eventID`.** It is `uuid5(run, jamfProID)`, and a group id is a different id
      space from a computer id (#234) — deriving one from the same formula would mint a
      correlation key that collides with a computer's by construction. #243's rider.
    * **no `hostName`, no `serialNumber`.** A smart group is not a Mac; its label is a
      group name. The same ruling that keeps `host` off the envelope for this subject
      (`_event_payload` below) keeps the hostname out of the body, for the same reason —
      an absent identity is recoverable, an invented one is not.

    `jamfProID` stays the object's own id on both subjects, which is #212's ruling kept by
    #243: `subjectKind` says which kind of object it belongs to, and the sourcetype
    (`loon:jamf:mac:computerGroup:change`) is what separates the two id spaces at search
    time.
    """
    run = get_run()
    is_computer = observation.subject_kind == SUBJECT_COMPUTER
    general = observation.sections.get(_GENERAL_SECTION)
    remote_management = (general.body or {}).get("remoteManagement") if general is not None else None
    meta: dict[str, object | None] = {
        # The run's half — jobID, trigger, connectionID, shortDate — from the one producer
        # #189's refusals are enforced in, so `comparison` and `collectionID` cannot arrive
        # here by a route the inventory family closed.
        **run_meta(),
        # Derived, not minted: `uuid5(run.id, jamfProID)` is the same formula
        # `mdm.service._device_meta` uses, over the same id, so a change and the inventory
        # event from the same pull name that pull with one value without either side
        # passing it along. The ids agree on both call paths today but not by construction
        # — the inventory side falls back on a falsy id (`computer.id or general.id`) and
        # the ledger side on a null one — so the agreement is pinned in
        # `tests/test_device_meta.py` rather than inherited (PR #255's note to this issue).
        "eventID": str(uuid.uuid5(run.id, observation.subject_id)) if run and is_computer else None,
        "serialNumber": observation.serial_number if is_computer else None,
        "jamfProID": observation.subject_id,
        # The observation's label IS the hostname for a computer: both are Jamf's
        # `general.name`, which is also what the Device row stores and what the envelope
        # ships as `host`.
        "hostName": observation.label if is_computer else None,
        # The device's own report date, which is what `observed_at` was parsed from and
        # what the inventory family reads off the row it writes from the same field. NOT
        # the row's `observed_at`, which falls back to collection time when GENERAL was not
        # read — a fallback is the right answer for `_time` and a lie for a freshness key.
        "lastReportDate": observation.observed_at.isoformat() if observation.observed_at else None,
        "managed": remote_management.get("managed") if isinstance(remote_management, dict) else None,
        "schemaVersion": WIRE_SCHEMA_VERSION,
    }
    return {key: value for key, value in meta.items() if value is not None}


def _event_payload(row: DeviceChange, connection: MdmConnection, device_meta: dict[str, object]) -> dict:
    """One change row as it goes out on the wire.

    camelCase with the token `ID` uppercased (#188), spelled to agree with the
    `deviceMeta` block on `device.inventory.changed` rather than merely to be camelCase.
    Since #223 that block rides here whole, so a change joins the inventory event from
    the same pull on `deviceMeta.eventID` — one key, one path, both device families —
    rather than the two-term join #189 rejected.

    **The device is named once (#308, ruled 2026-09-04).** This payload was built flat,
    before #189 existed; #223 folded `deviceMeta` in and could only *add*, because clause
    3 of the freeze ("a key that ships is never removed") was already in force. The result
    shipped five values twice — `trigger`, `jamfProID`, `connectionID`, `serialNumber`,
    and `subjectLabel` against `deviceMeta.hostName` — under a comment calling the
    duplication deliberate by analogy to #220's `jobID` hoist. The analogy did not hold:
    #220 hoisted `jobID` so ONE bare predicate joins every family, and the hoisted copies
    here did the opposite, because the inventory sub-event carries no top-level identity
    at all (`app.core.hec_fanout`). A customer's bare `serialNumber=` matched changes and
    silently returned nothing from inventory — a plausible subset with no error, the very
    failure #189 refused the two-term join for. The four exact twins are gone; the block
    is where both families agree.

    Removals are licensed only because no customer SPL exists yet. Body keys freeze at the
    public flip, when SPL can first exist (docs/runs.md: "customer SPL written against
    these names makes them permanent"); sourcetype strings froze the day they were minted,
    and none moves here, so clause 5 is untouched.

    Two more keys came off on their own arguments:

    * `comparison` — #189 CUT it (it describes run history, not the row: `delta` on every
      device of every run after the first, so it partitions nothing) and #258 removed it
      from the block. It survived one level up because both refusal guards read the block.
      It rides `run.completed`, joined by `jobID`. `tests/test_device_meta.py` now reads
      this payload's top level too, so it cannot come back at either depth.
    * `jamfUrl` — `app.core.wire`'s opening doctrine: anything that fits the envelope is
      envelope-only, "that is why the instance URL is `source` and not a key". This was
      the only family carrying it, beside an envelope `source` holding the same instance.
      The friendly name for the connection is `connectionName` on the run family (#103,
      #287), a `jobID` join away; `deviceMeta.connectionID` is scope, not readability.

    **Nulls are dropped, one rule for the whole event.** `_change_device_meta` already
    filtered its own; this dict did not, so `field` and `entryLabel` — null on *every*
    event a list-section sourcetype will ever emit — reached the index, and a group
    change shipped five structural nulls beside a block that correctly dropped them.
    Clause 3's own second sentence licenses this: a key that stops being computed "is
    absent under the null-dropping rule that already governs deviceMeta". It also makes
    `field=*` a clean selector for scalar changes instead of a predicate matching
    everything.

    **`subjectLabel` stays, unconditionally** (Kyle, ruling the #308 carve-out). On the
    fourteen section sourcetypes it can only be `deviceMeta.hostName`; on the fifteenth,
    `loon:jamf:mac:computerGroup:change`, it is the ONLY name the event carries — the
    block drops `hostName` for a group, the envelope drops `host`, and a group-definition
    change is a scalar diff, so `entryLabel` is null too. Without it a criteria change
    pages as `jamfProID: "12"` and nothing else. It is the subject-kind-agnostic name
    where `hostName` answers the narrower "this Mac's hostname" — two keys that agree on
    a computer, not a duplicate. Emitting it only when `hostName` is absent was refused:
    that forces `deviceMeta.hostName ?? subjectLabel` on every consumer, the coalesce
    docs/runs.md refuses by name for `jobID`.

    `entryIdentity` stays for the same shape of reason (#308 Q5): it is kind-agnostic, so
    one SPL reads `entryIdentity.name` across `*:change` without knowing that an app's
    identity is name+path+bundleId while an EA's is a definition id. It restates fields
    already in `old`/`new`, and that is the price of not making every consumer carry a
    per-kind identity table.

    The event's `sourcetype` is not set here. It is decided by
    `wire_vocabulary.change_sourcetype` and stamped by `app.core.outbox._build_body` on
    Splunk HEC deliveries only (#243, #223): a sourcetype is not part of the event, it is
    part of the delivery, and every other destination type gets this payload verbatim.
    That is also why `section`, `entryKind` and `subjectKind` stay though the sourcetype
    implies all three — a generic webhook receives this body with no sourcetype at all.

    One spelling was genuinely ambiguous and is ruled here: `udid` unchanged. It is one
    acronym, not a name ending in an `Id` token, and camelCase puts the leading word in
    lower case — `UDID` breaks that and `udID` reads as nonsense. Jamf spells it `udid`
    too. (`jamfUrl` vs `jamfURL` was ruled the same way and is moot now the key is gone.)
    """
    run = get_run()
    payload = {
        # `event`, matching the inventory family and now the run families. One
        # discriminator key is the whole point: `event=device.*` and `event=run.*` from
        # a single SPL predicate, which `event_type` on two of four families made
        # impossible.
        "event": EVENT_TYPE,
        # The run that observed this change. Same jobID as the inventory events from the
        # same pull, which is what lets a search collect everything one sweep produced.
        # This hoist stays: #220 ruled it so one bare `jobID=$id$` joins every family and
        # every sub-event, and the inventory families carry it at the root too — which is
        # exactly what the identity keys removed above did NOT do.
        "jobID": str(run.id) if run else None,
        # #189's block, whole (`_change_device_meta`). With `event` and `jobID` above it,
        # this event carries all three of the keys #220 ruled every sub-event carries —
        # `wire_vocabulary.SUB_EVENT_KEYS` — though a change is not a fan-out sub-event:
        # it was already at sub-event grain, one outbox event per kept change row.
        #
        # It is the one place this event names the device. `serialNumber`, `jamfProID`,
        # `hostName`, `trigger` and `connectionID` are read from here on both device
        # families, so a predicate written once works on both (#308).
        "deviceMeta": device_meta,
        "subjectKind": row.subject_kind,
        # The subject's own name, on every subject kind — see the docstring. Equal to
        # `deviceMeta.hostName` for a computer; the group's name, and the only one, for a
        # `computer_group`.
        "subjectLabel": row.subject_label,
        "udid": row.udid,
        # The device's own report date where GENERAL was read, and collection time where
        # it was not (`observed_at` above). NOT interchangeable with
        # `deviceMeta.lastReportDate`, which has no fallback and is dropped instead —
        # they agree on the happy path and mean different things off it.
        "observedAt": row.observed_at.isoformat(),
        "collectedAt": row.collected_at.isoformat(),
        "section": row.section,
        "field": row.field,
        "entryKind": row.entry_kind,
        "entryIdentity": row.entry_identity,
        "entryLabel": row.entry_label,
        "change": row.change,
        "old": row.old_value,
        "new": row.new_value,
        "level": row.level,
        "details": row.details,
        "spanID": str(row.span_id) if row.span_id else None,
        "previousSpanID": str(row.previous_span_id) if row.previous_span_id else None,
        "policyVersion": row.policy_version,
    }
    # One null rule for the whole event (#308), the rule `_change_device_meta` already
    # applies to its own half. Built before the envelope is attached, so the reserved
    # key is never a candidate — and `deviceMeta` is a dict, never None, so the block
    # survives even when every key in it was dropped.
    payload = {key: value for key, value in payload.items() if value is not None}
    # The envelope, on the same rule the inventory family uses (app.core.wire). Without
    # it every device.change landed at Splunk's *receive* time, so a change the sweep
    # observed at 01:00 sorted beside whatever the outbox happened to drain at 09:00.
    #
    # `event_time` rather than `row.observed_at` directly: that is the one back-dating
    # rule in this codebase (app.core.runs), and running a second rule here would put
    # a device's change and its own inventory event — same pull, same jobID — at two
    # different `_time`s. Under a sweep both are the run window; under a webhook both
    # are Jamf's reportDate, which is exactly what `observed_at` was parsed from.
    #
    # `host` only for a computer. `derive_and_record` also runs for computer_group
    # subjects, whose `subject_label` is a group name — shipping that as `host` would
    # invent Macs named "Devices out of Checkin Compliance" and corrupt every
    # `dc(host)` in the customer's index. An absent hint is recoverable; a wrong one
    # is not. `source` carries the instance for every subject, which is why no
    # `jamfUrl` key rides the body (#308).
    payload[ENVELOPE] = envelope(
        occurred_at=event_time(row.observed_at),
        host=row.subject_label if row.subject_kind == SUBJECT_COMPUTER else None,
        source=instance_label(connection.base_url),
    )
    return payload
