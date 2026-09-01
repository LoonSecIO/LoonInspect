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
from app.core.runs import event_time, get_run
from app.core.wire import ENVELOPE, envelope, instance_label
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

logger = logging.getLogger(__name__)

EVENT_TYPE = "device.change"
_OS_VERSION_FIELDS = ("version", "build", "supplementalBuildVersion", "rapidSecurityResponse")


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
    for row in rows:
        await enqueue_event(db, EVENT_TYPE, _event_payload(row, connection), request_id=get_request_id())
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


def _event_payload(row: DeviceChange, connection: MdmConnection) -> dict:
    """One change row as it goes out on the wire.

    camelCase with the token `ID` uppercased (#188), spelled to agree with the
    `deviceMeta` block on `device.inventory.changed` rather than merely to be camelCase:
    `jobID`, `jamfProID` and `serialNumber` are the same names carrying the same values,
    so a change and the inventory event from the same pull join on identical keys.

    Two spellings were genuinely ambiguous and are ruled here:

    * `jamfUrl`, not `jamfURL`. The law uppercases exactly one token, `ID`. Extending it
      to `URL` would be a second ruling made in passing, and Jamf's own API spells its
      url keys `...Url` — so the mechanical reading is also the one a Jamf admin expects.
    * `udid` unchanged. It is one acronym, not a name ending in an `Id` token, and
      camelCase puts the leading word in lower case — `UDID` breaks that and `udID`
      reads as nonsense. Jamf spells it `udid` too.
    """
    run = get_run()
    payload = {
        # `event`, matching the inventory family and now the run families. One
        # discriminator key is the whole point: `event=device.*` and `event=run.*` from
        # a single SPL predicate, which `event_type` on two of four families made
        # impossible.
        "event": EVENT_TYPE,
        # The run that observed this change. Same jobID as the inventory events from the
        # same pull, which is what lets a search collect everything one sweep produced —
        # the correlation triple below identifies the *device*, not the pass that saw it.
        "jobID": str(run.id) if run else None,
        "comparison": run.comparison if run else None,
        "connectionID": connection.id,
        "jamfUrl": connection.base_url,
        # `jamfProID`, the deviceMeta spelling, and the same value for a computer
        # subject. NOT a second name like `jamfID` for the object's Jamf Pro primary
        # key: `subjectKind` already says which kind of object the id belongs to, and a
        # group's id lives in the same Jamf Pro as a computer's.
        "jamfProID": row.subject_id,
        "subjectKind": row.subject_kind,
        "subjectLabel": row.subject_label,
        "serialNumber": row.serial_number,
        "udid": row.udid,
        "observedAt": row.observed_at.isoformat(),
        "collectedAt": row.collected_at.isoformat(),
        "trigger": row.trigger,
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
    # is not.
    payload[ENVELOPE] = envelope(
        occurred_at=event_time(row.observed_at),
        host=row.subject_label if row.subject_kind == SUBJECT_COMPUTER else None,
        source=instance_label(connection.base_url),
    )
    return payload
