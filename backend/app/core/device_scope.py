"""One device predicate for Installed Applications, patch plans, and audit exports."""

from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import and_, false, func, not_, or_, select

from app.models.schema import Device, DeviceExtensionAttribute, ObservationEntry, ObservationSection, ObservationSpan
from app.observations.departure import gone_for_good
from app.schemas.patch_plans import DeviceScope, ScopeGroup


def parse_scope(raw: str | None) -> DeviceScope:
    try:
        return DeviceScope.model_validate_json(raw) if raw else DeviceScope()
    except (ValidationError, ValueError) as exc:
        raise HTTPException(422, "The device filter is invalid. Check each condition or clear the filter and try again.") from exc


def _group_sections():
    span, section = ObservationSpan, ObservationSection
    return (
        select(section.id)
        .join(span, span.section_digests["group_memberships"].astext == section.digest)
        .where(
            span.mdm_connection_id == Device.mdm_connection_id,
            span.subject_id == Device.external_id,
            span.subject_kind == "computer",
            span.is_current.is_(True),
            section.section == "group_memberships",
        )
        .correlate(Device)
    )


def rule_predicate(rule, now):
    if rule.field in {"contact", "inventory"}:
        stamp = Device.last_check_in if rule.field == "contact" else Device.last_inventory_at
        if rule.operator == "unknown":
            return or_(stamp.is_(None), stamp > now)
        if rule.operator in {"before", "after"}:
            boundary = datetime.fromisoformat(rule.value).replace(tzinfo=UTC)
            if rule.operator == "before":
                return and_(stamp < boundary, stamp <= now)
            if rule.value == "9999-12-31":
                return false()
            return stamp.between(boundary + timedelta(days=1), now)
        cutoff = now - timedelta(days=int(rule.value))
        return stamp.between(cutoff, now) if rule.operator == "within" else stamp < cutoff
    if rule.field in {"managed", "supervised"}:
        flag = Device.managed if rule.field == "managed" else Device.supervised
        return flag.is_(None) if rule.operator == "unknown" else flag.is_(rule.value == "true")
    if rule.field == "ea":
        ea = DeviceExtensionAttribute
        known = select(ea.id).where(ea.device_id == Device.id, or_(ea.definition_id == rule.key, ea.name == rule.key))
        if rule.operator == "unknown":
            return ~known.where(ea.values != []).exists()
        if rule.operator in {"is", "is_not"}:
            match = ea.values.contains([rule.value])
        else:
            values = func.jsonb_array_elements_text(ea.values).table_valued("value").render_derived()
            value = values.c.value
            comparison = (
                value.icontains(rule.value, autoescape=True)
                if rule.operator in {"like", "not_like"}
                else value.regexp_match(rule.value, flags="i")
            )
            match = select(1).select_from(values).where(comparison).correlate(ea).exists()
        matching = known.where(match).exists()
        return (
            matching
            if rule.operator in {"is", "like", "matches_regex"}
            else and_(known.where(ea.values != []).exists(), ~matching)
        )
    if rule.field == "group":
        entry, section = ObservationEntry, ObservationSection
        known = _group_sections()
        matching = (
            known.join(entry, section.entry_digests.op("?")(entry.digest))
            .where(
                entry.kind == "group_membership",
                entry.body["groupId"].astext == rule.value,
            )
            .exists()
        )
        membership = matching if rule.operator == "is" else and_(known.exists(), not_(matching))
        return and_(Device.mdm_connection_id == int(rule.key), membership)
    column = {
        "site": Device.site,
        "department": Device.department_id,
        "building": Device.building_id,
        "os_version": Device.os_version,
    }[rule.field]
    if rule.operator == "unknown":
        return or_(column.is_(None), column == "")
    if rule.operator == "contains":
        return column.icontains(rule.value, autoescape=True)
    return column == rule.value if rule.operator == "is" else and_(column.is_not(None), column != "", column != rule.value)


def group_predicate(group, now):
    combine = and_ if group.match == "all" else or_
    return combine(
        *(group_predicate(node, now) if isinstance(node, ScopeGroup) else rule_predicate(node, now) for node in group.rules)
    )


def scoped_devices(scope: DeviceScope, now: datetime | None = None):
    now = now or datetime.now(UTC)
    stmt = select(Device.id, Device.mdm_connection_id, Device.external_id, Device.last_check_in, Device.last_inventory_at).where(
        Device.platform == "macos",
        Device.mdm_provider == "jamf",
        ~gone_for_good(Device.mdm_connection_id, Device.external_id, at=now),
    )
    if scope.connection_id is not None:
        stmt = stmt.where(Device.mdm_connection_id == scope.connection_id)
    if scope.mode == "smart_group":
        stmt = stmt.where(Device.managed.is_(True))
    if scope.rules:
        stmt = stmt.where(group_predicate(scope, now))
    return stmt.cte("patch_plan_devices")


def scope_description(scope: DeviceScope) -> list[str]:
    lines = [f"Jamf connection: {scope.connection_id or 'all'}", f"Match {scope.match} conditions; current Jamf macOS inventory."]
    lines.append(
        "Smart group style: managed devices only."
        if scope.mode == "smart_group"
        else "Advanced search: Managed is an explicit condition, if selected."
    )

    def describe(rule, depth):
        indent = "  " * depth
        if isinstance(rule, ScopeGroup):
            lines.append(f"{indent}{'AND' if rule.match == 'all' else 'OR'} (")
            for child in rule.rules:
                describe(child, depth + 1)
            lines.append(f"{indent})")
            return
        key = f" [{rule.key}]" if rule.key else ""
        suffix = (
            " days"
            if rule.operator in {"within", "older"}
            else " (UTC; selected day excluded)"
            if rule.operator in {"before", "after"}
            else ""
        )
        if rule.operator in {"like", "not_like"}:
            suffix = " (case-insensitive literal substring)"
        elif rule.operator in {"matches_regex", "does_not_match_regex"}:
            suffix = " (case-insensitive regex search)"
        value = "" if rule.operator == "unknown" else rule.value
        lines.append(indent + f"{rule.field}{key} {rule.operator.replace('_', ' ')} {value}{suffix}".strip())

    for rule in scope.rules:
        describe(rule, 0)
    return lines
