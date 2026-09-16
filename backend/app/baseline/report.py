"""The evidence artefact: #464's verdicts over #465's intervals, as the object an auditor receives (#472, #219 R5).

**The contract is docs/compliance-evidence.md** — read it before renaming anything here. The artefact is archived the
day it is first printed and next year's auditor compares against that copy, so every key is permanent on the terms
docs/splunk-wire-vocabulary.md sets: camelCase, the token `ID` uppercased, additive only. The three rulings this
shape carries — a header that names no framework, a sum that closes, a zero spelled in words — are §2, §4 and §5
there, each with the argument that produced it.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.baseline.catalogue import BaselineRule, catalogue
from app.baseline.evaluator import NOT_REPORTED, evaluate, field_value
from app.baseline.intervals import DEPARTED, NOT_OBSERVED, OBSERVED, Interval, ledger_heartbeat, section_intervals
from app.mdm.jamf.contract import SUBJECT_COMPUTER
from app.models.schema import MdmConnection, ObservationSection, ObservationSpan
from app.observations.departure import departure_windows

REFUSAL = "This is a record of technical state, not a judgement of compliance."
NOT_VISIBLE = ("policy controls", "process controls", "personnel controls")
UNDER_ONE_INTERVAL = "under one reporting interval"
NOT_CARRIED = "Jamf's record for this stretch carried no {field}."
METHOD = "What each Mac reported to one Jamf Pro connection at each inventory, read from LoonInspect's observation ledger."
NOT_VISIBLE_SAID = "Nothing here reads a policy, a process or a person; none of the three is visible from an MDM's inventory."
CLOCK = "Device time — the inventory time Jamf reported — is the interval clock, with LoonInspect's collection time beside it."

#: The five states in the artefact's spelling. `met` and `unmet` are the only two that assert anything about a Mac;
#: the other three are the named parts of `notObserved` and are never folded into the first two.
STATES = {"met": "met", "unmet": "unmet", NOT_REPORTED: "notReported", NOT_OBSERVED: "noObservation", DEPARTED: "departed"}
UNANSWERED = (NOT_REPORTED, NOT_OBSERVED, DEPARTED)


def _ts(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _span(seconds: float) -> dict[str, Any]:
    """Exact `seconds`, which the identity is asserted on, plus the reading figure — absent where it would be 0."""
    days = round(seconds / 86400, 2)
    return {"seconds": int(seconds), "days": days} if days else {"seconds": int(seconds)}


def _duration(seconds: float) -> str:
    """Never `0 days`: a zero meaning "seen once" must not wear a zero meaning "never happened" (R5 5.4)."""
    days = round(seconds / 86400, 2)
    return UNDER_ONE_INTERVAL if not days else ("1 day" if days == 1 else f"{days:g} days")


def _witnessed(rule: BaselineRule, body: dict | None) -> dict[str, Any]:
    """The field read and the value read. `field_value` answers None only for absence, so a field the aperture never
    collected says so in words rather than wearing a verdict's costume."""
    value = field_value(body or {}, rule.field_path)
    if value is None:
        return {"field": rule.field, "statement": NOT_CARRIED.format(field=rule.field)}
    said = rule.witnessed.format(field=rule.field, value=value, operand=rule.predicate.operand)
    return {"field": rule.field, "value": value, "statement": said}


def _mscp(rule: BaselineRule) -> dict[str, Any]:
    """The see-also, never MSCP's `references:` block — that is where the framework mappings live."""
    return {"mscp": {"ruleID": rule.mscp.id, "branch": rule.mscp.branch, "match": rule.mscp.match}} if rule.mscp else {}


def _row(rule: BaselineRule, subject_id: str, state: str, interval: Interval, body: dict | None, gone: tuple) -> dict:
    seconds = interval.duration.total_seconds()
    row: dict[str, Any] = {"ruleID": rule.id, "deviceID": subject_id, "state": STATES[state]}
    row |= {"from": _ts(interval.starts_at), "to": _ts(interval.ends_at), **_span(seconds), "duration": _duration(seconds)}
    if interval.longest_gap:
        row["longestGap"] = _span(interval.longest_gap.total_seconds())
    if interval.state == OBSERVED:
        row |= {"observations": interval.observation_count, "collectedFrom": _ts(interval.first_collected_at)}
        row["collectedTo"] = _ts(interval.last_collected_at)
    if interval.digest:
        # Prefixed with its contract version, so the row says *this content hashes to this under v0*.
        row |= {"sectionDigest": interval.digest, "contractVersion": interval.digest.split(":", 1)[0]}
        row["witnessed"] = _witnessed(rule, body)
    row |= _mscp(rule)
    opened = [at for at, _ in gone if at <= interval.starts_at]
    if state == DEPARTED and opened:
        row["departedAt"] = _ts(max(opened))
    return row


def _totals(acc: dict[str, float]) -> dict[str, Any]:
    """met + unmet + not observed = the window, and it closes. All three print even at zero — an identity a reader
    cannot check is not one — while a rule nothing could be counted for is absent from `byRule` instead."""
    unanswered = sum(acc[state] for state in UNANSWERED)
    out = {"met": _span(acc["met"]), "unmet": _span(acc["unmet"]), "notObserved": _span(unanswered)}
    out["window"] = _span(acc["met"] + acc["unmet"] + unanswered)
    parts = {STATES[state]: _span(acc[state]) for state in UNANSWERED if acc[state]}
    return out | ({"notObservedParts": parts} if parts else {})


def _verdicts(section: str, interval: Interval, rules: list[BaselineRule], bodies: dict[str, dict]) -> dict[str, str]:
    """A gap is that gap's state for every rule; a span not carrying the section is `not_reported`, never `unmet`."""
    if interval.state != OBSERVED:
        return dict.fromkeys((rule.id for rule in rules), interval.state)
    if interval.digest is None:
        return dict.fromkeys((rule.id for rule in rules), NOT_REPORTED)
    return evaluate(interval.digest.split(":", 1)[0], section, interval.digest, bodies.get(interval.digest))


async def _identities(db: AsyncSession, *, connection_id: int, subject_kind: str, as_of: datetime) -> dict[str, dict]:
    """The name a human uses plus the lineage triple — a repair keeps the serial and changes the UDID, so neither
    alone is a Mac over its life. Newest span at or below `as_of`, so an archive names it as it was named then."""
    named = (("name", "label"), ("udid", "udid"), ("serialNumber", "serial_number"), ("managementID", "management_id"))
    newest = (
        select(ObservationSpan)
        .where(
            ObservationSpan.mdm_connection_id == connection_id,
            ObservationSpan.subject_kind == subject_kind,
            ObservationSpan.first_observed_at <= as_of,
        )
        .distinct(ObservationSpan.subject_id)
        .order_by(ObservationSpan.subject_id, ObservationSpan.first_observed_at.desc())
    )
    spans = (await db.execute(newest)).scalars().all()
    return {s.subject_id: {"deviceID": s.subject_id, **{k: getattr(s, a) for k, a in named if getattr(s, a)}} for s in spans}


async def evidence_report(
    db: AsyncSession,
    *,
    connection: MdmConnection,
    window_from: datetime,
    as_of: datetime | None = None,
    subject_kind: str = SUBJECT_COMPUTER,
) -> dict[str, Any]:
    """The whole artefact for one connection over one window, as a JSON-ready document. `as_of` defaults to the
    ledger's own heartbeat, never `runs` — those purge at 30 days while the ledger has no retention at all, so last
    March is answerable long after the run that collected it is gone (R5 5.5)."""
    at = as_of or await ledger_heartbeat(db, connection_id=connection.id) or window_from
    rules = catalogue()
    by_section: dict[str, list[BaselineRule]] = defaultdict(list)
    for rule in rules.rules:
        by_section[rule.section].append(rule)

    # One query per section rather than per rule: ten rules across three sections is three walks of the ledger.
    ledgers = {
        section: await section_intervals(
            db, connection_id=connection.id, section=section, window_from=window_from, as_of=at, subject_kind=subject_kind
        )
        for section in by_section
    }
    digests = {i.digest for led in ledgers.values() for s in led.subjects for i in s.intervals if i.digest}
    bodies: dict[str, dict] = {}
    if digests:
        stored = select(ObservationSection.digest, ObservationSection.body).where(ObservationSection.digest.in_(digests))
        bodies = dict((await db.execute(stored)).all())
    gone = await departure_windows(db, connection_id=connection.id, subject_kind=subject_kind)

    rows: list[dict] = []
    per_rule: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    per_device: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    fleet: dict[str, float] = defaultdict(float)
    seen: set[str] = set()
    for section, section_rules in by_section.items():
        for subject in ledgers[section].subjects:
            for interval in subject.intervals:
                verdicts = _verdicts(section, interval, section_rules, bodies)
                body = bodies.get(interval.digest) if interval.digest else None
                seconds = interval.duration.total_seconds()
                seen |= {interval.digest.split(":", 1)[0]} if interval.digest else set()
                for rule in section_rules:
                    state = verdicts[rule.id]
                    rows.append(_row(rule, subject.subject_id, state, interval, body, gone.get(subject.subject_id, ())))
                    per_rule[rule.id][state] += seconds
                    per_device[subject.subject_id][state] += seconds
                    fleet[state] += seconds

    known = await _identities(db, connection_id=connection.id, subject_kind=subject_kind, as_of=at)
    # Five header items, in this order (R5 5.3). The second is an absence: no framework is named anywhere on the
    # artefact, and `notVisible` is the item a later session trims for space. It does not get trimmed.
    method = {"statement": METHOD, "source": "observation ledger"}
    method["connection"] = {"connectionID": connection.id, "name": connection.name, "provider": connection.provider}
    method |= {"catalogue": {"version": rules.version, "rules": len(rules.rules)}}
    method["window"] = {"start": _ts(window_from), "asOf": _ts(at)}
    return {
        "header": {
            "method": method,
            "notVisible": {"controls": list(NOT_VISIBLE), "statement": NOT_VISIBLE_SAID},
            "refusal": REFUSAL,
            "contractVersions": sorted(seen),
            "clock": {"interval": "device", "statement": CLOCK},
        },
        "rules": [
            {"ruleID": r.id, "title": r.title, "section": r.section, "field": r.field}
            | {"predicate": {"operator": r.predicate.operator, "operand": r.predicate.operand}, **_mscp(r)}
            for r in rules.rules
        ],
        "devices": [known.get(subject_id, {"deviceID": subject_id}) for subject_id in sorted(per_device)],
        "rows": rows,
        "totals": {
            "fleet": _totals(fleet) if fleet else {},
            "byRule": {key: _totals(acc) for key, acc in sorted(per_rule.items())},
            "byDevice": {key: _totals(acc) for key, acc in sorted(per_device.items())},
        },
    }
