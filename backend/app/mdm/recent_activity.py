"""Window checkpoints and read-only reconciliation of the daily Jamf crawl."""

import re
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import select, text

from app.core.scheduling import KIND_RECENT
from app.mdm.jamf.contract import V0_SECTIONS
from app.models.schema import Run


async def collection_scope(db, collection, end):
    scope = {
        "kind": collection.kind,
        "selector": collection.selector or "",
        "sections": sorted(collection.sections or V0_SECTIONS),
        "quarantine": sorted(collection.quarantined_extension_attributes or []),
    }
    if collection.kind != KIND_RECENT:
        return scope
    prior = select(Run).where(
        Run.collection_id == collection.id,
        Run.coverage_scope.contains(scope),
        Run.coverage_scope["sections"] == scope["sections"],
        Run.coverage_scope["quarantine"] == scope["quarantine"],
    )
    last = await db.scalar(
        prior.where(Run.status == "succeeded", Run.devices_failed == 0).order_by(Run.started_at.desc()).limit(1)
    )
    if last:
        start = datetime.fromisoformat(last.coverage_scope["end"]) - timedelta(minutes=2)
    else:
        first = await db.scalar(prior.order_by(Run.started_at).limit(1))
        start = datetime.fromisoformat(first.coverage_scope["start"]) if first else end - timedelta(minutes=17)
    return {**scope, "start": start.isoformat(), "end": end.isoformat()}


def inventory_api_version(version):
    release = re.match(r"^(\d+)\.(\d+)", version or "")
    if not release:
        raise ValueError("Recent activity needs the Jamf Pro version. Check permission to read the Jamf Pro version.")
    return 4 if tuple(map(int, release.groups())) >= (11, 31) else 3


def activity_selector(scope, version):
    fields = ["reportDate"]
    fields.extend(["lastContact", "lastCheckIn"] if inventory_api_version(version) == 4 else ["lastContactTime"])

    def stamp(key):
        return datetime.fromisoformat(scope[key]).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    start, end = stamp("start"), stamp("end")
    windows = ",".join(f'(general.{field}>="{start}";general.{field}<="{end}")' for field in fields)
    return f"({scope['selector']});({windows})" if scope["selector"] else f"({windows})"


def classify(report_at, section, full, polls):
    if report_at is None:
        return "missingReportTime", None
    eligible = [
        p
        for p in polls
        if (not p["selector"] or p["selector"] == full["selector"])
        and section in p["sections"]
        and p["quarantine"] == full["quarantine"]
    ]
    covering = [p for p in eligible if datetime.fromisoformat(p["start"]) <= report_at <= datetime.fromisoformat(p["end"])]
    for poll in covering:
        if poll["complete"]:
            return "coveredMiss", poll
    if covering:
        return "failedWindow", covering[0]
    if any(datetime.fromisoformat(p["start"]) <= report_at <= datetime.fromisoformat(p["end"]) for p in polls):
        return "incomparableScope", None
    if (
        eligible
        and all(report_at > datetime.fromisoformat(p["end"]) for p in eligible if p["complete"])
        and any(p["complete"] for p in eligible)
    ):
        return "afterLastWindow", None
    return "uncovered", None


async def coverage(db, crawl, page):
    scope = crawl.coverage_scope or {}
    if scope.get("kind") != "device_sweep" or crawl.status != "succeeded" or crawl.devices_failed:
        return {"complete": False, "rows": [], "counts": {}, "polls": []}
    previous = await db.scalar(
        select(Run.started_at)
        .where(
            Run.mdm_connection_id == crawl.mdm_connection_id,
            Run.id != crawl.id,
            Run.started_at < crawl.started_at,
            Run.status == "succeeded",
            Run.devices_failed == 0,
            Run.coverage_scope["kind"].astext == "device_sweep",
        )
        .order_by(Run.started_at.desc())
        .limit(1)
    )
    since = previous or crawl.started_at - timedelta(days=1)
    runs = await db.scalars(
        select(Run)
        .where(
            Run.mdm_connection_id == crawl.mdm_connection_id,
            Run.started_at < crawl.started_at,
            Run.finished_at >= since,
            Run.finished_at <= crawl.started_at,
            Run.coverage_scope["kind"].astext == KIND_RECENT,
        )
        .order_by(Run.started_at.desc())
    )
    polls = [
        {
            **r.coverage_scope,
            "id": str(r.id),
            "complete": r.status == "succeeded" and not r.devices_failed,
            "selected": r.device_count,
            "status": "partial" if r.devices_failed else r.status,
            "requests": r.coverage_scope.get("requests", (r.observations or {}).get("requests")),
        }
        for r in runs
    ]
    changes = (
        await db.execute(
            text("""
        SELECT s.id, s.subject_id, d.id AS device, d.hostname, s.first_collected_at AS discovered, s.report_at,
               s.previous_id, c.id AS change_id, c.field, c.entry_label, c.change, diff.key AS section,
               p.section_digests->>diff.key AS prior, diff.value AS current,
               o.body->>'build' AS build, old.body->>'build' AS old_build
        FROM observation_spans s LEFT JOIN observation_spans p ON p.id=s.previous_id
        LEFT JOIN devices d ON d.external_id=s.subject_id AND d.mdm_connection_id=s.mdm_connection_id AND d.platform='macos'
        CROSS JOIN LATERAL jsonb_each_text(CASE WHEN p.id IS NULL THEN '{"baseline":""}'::jsonb ELSE s.section_digests END) diff
        LEFT JOIN device_changes c ON c.span_id=s.id AND c.section=diff.key
        LEFT JOIN observation_sections o ON o.tenant_id=s.tenant_id AND o.digest=diff.value AND diff.key='operating_system'
        LEFT JOIN observation_sections old ON old.tenant_id=s.tenant_id AND old.digest=p.section_digests->>diff.key
                AND diff.key='operating_system'
        WHERE s.first_run_id=:job AND s.subject_kind='computer'
          AND (p.id IS NULL OR p.section_digests->>diff.key IS DISTINCT FROM diff.value)
        ORDER BY s.first_collected_at,s.id,diff.key,c.id
    """),
            {"job": crawl.id},
        )
    ).mappings()
    counts, macs, rows = Counter(), set(), []
    for change in changes:
        status, poll = (
            ("baseline", None) if not change["previous_id"] else classify(change["report_at"], change["section"], scope, polls)
        )
        if change["previous_id"] and change["prior"] is None:
            status, poll = "incomparableScope", None
        index = sum(counts.values())
        counts[status] += 1
        if status == "coveredMiss":
            macs.add(change["subject_id"])
        if page * 100 <= index < (page + 1) * 100:
            rows.append(
                {
                    **change,
                    "status": status,
                    "poll": poll["id"] if poll else None,
                    "delaySeconds": (change["discovered"] - change["report_at"]).total_seconds() if change["report_at"] else None,
                }
            )
    cursor = since
    gaps = []
    for poll in sorted((p for p in polls if p["complete"]), key=lambda p: p["start"]):
        start, end = datetime.fromisoformat(poll["start"]), datetime.fromisoformat(poll["end"])
        if start > cursor:
            gaps.append([cursor, start])
        cursor = max(cursor, end)
    if cursor < crawl.started_at:
        gaps.append([cursor, crawl.started_at])
    return {
        "gaps": gaps,
        "complete": True,
        "since": since,
        "until": crawl.started_at,
        "counts": counts,
        "affectedMacs": len(macs),
        "polls": polls,
        "rows": rows,
        "total": sum(counts.values()),
    }
