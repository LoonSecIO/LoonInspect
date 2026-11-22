"""Fleet adoption and device transition history from retained Jamf observation spans."""

from collections import Counter
from datetime import UTC, date, datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text

from app.core.auth import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.core.sofa import assessment, catalog_for, refresh_catalog
from app.models.schema import Device

router = APIRouter(prefix="/api/os-posture", tags=["macOS posture"], dependencies=[Depends(require(Permission.DEVICE_READ))])

# Carry the newest reported span for each Mac across quiet days. Explicitly missing sections stay unknown.
_SPANS = """
SELECT d.id, d.hostname, s.first_observed_at AS observed, s.last_observed_at AS last_observed,
       s.first_collected_at AS collected, s.id AS span_id, o.body->>'version' AS version,
       o.body->>'build' AS build, h.body->>'modelIdentifier' AS model
FROM observation_spans s
JOIN devices d ON d.mdm_connection_id = s.mdm_connection_id AND d.external_id = s.subject_id AND d.platform='macos'
LEFT JOIN observation_sections o ON o.tenant_id=s.tenant_id AND o.digest=s.section_digests->>'operating_system'
LEFT JOIN observation_sections h ON h.tenant_id=s.tenant_id AND h.digest=s.section_digests->>'hardware'
WHERE s.subject_kind='computer'
"""


@router.get("")
async def adoption(
    day: date | None = None,
    target: int | None = Query(None, ge=1, le=999),
    version: str | None = None,
    eligibility: str | None = None,
    page: int = Query(0, ge=0),
    db=Depends(get_db),
):
    today = datetime.now(UTC).date()
    selected = day or today
    if selected > today:
        raise HTTPException(422, "Choose today or an earlier observation date.")
    start = selected - timedelta(days=29)
    end = datetime.combine(selected + timedelta(days=1), datetime.min.time(), UTC)
    begin = end - timedelta(days=30)
    # One seed per Mac plus only the last change of each subsequent day.
    statement = text(f"""
        WITH spans AS ({_SPANS} AND s.first_observed_at < :end),
        seeds AS (SELECT DISTINCT ON (id) * FROM spans WHERE observed < :begin
                  ORDER BY id, observed DESC, collected DESC, span_id DESC),
        days AS (SELECT DISTINCT ON (id, (observed AT TIME ZONE 'UTC')::date) *
                 FROM spans WHERE observed >= :begin
                 ORDER BY id, (observed AT TIME ZONE 'UTC')::date, observed DESC, collected DESC, span_id DESC)
        SELECT * FROM (SELECT * FROM seeds UNION ALL SELECT * FROM days) AS history ORDER BY observed, collected, span_id
    """)
    # Spans retain endpoints even when repeated identical reports collapse into one row.
    # An interior day of a long span cannot prove that Jamf supplied fresh inventory that day.
    evidence_sql = text(f"""
        SELECT DISTINCT (point AT TIME ZONE 'UTC')::date FROM ({_SPANS}) history
        CROSS JOIN LATERAL (VALUES (observed), (last_observed)) AS bounds(point)
        WHERE point >= :begin AND point < :end
    """)
    evidence_days = set((await db.scalars(evidence_sql, {"begin": begin, "end": end})).all())
    rows = iter((await db.execute(statement, {"begin": begin, "end": end})).mappings())
    row = next(rows, None)
    devices, counts, series = {}, Counter(), []
    for index in range(30):
        current_day = start + timedelta(days=index)
        while row and row["observed"].astimezone(UTC).date() <= current_day:
            old = devices.get(row["id"])
            if old:
                counts[old["version"] or "unknown"] -= 1
            devices[row["id"]] = row
            counts[row["version"] or "unknown"] += 1
            row = next(rows, None)
        series.append(
            {
                "day": current_day,
                "freshEvidence": current_day in evidence_days,
                "counts": {key: n for key, n in counts.items() if n},
            }
        )
    catalog = catalog_for(selected)
    calendar = catalog or catalog_for(today) or {}
    targets = sorted((catalog or {}).get("branches", {}), key=int, reverse=True)
    target_key = str(target) if target else next(iter(targets), "")
    matches, totals = [], Counter()
    for item in sorted(devices.values(), key=lambda r: (r["hostname"] or "", r["id"])):
        patch, latest, compatible = assessment(item["version"], item["build"], item["model"], target_key, catalog)
        totals[compatible] += 1
        if (version and version != (item["version"] or "unknown")) or (eligibility and eligibility != compatible):
            continue
        matches.append(
            {
                "id": item["id"],
                "name": item["hostname"],
                "version": item["version"],
                "build": item["build"],
                "model": item["model"],
                "observed": item["last_observed"] if item["last_observed"] < end else item["observed"],
                "latest": latest,
                "patch": patch,
                "eligibility": compatible,
            }
        )
    return {
        "series": series,
        "targets": targets,
        "target": target_key,
        "asOf": catalog["asOf"] if catalog else None,
        "eligibilityCounts": totals,
        "devices": matches[page * 100 : page * 100 + 100],
        "total": len(matches),
        "releases": [r for r in calendar.get("releases", []) if start.isoformat() <= r["released"] <= selected.isoformat()],
    }


@router.get("/device/{device_id}")
async def transitions(device_id: int, db=Depends(get_db)):
    if await db.get(Device, device_id) is None:
        raise HTTPException(404, "Device not found")
    rows = (
        await db.execute(text(_SPANS + " AND d.id=:device ORDER BY observed, collected, span_id"), {"device": device_id})
    ).mappings()
    result, previous = [], None
    for row in rows:
        state = (row["version"], row["build"])
        if previous is None or state != previous[0]:
            result.append(
                {
                    "version": state[0],
                    "build": state[1],
                    "observed": row["observed"],
                    "previousObserved": previous[1] if previous else None,
                }
            )
        previous = state, row["last_observed"]
    return result[::-1]


@router.post("/refresh", dependencies=[Depends(require(Permission.PATCH_CATALOG_SYNC))])
async def refresh():
    try:
        data = await refresh_catalog()
    except httpx.HTTPError as exc:
        raise HTTPException(424, "The SOFA feed could not be read. Check the feed connection and refresh again.") from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(424, "The SOFA feed has an unexpected format. Check the feed status and try again.") from exc
    except OSError as exc:
        raise HTTPException(
            409, "The SOFA catalog could not be saved. Check space and permissions on the cache directory."
        ) from exc
    return {"asOf": data["asOf"]}
