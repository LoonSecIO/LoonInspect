"""Retain release-scoped answers in the existing device history ledger (#621).

Snapshots describe the last observed inventory, not a new observation or remediation.
The caller owns the assessment transaction; a failed evidence write prevents selection.
Only the opt-in tenant-selection path calls this module. No historical data is backfilled.
"""

from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import and_, select

from app.models.schema import AppCatalogEntry, Device, DeviceHistoryPoint, InstalledApp, ObservationSpan, VulnCorpusRelease


async def build_evidence(db, device_ids, signature):
    """Read stored answer/provenance once for a bounded batch, never one query per app."""
    release = await db.get(VulnCorpusRelease, signature)
    if release is None:
        raise ValueError(
            "Assessment history could not be saved: selected intelligence is missing. Restore a complete database backup."
        )
    entries = (
        await db.execute(
            select(InstalledApp, AppCatalogEntry.vuln_evaluated_at)
            .join(Device, Device.id == InstalledApp.device_id)
            .outerjoin(
                AppCatalogEntry,
                and_(
                    AppCatalogEntry.version_hash == InstalledApp.version_hash,
                    AppCatalogEntry.platform == Device.platform,
                    AppCatalogEntry.vuln_signature == signature,
                ),
            )
            .where(InstalledApp.device_id.in_(device_ids))
            .order_by(InstalledApp.device_id, InstalledApp.key_full, InstalledApp.id)
            .execution_options(populate_existing=True)
        )
    ).all()
    grouped = defaultdict(dict)
    for app, evaluated in entries:
        current = app.vuln_signature == signature
        covered = current and app.vuln_assessment == "covered"
        grouped[app.device_id][app.key_full] = {
            "keyFull": app.key_full,
            "keyTitle": app.key_title,
            "name": app.name,
            "bundleId": app.bundle_id,
            "version": app.version,
            "shortVersion": app.short_version,
            "assessment": "covered" if covered else "unknown_app",
            "counts": app.vuln_counts if covered else None,
            "ids": app.vuln_ids if covered else None,
            "idsTruncated": app.vuln_ids_truncated if covered else None,
            "oldestPublished": app.vuln_oldest_published if covered else None,
            "evaluatedAt": evaluated.isoformat() if current and evaluated else None,
        }
    return {
        device_id: {
            "releaseDigest": signature,
            "corpusAsOf": release.asof.isoformat(),
            "builds": list(grouped[device_id].values()),
        }
        for device_id in device_ids
    }


def comparable(assessment):
    """Ignore execution clocks when deciding whether an assertion actually changed."""
    result = {key: value for key, value in assessment.items() if key not in ("lastCheckIn", "basis")}
    evidence = result.get("vulnerabilityEvidence")
    if evidence is not None:
        result.pop("evidenceDigest", None)  # The observation span already identifies inventory.
        result["vulnerabilityEvidence"] = {
            **evidence,
            "builds": [{key: value for key, value in build.items() if key != "evaluatedAt"} for build in evidence["builds"]],
        }
    return result


def totals(evidence):
    builds = evidence["builds"]
    covered = [build for build in builds if build["assessment"] == "covered"]
    return {
        "total": sum(build["counts"]["total"] for build in covered) if covered else None,
        "critical": sum(build["counts"]["critical"] for build in covered) if covered else None,
        "covered": len(covered),
        "outside": len(builds) - len(covered),
        "corpus": [evidence["corpusAsOf"][:10]] if builds else [],
        "vulnerabilityEvidence": evidence,
    }


async def capture_release_transition(db, signature, *, now=None):
    """Append assessment points in batches inside selection, retaining observation clocks.

    A device without a recorded application observation has no defensible history point;
    its next real ingest records the baseline. Quiet/repeated assessments append nothing.
    Source is NULL because no inventory event occurred, never a fabricated event ID.
    """
    now = now or datetime.now(UTC)
    cursor = 0
    while True:
        batch = (
            await db.execute(
                select(Device.id, Device.last_check_in, ObservationSpan)
                .join(
                    ObservationSpan,
                    and_(
                        ObservationSpan.mdm_connection_id == Device.mdm_connection_id,
                        ObservationSpan.subject_kind == "computer",
                        ObservationSpan.subject_id == Device.external_id,
                        ObservationSpan.is_current.is_(True),
                    ),
                )
                .where(Device.id > cursor, ObservationSpan.section_digests.has_key("applications"))
                .order_by(Device.id)
                .limit(100)
            )
        ).all()
        if not batch:
            break
        ids = [row[0] for row in batch]
        evidence = await build_evidence(db, ids, signature)
        prior = {
            point.device_id: point
            for point in (
                await db.scalars(
                    select(DeviceHistoryPoint)
                    .where(DeviceHistoryPoint.device_id.in_(ids))
                    .distinct(DeviceHistoryPoint.device_id)
                    .order_by(DeviceHistoryPoint.device_id, DeviceHistoryPoint.collected_at.desc(), DeviceHistoryPoint.id.desc())
                )
            ).all()
        }
        for device_id, last_check_in, span in batch:
            assessment = totals(evidence[device_id])
            previous = prior.get(device_id)
            if previous and previous.span_id == span.id and comparable(previous.assessment) == comparable(assessment):
                continue
            assessment["basis"] = "corpus_assessment"
            if last_check_in:
                assessment["lastCheckIn"] = last_check_in.isoformat()
            db.add(
                DeviceHistoryPoint(
                    device_id=device_id,
                    span_id=span.id,
                    source_id=None,
                    observed_at=span.last_observed_at,
                    collected_at=now,
                    assessment=assessment,
                )
            )
        await db.flush()
        cursor = ids[-1]
