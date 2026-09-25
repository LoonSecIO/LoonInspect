"""Retain assessment totals at ingest and summary outcomes at completion, without AI calls (#605)."""

from sqlalchemy import select, update

from app.core.config import settings
from app.models.schema import DeviceHistoryPoint, ObservationSpan
from app.summaries.evidence import compact, digest


def assessment_totals(payload: dict) -> dict:
    """Counts are app-build/finding pairs, summed once per distinct app name/bundle/version.

    They are the uncapped counts already recorded in the inventory event, not a union of
    truncated CVE lists. Coverage remains explicit; no covered builds means unknown.
    """
    if "app" not in payload:
        return {"total": None, "critical": None, "covered": 0, "outside": 0, "corpus": []}
    seen, corpus = set(), set()
    total = critical = covered = outside = 0
    for item in payload["app"] or []:
        app, vuln = item.get("app", {}), item.get("vuln", {})
        key = (app.get("name"), app.get("bundleId"), app.get("version"))
        if key in seen:
            continue
        seen.add(key)
        if vuln.get("corpusAsOf"):
            corpus.add(vuln["corpusAsOf"])
        counts = vuln.get("counts")
        if vuln.get("assessment") == "covered" and isinstance(counts, dict):
            covered += 1
            total += counts.get("total", 0)
            critical += counts.get("severity", {}).get("critical", 0)
        else:
            outside += 1
    return {
        "total": total if covered else None,
        "critical": critical if covered else None,
        "covered": covered,
        "outside": outside,
        "corpus": sorted(corpus),
    }


async def capture(db, *, device, event):
    span = await db.scalar(
        select(ObservationSpan).where(
            ObservationSpan.mdm_connection_id == device.mdm_connection_id,
            ObservationSpan.subject_kind == "computer",
            ObservationSpan.subject_id == device.external_id,
            ObservationSpan.is_current.is_(True),
        )
    )
    if span is None:
        return
    evidence = None
    if settings.vuln_tenant_selection and "app" in event.payload and "applications" in span.section_digests:
        from app.core.vuln_selection import selected_signature
        from app.observations.assessment_evidence import build_evidence

        signature = await selected_signature(db)
        if signature is not None:
            evidence = (await build_evidence(db, [device.id], signature))[device.id]
    return await capture_at(
        db,
        device=device,
        event=event,
        span=span,
        observed_at=span.last_observed_at,
        last_check_in=device.last_check_in,
        evidence=evidence,
    )


async def capture_at(db, *, device, event, span, observed_at, last_check_in=None, evidence=None):
    if await db.scalar(select(DeviceHistoryPoint.id).where(DeviceHistoryPoint.source_id == event.id)):
        return None
    assessment = assessment_totals(event.payload)
    # Without the extension attributes (#644): the span already keys on that section, so a
    # value change opens a point through the span, and a digest that widened on upgrade would
    # open one new point per device on the first quiet sweep after it.
    assessment["evidenceDigest"] = digest(compact(event.payload, extension_attributes=False))
    if evidence is not None:
        assessment["vulnerabilityEvidence"] = evidence
    prior = await db.scalar(
        select(DeviceHistoryPoint)
        .where(DeviceHistoryPoint.device_id == device.id, DeviceHistoryPoint.collected_at <= event.created_at)
        .order_by(DeviceHistoryPoint.collected_at.desc(), DeviceHistoryPoint.id.desc())
        .limit(1)
    )
    from app.observations.assessment_evidence import comparable

    prior_evidence = comparable(prior.assessment) if prior else None
    if (
        prior
        and prior.span_id == span.id
        and prior_evidence == comparable(assessment)
        and (not last_check_in or "lastCheckIn" in prior.assessment)
    ):
        return  # Quiet sweeps do not create another historical receipt.
    if last_check_in:
        assessment["lastCheckIn"] = last_check_in.isoformat()
    point = DeviceHistoryPoint(
        device_id=device.id,
        span_id=span.id,
        source_id=event.id,
        observed_at=observed_at,
        collected_at=event.created_at,
        assessment=assessment,
    )
    db.add(point)
    await db.flush()
    return point


async def retain_summary(db, source_id, status, summary=None, provider=None, reason=None):
    if source_id is None:
        return  # A reassessment has no inventory source or corresponding AI summary.
    # Exact source receipt, never nearest timestamp: sweep time and inventory time differ.
    await db.execute(
        update(DeviceHistoryPoint)
        .where(DeviceHistoryPoint.source_id == source_id)
        .values(summary_status=status, summary=summary, summary_provider=provider, summary_reason=reason)
    )
