"""Read models for the existing AI usage ledger: historical attribution and live work."""

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, case, exists, func, or_, select

from app.core.ai_configs import list_configs
from app.core.ai_usage import (
    MEASURES,
    RETENTION_DAYS,
    _last_recording_failures,
    _recording_failures,
    metadata_model,
    service_identity,
)
from app.core.config import settings
from app.core.database import bound_tenant_id
from app.models.schema import AIUsageAttempt as Attempt
from app.models.schema import AIUsageCoverage as Coverage
from app.models.schema import AIUsageDaily as Daily
from app.models.schema import AIUsageWork as Work
from app.models.schema import (
    ApplicationPatchPlan,
    DataSharingSettings,
    FeatureFlag,
    InventorySummaryJob,
    InventorySummarySettings,
)

PURPOSES = {
    "inventory_summary": "Inventory summaries",
    "changes_prompt": "Change Detection questions",
    "vulnerabilities_prompt": "Vulnerability questions",
    "application_patch_plan": "Patch-plan investigation",
    "device_scope_proposal": "Device-filter proposals",
    "exclusion_ranking": "Exclusion ranking",
    "patch_policy_rules": "Patch-policy drafting",
    "ai_test_box": "Test prompts",
}
OUTCOMES = {
    "completed": "Useful result",
    "answered": "Answered; acceptance not measured",
    "unusable": "Unusable reply",
    "unsupported": "Unsupported request",
    "waiting_timeout": "Timed out before dispatch",
    "timeout": "Request timed out",
    "rate_limited": "Rate limited",
    "authentication": "Authentication refused",
    "forbidden": "Access refused",
    "unavailable": "Service unavailable",
    "interrupted": "Interrupted",
    "empty": "Empty reply",
    "budget_exhausted_thinking": "Token budget exhausted before an answer",
    "failed": "Failed",
    "http_status": "Legacy HTTP refusal",
    "unreachable": "Legacy connection failure",
    "malformed": "Malformed reply",
    "too_large": "Reply too large",
    "cached": "Cached result",
    "skipped": "Skipped",
    "expired": "Expired",
}
FAILURES = {
    "waiting_timeout",
    "timeout",
    "rate_limited",
    "authentication",
    "forbidden",
    "unavailable",
    "interrupted",
    "failed",
    "http_status",
    "unreachable",
    "malformed",
    "too_large",
    "empty",
    "budget_exhausted_thinking",
    "unusable",
    "unsupported",
}
RAW = (
    "attempts",
    "answered",
    "failed",
    "dispatches",
    "dispatchReports",
    "usefulResults",
    "usefulReports",
    "unusable",
    "waitingTimeouts",
    "retries",
    "fallbacks",
    "inputTokens",
    "inputReports",
    "outputTokens",
    "outputReports",
    "cachedTokens",
    "cacheReports",
    "waitMs",
    "waitReports",
    "requestMs",
    "requestReports",
    "totalMs",
    "totalReports",
    "providerMs",
    "providerReports",
    "detailedAttempts",
    "legacyAttempts",
)
ACTIVE = ("waiting", "running", "validating")


def identity(row):
    return {
        "serviceId": row["service_id"],
        "serviceLabel": row["service_label"],
        "serviceKind": row["service_kind"],
        "provider": row["provider"],
    }


def zero():
    return dict.fromkeys(RAW, 0)


def plus(target, values):
    for key in RAW:
        target[key] += values.get(key, 0) or 0


def metrics(raw):
    result = {
        key: raw[key]
        for key in (
            "attempts",
            "answered",
            "failed",
            "dispatchReports",
            "usefulReports",
            "inputReports",
            "outputReports",
            "cacheReports",
            "waitReports",
            "requestReports",
            "totalReports",
            "providerReports",
        )
    }
    for field, coverage in (
        ("dispatches", "dispatchReports"),
        ("usefulResults", "usefulReports"),
        ("inputTokens", "inputReports"),
        ("outputTokens", "outputReports"),
        ("cachedTokens", "cacheReports"),
        ("unusable", "usefulReports"),
        ("waitingTimeouts", "detailedAttempts"),
        ("retries", "detailedAttempts"),
        ("fallbacks", "detailedAttempts"),
    ):
        result[field] = raw[field] if raw[coverage] else None
    for field, coverage in (
        ("Wait", "waitReports"),
        ("Request", "requestReports"),
        ("Total", "totalReports"),
        ("Provider", "providerReports"),
    ):
        result[f"avg{field}Ms"] = round(raw[field.lower() + "Ms"] / raw[coverage], 2) if raw[coverage] else None
    return result


def matches(row, filters):
    return (
        (not filters.get("service") or filters["service"] == row["serviceId"])
        and (not filters.get("provider") or filters["provider"] == row["provider"])
        and (not filters.get("purpose") or filters["purpose"] == row["feature"])
        and (not filters.get("model") or filters["model"] in (row["requested"], row.get("reported", "")))
        and (not filters.get("outcome") or filters["outcome"] == row["outcome"])
    )


async def flags(db):
    enabled = bool(await db.scalar(select(FeatureFlag.enabled).where(FeatureFlag.key == "ai_features")))
    consent = bool(await db.scalar(select(DataSharingSettings.ai_inference)))
    return enabled, consent


async def current_services(db):
    return [
        identity({"provider": config.provider, **service_identity(config.provider, config)}) for config in await list_configs(db)
    ]


async def coverage_state(db, *, start=None, end=None):
    row = await db.get(Coverage, bound_tenant_id(db))
    degraded = (row.degraded_since if row else None) or _recording_failures.get(bound_tenant_id(db))
    gaps = [value for value in ((row.last_gap_at if row else None), _last_recording_failures.get(bound_tenant_id(db))) if value]
    last_gap = max(gaps) if gaps else degraded
    if degraded and ((start and last_gap < start) or (end and degraded >= end)):
        degraded = None
    return row.first_measured_at if row else None, degraded


def _sum(value, name):
    return func.coalesce(func.sum(value), 0).label(name)


def _count_if(condition, name):
    return _sum(case((condition, 1), else_=0), name)


async def historical_groups(db, start, end):
    """Subtract mirrored detailed facts from daily totals; mixed-version writers remain visible."""
    day = func.date(func.timezone("UTC", Attempt.finished_at))
    window_start = datetime.combine(start, datetime.min.time(), UTC)
    window_end = datetime.combine(end + timedelta(days=1), datetime.min.time(), UTC)
    dims = (
        "feature",
        "provider",
        "service_id",
        "service_label",
        "service_kind",
        "requested",
        "reported",
        "outcome",
        "legacy_outcome",
        "work_outcome",
    )
    columns = [getattr(Attempt, key) for key in dims]
    sums = [
        func.count().label("events"),
        _count_if(Attempt.dispatched_at.is_not(None), "dispatches"),
        _count_if(or_(Attempt.outcome != "interrupted", Attempt.dispatched_at.is_not(None)), "dispatch_reports"),
        _count_if(Attempt.attempt_number > 1, "retries"),
        _count_if(Attempt.fallback.is_(True), "fallbacks"),
    ]
    for name in ("wait_ms", "request_ms", "total_ms", "input_tokens", "output_tokens", "cached_tokens", "provider_ms"):
        sums.extend([_sum(getattr(Attempt, name), name), func.count(getattr(Attempt, name)).label(name + "_reports")])
    detailed = (
        (
            await db.execute(
                select(day.label("day"), *columns, *sums)
                .where(Attempt.finished_at >= window_start, Attempt.finished_at < window_end)
                .group_by(day, *columns)
            )
        )
        .mappings()
        .all()
    )
    mirrored = defaultdict(lambda: dict.fromkeys(MEASURES[:10], 0))
    result = []
    for row in detailed:
        key = tuple(row[k] for k in ("day", "feature", "provider", "requested", "reported", "legacy_outcome"))
        mirror = mirrored[key]
        mirror["events"] += row["events"]
        mirror["request_ms"] += row["request_ms"]
        for value, report in (
            ("input_tokens", "input_reports"),
            ("output_tokens", "output_reports"),
            ("cached_tokens", "cache_reports"),
            ("provider_ms", "provider_reports"),
        ):
            mirror[value] += row[value]
            mirror[report] += row[value + "_reports"]
        raw = zero()
        n, final = row["events"], row["work_outcome"] or row["outcome"]
        raw.update(
            attempts=n,
            detailedAttempts=n,
            dispatchReports=row["dispatch_reports"],
            dispatches=row["dispatches"],
            answered=n if row["outcome"] == "answered" else 0,
            failed=n if row["outcome"] in FAILURES or final in FAILURES else 0,
            usefulReports=n if row["work_outcome"] or row["outcome"] != "answered" else 0,
            usefulResults=n if row["work_outcome"] == "completed" else 0,
            unusable=n if final in ("unusable", "unsupported", "empty", "budget_exhausted_thinking", "malformed") else 0,
            waitingTimeouts=n if row["outcome"] == "waiting_timeout" else 0,
            retries=row["retries"],
            fallbacks=row["fallbacks"],
        )
        for source, total, reports in (
            ("wait_ms", "waitMs", "waitReports"),
            ("request_ms", "requestMs", "requestReports"),
            ("total_ms", "totalMs", "totalReports"),
            ("input_tokens", "inputTokens", "inputReports"),
            ("output_tokens", "outputTokens", "outputReports"),
            ("cached_tokens", "cachedTokens", "cacheReports"),
            ("provider_ms", "providerMs", "providerReports"),
        ):
            raw[total], raw[reports] = row[source], row[source + "_reports"]
        result.append(
            {
                **identity(row),
                "day": row["day"],
                "feature": row["feature"],
                "purpose": PURPOSES.get(row["feature"], "Other measured AI work"),
                "requested": metadata_model(row["requested"]),
                "reported": metadata_model(row["reported"]),
                "outcome": final,
                "legacy": False,
                "raw": raw,
            }
        )
    daily = (await db.scalars(select(Daily).where(Daily.day >= start, Daily.day <= end, Daily.kind == "call"))).all()
    for row in daily:
        key = (row.day, row.feature, row.provider, row.requested, row.reported, row.outcome)
        remaining = {k: max(0, getattr(row, k) - mirrored[key][k]) for k in MEASURES[:10]}
        if not remaining["events"]:
            continue
        n = remaining["events"]
        raw = zero()
        raw.update(
            attempts=n,
            legacyAttempts=n,
            answered=n if row.outcome == "answered" else 0,
            failed=n if row.outcome in FAILURES else 0,
            # Old adapter timers mixed wire-slot waiting with request time.
            # Do not average those observations into the new request boundary.
        )
        for source, total, reports, coverage in (
            ("input_tokens", "inputTokens", "inputReports", "input_reports"),
            ("output_tokens", "outputTokens", "outputReports", "output_reports"),
            ("cached_tokens", "cachedTokens", "cacheReports", "cache_reports"),
            ("provider_ms", "providerMs", "providerReports", "provider_reports"),
        ):
            raw[total], raw[reports] = remaining[source], remaining[coverage]
        labels = {"apple_fm": "Apple Foundation Models (legacy)", "anthropic": "Anthropic (legacy)"}
        result.append(
            {
                "day": row.day,
                "serviceId": "legacy-" + row.provider,
                "serviceLabel": labels.get(row.provider, "Legacy / unknown compatible service"),
                "serviceKind": "legacy",
                "provider": row.provider,
                "feature": row.feature,
                "purpose": PURPOSES.get(row.feature, "Other measured AI work"),
                "requested": metadata_model(row.requested),
                "reported": metadata_model(row.reported),
                "outcome": row.outcome,
                "legacy": True,
                "raw": raw,
            }
        )
    return result


async def historical_work(db, start, end, filters):
    start_at = datetime.combine(start, datetime.min.time(), UTC)
    end_at = datetime.combine(end + timedelta(days=1), datetime.min.time(), UTC)
    arrived = and_(Work.arrived_at >= start_at, Work.arrived_at < end_at)
    finished = and_(Work.finished_at >= start_at, Work.finished_at < end_at)
    conditions = [or_(arrived, finished)]
    for field, column in (("service", Work.service_id), ("provider", Work.provider), ("purpose", Work.feature)):
        if filters.get(field):
            conditions.append(column == filters[field])
    attempt_conditions = [Attempt.work_id == Work.id]
    if filters.get("model"):
        model = filters["model"]
        attempt_conditions.append(or_(Attempt.requested == model, Attempt.reported == model))
    if filters.get("outcome"):
        attempt_conditions.append(func.coalesce(Attempt.work_outcome, Attempt.outcome) == filters["outcome"])
    if filters.get("model") or filters.get("outcome"):
        direct = []
        if filters.get("model"):
            direct.append(Work.requested == filters["model"])
        if filters.get("outcome"):
            direct.append(Work.outcome == filters["outcome"])
        conditions.append(or_(and_(*direct), exists(select(Attempt.id).where(*attempt_conditions))))
    rows = (
        await db.execute(
            select(Work.outcome, _count_if(arrived, "arrivals"), _count_if(finished, "finishes"))
            .where(*conditions)
            .group_by(Work.outcome)
        )
    ).all()
    totals = dict.fromkeys(("arrivals", "completed", "failed", "cached", "skipped", "expired", "retries", "fallbacks"), 0)
    for outcome, arrivals, count in rows:
        totals["arrivals"] += arrivals
        if outcome in totals:
            totals[outcome] += count
        elif outcome in ("unusable", "unsupported"):
            totals["failed"] += count
    return totals


async def activity_report(db, start, end, **filters):
    all_rows = await historical_groups(db, start, end)
    rows = [row for row in all_rows if matches(row, filters)]
    total, services, purposes, days, groups = zero(), {}, {}, {}, {}
    for row in rows:
        plus(total, row["raw"])
        service_key = (row["serviceId"], row["serviceLabel"], row["serviceKind"], row["provider"])
        service = services.setdefault(
            service_key, {**{k: row[k] for k in ("serviceId", "serviceLabel", "serviceKind", "provider")}, "raw": zero()}
        )
        purpose = purposes.setdefault(row["feature"], {"feature": row["feature"], "label": row["purpose"], "raw": zero()})
        day = days.setdefault(row["day"], zero())
        group_key = service_key + tuple(row[k] for k in ("feature", "requested", "reported", "outcome", "legacy"))
        group = groups.setdefault(group_key, {**{k: v for k, v in row.items() if k not in ("day", "raw")}, "raw": zero()})
        for target in (service["raw"], purpose["raw"], day, group["raw"]):
            plus(target, row["raw"])

    def output(group):
        return {**{k: v for k, v in group.items() if k != "raw"}, **metrics(group["raw"])}

    since, degraded = await coverage_state(
        db,
        start=datetime.combine(start, datetime.min.time(), UTC),
        end=datetime.combine(end + timedelta(days=1), datetime.min.time(), UTC),
    )
    enabled, _ = await flags(db)
    current = await current_services(db)
    service_facets = {
        (r["serviceId"], r["serviceLabel"]): {k: r[k] for k in ("serviceId", "serviceLabel", "serviceKind", "provider")}
        for r in all_rows
    }
    work = await historical_work(db, start, end, filters)
    work.update(retries=total["retries"], fallbacks=total["fallbacks"])
    return {
        "asOf": datetime.now(UTC),
        "start": start,
        "end": end,
        "timeZone": "UTC",
        "retentionDays": RETENTION_DAYS,
        "firstMeasured": await db.scalar(select(func.min(Daily.day))),
        "detailedSince": since,
        "aiEnabled": enabled,
        "usageEnabled": True,
        "configuredServices": current,
        "state": "unavailable" if degraded else "ready" if rows else "no_matches" if all_rows else "no_calls",
        "totals": metrics(total),
        "services": [output(s) for s in services.values()],
        "purposes": [output(p) for p in purposes.values()],
        "groups": [output(g) for g in groups.values()],
        "trend": [
            {"day": start + timedelta(days=i), **metrics(days.get(start + timedelta(days=i), zero()))}
            for i in range((end - start).days + 1)
        ],
        "work": work,
        "facets": {
            "services": list(service_facets.values()),
            "purposes": [
                {"id": key, "label": PURPOSES.get(key, "Other measured AI work")}
                for key in sorted({r["feature"] for r in all_rows})
            ],
            "models": sorted({r[key] for r in all_rows for key in ("requested", "reported") if r[key]}),
            "outcomes": [
                {"id": key, "label": OUTCOMES.get(key, "Other recorded outcome")}
                for key in sorted({r["outcome"] for r in all_rows})
            ],
        },
        "coverage": {
            "legacyAttempts": total["legacyAttempts"],
            "detailedAttempts": total["detailedAttempts"],
            "recordingDegradedSince": degraded,
            "missing": [
                "Legacy aggregates have no dispatch, local-wait, separate request-time or useful-result measurements.",
                "Control/discovery requests and unchanged inventory that creates no logical job are excluded.",
                "Historical attempts are grouped by the UTC day they finished; active attempts appear in Live workload.",
            ],
        },
    }


def health(
    *,
    enabled,
    consent,
    configured,
    degraded,
    since,
    now,
    waiting,
    running,
    oldest,
    arrivals,
    completed,
    expired,
    failures,
    limited,
    stalled,
    inventory_undrained=False,
):
    """Every verdict names both its evidence and the operator's next check."""
    if not enabled or not consent:
        return (
            "disabled",
            "Not running",
            "AI features or inference consent is off.",
            "Check AI features and inference consent in Settings.",
            "AI enabled and inference consent must both be on.",
        )
    if not configured:
        return (
            "no_provider",
            "No provider configured",
            "No saved AI provider can accept new work.",
            "Save and test a provider in Settings → AI.",
            "Configured provider count is zero.",
        )
    if degraded:
        return (
            "unavailable",
            "Measurement unavailable",
            "Some usage records could not be saved; totals may be incomplete.",
            "Check database health and the AI Activity migration; inspect the server's usage-recording warning.",
            "A telemetry write failed in this measurement period.",
        )
    if inventory_undrained:
        return (
            "not_running",
            "Not running",
            "Inventory summaries are waiting and nothing is processing them; this container runs no scheduler.",
            "Check that one app container runs the scheduler: read scheduler_enabled on its starting line "
            "(docker compose logs app | grep scheduler_enabled).",
            "SCHEDULER_ENABLED is off here, inventory has waited over 120 seconds, "
            "and no inventory attempt started in the last 300 seconds.",
        )
    if stalled:
        return (
            "stalled",
            "Work appears stalled",
            "Recorded active work has passed its declared deadline.",
            "Check the worker and provider connection. Restart a stopped worker; "
            "scheduled maintenance expires abandoned interactive work.",
            "At least one active work item is past its deadline.",
        )
    if limited:
        return (
            "rate_limited",
            "Rate limits observed",
            "The provider refused recent attempts due to rate limits.",
            "Check the provider's capacity and rate-limit reset; inspect inventory retries.",
            "Recent rate-limited attempts are greater than zero.",
        )
    if oldest is not None and oldest > 120:
        return (
            "waiting_too_long",
            "Work waiting too long",
            "The oldest measured waiting item is older than two minutes.",
            "Check the provider test, worker and Apple FM's shared local lane.",
            "Oldest waiting age exceeds 120 seconds.",
        )
    if not since or (now - since).total_seconds() < 900:
        return (
            "observing",
            "Collecting a baseline",
            "A complete 15-minute workload window has not been measured yet.",
            "Keep this view open; inspect current waiting/running counts while measurements accumulate.",
            "Detailed coverage is younger than the 900-second comparison window.",
        )
    if waiting and arrivals > completed:
        return (
            "backlog_growing",
            "Backlog growing",
            "More logical work arrived than completed usefully while work waits.",
            "Compare purposes and provider failures; check capacity before changing any concurrency setting.",
            "Waiting count > 0 and arrivals > useful completions in the same 15-minute interval.",
        )
    if expired:
        return (
            "expired",
            "Work expired",
            "Some recent work expired without a useful result.",
            "Check queue age and provider availability; expired inventory jobs need fresh inventory.",
            "Recent expired logical work is greater than zero.",
        )
    if failures:
        return (
            "failures",
            "Failures observed",
            "Recent attempts failed even though the measured queue is not growing.",
            "Open the service/purpose breakdown and test the affected provider in Settings → AI.",
            "Recent failed attempts are greater than zero.",
        )
    if not waiting and not running and not arrivals:
        return (
            "idle",
            "Idle",
            "No measured AI work is waiting, running or arriving in the recent window.",
            "No action needed; external clients using the provider are outside this view.",
            "Waiting, running and recent arrivals are all zero with readable measurements.",
        )
    return (
        "keeping_up",
        "Keeping up",
        "Measured work is completing without evidence of a growing queue.",
        "Continue monitoring; source investigation and external clients have separate coverage limits.",
        "No overdue/old waiting work or recent failures; waiting work is not outpacing useful completions.",
    )


async def live_report(db):
    now = datetime.now(UTC)
    since, degraded = await coverage_state(db, start=now - timedelta(minutes=15))
    start = max(now - timedelta(minutes=15), since) if since else now - timedelta(minutes=15)
    enabled, consent = await flags(db)
    configured = await current_services(db)
    # A processing inventory job may still be waiting for FM's lane or a wire slot.
    lane_wait = exists(
        select(Attempt.id).where(
            Attempt.work_id == InventorySummaryJob.id,
            Attempt.finished_at.is_(None),
            Attempt.dispatched_at.is_(None),
        )
    )
    job_state = case((or_(InventorySummaryJob.status == "pending", lane_wait), "pending"), else_="processing")
    jobs = (
        (
            await db.execute(
                select(
                    job_state.label("status"),
                    func.count().label("count"),
                    func.min(InventorySummaryJob.created_at).label("oldest"),
                    func.min(InventorySummaryJob.expires_at).label("deadline"),
                )
                .where(InventorySummaryJob.status.in_(("pending", "processing")))
                .group_by(job_state)
            )
        )
        .mappings()
        .all()
    )
    inventory = {
        "waiting": 0,
        "running": 0,
        "oldestWaitingSeconds": None,
        "enabled": bool(await db.scalar(select(InventorySummarySettings.enabled))),
    }
    stalled = 0
    for row in jobs:
        inventory["waiting" if row["status"] == "pending" else "running"] += row["count"]
        if row["status"] == "pending":
            inventory["oldestWaitingSeconds"] = max(0, (now - row["oldest"]).total_seconds())
        stalled += int(row["deadline"] <= now)
    active = (
        await db.scalars(
            select(Work).where(Work.finished_at.is_(None), Work.feature != "inventory_summary", Work.outcome.in_(ACTIVE))
        )
    ).all()
    interactive = {
        "waiting": sum(w.outcome == "waiting" for w in active),
        "running": sum(w.outcome != "waiting" for w in active),
        "oldestWaitingSeconds": max(
            ((now - w.arrived_at).total_seconds() for w in active if w.outcome == "waiting"), default=None
        ),
    }
    stalled += sum(w.deadline_at <= now for w in active)
    waiting, running = inventory["waiting"] + interactive["waiting"], inventory["running"] + interactive["running"]
    oldest = max(
        (age for age in (inventory["oldestWaitingSeconds"], interactive["oldestWaitingSeconds"]) if age is not None), default=None
    )
    arrivals = await db.scalar(select(func.count()).select_from(Work).where(Work.arrived_at >= start, Work.arrived_at <= now))
    finished = (
        await db.execute(
            select(Work.outcome, func.count()).where(Work.finished_at >= start, Work.finished_at <= now).group_by(Work.outcome)
        )
    ).all()
    work_counts = dict(finished)
    completed = work_counts.get("completed", 0) + work_counts.get("cached", 0)
    attempt_outcome = func.coalesce(Attempt.work_outcome, Attempt.outcome)
    attempts = dict(
        (
            await db.execute(
                select(attempt_outcome, func.count())
                .where(Attempt.finished_at >= start, Attempt.finished_at <= now)
                .group_by(attempt_outcome)
            )
        ).all()
    )
    failed = sum(count for outcome, count in attempts.items() if outcome in FAILURES)
    expired, limited = work_counts.get("expired", 0), attempts.get("rate_limited", 0)
    count, oldest_research = (
        await db.execute(
            select(func.count(), func.min(ApplicationPatchPlan.research_started_at)).where(
                ApplicationPatchPlan.research_status == "running"
            )
        )
    ).one()
    # SCHEDULER_ENABLED describes only the process answering this request. A web-only
    # container can sit beside one that drains the queue (operations.md §7), so "not
    # running" also needs the database to show nothing draining it: inventory has waited
    # past two minutes and no inventory attempt has started for five.
    undrained = False
    if not settings.scheduler_enabled and (inventory["oldestWaitingSeconds"] or 0) > 120:
        last = await db.scalar(select(func.max(Attempt.started_at)).where(Attempt.feature == "inventory_summary"))
        undrained = last is None or (now - last).total_seconds() > 300
    verdict = health(
        enabled=enabled,
        consent=consent,
        configured=bool(configured),
        degraded=degraded,
        since=since,
        now=now,
        waiting=waiting,
        running=running,
        oldest=oldest,
        arrivals=arrivals,
        completed=completed,
        expired=expired,
        failures=failed,
        limited=limited,
        stalled=stalled,
        inventory_undrained=undrained,
    )
    return {
        "asOf": now,
        "windowStart": start,
        "windowSeconds": 900,
        "windowComplete": bool(since and since <= now - timedelta(minutes=15)),
        **dict(zip(("state", "label", "message", "nextCheck", "rule"), verdict, strict=True)),
        "aiEnabled": enabled,
        "usageEnabled": True,
        "waiting": waiting,
        "running": running,
        "oldestWaitingSeconds": oldest,
        "arrivals": arrivals,
        "usefulCompletions": completed,
        "failed": failed,
        "expired": expired,
        "rateLimited": limited,
        "timeouts": attempts.get("timeout", 0),
        "waitingTimeouts": attempts.get("waiting_timeout", 0),
        "inventory": inventory,
        "interactive": interactive,
        "patchInvestigations": {
            "running": count,
            "oldestRunningSeconds": max(0, (now - oldest_research).total_seconds()) if oldest_research else None,
            "coverage": "partial",
        },
        "coverage": {
            "detailedSince": since,
            "recordingDegradedSince": degraded,
            "missing": [
                "Patch investigation counts include source research; pre-inference arrivals/completions are not measured.",
                "Model discovery, requests refused before inference, and external provider clients are not measured.",
                "An old process or telemetry outage can leave a gap; only measured LoonInspect work is described.",
                "Abandoned interactive work expires after its deadline plus 120 seconds of grace; "
                "dispatch can be unknown after a crash.",
            ],
        },
    }
