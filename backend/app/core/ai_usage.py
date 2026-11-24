"""Metadata-only AI accounting: daily compatibility, attempts and logical work."""

import asyncio
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert

from app.core.database import bound_tenant_id, session_for_tenant
from app.models.schema import AIUsageAttempt as Attempt
from app.models.schema import AIUsageCoverage as Coverage
from app.models.schema import AIUsageDaily as Daily
from app.models.schema import AIUsageWork as Work
from app.models.schema import InventorySummaryJob as Job

RETENTION_DAYS = 90
ABANDONED_GRACE_SECONDS = 120
logger = logging.getLogger(__name__)
_recording_failures: dict[uuid.UUID, datetime] = {}
_last_recording_failures: dict[uuid.UUID, datetime] = {}
MEASURES = (
    "events",
    "request_ms",
    "input_tokens",
    "input_reports",
    "output_tokens",
    "output_reports",
    "cached_tokens",
    "cache_reports",
    "provider_ms",
    "provider_reports",
    "queue_wait_ms",
    "max_queue_wait_ms",
)


async def add(db, *, feature, provider, outcome, kind, requested="", reported="", at=None, **measurements):
    values = {"events": 1, **measurements}
    statement = insert(Daily).values(
        day=(at or datetime.now(UTC)).date(),
        feature=feature,
        provider=provider,
        requested=requested[:200],
        reported=reported[:200],
        outcome=outcome,
        kind=kind,
        **values,
    )
    update = {k: getattr(Daily, k) + getattr(statement.excluded, k) for k in values}
    if "max_queue_wait_ms" in values:
        update["max_queue_wait_ms"] = func.greatest(Daily.max_queue_wait_ms, statement.excluded.max_queue_wait_ms)
    await db.execute(statement.on_conflict_do_update(index_elements=list(Daily.__table__.primary_key), set_=update))


def metadata_model(value):
    value = value if isinstance(value, str) else ""
    return "" if "://" in value else value[:200]


def service_identity(provider, config=None, *, base_url=None):
    """Snapshot safe attribution now; callers never join old usage to today's config."""
    provider = str(provider)
    base = base_url or getattr(config, "base_url", "") or ""
    if config is None and not base:
        labels = {"apple_fm": "Apple Foundation Models (legacy)", "anthropic": "Anthropic (legacy)"}
        return {
            "service_id": "legacy-" + provider,
            "service_label": labels.get(provider, "Legacy / unknown compatible service"),
            "service_kind": "legacy",
        }
    kind = getattr(config, "service_kind", None)
    if provider in ("apple_fm", "anthropic"):
        kind = provider
    elif kind not in ("openai", "ollama", "compatible"):
        host = urlsplit(base).hostname if base else None
        kind = "openai" if host == "api.openai.com" else "ollama" if getattr(config, "ollama_policy", None) else "compatible"
    labels = {
        "apple_fm": "Apple Foundation Models (FM)",
        "anthropic": "Anthropic",
        "openai": "OpenAI",
        "ollama": "Ollama",
        "compatible": "Unknown compatible service",
    }
    label = getattr(config, "service_label", None) or labels[kind]
    identity = getattr(config, "service_id", None)
    # Unsaved test calls have no config ID. An opaque fingerprint groups the same
    # tested endpoint without storing its address, and never involves the API key.
    if identity:
        identity = str(identity)
    else:
        test = hasattr(config, "prompt")
        identity = ("test-" if test else "unidentified-") + uuid.uuid5(
            uuid.NAMESPACE_URL, ":".join((provider, base, kind, label))
        ).hex
        label += " (test endpoint)" if test else " (identity unavailable)"
    return {"service_id": identity, "service_label": label, "service_kind": kind}


async def touch_coverage(db, at):
    tenant = bound_tenant_id(db)
    failed = _recording_failures.get(tenant)
    statement = insert(Coverage).values(
        first_measured_at=at, last_recorded_at=at, degraded_since=failed, last_gap_at=_last_recording_failures.get(tenant)
    )
    await db.execute(
        statement.on_conflict_do_update(
            index_elements=["tenant_id"],
            set_={
                "last_recorded_at": at,
                "degraded_since": func.coalesce(Coverage.degraded_since, statement.excluded.degraded_since),
                "last_gap_at": func.greatest(Coverage.last_gap_at, statement.excluded.last_gap_at),
            },
        )
    )


def recording_failure(tenant):
    if tenant:
        _recording_failures.setdefault(tenant, datetime.now(UTC))
        _last_recording_failures[tenant] = datetime.now(UTC)
    logger.warning("AI usage could not be saved. Activity measurement is incomplete; check database health and migrations.")


async def work_event(
    db, work_id, feature, provider, outcome, at, *, config=None, requested="", arrived_at=None, deadline_at=None, reason=None
):
    """The logical-work half of existing usage accounting; no inventory/prompt fields."""
    arrived = arrived_at or at
    values = {
        "id": work_id,
        "feature": feature,
        "provider": str(provider),
        **service_identity(provider, config),
        "requested": metadata_model(requested),
        "arrived_at": arrived,
        "deadline_at": deadline_at or arrived + timedelta(hours=1),
        "outcome": outcome,
        "reason": reason,
    }
    if outcome not in ("waiting", "running", "validating"):
        values["finished_at"] = at
    if outcome == "running":
        values["started_at"] = at
    statement = insert(Work).values(**values)
    changes = {k: statement.excluded[k] for k in ("outcome", "reason", "finished_at", "started_at") if k in values}
    if requested:
        changes["requested"] = statement.excluded.requested
    await db.execute(statement.on_conflict_do_update(index_elements=["id"], set_=changes))
    await touch_coverage(db, at)


def failure_category(outcome, status, dispatched):
    if outcome == "timeout" and not dispatched:
        return "waiting_timeout"
    if status == 429:
        return "rate_limited"
    if status == 401:
        return "authentication"
    if status == 403:
        return "forbidden"
    if outcome == "unreachable" or (status and status >= 500):
        return "unavailable"
    return outcome


class UsageRecorder:
    """The existing recorder extended with attempt and logical-work lifecycle facts."""

    def __init__(self, db, feature, provider, requested, *, config=None, work_id=None, attempt_number=1, fallback=False):
        self.db, self.tenant = db, None
        self.feature, self.provider, self.requested = feature, str(provider), metadata_model(requested)
        self.identity = service_identity(provider, config)
        self.id, self.work_id = uuid.uuid4(), work_id or uuid.uuid4()
        self.managed_work = work_id is not None
        self.number, self.fallback = attempt_number, fallback
        self.started_at = self.dispatched_at = None
        self.started_clock = self.dispatch_clock = None
        self.dispatch_task = None
        self.outcome = None

    async def _save(self, action, *, detailed=True):
        try:
            self.tenant = self.tenant or bound_tenant_id(self.db)
            async with asyncio.timeout(2), session_for_tenant(self.tenant) as session:
                await action(session)
                if detailed:
                    await touch_coverage(session, datetime.now(UTC))
                await session.commit()
        except Exception:
            recording_failure(self.tenant)

    async def start(self, timeout_seconds):
        self.started_at, self.started_clock = datetime.now(UTC), time.monotonic()

        async def write(session):
            if not self.managed_work:
                session.add(
                    Work(
                        id=self.work_id,
                        feature=self.feature,
                        provider=self.provider,
                        **self.identity,
                        requested=self.requested,
                        arrived_at=self.started_at,
                        deadline_at=self.started_at + timedelta(seconds=timeout_seconds + 30),
                        outcome="waiting",
                    )
                )
            session.add(
                Attempt(
                    id=self.id,
                    work_id=self.work_id,
                    feature=self.feature,
                    provider=self.provider,
                    **self.identity,
                    requested=self.requested,
                    started_at=self.started_at,
                    attempt_number=self.number,
                    fallback=self.fallback,
                    outcome="waiting",
                )
            )

        await self._save(write)

    def dispatch(self):
        """Called synchronously when the adapter hands this request to HTTP transport."""
        self.dispatched_at, self.dispatch_clock = datetime.now(UTC), time.monotonic()

        async def write(session):
            await session.execute(
                update(Attempt)
                .where(Attempt.id == self.id, Attempt.finished_at.is_(None))
                .values(dispatched_at=self.dispatched_at, outcome="running")
            )
            await session.execute(
                update(Work)
                .where(Work.id == self.work_id, Work.finished_at.is_(None))
                .values(outcome="running", started_at=self.dispatched_at)
            )

        self.dispatch_task = asyncio.create_task(self._save(write))

    async def finish_attempt(self, outcome, result, *, status=None):
        finished, clock = datetime.now(UTC), time.monotonic()
        if self.dispatch_task:
            await self.dispatch_task
        total_ms = max(0, int((clock - self.started_clock) * 1000))
        wait_ms = max(0, int(((self.dispatch_clock or clock) - self.started_clock) * 1000))
        request_ms = max(0, int((clock - self.dispatch_clock) * 1000)) if self.dispatch_clock is not None else None
        reported = metadata_model(getattr(result, "model", ""))
        category = failure_category(outcome, status, self.dispatched_at is not None)
        self.outcome = category
        measured = {
            field: getattr(result, source, None)
            for field, source in (
                ("input_tokens", "input_tokens"),
                ("output_tokens", "completion_tokens"),
                ("cached_tokens", "cached_tokens"),
                ("provider_ms", "provider_ms"),
            )
        }

        async def write(session):
            values = {"request_ms": request_ms or 0}
            for field, coverage in (
                ("input_tokens", "input_reports"),
                ("output_tokens", "output_reports"),
                ("cached_tokens", "cache_reports"),
                ("provider_ms", "provider_reports"),
            ):
                if measured[field] is not None:
                    values[field], values[coverage] = measured[field], 1
            # Claim finalization once. Maintenance may already have expired a crashed
            # request; a late callback must not add a second daily contribution.
            updated = await session.execute(
                update(Attempt)
                .where(Attempt.id == self.id, Attempt.finished_at.is_(None))
                .values(
                    reported=reported,
                    outcome=category,
                    legacy_outcome=outcome,
                    finished_at=finished,
                    dispatched_at=self.dispatched_at,
                    status_code=status,
                    wait_ms=wait_ms,
                    request_ms=request_ms,
                    total_ms=total_ms,
                    **measured,
                )
            )
            if not updated.rowcount and await session.scalar(select(Attempt.id).where(Attempt.id == self.id)):
                return
            # Daily compatibility and detailed facts commit together. If start could
            # not be saved, the daily row remains a legacy/unknown contribution and
            # the recording-failure marker makes that coverage gap explicit.
            await add(
                session,
                feature=self.feature,
                provider=self.provider,
                requested=self.requested,
                reported=reported,
                outcome=outcome,
                kind="call",
                at=finished,
                **values,
            )
            if not self.managed_work:
                terminal = category != "answered"
                await session.execute(
                    update(Work)
                    .where(Work.id == self.work_id)
                    .values(
                        outcome="failed" if terminal else "validating",
                        reason=category if terminal else None,
                        finished_at=finished if terminal else None,
                    )
                )

        await self._save(write)

    async def accepted(self, outcome):
        if outcome not in ("completed", "unusable", "unsupported", "skipped", "expired"):
            raise ValueError("Unknown logical AI-work outcome")

        async def write(session):
            await session.execute(
                update(Attempt).where(Attempt.id == self.id, Attempt.outcome != "interrupted").values(work_outcome=outcome)
            )
            if not self.managed_work:
                await session.execute(
                    update(Work)
                    .where(Work.id == self.work_id, Work.outcome != "expired")
                    .values(outcome=outcome, finished_at=datetime.now(UTC))
                )

        await self._save(write)

    async def __call__(self, outcome, result, elapsed_ms):
        # Older adapters supply only one elapsed timer, with no dispatch/work
        # boundaries. Preserve that daily contract without fabricating detailed facts.
        async def write(session):
            values = {"request_ms": elapsed_ms}
            for source, field, reports in (
                ("input_tokens", "input_tokens", "input_reports"),
                ("completion_tokens", "output_tokens", "output_reports"),
                ("cached_tokens", "cached_tokens", "cache_reports"),
                ("provider_ms", "provider_ms", "provider_reports"),
            ):
                value = getattr(result, source, None)
                if value is not None:
                    values[field], values[reports] = value, 1
            await add(
                session,
                feature=self.feature,
                provider=self.provider,
                requested=self.requested,
                reported=metadata_model(getattr(result, "model", "")),
                outcome=outcome,
                kind="call",
                **values,
            )

        await self._save(write, detailed=False)


def recorder(db, feature, provider, requested, **kwargs):
    return UsageRecorder(db, feature, provider, requested, **kwargs)


async def accepted(result, outcome="completed"):
    meter = getattr(result, "activity", None)
    if isinstance(meter, UsageRecorder):
        await meter.accepted(outcome)


async def queue_event(
    db,
    provider,
    outcome,
    at,
    wait_ms=None,
    *,
    work_id=None,
    config=None,
    arrived_at=None,
    deadline_at=None,
    requested="",
    reason=None,
):
    measures = {} if wait_ms is None else {"queue_wait_ms": wait_ms, "max_queue_wait_ms": wait_ms}
    await add(db, feature="inventory_summary", provider=provider, kind="queue", outcome=outcome, at=at, **measures)
    if work_id is not None:
        state = {
            "received": "waiting",
            "started": "running",
            "retry": "running",
            "waiting_retry": "waiting",
            "capacity": "failed",
            "dropped": "skipped",
        }.get(outcome, outcome)
        await work_event(
            db,
            work_id,
            "inventory_summary",
            provider,
            state,
            at,
            config=config,
            requested=requested,
            arrived_at=arrived_at,
            deadline_at=deadline_at,
            reason=reason,
        )


async def interrupt_attempts(db, work_ids, at):
    """Finalize unfinished attempts when their owning worker abandons/reclaims work.

    Preserve any observed dispatch; a crash supplies no finish duration. The daily
    mirror and conditional finalization commit together, once, in the caller's
    transaction. Callers already own the job lease or have applied deadline + grace.
    """
    if not work_ids:
        return 0
    # Match the recorder's lock order (attempt, then work) and finalize only once.
    attempts = (
        await db.scalars(
            update(Attempt)
            .where(Attempt.work_id.in_(work_ids), Attempt.finished_at.is_(None))
            .values(outcome="interrupted", legacy_outcome="interrupted", finished_at=at)
            .returning(Attempt)
        )
    ).all()
    for attempt in attempts:
        await add(
            db,
            feature=attempt.feature,
            provider=attempt.provider,
            requested=attempt.requested,
            reported=attempt.reported,
            kind="call",
            outcome="interrupted",
            at=at,
        )
    # The owner updates Work, then Coverage: keep the recorder's lock order.
    return len(attempts)


async def expire_abandoned(db, at):
    """Scheduled metadata maintenance expires interactive work after deadline + grace.

    No inference is retried or cancelled here. Inventory jobs keep their existing
    worker recovery. The grace leaves overdue activity visible as stalled first.
    """
    ids = (
        await db.scalars(
            select(Work.id)
            .where(
                Work.feature != "inventory_summary",
                Work.outcome.in_(("waiting", "running", "validating")),
                Work.deadline_at < at - timedelta(seconds=ABANDONED_GRACE_SECONDS),
            )
            .order_by(Work.deadline_at)
            .limit(200)
        )
    ).all()
    if not ids:
        return
    await interrupt_attempts(db, ids, at)
    await db.execute(
        update(Work)
        .where(Work.id.in_(ids), Work.outcome.in_(("waiting", "running", "validating")))
        .values(outcome="expired", reason="abandoned_after_deadline", finished_at=at)
    )
    await touch_coverage(db, at)


async def prune(db, today):
    await expire_abandoned(db, datetime.now(UTC))
    # retention-clock: ai-usage — daily counts expire even while the feature is switched off.
    await db.execute(delete(Daily).where(Daily.day < today - timedelta(days=RETENTION_DAYS - 1)))
    cutoff = datetime.combine(today - timedelta(days=RETENTION_DAYS - 1), datetime.min.time(), UTC)
    # retention-clock: ai-usage — terminal facts expire by their finished UTC day.
    await db.execute(delete(Attempt).where(func.coalesce(Attempt.finished_at, Attempt.started_at) < cutoff))
    # retention-clock: ai-usage — retain completions that cross the arrival-day boundary.
    await db.execute(delete(Work).where(func.coalesce(Work.finished_at, Work.arrived_at) < cutoff))


async def usage_report(db, start, end):
    first = await db.scalar(select(func.min(Daily.day)))
    names = ("feature", "provider", "requested", "reported", "outcome")
    dimensions = [getattr(Daily, n) for n in names]
    window = (Daily.day >= start, Daily.day <= end)
    measures = [func.sum(getattr(Daily, k)).label(k) for k in MEASURES[:10]]
    calls = (
        (
            await db.execute(
                select(*dimensions, *measures).where(*window, Daily.kind == "call").group_by(*dimensions).order_by(*dimensions)
            )
        )
        .mappings()
        .all()
    )
    queue = (
        (
            await db.execute(
                select(Daily.day, Daily.provider, Daily.outcome, Daily.events, Daily.queue_wait_ms, Daily.max_queue_wait_ms)
                .where(*window, Daily.kind == "queue")
                .order_by(Daily.day, Daily.provider, Daily.outcome)
            )
        )
        .mappings()
        .all()
    )
    pending, oldest = (
        await db.execute(select(func.count(), func.min(Job.created_at)).where(Job.status.in_(("pending", "processing"))))
    ).one()
    now = datetime.now(UTC)
    return {
        "firstMeasured": first,
        "retentionDays": RETENTION_DAYS,
        "calls": calls,
        "queue": queue,
        "pending": pending,
        "oldestPendingSeconds": max(0, (now - oldest).total_seconds()) if oldest else None,
    }
