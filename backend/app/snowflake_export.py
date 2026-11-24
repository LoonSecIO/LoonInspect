"""Public event rows and explicit delivery accounting for native Snowflake export (#848).

One row preserves one source outbox event, including a whole inventory snapshot.
The adapter persists its source namespace and uses the original event id
on every retry. It establishes row-level commit/rejection evidence before calling
``account_for``; an HTTP acknowledgement or advancing channel offset is insufficient.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from app.core.wire import ENVELOPE


@dataclass(frozen=True)
class ExportRow:
    key: str
    ndjson: bytes


@dataclass(frozen=True)
class ExportBatch:
    keys: tuple[str, ...]
    ndjson: bytes


@dataclass(frozen=True)
class BatchOutcome:
    accepted: tuple[str, ...]
    rejected: tuple[tuple[str, str], ...]
    unresolved: tuple[str, ...]

    @property
    def delivered(self) -> bool:
        return bool(self.accepted) and not self.rejected and not self.unresolved


def _occurred_at(payload: Mapping[str, object], hints: Mapping[str, object]) -> str | None:
    value = payload.get("occurredAt")
    if value is not None:
        if not isinstance(value, str):
            raise ValueError("Snowflake event time must be an ISO timestamp with a timezone")
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("Snowflake event time must include its timezone")
    elif hints.get("time") is not None:
        value = hints["time"]
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError("Snowflake envelope time must be epoch seconds")
        instant = datetime.fromtimestamp(value, UTC)
    else:
        return None
    return instant.astimezone(UTC).isoformat()


def event_row(
    payload: Mapping[str, object],
    *,
    source_id: str,
    tenant_id: str,
    event_id: str,
    event_type: str,
    queued_at: datetime | None = None,
) -> ExportRow:
    """Freeze a public event as NDJSON, with a destination-independent replay key.

    ``source_id`` identifies the originating tenant database lineage, not a worker or
    destination. ``event_id`` identifies the durable outbox row, not deviceMeta.eventID
    (several changes share that device-pull id). Warehouse load time is intentionally
    absent: the table must assign it when loading, without changing occurrence time.
    """
    if any(not isinstance(value, str) or not value.strip() for value in (source_id, tenant_id, event_id, event_type)):
        raise ValueError("Snowflake rows require source, tenant, source event id and event type")
    if payload.get("event") != event_type:
        raise ValueError("Snowflake event type must match the stored payload")
    identity = json.dumps([source_id, tenant_id, event_id], ensure_ascii=False, separators=(",", ":"))
    key = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    hints = payload.get(ENVELOPE) or {}
    if not isinstance(hints, Mapping):
        raise ValueError("Snowflake event envelope must be an object")
    if queued_at is not None and (queued_at.tzinfo is None or queued_at.utcoffset() is None):
        raise ValueError("Snowflake queue time must include its timezone")
    row = {
        "SOURCE_ID": source_id,
        "TENANT_ID": tenant_id,
        "SOURCE_EVENT_KEY": key,
        "EVENT_TYPE": event_type,
        "OCCURRED_AT": _occurred_at(payload, hints),
        "QUEUED_AT": queued_at.astimezone(UTC).isoformat() if queued_at is not None else None,
        "PAYLOAD": {name: value for name, value in payload.items() if name != ENVELOPE},
    }
    encoded = json.dumps(row, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return ExportRow(key, (encoded + "\n").encode("utf-8"))


def batches(rows: Iterable[ExportRow], *, max_bytes: int, max_rows: int) -> Iterator[ExportBatch]:
    """Bound each batch by encoded bytes and rows, preserving input order.

    Oversized rows fail explicitly, never bypass the ceiling or get truncated.
    The worker owns time-based flushing and durable batch membership.
    """
    if max_bytes < 1 or max_rows < 1:
        raise ValueError("Snowflake batch byte and row limits must be positive")
    keys: list[str] = []
    bodies: list[bytes] = []
    size = 0
    for row in rows:
        if len(row.ndjson) > max_bytes:
            raise ValueError(f"Snowflake event {row.key} exceeds the batch byte limit; retain the event for recovery")
        if keys and (size + len(row.ndjson) > max_bytes or len(keys) >= max_rows):
            yield ExportBatch(tuple(keys), b"".join(bodies))
            keys, bodies, size = [], [], 0
        if row.key in keys:
            raise ValueError("Snowflake batch contains a repeated source event key; check its source membership")
        keys.append(row.key)
        bodies.append(row.ndjson)
        size += len(row.ndjson)
    if keys:
        yield ExportBatch(tuple(keys), b"".join(bodies))


def account_for(batch: ExportBatch, *, accepted: Iterable[str] = (), rejected: Mapping[str, str] | None = None) -> BatchOutcome:
    """Partition a batch using explicit row evidence; everything else stays unresolved."""
    accepted_keys = set(accepted)
    rejected = rejected or {}
    known = set(batch.keys)
    if len(known) != len(batch.keys) or not known:
        raise ValueError("Snowflake accounting requires a nonempty batch with unique source event keys")
    if (accepted_keys | rejected.keys()) - known or accepted_keys & rejected.keys():
        raise ValueError("Snowflake receipt has unknown or contradictory source event keys; retain the batch for reconciliation")
    if any(not isinstance(reason, str) or not reason.strip() for reason in rejected.values()):
        raise ValueError("Snowflake rejected rows require a reason before reconciliation")
    return BatchOutcome(
        accepted=tuple(key for key in batch.keys if key in accepted_keys),
        rejected=tuple((key, rejected[key]) for key in batch.keys if key in rejected),
        unresolved=tuple(key for key in batch.keys if key not in accepted_keys and key not in rejected),
    )
