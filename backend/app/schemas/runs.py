from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class RunOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    # The jobID: what every event this run produced carries, and what the log is
    # filtered by.
    id: uuid.UUID
    mdm_connection_id: int
    collection_id: int | None
    trigger: str  # sweep | manual | webhook
    comparison: str  # baseline | delta
    lock_class: str  # device_sweep | catalog | webhook
    status: str  # running | succeeded | failed
    window_start: datetime
    window_end: datetime | None
    started_at: datetime
    finished_at: datetime | None
    heartbeat_at: datetime
    device_count: int
    group_count: int
    # Failure accounting (#92): processed + failed = device_count (attempted). A run
    # can be `succeeded` with failures > 0 — isolated device failures inside the
    # sweep's tolerance — which is what "39,998 processed, 2 failed" renders from.
    devices_processed: int
    devices_failed: int
    observations: dict | None
    error: str | None
    actor_label: str | None


class RunLogLineOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    # Monotonic within a run, and the cursor the poller passes back as `after` — the
    # panel asks for what it has not seen rather than re-fetching the whole log every
    # two seconds.
    id: int
    ts: datetime
    level: str
    message: str
    fields: dict | None


class RunLogResponse(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    run: RunOut
    lines: list[RunLogLineOut]
    # The client stops polling on this rather than on an empty page: a run mid-sweep can
    # produce no new lines for a minute and still be very much alive.
    complete: bool
