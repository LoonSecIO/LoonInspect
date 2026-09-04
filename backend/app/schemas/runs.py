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


class RunSummaryOut(BaseModel):
    """The three run facts the status strip states about one connection (#105).

    This exists because the obvious client-side answer does not survive the webhook
    path. `ingest_webhook` mints one run row per allowlisted Jamf event (lock class
    `webhook`), runs are kept for `RUN_RETENTION_DAYS` (30), and `/api/runs` caps
    `limit` at 200 — so on a fleet firing ComputerAdded and InventoryCompleted all day
    the last completed full sweep has already fallen off any page the API will serve.
    Filtering a page client-side would make the run segment vanish and the "+N" silently
    undercount on exactly the busy pods where the stamp matters most. So the pinning
    question is answered where the whole run table is in reach.

    Shaped per connection rather than per pod: the strip prints one line per connection,
    and a pod with two Jamf instances has two different last-full-sweeps.
    """

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    mdm_connection_id: int
    # The run the strip's stamp names: the last COMPLETED FULL sweep. Null on a
    # connection that has never finished one — which is a state the strip renders, not
    # an error.
    last_full_sweep: RunOut | None
    # Succeeded webhook sweeps that started after that one finished. This is the clause
    # that makes the stamp honest: the device counts beside it may be newer than the run
    # it names, and the line says so instead of implying the fleet stopped moving at
    # `finished_at`.
    webhook_sweeps_since: int
    # The newest run of any lock class. Carried here so #106's "the latest run failed"
    # row reads a value this page already fetched rather than adding a second run
    # request to the same fifteen-second refresh.
    latest_run: RunOut | None


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
