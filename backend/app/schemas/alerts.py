from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class AlertOut(_Base):
    """One latch, with enough of the device on it to render a row without a second call.

    `device_label` is the device's hostname, joined at read time rather than stored:
    unlike `app_name` and `bundle_id` — which the close *deletes* the source of — the
    device row outlives every alert on it by CASCADE, so denormalising its name would
    only buy a stale one after a rename.
    """

    id: int
    kind: str
    level: str
    device_id: int
    device_label: str
    app_hash: str
    app_name: str
    bundle_id: str
    opened_at: datetime
    closed_at: datetime | None


class AlertListResponse(_Base):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int
