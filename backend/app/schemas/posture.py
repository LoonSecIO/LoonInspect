from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class PostureRowOut(_Base):
    """One row of the tape as written: one metric, one capture, one population. Deliberately not
    a grid — the table's own grain is the only shape in which a key that recorded nothing is
    *nothing*: no cell, so no zero to fill it with. `full_sweep_run_id` is null once the run is
    purged at 30 days while this row keeps the 12-month history."""

    key: str
    value: float
    captured_at: datetime
    platform: str
    full_sweep_run_id: str | None


class PostureListResponse(_Base):
    items: list[PostureRowOut]
    total: int
    page: int
    page_size: int


class PostureKeyOut(_Base):
    key: str
    status: str
    definition: str


class PostureRegistryOut(_Base):
    """Every key the tape can carry, what a missing one means, and the population written today."""

    keys: list[PostureKeyOut]
    absence: str
    capture_platform: str
