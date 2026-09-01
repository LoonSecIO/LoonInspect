from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class SmartGroupCriterionOut(_Base):
    """One criterion as Jamf reported it, plus the class its operator falls into.

    `operator` is Jamf's `searchType` verbatim and `operatorClass` is ours; both are
    sent so the page can show what Jamf said next to what we made of it, and so a
    reader can disagree with the classification without having to trust it.
    """

    name: str
    priority: int
    conjunction: str
    operator: str
    operator_class: str
    value: str
    opening_paren: bool
    closing_paren: bool
    depth: int
    extension_attribute: bool


class SmartGroupCostOut(_Base):
    id: str  # the Jamf smart group id
    name: str | None
    mdm_connection_id: int
    band: str
    class_counts: dict[str, int]
    criteria_count: int
    dependent_count: int
    max_depth: int
    criteria: list[SmartGroupCriterionOut]
    # When the ledger first saw this definition and last confirmed it — the group's own
    # cadence, which is finer than the device sweep's (docs/ingest-scheduling.md §3).
    first_observed_at: datetime
    last_observed_at: datetime


class SmartGroupCostResponse(_Base):
    items: list[SmartGroupCostOut]
    total: int
    # The heuristic that produced the order. Stamped so a consumer holding yesterday's
    # answer can tell "the group changed" from "LoonInspect changed its mind".
    ranking: str
    # Repeated in the payload and not only in the docs, because an API consumer that
    # never opens the page is exactly who would otherwise quote this as a measurement.
    advisory: str
