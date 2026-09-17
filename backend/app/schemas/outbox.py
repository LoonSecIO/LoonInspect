"""The three states of an outbox event, named once (#468). Nowhere else are they renamed.

**held** — produced, `fanned_out` still false: considered against no enabled destination,
holding no delivery row at all. The ruled onboarding path (`app.core.outbox.fan_out_pending`)
— the stepper calls the destination step optional, so a whole baseline sweep normally lands
before a destination exists. Held events age out on `event_outbox_retention_days` like
everything else, so `oldestAgeSeconds` against that window is the time left to add one.

**pending** — a delivery row still inside the retry envelope, counted in rows rather than
events: one event fanning out to three destinations has three retry histories.

**dead-lettered** — a delivery row that spent all ten attempts and waits for a redrive, and
the orphan a deleted destination leaves behind: failed on the spot, attempts unspent, and on
no destination row for anything else to count. `oldestExpiresAt` is when the oldest stops
being redrivable: its event is kept for `dead_letter_retention_days`, then purged, and the
gap in the trail is permanent after that.

Tenant-wide, never a per-destination breakdown: those rows already are that, and a held event
has none for them to count. The posture tape's `outbox.pending` unions held events with events
holding a pending delivery; this read splits that union where an operator acts, redefining nothing.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class HeldEvents(_CamelModel):
    events: int
    # Absent, never zero, on every age here: `null` is "the set is empty", where `0` would
    # be "produced this second". The tape's rule, on the read side.
    oldest_age_seconds: int | None = None
    # Why, when that is knowable and worth saying. `null` is every hold that resolves on its
    # own — the seconds before the next tick, and the minutes a backlog over `_TICK_LIMIT`
    # spends draining a thousand events at a time. `no_enabled_destination` is the one that
    # does not, and the only one the page speaks a sentence about.
    reason: Literal["no_enabled_destination"] | None = None


class PendingDeliveries(_CamelModel):
    deliveries: int
    oldest_age_seconds: int | None = None


class DeadLetteredDeliveries(_CamelModel):
    deliveries: int
    oldest_expires_at: datetime | None = None


# The two windows and the next purge, so the deadline is readable without the source.
class OutboxRetention(_CamelModel):
    event_retention_days: int
    dead_letter_retention_days: int
    next_purge_at: datetime


class OutboxDepthOut(_CamelModel):
    held: HeldEvents
    pending: PendingDeliveries
    dead_lettered: DeadLetteredDeliveries
    retention: OutboxRetention
