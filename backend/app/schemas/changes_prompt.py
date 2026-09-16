"""The Changes page's Prompt bar on the wire (app.api.changes_prompt)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from app.ai.providers import Provider
from app.schemas.ai import AIErrorOut

# The body's bound. What is sent is shorter still (app.ai.changes_prompt.MAX_QUESTION_CHARS).
QUESTION_MAX_LENGTH = 2000


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class PromptProviderOut(_Base):
    provider: Provider
    model: str


class PromptStatusOut(_Base):
    """Whether the bar is shown, and if not, which switch is why."""

    available: bool
    reason: Literal["flag_off", "consent_off", "no_provider"] | None
    # The saved configs, provider and model only: the bar names where a question goes,
    # and a viewer has no business with the URL or the key.
    providers: list[PromptProviderOut]


class PromptIn(_Base):
    # Bounded in the route rather than by a validator, for the sentences: too long says how
    # much the bar reads, and empty is judged after sanitising ("Type a question first."),
    # where pydantic's refusals would only count characters. The bounds are still stated in
    # the schema. The question is never returned either way (docs/ai-threat-model.md, F5):
    # app.main answers a refused body without the values it refused.
    question: str = Field(json_schema_extra={"minLength": 1, "maxLength": QUESTION_MAX_LENGTH})
    # None asks the first saved config, in the Settings > AI cards' order.
    provider: Provider | None = None
    # The viewer's IANA zone ("America/Chicago"). It never leaves this server: it resolves the
    # start a question's own words ask for, so "today" is the operator's day (#444). Missing, or
    # a name this build's tzdb does not hold, is UTC — never a refusal.
    zone: str | None = Field(default=None, max_length=64)


class PromptFiltersOut(_Base):
    """The Changes page's own URL keys; None is "any" or unset."""

    q: str | None
    artifact: str | None
    level: Literal["low", "normal", "high"] | None
    section: str | None
    change: Literal["added", "removed", "updated", "changed"] | None
    # The start the question's own words asked for, ISO 8601 in UTC, resolved against the
    # viewer's zone (#444) and never written by the model. It rides the page's own `since` URL
    # key, which the Overview's feed has set since #107, and shows as that chip.
    since: str | None = None
    # Dimensions stamped on the row, which the model never names: a repair moved a Search value
    # into one of them when the fleet had no device by that name but did have this (#447). The
    # page has no control for any of them, so an applied one shows as a chip.
    model: str | None = None
    os_version: str | None = None
    department: str | None = None
    managed: str | None = None
    # The department's name as Jamf's catalog holds it, when a repair set `department` — so the
    # readback says "Engineering : Product" rather than an id nobody can act on (#450). Not a
    # URL key: the page's chip reads the same catalog for itself.
    department_name: str | None = None


class PromptDeviceOut(_Base):
    connection_id: int
    subject_id: str
    label: str | None
    serial: str | None
    added: int
    removed: int
    updated: int
    changed: int
    # This computer's newest matching change — the column the list is ordered by, said out
    # loud, so "when did this Mac get it" is answered beside the counts.
    last_observed_at: datetime


class PromptWhenOut(_Base):
    """When the matching changes were observed, and the window the newest one happened in.

    ``observed_at`` is the device's own inventory time (Jamf's reportDate, carried by
    ``device_changes.observed_at``): when the Mac's inventory first held the change, never
    when someone made it. The change happened between the inventory before it and that one,
    so ``previous_observed_at`` — the last inventory time of the span the change moved away
    from — is the other end of the window, and the page states both rather than let an
    observation read as an install (Kyle, 2026-09-15, ruling R1 on #443).

    ``device_time_moved`` is false when the two are equal: the Mac's inventory time did not
    move between the two reads, so nothing on the Mac dated the change — Jamf's own copy
    changed, or the aperture we read it through did. Then only our clock bounds it, and
    ``previous_collected_at`` to ``collected_at`` is the honest window.
    """

    observed_at: datetime
    oldest_observed_at: datetime
    collected_at: datetime
    previous_observed_at: datetime | None
    previous_collected_at: datetime | None
    device_time_moved: bool


class PromptSummaryOut(_Base):
    """What the page will show for the filters, counted by Postgres — never by the model."""

    # Every matching change row.
    total: int
    # Distinct computers among them; `devices` is the newest of them, at most 25.
    devices_total: int
    truncated: bool
    # Matching rows on a smart group or an extension attribute definition.
    other_subjects: int
    devices: list[PromptDeviceOut]
    # When they were observed; None only when nothing matched.
    when: PromptWhenOut | None = None


class PromptOut(_Base):
    # applied (the page runs the filters) | proposed (a repair widened the answer, so the
    # page shows the filters for a person to apply; ruled 1C, #436) | invalid (the question
    # is not one the filters can answer, so nothing runs; `error` carries the reason and the
    # page's sentence) | error (the endpoint failed) | unparseable (it answered, but not
    # filters)
    outcome: Literal["applied", "proposed", "invalid", "error", "unparseable"]
    filters: PromptFiltersOut | None
    # The model's own note on what the filters cannot express. The only model-written
    # text that reaches the page, and the page renders it as text.
    unsupported: str | None
    repairs: list[str]
    # The repairs, of those above, that widened the answer: non-empty exactly when the
    # outcome is `proposed`, and the page's reason for not running the filters.
    widening: list[str] = Field(default_factory=list)
    summary: PromptSummaryOut | None
    provider: Provider
    model: str
    destination: str
    latency_ms: int
    error: AIErrorOut | None = None
