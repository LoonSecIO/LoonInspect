"""The Changes page's Prompt bar on the wire (app.api.changes_prompt)."""

from __future__ import annotations

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


class PromptFiltersOut(_Base):
    """The Changes page's own URL keys; None is "any" or unset."""

    q: str | None
    artifact: str | None
    level: Literal["low", "normal", "high"] | None
    section: str | None
    change: Literal["added", "removed", "updated", "changed"] | None


class PromptDeviceOut(_Base):
    connection_id: int
    subject_id: str
    label: str | None
    serial: str | None
    added: int
    removed: int
    updated: int
    changed: int


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
