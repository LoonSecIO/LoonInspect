from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from app.ai.providers import HostReach, Provider, Wire

ReasoningEffort = Literal["none", "minimal", "low", "medium", "high"]

# An API key's bound. Enforced in the routes (app.api.ai) rather than by a validator,
# for the sentence: the route's refusal says what to check, where pydantic's would only
# count characters. The schema still states it. Neither refusal carries the key: app.main
# answers a refused body without the values it refused.
API_KEY_MAX_LENGTH = 512


class AITestIn(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    provider: Provider
    # Omitted means the card's default: docker_desktop for a host-local entry,
    # custom otherwise. Reserved values are refused by name (400).
    host_reach: HostReach | None = None
    base_url: str = Field(max_length=512)
    model: str = Field(min_length=1, max_length=200)
    # Request-scoped: never stored, never logged, never echoed back.
    api_key: str | None = Field(default=None, json_schema_extra={"maxLength": API_KEY_MAX_LENGTH})
    prompt: str = Field(min_length=1, max_length=4000)
    reasoning_effort: ReasoningEffort | None = None
    max_tokens: int = Field(default=1024, ge=1, le=4096)


class AIErrorOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    kind: str
    message: str
    status: int | None = None


class AITestOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    provider: Provider
    wire: Wire
    destination: str
    model: str | None
    # answered | empty | budget_exhausted_thinking | error
    outcome: str
    content: str
    reasoning: str | None
    finish_reason: str | None
    completion_tokens: int | None
    latency_ms: int
    error: AIErrorOut | None = None


class AIModelsIn(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    provider: Provider
    host_reach: HostReach | None = None
    base_url: str = Field(max_length=512)
    api_key: str | None = Field(default=None, json_schema_extra={"maxLength": API_KEY_MAX_LENGTH})


class AIModelOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: str
    label: str | None = None


class AIModelsOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    provider: Provider
    wire: Wire
    destination: str
    models: list[AIModelOut]
    latency_ms: int
    error: AIErrorOut | None = None


class ProviderEntryOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    provider: Provider
    wire: Wire
    base_url: str
    model: str
    key: str
    reasoning_effort: str | None
    uses_host_reach: bool
    models: list[str]


class HostReachOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    reach: HostReach
    hostname: str | None
    implemented: bool


class ProvidersOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    entries: list[ProviderEntryOut]
    reaches: list[HostReachOut]
    reasoning_efforts: list[str]


class HostDetectionOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    runtime: str
    host_os: str
    apple_silicon: bool
    alias: str
    alias_resolves: bool
    docker_desktop_on_macos: bool
    evidence: dict[str, str]


class AIConfigIn(BaseModel):
    """A card's Save. The provider is the path."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    host_reach: HostReach | None = None
    base_url: str = Field(max_length=512)
    model: str = Field(min_length=1, max_length=200)
    reasoning_effort: ReasoningEffort | None = None
    # Write-only: stored encrypted, never returned. Omitted or null keeps the stored key.
    api_key: str | None = Field(default=None, json_schema_extra={"maxLength": API_KEY_MAX_LENGTH})
    # Removes the stored key. A key sent beside it replaces the stored one instead.
    clear_key: bool = False


class AIConfigOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    provider: Provider
    host_reach: HostReach | None
    base_url: str
    model: str
    reasoning_effort: str | None
    # Whether a key is stored. The key itself never leaves the server.
    has_key: bool
    updated_at: datetime | None
    updated_by: str | None


class AIConfigsOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    # apple_fm, openai_compatible, anthropic: the cards' order, and the order a feature
    # falls back through.
    configs: list[AIConfigOut]
