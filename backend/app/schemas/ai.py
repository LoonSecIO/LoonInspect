from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from app.ai.providers import HostReach, Provider, Wire

ReasoningEffort = Literal["none", "minimal", "low", "medium", "high"]


class AITestIn(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    provider: Provider
    # Omitted means the card's default: docker_desktop for a host-local entry,
    # custom otherwise. Reserved values are refused by name (400).
    host_reach: HostReach | None = None
    base_url: str = Field(max_length=512)
    model: str = Field(min_length=1, max_length=200)
    # Request-scoped: never stored, never logged, never echoed back.
    api_key: str | None = Field(default=None, max_length=512)
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
