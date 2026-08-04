from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class ApiTokenOut(_CamelModel):
    """Everything about a token except the one thing that matters — deliberately.
    The secret exists in a response exactly once, at creation."""

    id: str
    name: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None


class ApiTokenCreated(ApiTokenOut):
    token: str


class ApiTokenCreateRequest(_CamelModel):
    name: str = Field(min_length=1, max_length=255)
    # Empty inherits the creator's current permissions. Anything listed is intersected
    # with them, so this can only ever narrow.
    scopes: list[str] = Field(default_factory=list)
    # Capped at a year: a token that never expires is one nobody ever revisits.
    expires_in_days: int | None = Field(default=None, ge=1, le=365)
