from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class MfaChallengeOut(_CamelModel):
    """What the password step answers with, as HTTP 202, when the account has a second
    factor: a short-lived challenge and the ways to answer it."""

    challenge: str
    methods: list[str]


class MfaLoginRequest(_CamelModel):
    challenge: str = Field(min_length=1, max_length=512)
    # Six digits; spaces are forgiven.
    code: str = Field(min_length=6, max_length=32)
