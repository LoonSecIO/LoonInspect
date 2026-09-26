"""Tenant settings that are typed text (#116) or one word of a few (#653), rather than switches."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from app.core import mfa

# Long enough for a paragraph an auditor reads, short enough that the page header stays a
# header. A policy longer than this is a document, and belongs in one.
STATEMENT_MAX_LENGTH = 4000


class PatchingPolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)

    # "" when the org has stated nothing; the page says so in words rather than showing
    # nothing, so an empty statement and a failed read cannot look alike (#150).
    statement: str = ""
    updated_at: datetime | None = None
    updated_by: str | None = None


class PatchingPolicyUpdate(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    statement: str = Field(max_length=STATEMENT_MAX_LENGTH)


class MfaPolicy(BaseModel):
    """Who must sign in with a second factor (#653); any other word is refused before the row."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    mfa_required: mfa.Policy
